// Package fsx measures disk usage the way APFS allocates it, without following links.
package fsx

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const sfDataless = 0x40000000 // iCloud placeholder: the file content is not on this disk

// Usage is the measured size of one path.
type Usage struct {
	Bytes    int64 // allocated bytes (st_blocks*512), so sparse VM images count as used, not as apparent size
	Files    int64
	Newest   time.Time // newest modification time inside
	Denied   int       // folders the scan could not read (TCC or root-only)
	Dataless int       // iCloud files that use no local space
	Shared   int64     // bytes in files with more than one hard link
	Symlinks int
	Exists   bool
	Skipped  bool // a File Provider folder that the scan must not open
	TimedOut bool
	Cloned   int64 // bytes in large files that share blocks with an APFS clone
	Freeable int64 // what deleting everything would free: Bytes minus clone-shared blocks
}

// providerRoots are File Provider folders (iCloud Drive, Google Drive, Dropbox, OneDrive).
// Opening them can download files or block on a privacy prompt, so the scan never opens them.
var providerRoots = []string{"Library/Mobile Documents", "Library/CloudStorage", "Library/Containers/com.apple.CloudDocs.MobileDocumentsFileProvider"}

// Provider reports whether p is a File Provider folder or is inside one.
func Provider(p, home string) bool {
	for _, r := range providerRoots {
		if Under(p, filepath.Join(home, r)) {
			return true
		}
	}
	return false
}

// Home is the folder that Provider checks against. The scanner sets it once.
var Home string

// MeasureWithin is Measure that gives up only when the walk stalls: no new entry for the stall time.
// A big folder takes as long as it needs; a syscall that blocks for good (a privacy prompt) is abandoned.
func MeasureWithin(root string, stall time.Duration) Usage {
	done := make(chan Usage, 1)
	var seen, bytes atomic.Int64
	go func() { done <- measure(root, &seen, &bytes) }()
	last, lastAt := int64(-1), time.Now()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case u := <-done:
			return u
		case <-tick.C:
			if n := seen.Load(); n != last {
				last, lastAt = n, time.Now()
			} else if time.Since(lastAt) > stall {
				return Usage{Exists: true, TimedOut: true, Bytes: bytes.Load(), Freeable: bytes.Load()}
			}
		}
	}
}

// Measure walks root on one device. Hard links are counted once.
func Measure(root string) Usage { return measure(root, nil, nil) }

func measure(root string, seenN, bytesN *atomic.Int64) Usage {
	var u Usage
	st, err := os.Lstat(root)
	if err != nil {
		return u
	}
	u.Exists = true
	if Home != "" && Provider(root, Home) {
		u.Skipped = true
		return u
	}
	rootSys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return u
	}
	if !st.IsDir() {
		add(&u, root, st, rootSys, nil)
		return u
	}
	seen := map[uint64]bool{}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if seenN != nil {
			seenN.Add(1)
		}
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				u.Denied++
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		sys, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		if d.IsDir() && (sys.Dev != rootSys.Dev || (Home != "" && p != root && Provider(p, Home))) {
			return fs.SkipDir
		}
		before := u.Bytes
		add(&u, p, info, sys, seen)
		if bytesN != nil {
			bytesN.Add(u.Bytes - before)
		}
		return nil
	})
	return u
}

func add(u *Usage, p string, info fs.FileInfo, sys *syscall.Stat_t, seen map[uint64]bool) {
	if info.Mode()&fs.ModeSymlink != 0 {
		u.Symlinks++
	}
	if !info.IsDir() {
		u.Files++
		if sys.Flags&sfDataless != 0 {
			u.Dataless++
		}
		if sys.Nlink > 1 && seen != nil {
			if seen[sys.Ino] {
				return
			}
			seen[sys.Ino] = true
			u.Shared += sys.Blocks * 512
		}
	}
	b := sys.Blocks * 512
	u.Bytes += b
	u.Freeable += b
	if !info.IsDir() && b >= 1<<20 {
		if priv, ok := PrivateSize(p); ok && priv < b {
			u.Cloned += b - priv
			u.Freeable -= b - priv
		}
	}
	if m := info.ModTime(); m.After(u.Newest) && !m.After(time.Now().Add(24*time.Hour)) {
		u.Newest = m
	}
}

// Under reports whether p is root or inside root.
func Under(p, root string) bool {
	return p == root || strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/")
}

// Expand turns a leading ~ into the home folder.
func Expand(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

// Glob expands ~ and wildcards and returns only paths that exist.
func Glob(pattern, home string) []string {
	pattern = Expand(pattern, home)
	if !strings.ContainsAny(pattern, "*?[") {
		if _, err := os.Lstat(pattern); err == nil {
			return []string{pattern}
		}
		return nil
	}
	m, _ := filepath.Glob(pattern)
	return m
}

// Exists reports whether a path exists without following a final symlink.
func Exists(p string) bool { _, err := os.Lstat(p); return err == nil }

// Human formats bytes with binary units.
func Human(b int64) string {
	if b < 1024 {
		return strconv.FormatInt(b, 10) + " B"
	}
	units := []string{"KB", "MB", "GB", "TB"}
	f := float64(b) / 1024
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if f >= 100 {
		return strconv.FormatFloat(f, 'f', 0, 64) + " " + units[i]
	}
	return strconv.FormatFloat(f, 'f', 1, 64) + " " + units[i]
}
