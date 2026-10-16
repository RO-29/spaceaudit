package scan

import (
	"crypto/sha1"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RO-29/spaceaudit/internal/fsx"
	"github.com/RO-29/spaceaudit/internal/model"
	"github.com/RO-29/spaceaudit/internal/probe"
)

// Options control one scan.
type Options struct {
	Home       string
	MinBytes   int64         // findings smaller than this are dropped
	LargeBytes int64         // single files or bundles at or above this are listed
	ActiveFor  time.Duration // a project edited within this window counts as active
	StaleAfter time.Duration // a project untouched for this long counts as stale
	Quick      bool          // skip the full home walk
	NoDocker   bool
	Jobs       int
	Progress   func(string)
}

// Env is the shared, read-only state for every rule.
type Env struct {
	Opt    Options
	Home   string
	Now    time.Time
	open   []openFile // sorted by path
	procs  map[int]string
	gitMu  sync.Mutex
	git    map[string]*repoInfo
	Facts  []model.Fact
	Warn   []string
	sizes  sync.Map // path -> fsx.Usage measured during the home walk
	warnMu sync.Mutex
}

type openFile struct {
	path string
	pid  int
}

type repoInfo struct {
	top        string
	lastCommit time.Time
	dirty      int
}

func newEnv(o Options) *Env {
	e := &Env{Opt: o, Home: o.Home, Now: time.Now(), procs: map[int]string{}, git: map[string]*repoInfo{}}
	e.loadOpenFiles()
	return e
}

func (e *Env) warn(s string) {
	e.warnMu.Lock()
	e.Warn = append(e.Warn, s)
	e.warnMu.Unlock()
}

func (e *Env) fact(k, v, note string) {
	e.warnMu.Lock()
	e.Facts = append(e.Facts, model.Fact{Key: k, Value: v, Note: note})
	e.warnMu.Unlock()
}

// loadOpenFiles takes one lsof snapshot of every file and folder this user's processes hold open.
func (e *Env) loadOpenFiles() {
	out, err := probe.Run(90*time.Second, "lsof", "-nP", "-u", strconv.Itoa(os.Getuid()), "-Fpcn")
	if err != nil && out == "" {
		e.warn("lsof failed, so the scan cannot see which folders running programs use: " + err.Error())
		return
	}
	pid := 0
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
		case 'c':
			e.procs[pid] = line[1:]
		case 'n':
			if strings.HasPrefix(line[1:], "/") {
				e.open = append(e.open, openFile{path: line[1:], pid: pid})
			}
		}
	}
	sort.Slice(e.open, func(i, j int) bool { return e.open[i].path < e.open[j].path })
}

// measure reuses a size from the home walk when there is one.
func (e *Env) measure(p string) fsx.Usage {
	if u, ok := e.sizes.Load(p); ok {
		return u.(fsx.Usage)
	}
	return fsx.Measure(p)
}

// UsersOf returns the programs that hold a file open at or below path.
func (e *Env) UsersOf(path string) []string {
	path = strings.TrimSuffix(path, "/")
	i := sort.Search(len(e.open), func(i int) bool { return e.open[i].path >= path })
	seen := map[int]bool{}
	var names []string
	for ; i < len(e.open); i++ {
		p := e.open[i].path
		if p != path && !strings.HasPrefix(p, path+"/") {
			break
		}
		pid := e.open[i].pid
		if pid == os.Getpid() || seen[pid] {
			continue
		}
		seen[pid] = true
		names = append(names, e.procs[pid]+" (pid "+strconv.Itoa(pid)+")")
	}
	return names
}

// AppRunning reports whether a process with one of these command names runs.
func (e *Env) AppRunning(names ...string) string {
	for _, c := range e.procs {
		for _, n := range names {
			if strings.EqualFold(c, n) || (len(n) > 4 && strings.HasPrefix(strings.ToLower(c), strings.ToLower(n))) {
				return c
			}
		}
	}
	return ""
}

// GitTop finds the repository root that contains dir, stopping at the home folder.
func GitTop(dir, home string) string {
	for d := dir; len(d) >= len(home) && d != "/"; d = filepath.Dir(d) {
		if _, err := os.Lstat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		if d == home {
			break
		}
	}
	return ""
}

func (e *Env) repo(top string) *repoInfo {
	e.gitMu.Lock()
	if r, ok := e.git[top]; ok {
		e.gitMu.Unlock()
		return r
	}
	r := &repoInfo{top: top}
	e.git[top] = r
	e.gitMu.Unlock()
	if out, err := probe.Run(15*time.Second, "git", "-C", top, "log", "-1", "--format=%ct"); err == nil {
		if ts, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64); err == nil {
			r.lastCommit = time.Unix(ts, 0)
		}
	}
	if out, err := probe.Run(30*time.Second, "git", "-C", top, "status", "--porcelain", "--untracked-files=no"); err == nil {
		r.dirty = strings.Count(out, "\n")
	}
	return r
}

// Tracked reports whether git tracks any file under path.
func Tracked(top, path string) bool {
	out, err := probe.Run(20*time.Second, "git", "-C", top, "ls-files", "--", path)
	return err == nil && strings.TrimSpace(out) != ""
}

// Ignored reports whether git ignores path.
func Ignored(top, path string) bool {
	_, err := probe.Run(10*time.Second, "git", "-C", top, "check-ignore", "-q", "--", path)
	return err == nil
}

// Q quotes a path for a shell command. Paths in the home folder use "$HOME" so the line stays portable.
func (e *Env) Q(p string) string {
	if rel, ok := strings.CutPrefix(p, e.Home+"/"); ok {
		return `"$HOME"/` + shq(rel)
	}
	return shq(p)
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// Trash returns a Finder command that moves a path to the Trash, or "" when the path cannot be quoted safely.
func Trash(p string) string {
	if strings.ContainsAny(p, "\"\\'\n") {
		return ""
	}
	return `osascript -e 'tell application "Finder" to delete POSIX file "` + p + `"'`
}

// Rm builds the delete command for paths.
func (e *Env) Rm(sudo bool, paths ...string) string {
	q := make([]string, len(paths))
	for i, p := range paths {
		q[i] = e.Q(p)
	}
	cmd := "rm -rf -- " + strings.Join(q, " ")
	if sudo {
		cmd = "sudo " + cmd
	}
	return cmd
}

// Pretty shortens a path for display.
func (e *Env) Pretty(p string) string {
	if rel, ok := strings.CutPrefix(p, e.Home+"/"); ok {
		return "~/" + rel
	}
	return p
}

func id(parts ...string) string {
	h := sha1.Sum([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:6])
}

// Ago writes a duration in days or hours.
func Ago(now, t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	d := now.Sub(t)
	switch {
	case d < 0:
		return "in the future (clock skew)"
	case d < time.Hour:
		return "less than 1 hour ago"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d.Hours())) + " hours ago"
	}
	return strconv.Itoa(int(d.Hours()/24)) + " days ago (" + t.Format("2006-01-02") + ")"
}
