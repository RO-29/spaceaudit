package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/RO-29/spaceaudit/internal/fsx"
	"github.com/RO-29/spaceaudit/internal/model"
	"github.com/RO-29/spaceaudit/internal/probe"
)

// nodeVersions reports Node.js installs that are not the default or the current version.
func (e *Env) nodeVersions() []model.Finding {
	type mgr struct{ name, glob, defFile, uninstall string }
	mgrs := []mgr{
		{"nvm", "~/.nvm/versions/node/*", "~/.nvm/alias/default", "nvm uninstall"},
		{"fnm", "~/.local/share/fnm/node-versions/*", "~/.local/share/fnm/aliases/default", "fnm uninstall"},
		{"fnm", "~/Library/Application Support/fnm/node-versions/*", "~/Library/Application Support/fnm/aliases/default", "fnm uninstall"},
		{"volta", "~/.volta/tools/image/node/*", "", ""},
	}
	current := ""
	if nb := os.Getenv("NVM_BIN"); nb != "" {
		current = filepath.Base(filepath.Dir(nb)) // the version that this shell uses
	}
	var out []model.Finding
	for _, m := range mgrs {
		dirs := fsx.Glob(m.glob, e.Home)
		if len(dirs) < 2 {
			continue
		}
		def := ""
		if m.defFile != "" {
			p := fsx.Expand(m.defFile, e.Home)
			if t, err := os.Readlink(p); err == nil {
				def = filepath.Base(t)
			} else if b, err := os.ReadFile(p); err == nil {
				def = strings.TrimSpace(string(b))
			}
			// An alias such as lts/iron or node points to another alias file.
			for i := 0; i < 3 && def != "" && !strings.ContainsAny(def[:1], "0123456789v"); i++ {
				b, err := os.ReadFile(filepath.Join(filepath.Dir(p), def))
				if err != nil {
					def = "" // unknown default: report nothing rather than a wrong version
					break
				}
				def = strings.TrimSpace(string(b))
			}
			if def == "" {
				continue
			}
		}
		for _, d := range dirs {
			v := filepath.Base(d)
			if v == current || v == def || "v"+def == v || (def != "" && strings.HasPrefix(v, "v"+strings.TrimPrefix(def, "v")+".")) {
				continue
			}
			u := fsx.Measure(d)
			if u.Bytes < e.Opt.MinBytes {
				continue
			}
			globals := 0
			if ents, err := os.ReadDir(filepath.Join(d, "lib/node_modules")); err == nil {
				for _, en := range ents {
					if en.Name() != "npm" && en.Name() != "corepack" && !strings.HasPrefix(en.Name(), ".") {
						globals++
					}
				}
			}
			cmd := m.uninstall + " " + v
			if m.uninstall == "" {
				cmd, _ = e.del(delAuto, d, false) // volta has no command to remove one Node version
			}
			f := model.Finding{
				ID: id("node", d), Rule: "node-version", Category: catDev, Title: m.name + " Node.js " + v, Paths: []string{d},
				Bytes: u.Bytes, Files: u.Files, Safety: model.Review, Confidence: "high", Modified: u.Newest,
				Reasons:  []string{"It is not the default version (" + def + ")" + map[bool]string{true: " and not the version of this shell (" + current + ")", false: ""}[current != ""] + "."},
				Risks:    []string{"A project with .nvmrc, .node-version or engines that names this version needs it."},
				Verify:   []string{"find ~ -maxdepth 4 -path ~/Library -prune -o \\( -name .nvmrc -o -name .node-version \\) -print 2>/dev/null | xargs grep -l " + strings.TrimPrefix(v, "v") + " 2>/dev/null"},
				Commands: []string{cmd},
				Restore:  m.name + " install " + v,
			}
			if globals > 0 {
				f.Risks = append(f.Risks, strconv.Itoa(globals)+" global npm packages are installed in this version. Their commands go away with it.")
			}
			out = append(out, f)
		}
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// sandboxWebCaches covers Chromium caches inside sandboxed app containers, such as new Teams.
func (e *Env) sandboxWebCaches(claimed []string) []model.Finding {
	conts, _ := filepath.Glob(filepath.Join(e.Home, "Library/Containers/*/Data/Library"))
	var out []model.Finding
	for _, lib := range conts {
		var paths []string
		walkDepth(lib, 6, func(p, name string) bool {
			if s, ok := webCacheNames[name]; ok && s == model.Safe && !isClaimed(p, claimed) {
				paths = append(paths, p)
				return true
			}
			return false
		})
		if len(paths) == 0 {
			continue
		}
		u := measureAll(paths)
		if u.Bytes < e.Opt.MinBytes {
			continue
		}
		app := filepath.Base(filepath.Dir(filepath.Dir(lib)))
		r := Rule{ID: "sandbox-web-cache", Category: catBrowser, Title: app + " web caches", Safety: model.Safe,
			Reasons: []string{"These are Chromium HTTP, code and GPU caches inside the app's sandbox. The app rebuilds them."},
			Risks:   []string{"The app starts slower once."},
			Verify:  []string{"du -sh {p}"}, Commands: []string{"{rm}"}, Restore: "The app rebuilds the cache."}
		f := e.build(r, paths, u)
		e.blockApp(&f, filepath.Dir(filepath.Dir(lib)))
		out = append(out, f)
	}
	return out
}

// duplicates finds identical large files. It compares size, then a partial hash, then a full hash.
func (e *Env) duplicates(files []large) []model.Finding {
	bySize := map[int64][]large{}
	repoOf := map[string]bool{}
	for _, f := range files {
		if !e.userOwned(f.path, repoOf) {
			continue
		}
		bySize[f.apparent] = append(bySize[f.apparent], f)
	}
	var groups [][]large
	for size, fs := range bySize {
		if len(fs) < 2 || size == 0 {
			continue
		}
		byPart := map[string][]large{}
		for _, f := range fs {
			if h := hashFile(f.path, 1<<20); h != "" {
				byPart[h] = append(byPart[h], f)
			}
		}
		for _, same := range byPart {
			if len(same) < 2 {
				continue
			}
			byFull := map[string][]large{}
			for _, f := range same {
				if h := hashFile(f.path, -1); h != "" {
					byFull[h] = append(byFull[h], f)
				}
			}
			for _, g := range byFull {
				if len(g) > 1 && !sameInode(g) {
					groups = append(groups, g)
				}
			}
		}
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i][0].bytes*int64(len(groups[i])) > groups[j][0].bytes*int64(len(groups[j]))
	})
	var out []model.Finding
	for _, g := range groups {
		sort.Slice(g, func(i, j int) bool { return g[i].mod.Before(g[j].mod) })
		var paths []string
		for _, f := range g {
			paths = append(paths, f.path)
		}
		var extra int64
		for _, f := range g[1:] {
			if priv, ok := fsx.PrivateSize(f.path); ok {
				extra += priv // a clone of the kept copy frees almost nothing
			} else {
				extra += f.bytes
			}
		}
		if extra < 1<<20 {
			continue // they are APFS clones: deleting copies frees nothing
		}
		var cmds []string
		for _, p := range paths[1:] {
			c, _ := e.del(delAuto, p, false)
			cmds = append(cmds, c+"   # keeps the oldest copy: "+e.Pretty(paths[0]))
		}
		quoted := make([]string, len(paths))
		for i, p := range paths {
			quoted[i] = e.Q(p)
		}
		out = append(out, model.Finding{
			ID: id("dup", strings.Join(paths, "|")), Rule: "duplicate-files", Category: catUser,
			Title: strconv.Itoa(len(g)) + " identical copies of " + filepath.Base(paths[0]), Paths: paths,
			Bytes: extra, Files: int64(len(g) - 1), Safety: model.Review, Confidence: "high", Modified: g[len(g)-1].mod,
			Reasons:  []string{"These files have the same size and the same SHA-256 hash, so their content is identical.", "The size shown is what deleting the extra copies frees, from APFS. Copies that are clones count as zero."},
			Risks:    []string{"An app or a document can expect a file at one of these paths. Keep the copy that you use."},
			Verify:   []string{"shasum -a 256 " + strings.Join(quoted, " ")},
			Commands: cmds,
			Restore:  "Copy the kept file back to the deleted path.",
		})
		if len(out) >= 30 {
			break
		}
	}
	return out
}

// userOwned is true for your own files. Copies inside git trees, hidden tool folders, ~/Library
// and app bundles belong to a repo or an app, and deleting one of them breaks it.
func (e *Env) userOwned(p string, repoOf map[string]bool) bool {
	rel, ok := strings.CutPrefix(p, e.Home+"/")
	if !ok || strings.HasPrefix(rel, "Library/") {
		return false
	}
	for _, part := range strings.Split(filepath.Dir(rel), "/") {
		if (part != "." && strings.HasPrefix(part, ".")) || strings.HasSuffix(part, ".app") {
			return false
		}
	}
	dir := filepath.Dir(p)
	inRepo, seen := repoOf[dir]
	if !seen {
		inRepo = GitTop(dir, e.Home) != ""
		repoOf[dir] = inRepo
	}
	return !inRepo
}

func hashFile(p string, limit int64) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	var r io.Reader = f
	if limit > 0 {
		r = io.LimitReader(f, limit)
	}
	if _, err := io.Copy(h, r); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// sameInode drops groups that are hard links to one file, because they use the space once.
func sameInode(g []large) bool {
	var first uint64
	for i, f := range g {
		var st syscall.Stat_t
		if syscall.Stat(f.path, &st) != nil {
			return false
		}
		if i == 0 {
			first = st.Ino
		} else if st.Ino != first {
			return false
		}
	}
	return true
}

// simRuntimes reads simulator runtimes from simctl. They are disk images under SIP, so only simctl may remove them.
func (e *Env) simRuntimes() []model.Finding {
	out, err := probe.Run(30*time.Second, "xcrun", "simctl", "runtime", "list", "-v")
	if err != nil {
		return nil
	}
	var res []model.Finding
	var name, image, lastUsed, deletable, ident string
	flush := func() {
		if ident == "" || image == "" {
			return
		}
		u := fsx.MeasureWithin(image, time.Minute)
		if u.Bytes < e.Opt.MinBytes {
			return
		}
		used, _ := time.Parse("2006-01-02 15:04:05 -0700", lastUsed)
		when := "Last use is unknown."
		if !used.IsZero() {
			when = "Last used " + Ago(e.Now, used) + "."
		}
		f := model.Finding{
			ID: id("simrt", ident), Rule: "simulator-runtime", Category: catDev, Title: "Simulator runtime " + name, Paths: []string{image},
			Bytes: u.Bytes, Files: 1, Safety: model.Review, Confidence: "high", LastUsed: used, UsedSource: "simctl Last Used At",
			Reasons:  []string{"Xcode keeps each simulator runtime as a disk image. " + when},
			Risks:    []string{"Simulators that use this runtime go away. Never delete the image file: it is under System Integrity Protection and simctl tracks it."},
			Verify:   []string{"xcrun simctl runtime list -v"},
			Commands: []string{"xcrun simctl runtime delete " + ident + "   # or all unused for 90 days: xcrun simctl runtime delete --notUsedSinceDays 90 --dry-run"},
			Restore:  "Xcode > Settings > Components, or xcodebuild -downloadPlatform iOS",
		}
		if deletable == "NO" {
			f.Safety = model.Keep
			f.Commands = []string{"simctl says this runtime is not deletable. Manage it in Xcode > Settings > Components."}
		}
		res = append(res, f)
	}
	for _, r := range parseSimRuntimes(out) {
		name, ident, image, lastUsed, deletable = r.name, r.ident, r.image, r.lastUsed, r.deletable
		flush()
	}
	ident = ""
	flush()
	return res
}

// sandboxCaches covers ~/Library/Containers/<app>/Data/Library/Caches, which the generic rule does not see.
func (e *Env) sandboxCaches(claimed []string) []model.Finding {
	dirs, _ := filepath.Glob(filepath.Join(e.Home, "Library/Containers/*/Data/Library/Caches"))
	return parallel(e.Opt.Jobs, len(dirs), func(i int) *model.Finding {
		d := dirs[i]
		if isClaimed(d, claimed) {
			return nil
		}
		u := fsx.MeasureWithin(d, time.Minute)
		if u.Bytes < e.Opt.MinBytes {
			return nil
		}
		app := filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(d))))
		r := Rule{ID: "sandbox-cache", Category: catBrowser, Title: "Cache of " + app, Safety: model.Review,
			Reasons: []string{"A sandboxed app keeps its cache here. Apps are expected to rebuild their caches."},
			Risks:   []string{"Some apps keep downloads in their cache folder. Check what is inside first."},
			Verify:  []string{"du -sh {p}/*"}, Commands: []string{"{contents}"}, Restore: "The app fills the cache again."}
		if strings.HasPrefix(app, "com.apple.") {
			r.Risks = append(r.Risks, "This is a macOS app. Delete only when it is large, then restart.")
		}
		f := e.build(r, []string{d}, u)
		e.blockApp(&f, filepath.Dir(filepath.Dir(filepath.Dir(d))))
		return &f
	})
}

type simRT struct{ name, ident, image, lastUsed, deletable string }

// parseSimRuntimes reads "xcrun simctl runtime list -v". Formats differ between Xcode versions, so a runtime
// starts at any line that holds its UUID outside a "key: value" field, and its fields are the lines after it.
func parseSimRuntimes(out string) []simRT {
	uuid := regexp.MustCompile(`[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`)
	field := regexp.MustCompile(`^([A-Z][A-Za-z ]{1,30}):\s*(.*)$`)
	var res []simRT
	var cur *simRT
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if m := field.FindStringSubmatch(t); m != nil && cur != nil {
			switch m[1] {
			case "Image Path":
				cur.image = m[2]
			case "Last Used At":
				cur.lastUsed = m[2]
			case "Deletable":
				cur.deletable = m[2]
			}
			continue
		}
		if id := uuid.FindString(t); id != "" {
			res = append(res, simRT{name: strings.TrimSpace(strings.Split(t, " - ")[0]), ident: id})
			cur = &res[len(res)-1]
		}
	}
	return res
}
