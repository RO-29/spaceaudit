package scan

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/RO-29/spaceaudit/internal/fsx"
	"github.com/RO-29/spaceaudit/internal/model"
)

// build turns measured paths plus rule text into one finding, and applies the live blockers.
func (e *Env) build(r Rule, paths []string, u fsx.Usage) model.Finding {
	f := model.Finding{
		ID: id(r.ID, strings.Join(paths, "|")), Rule: r.ID, Category: r.Category, Title: r.Title, Paths: paths,
		Bytes: u.Bytes, Files: u.Files, Safety: r.Safety, Confidence: orDefault(r.Confidence, "high"), Modified: u.Newest,
		Reasons: append([]string{}, r.Reasons...), Risks: append([]string{}, r.Risks...), Restore: r.Restore, NeedsSudo: r.Sudo,
	}
	toolOK := r.Tool == "" || haveTool(r.Tool)
	for _, p := range paths {
		for _, v := range r.Verify {
			f.Verify = append(f.Verify, e.expand(v, p, r.Sudo))
		}
	}
	f.Verify = uniq(f.Verify)
	cmds := r.Commands
	if !toolOK {
		f.Notes = append(f.Notes, r.Tool+" is not installed, so the command falls back to a plain delete.")
		cmds = []string{"{rm}"}
	}
	for _, c := range cmds {
		if strings.Contains(c, "{p}") || strings.Contains(c, "{rm}") || strings.Contains(c, "{contents}") {
			for _, p := range paths {
				f.Commands = append(f.Commands, e.expand(c, p, r.Sudo))
			}
		} else {
			f.Commands = append(f.Commands, c)
		}
	}
	f.Commands = uniq(f.Commands)
	if f.Safety != model.Keep && len(paths) == 1 {
		if t := Trash(paths[0]); t != "" && !r.Sudo {
			f.Alternate = append(f.Alternate, t+"   # moves it to the Trash, so you can undo until you empty the Trash")
		}
	}
	if !u.Newest.IsZero() {
		f.Reasons = append(f.Reasons, "Newest file inside changed "+Ago(e.Now, u.Newest)+".")
	}
	e.annotate(&f, u)
	if app := e.AppRunning(r.Quit...); app != "" && len(r.Quit) > 0 {
		f.Blockers = append(f.Blockers, "Quit "+app+" first. A running program can write here while you delete.")
	}
	for _, p := range paths {
		if users := e.UsersOf(p); len(users) > 0 {
			f.Blockers = append(f.Blockers, "Open now by "+strings.Join(limit(users, 4), ", ")+".")
		}
	}
	if len(f.Blockers) > 0 && f.Safety == model.Safe {
		f.Safety = model.Review
		f.Reasons = append(f.Reasons, "Moved from safe to review because a program uses it now.")
	}
	return f
}

// annotate adds the measurement caveats that change how much space a delete frees.
func (e *Env) annotate(f *model.Finding, u fsx.Usage) {
	if f.Allocated == 0 {
		f.Allocated = u.Bytes
	}
	if u.Cloned > 0 && u.Freeable >= 0 {
		f.Notes = append(f.Notes, fsx.Human(u.Cloned)+" of "+fsx.Human(u.Bytes)+" is shared with APFS clones, so a delete frees about "+fsx.Human(u.Freeable)+". The size shown is that smaller number.")
		f.Bytes = u.Freeable
	}
	if u.TimedOut {
		f.Partial = true
		f.Notes = append(f.Notes, "Measuring stopped because a folder gave no answer for one minute (a privacy prompt or a cloud folder). The real size can be larger.")
	}
	if u.Denied > 0 {
		f.Partial = true
		f.Notes = append(f.Notes, strconv.Itoa(u.Denied)+" folders were not readable, so the real size can be larger. Give Full Disk Access to the terminal or the app and scan again.")
	}
	if u.Shared > 0 {
		f.Notes = append(f.Notes, fsx.Human(u.Shared)+" is in hard-linked files. A delete frees that part only when no other link remains.")
	}
	if u.Dataless > 0 {
		f.Notes = append(f.Notes, strconv.Itoa(u.Dataless)+" iCloud files are online only and use no space on this Mac.")
	}
	if u.Symlinks > 0 {
		f.Notes = append(f.Notes, strconv.Itoa(u.Symlinks)+" symbolic links inside. rm removes the links, never their targets.")
	}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func (e *Env) expand(tmpl, p string, sudo bool) string {
	if strings.Contains(tmpl, "{rm}") {
		c, _ := e.del(delAuto, p, sudo)
		return strings.ReplaceAll(tmpl, "{rm}", c)
	}
	if strings.Contains(tmpl, "{contents}") {
		c, _ := e.del(delContents, p, sudo)
		return strings.ReplaceAll(tmpl, "{contents}", c)
	}
	return strings.ReplaceAll(tmpl, "{p}", e.Q(p))
}

var toolCache sync.Map

func haveTool(n string) bool {
	if v, ok := toolCache.Load(n); ok {
		return v.(bool)
	}
	v := probeHave(n)
	toolCache.Store(n, v)
	return v
}

// staticRules measures every catalog rule and returns the paths it claimed.
func (e *Env) staticRules() ([]model.Finding, []string) {
	var out []model.Finding
	var claimed []string
	type job struct {
		r     Rule
		paths []string
	}
	var jobs []job
	for _, r := range catalog {
		var paths []string
		for _, g := range r.Paths {
			paths = append(paths, fsx.Glob(g, e.Home)...)
		}
		if len(paths) == 0 {
			continue
		}
		claimed = append(claimed, paths...)
		if r.PerPath {
			for _, p := range paths {
				jobs = append(jobs, job{r, []string{p}})
			}
		} else {
			jobs = append(jobs, job{r, paths})
		}
	}
	res := parallel(e.Opt.Jobs, len(jobs), func(i int) *model.Finding {
		j := jobs[i]
		u := measureAll(j.paths)
		if j.r.OlderDays > 0 {
			u = measureOlder(j.paths, e.Now.Add(-time.Duration(j.r.OlderDays)*24*time.Hour))
		}
		if !u.TimedOut && u.Bytes < e.Opt.MinBytes && j.r.Safety != model.Keep {
			return nil
		}
		if !u.TimedOut && u.Bytes < 1<<20 {
			return nil
		}
		f := e.build(j.r, j.paths, u)
		f.OlderDays = j.r.OlderDays
		return &f
	})
	out = append(out, res...)
	return out, claimed
}

const measureLimit = time.Minute // stall limit, not a total limit

func measureAll(paths []string) fsx.Usage {
	var t fsx.Usage
	for _, p := range paths {
		u := fsx.MeasureWithin(p, measureLimit)
		t.TimedOut = t.TimedOut || u.TimedOut
		t.Skipped = t.Skipped || u.Skipped
		t.Bytes += u.Bytes
		t.Files += u.Files
		t.Denied += u.Denied
		t.Dataless += u.Dataless
		t.Shared += u.Shared
		t.Symlinks += u.Symlinks
		t.Cloned += u.Cloned
		t.Freeable += u.Freeable
		if u.Newest.After(t.Newest) {
			t.Newest = u.Newest
		}
	}
	return t
}

// measureOlder counts only files older than cutoff, for rules whose command uses find -mtime.
func measureOlder(paths []string, cutoff time.Time) fsx.Usage {
	var u fsx.Usage
	for _, root := range paths {
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if info, err := d.Info(); err == nil && info.ModTime().Before(cutoff) {
				if sys, ok := info.Sys().(*syscall.Stat_t); ok {
					u.Bytes += sys.Blocks * 512
					u.Files++
				}
			}
			return nil
		})
	}
	return u
}

func isClaimed(p string, claimed []string) bool {
	for _, c := range claimed {
		if fsx.Under(p, c) || fsx.Under(c, p) {
			return true
		}
	}
	return false
}

// cacheChildren covers every folder in ~/Library/Caches and ~/.cache that no specific rule claimed.
func (e *Env) cacheChildren(claimed []string) []model.Finding {
	type item struct{ path, parent string }
	var items []item
	for _, parent := range []string{"~/Library/Caches", "~/.cache"} {
		dir := fsx.Expand(parent, e.Home)
		ents, _ := os.ReadDir(dir)
		for _, en := range ents {
			p := filepath.Join(dir, en.Name())
			if !en.IsDir() || isClaimed(p, claimed) {
				continue
			}
			items = append(items, item{p, parent})
		}
	}
	return parallel(e.Opt.Jobs, len(items), func(i int) *model.Finding {
		it := items[i]
		u := fsx.Measure(it.path)
		if u.Bytes < e.Opt.MinBytes {
			return nil
		}
		name := filepath.Base(it.path)
		if lh := findNamed(it.path, "LocalHistory", 3); lh != "" {
			r := Rule{ID: "cache-folder", Category: catIDE, Title: "Cache: " + name + " (holds IDE local history)", Safety: model.Review,
				Reasons: []string{"An IDE keeps its caches here, and LocalHistory with them."},
				Risks:   []string{e.Pretty(lh) + " can be the only copy of edits that you did not commit. Use the IDE's Invalidate Caches, or keep LocalHistory."},
				Verify:  []string{"du -sh {p}/*"}, Commands: []string{"Use File > Invalidate Caches in the IDE."}}
			f := e.build(r, []string{it.path}, u)
			return &f
		}
		r := Rule{ID: "cache-folder", Category: catBrowser, Title: "Cache: " + name, Safety: model.Safe,
			Reasons: []string{"Programs put data here that they are expected to download or compute again."},
			Risks:   []string{"The program is slower the first time and can ask you to log in again."},
			Verify:  []string{"du -sh {p}/* | sort -h | tail"}, Restore: "The program fills the cache again."}
		r.Commands = []string{"{contents}"}
		if it.parent == "~/.cache" {
			r.Safety = model.Review
			r.Reasons = []string{"Command-line tools keep caches here. Most rebuild, but some tools keep state in ~/.cache by mistake."}
		}
		switch {
		case name == "CloudKit" || name == "com.apple.bird" || strings.HasPrefix(name, "com.apple.Safari"):
			r.Safety = model.Review
			r.Risks = append(r.Risks, "This macOS cache syncs again from iCloud, which takes time and bandwidth.")
		case strings.HasPrefix(name, "com.apple."):
			r.Safety = model.Review
			r.Risks = append(r.Risks, "macOS rebuilds this cache. Delete it only when it is large, and restart after the delete.")
		}
		f := e.build(r, []string{it.path}, u)
		return &f
	})
}

var webCacheNames = map[string]model.Safety{
	"Cache": model.Safe, "Code Cache": model.Safe, "GPUCache": model.Safe, "ShaderCache": model.Safe, "GrShaderCache": model.Safe,
	"GraphiteDawnCache": model.Safe, "DawnGraphiteCache": model.Safe, "DawnWebGPUCache": model.Safe, "component_crx_cache": model.Safe,
	"ScriptCache": model.Review, "CacheStorage": model.Review,
}

// webCacheDeny are apps whose folders can hold real data under a cache-like name.
var webCacheDeny = []string{"Signal", "Telegram Desktop", "Blackmagic Design", "1Password", "Bitwarden", "KeePassXC", "Adobe", "DriveFS", "Obsidian", "Logseq"}

// chromiumProfile reports whether dir looks like a Chromium or Electron profile, so a folder named Cache in it is a web cache.
func chromiumProfile(dir string) bool {
	n := 0
	for _, m := range []string{"Preferences", "Local State", "Local Storage", "Session Storage", "IndexedDB", "Cookies", "Network", "blob_storage", "Code Cache", "GPUCache", "DIPS"} {
		if fsx.Exists(filepath.Join(dir, m)) {
			n++
		}
	}
	return n >= 2
}

// webCaches finds Chromium and Electron cache folders inside each app's Application Support folder.
func (e *Env) webCaches(claimed []string) []model.Finding {
	base := fsx.Expand("~/Library/Application Support", e.Home)
	ents, _ := os.ReadDir(base)
	var apps []string
	for _, en := range ents {
		if en.IsDir() {
			apps = append(apps, filepath.Join(base, en.Name()))
		}
	}
	return parallelMulti(e.Opt.Jobs, len(apps), func(i int) []model.Finding {
		app := apps[i]
		var safe, sw []string
		for _, d := range webCacheDeny {
			if strings.Contains(app, "/"+d) {
				return nil
			}
		}
		walkDepth(app, 5, func(p, name string) bool {
			s, ok := webCacheNames[name]
			if !ok || isClaimed(p, claimed) {
				return false
			}
			if name == "CacheStorage" || name == "ScriptCache" {
				if filepath.Base(filepath.Dir(p)) != "Service Worker" || !chromiumProfile(filepath.Dir(filepath.Dir(p))) {
					return false
				}
				sw = append(sw, p)
				return true
			}
			if name != "component_crx_cache" && !chromiumProfile(filepath.Dir(p)) {
				return false // a folder named Cache in an app that is not Chromium can be real data
			}
			if s == model.Safe {
				safe = append(safe, p)
			}
			return true
		})
		name := filepath.Base(app)
		var fs []model.Finding
		if len(safe) > 0 {
			u := measureAll(safe)
			if u.Bytes >= e.Opt.MinBytes {
				r := Rule{ID: "web-cache", Category: catBrowser, Title: name + " web caches", Safety: model.Safe,
					Reasons: []string{"These are Chromium HTTP, code and GPU caches. The app rebuilds them."},
					Risks:   []string{"The app starts slower once. Logins and settings stay, because they live in other folders."},
					Verify:  []string{"du -sh {p}"}, Commands: []string{"{rm}"}, Restore: "The app rebuilds the cache."}
				f := e.build(r, safe, u)
				e.blockApp(&f, app)
				fs = append(fs, f)
			}
		}
		if len(sw) > 0 {
			u := measureAll(sw)
			if u.Bytes >= e.Opt.MinBytes {
				r := Rule{ID: "service-worker", Category: catBrowser, Title: name + " service worker storage", Safety: model.Review,
					Reasons: []string{"Web apps keep offline copies of their files here."},
					Risks:   []string{"Offline pages and offline mode of web apps go away until you open them online again."},
					Verify:  []string{"du -sh {p}"}, Commands: []string{"{rm}"}, Restore: "Open the web app online."}
				f := e.build(r, sw, u)
				e.blockApp(&f, app)
				fs = append(fs, f)
			}
		}
		return fs
	})
}

// blockApp marks a finding when the app that owns the folder runs now.
func (e *Env) blockApp(f *model.Finding, appDir string) {
	if users := e.UsersOf(appDir); len(users) > 0 && len(f.Blockers) == 0 {
		f.Blockers = append(f.Blockers, "Quit the app first. Open now by "+strings.Join(limit(users, 3), ", ")+".")
		if f.Safety == model.Safe {
			f.Safety = model.Review
		}
	}
}

// findNamed returns the first folder with this name within depth levels, or "".
func findNamed(root, name string, depth int) string {
	found := ""
	walkDepth(root, depth, func(p, n string) bool {
		if found == "" && n == name {
			found = p
		}
		return found != ""
	})
	return found
}

// walkDepth calls fn for each folder up to depth. fn returns true to stop descent into that folder.
func walkDepth(root string, depth int, fn func(p, name string) bool) {
	if depth == 0 {
		return
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, en := range ents {
		if !en.IsDir() || en.Type()&os.ModeSymlink != 0 {
			continue
		}
		p := filepath.Join(root, en.Name())
		if fn(p, en.Name()) {
			continue
		}
		walkDepth(p, depth-1, fn)
	}
}

var editors = []struct{ name, support, ext string }{
	{"VS Code", "Code", "~/.vscode/extensions"},
	{"VS Code Insiders", "Code - Insiders", "~/.vscode-insiders/extensions"},
	{"Cursor", "Cursor", "~/.cursor/extensions"},
	{"Windsurf", "Windsurf", "~/.windsurf/extensions"},
	{"VSCodium", "VSCodium", "~/.vscode-oss/extensions"},
}

// editorLeftovers finds workspace state for folders that no longer exist and extension versions that are not installed.
func (e *Env) editorLeftovers() []model.Finding {
	var out []model.Finding
	for _, ed := range editors {
		ws := filepath.Join(e.Home, "Library/Application Support", ed.support, "User/workspaceStorage")
		ents, err := os.ReadDir(ws)
		if err == nil {
			var orphans []string
			for _, en := range ents {
				dir := filepath.Join(ws, en.Name())
				target, ok := workspaceTarget(dir)
				if ok && target != "" && !fsx.Exists(target) {
					orphans = append(orphans, dir)
				}
			}
			if len(orphans) > 0 {
				u := measureAll(orphans)
				if u.Bytes >= e.Opt.MinBytes {
					r := Rule{ID: "workspace-orphans", Category: catIDE, Title: ed.name + " state for deleted folders", Safety: model.Safe,
						Reasons: []string{strconv.Itoa(len(orphans)) + " workspace state folders point at project folders that no longer exist."},
						Risks:   []string{"Nothing that you can open again uses them. Remote and WSL workspaces are not counted."},
						Quit:    []string{ed.support}, Verify: []string{"cat {p}/workspace.json"}, Commands: []string{"{rm}"}, Restore: "Nothing to restore."}
					out = append(out, e.build(r, orphans, u))
				}
			}
		}
		extDir := fsx.Expand(ed.ext, e.Home)
		if stale := staleExtensions(extDir); len(stale) > 0 {
			u := measureAll(stale)
			if u.Bytes >= e.Opt.MinBytes {
				r := Rule{ID: "old-extensions", Category: catIDE, Title: ed.name + " old extension versions", Safety: model.Safe,
					Reasons: []string{strconv.Itoa(len(stale)) + " extension folders are not in extensions.json, so the editor does not load them. They are old versions left after updates."},
					Quit:    []string{ed.support}, Verify: []string{"ls -d {p}"}, Commands: []string{"{rm}"}, Restore: "Install the extension again from the marketplace."}
				out = append(out, e.build(r, stale, u))
			}
		}
	}
	return out
}

func workspaceTarget(dir string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(dir, "workspace.json"))
	if err != nil {
		return "", false
	}
	var w struct{ Folder, Workspace string }
	if json.Unmarshal(b, &w) != nil {
		return "", false
	}
	uri := w.Folder
	if uri == "" {
		uri = w.Workspace
	}
	pu, err := url.Parse(uri)
	if err != nil || pu.Scheme != "file" {
		return "", false
	}
	return pu.Path, true
}

func staleExtensions(dir string) []string {
	b, err := os.ReadFile(filepath.Join(dir, "extensions.json"))
	if err != nil {
		return nil
	}
	var list []struct {
		RelativeLocation string `json:"relativeLocation"`
		Location         struct {
			Path   string `json:"path"`
			FsPath string `json:"fsPath"`
		} `json:"location"`
	}
	if json.Unmarshal(b, &list) != nil || len(list) == 0 {
		return nil
	}
	live := map[string]bool{}
	for _, x := range list {
		if x.RelativeLocation != "" {
			live[x.RelativeLocation] = true
		}
		for _, p := range []string{x.Location.Path, x.Location.FsPath} {
			if p != "" {
				live[filepath.Base(p)] = true
			}
		}
	}
	ents, _ := os.ReadDir(dir)
	var stale []string
	for _, en := range ents {
		if en.IsDir() && !strings.HasPrefix(en.Name(), ".") && !live[en.Name()] {
			stale = append(stale, filepath.Join(dir, en.Name()))
		}
	}
	return stale
}

func uniq(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func limit(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], "+"+strconv.Itoa(len(s)-n)+" more")
}
