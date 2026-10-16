package scan

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RO-29/spaceaudit/internal/fsx"
	"github.com/RO-29/spaceaudit/internal/model"
	"github.com/RO-29/spaceaudit/internal/probe"
)

type heldFile struct {
	pid  int
	cmd  string
	fd   string
	size int64
	path string
}

type proc struct {
	exe     string
	started time.Time
}

// cause groups deleted-but-open files by why they exist, because each cause has a different fix.
type cause struct {
	key, title, reason, action, restore string
	safety                              model.Safety
	files                               []heldFile
}

// deletedOpen explains deleted files that running programs still hold, grouped by cause and by program.
func (e *Env) deletedOpen() []model.Finding {
	out, err := probe.Run(60*time.Second, "lsof", "-nP", "+L1")
	if err != nil {
		return nil
	}
	var files []heldFile
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 10 || f[4] != "REG" {
			continue
		}
		key := f[5] + ":" + f[8] // one file mapped by many processes counts once
		if seen[key] {
			continue
		}
		seen[key] = true
		size, _ := strconv.ParseInt(f[6], 10, 64)
		pid, _ := strconv.Atoi(f[1])
		files = append(files, heldFile{pid: pid, cmd: f[0], fd: f[3], size: size, path: strings.Join(f[9:], " ")})
	}
	procs := processTable()
	tmp := strings.TrimSuffix(os.TempDir(), "/")
	groups := map[string]*cause{}
	get := func(k string, mk func() *cause) *cause {
		if g, ok := groups[k]; ok {
			return g
		}
		g := mk()
		groups[k] = g
		return g
	}
	for _, h := range files {
		exe := procs[h.pid].exe
		switch {
		case strings.Contains(h.path, ".app/Contents/") && h.fd == "txt" || strings.Contains(h.path, ".app/Contents/Resources/app/"):
			app := appName(h.path)
			get("app:"+app, func() *cause {
				return &cause{key: "updated-app", title: app + " runs an old version after an update", safety: model.Review,
					reason: app + " updated itself while it was running. The old program files are deleted, but the running copy keeps them on disk.",
					action: "Quit " + app + " and open it again. If it shows Restart to Update, use that.", restore: "Nothing to restore: the new version starts."}
			}).files = append(groups["app:"+app].files, h)
		case strings.Contains(h.path, "/.local/share/claude/versions/"):
			get("claude", func() *cause {
				return &cause{key: "old-cli", title: "Claude Code sessions run old versions", safety: model.Review,
					reason: "Claude Code updated itself. Sessions that were open before the update keep running the old binary until they end.",
					action: "Finish and exit these Claude Code sessions when their work is done. New sessions use the new version. Do not kill a session that is working.", restore: "Start a new claude session."}
			}).files = append(groups["claude"].files, h)
		case strings.Contains(h.path, "/extensions/") && (strings.Contains(h.path, "/.vscode") || strings.Contains(h.path, "/.cursor") || strings.Contains(h.path, "/.windsurf")):
			get("ext", func() *cause {
				return &cause{key: "old-extension", title: "Editor extensions run old versions after an update", safety: model.Review,
					reason: "These extensions updated, but the extension host still runs the old binaries.",
					action: "In the editor, run Developer: Reload Window (or quit and open the editor).", restore: "Nothing to restore."}
			}).files = append(groups["ext"].files, h)
		case h.fd != "txt" && (strings.HasPrefix(h.path, tmp) || strings.HasPrefix(h.path, "/private/var/folders/") && strings.Contains(h.path, "/T/")):
			get("tmp", func() *cause {
				return &cause{key: "temp", title: "Temporary files that apps deleted on purpose", safety: model.Keep,
					reason: "Browsers and Electron apps make a temporary file, delete it at once and keep using it. This is normal. The space returns when the app quits.",
					action: "No action is needed. Quitting the app frees it."}
			}).files = append(groups["tmp"].files, h)
		case strings.HasPrefix(h.path, "/System/") || strings.Contains(h.path, "com.apple.LaunchServices") || strings.HasPrefix(h.path, "/private/var/db/") || strings.HasPrefix(exe, "/System/") || strings.HasPrefix(exe, "/usr/libexec/") || !strings.HasPrefix(h.path, "/"):
			get("system", func() *cause {
				return &cause{key: "system", title: "macOS system files held by system services", safety: model.Keep,
					reason: "macOS services keep old copies of system databases (LaunchServices, Spotlight resources). macOS frees them when the services restart.",
					action: "No action is needed. A restart or log out frees it."}
			}).files = append(groups["system"].files, h)
		default:
			get("other", func() *cause {
				return &cause{key: "other", title: "Other deleted files that programs hold open", safety: model.Review,
					reason: "These programs keep files open that were deleted. The space returns when each program closes them.",
					action: "Quit and open each listed program again when its work is done.", restore: "Nothing to restore."}
			}).files = append(groups["other"].files, h)
		}
	}
	var res []model.Finding
	for k, g := range groups {
		var total int64
		for _, h := range g.files {
			total += h.size
		}
		if total < e.Opt.MinBytes {
			continue
		}
		sort.Slice(g.files, func(i, j int) bool { return g.files[i].size > g.files[j].size })
		byPID := map[int]int64{}
		var order []int
		for _, h := range g.files {
			if _, ok := byPID[h.pid]; !ok {
				order = append(order, h.pid)
			}
			byPID[h.pid] += h.size
		}
		sort.Slice(order, func(i, j int) bool { return byPID[order[i]] > byPID[order[j]] })
		var holders []string
		for _, pid := range limitInts(order, 6) {
			p := procs[pid]
			name := filepath.Base(p.exe)
			if name == "." || name == "" {
				name = cmdOf(g.files, pid)
			}
			h := name + " (pid " + strconv.Itoa(pid) + ") holds " + fsx.Human(byPID[pid])
			if !p.started.IsZero() {
				h += ", running for " + runFor(e.Now.Sub(p.started)) + ", since " + p.started.Format("Jan 2 15:04")
			}
			holders = append(holders, h)
		}
		if len(order) > 6 {
			holders = append(holders, strconv.Itoa(len(order)-6)+" more processes")
		}
		var top []string
		for _, h := range g.files[:min(5, len(g.files))] {
			top = append(top, fsx.Human(h.size)+"  "+e.Pretty(h.path)+fdNote(h.fd))
		}
		f := model.Finding{
			ID: id("held", k), Rule: "deleted-open-" + g.key, Category: catSystem, Title: g.title,
			Paths: []string{}, Bytes: total, Files: int64(len(g.files)), Safety: g.safety, Confidence: "high",
			Reasons:  append([]string{g.reason, strconv.Itoa(len(g.files)) + " deleted files in " + strconv.Itoa(len(order)) + " processes."}, holders...),
			Risks:    []string{"Quitting a program ends its current work. Save first."},
			Verify:   []string{"lsof -nP +L1 -p " + joinPIDs(limitInts(order, 6))},
			Commands: []string{g.action},
			Notes:    append([]string{"Largest files:"}, top...),
			Restore:  g.restore,
		}
		if g.safety == model.Keep {
			f.Risks = []string{"Nothing to do. Do not kill system services."}
		}
		res = append(res, f)
	}
	return res
}

func runFor(d time.Duration) string {
	switch {
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + " minutes"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d.Hours())) + " hours"
	}
	return strconv.Itoa(int(d.Hours()/24)) + " days"
}

func fdNote(fd string) string {
	if fd == "txt" {
		return "  (program code in use)"
	}
	return ""
}

// appName returns "Visual Studio Code" for a path inside "/Applications/Visual Studio Code.app/...".
func appName(p string) string {
	i := strings.Index(p, ".app/")
	if i < 0 {
		return "an app"
	}
	return filepath.Base(p[:i])
}

func cmdOf(fs []heldFile, pid int) string {
	for _, f := range fs {
		if f.pid == pid {
			return strings.ReplaceAll(f.cmd, `\x20`, " ")
		}
	}
	return "process"
}

// processTable maps pid to the full program path and start time.
func processTable() map[int]proc {
	out, err := probe.Run(15*time.Second, "ps", "-axo", "pid=,lstart=,comm=")
	m := map[int]proc{}
	if err != nil {
		return m
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		sp := strings.IndexByte(line, ' ')
		if sp < 0 || len(line) < sp+26 {
			continue
		}
		pid, err := strconv.Atoi(line[:sp])
		if err != nil {
			continue
		}
		rest := strings.TrimSpace(line[sp:])
		if len(rest) < 25 {
			continue
		}
		t, _ := time.ParseInLocation("Mon Jan _2 15:04:05 2006", rest[:24], time.Local)
		m[pid] = proc{exe: strings.TrimSpace(rest[24:]), started: t}
	}
	return m
}

func limitInts(s []int, n int) []int {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func joinPIDs(p []int) string {
	s := make([]string, len(p))
	for i, v := range p {
		s[i] = strconv.Itoa(v)
	}
	return strings.Join(s, ",")
}
