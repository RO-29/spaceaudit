package scan

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RO-29/spaceaudit/internal/fsx"
	"github.com/RO-29/spaceaudit/internal/model"
)

// The inventory explains where space goes per browser, AI tool, language and Downloads category.
// It never adds commands: findings carry the advice, the inventory carries the map.

const invStall = time.Minute

func (e *Env) part(name, path, explain string, s model.Safety) (model.Part, bool) {
	u := fsx.MeasureWithin(path, invStall)
	if !u.Exists {
		return model.Part{}, false
	}
	b := u.Freeable
	if b == 0 {
		b = u.Bytes
	}
	return model.Part{Name: name, Path: path, Bytes: b, Explain: explain, Safety: s, Partial: u.TimedOut || u.Denied > 0}, true
}

func sumParts(ps []model.Part) int64 {
	var t int64
	for _, p := range ps {
		t += p.Bytes
	}
	return t
}

func sortParts(ps []model.Part) {
	sort.Slice(ps, func(i, j int) bool { return ps[i].Bytes > ps[j].Bytes })
}

// ---------- Browsers ----------

type browser struct {
	name, app, data, cache, kind string // kind: chromium, firefox, safari
	proc                         []string
}

var browsers = []browser{
	{"Google Chrome", "Google Chrome", "Library/Application Support/Google/Chrome", "Library/Caches/Google/Chrome", "chromium", []string{"Google Chrome"}},
	{"Chrome Beta", "Google Chrome Beta", "Library/Application Support/Google/Chrome Beta", "Library/Caches/Google/Chrome Beta", "chromium", []string{"Google Chrome Beta"}},
	{"Chrome Canary", "Google Chrome Canary", "Library/Application Support/Google/Chrome Canary", "Library/Caches/Google/Chrome Canary", "chromium", []string{"Google Chrome Canary"}},
	{"Chromium", "Chromium", "Library/Application Support/Chromium", "Library/Caches/Chromium", "chromium", []string{"Chromium"}},
	{"Arc", "Arc", "Library/Application Support/Arc/User Data", "Library/Caches/Arc/User Data", "chromium", []string{"Arc"}},
	{"Dia", "Dia", "Library/Application Support/Dia/User Data", "Library/Caches/Dia/User Data", "chromium", []string{"Dia"}},
	{"Brave", "Brave Browser", "Library/Application Support/BraveSoftware/Brave-Browser", "Library/Caches/BraveSoftware/Brave-Browser", "chromium", []string{"Brave Browser"}},
	{"Microsoft Edge", "Microsoft Edge", "Library/Application Support/Microsoft Edge", "Library/Caches/Microsoft Edge", "chromium", []string{"Microsoft Edge"}},
	{"Vivaldi", "Vivaldi", "Library/Application Support/Vivaldi", "Library/Caches/Vivaldi", "chromium", []string{"Vivaldi"}},
	{"Opera", "Opera", "Library/Application Support/com.operasoftware.Opera", "Library/Caches/com.operasoftware.Opera", "chromium", []string{"Opera"}},
	{"Opera GX", "Opera GX", "Library/Application Support/com.operasoftware.OperaGX", "Library/Caches/com.operasoftware.OperaGX", "chromium", []string{"Opera GX"}},
	{"Comet", "Comet", "Library/Application Support/Comet", "Library/Caches/Comet", "chromium", []string{"Comet"}},
	{"Firefox", "Firefox", "Library/Application Support/Firefox", "Library/Caches/Firefox", "firefox", []string{"firefox"}},
	{"Firefox Developer Edition", "Firefox Developer Edition", "Library/Application Support/Firefox", "Library/Caches/Firefox", "firefox-dev", []string{"firefox"}},
	{"Zen", "Zen", "Library/Application Support/zen", "Library/Caches/zen", "firefox", []string{"zen"}},
	{"LibreWolf", "LibreWolf", "Library/Application Support/librewolf", "Library/Caches/librewolf", "firefox", []string{"librewolf"}},
	{"Floorp", "Floorp", "Library/Application Support/Floorp", "Library/Caches/Floorp", "firefox", []string{"floorp"}},
	{"Waterfox", "Waterfox", "Library/Application Support/Waterfox", "Library/Caches/Waterfox", "firefox", []string{"waterfox"}},
	{"Safari", "Safari", "Library/Safari", "Library/Caches/com.apple.Safari", "safari", []string{"Safari"}},
	{"Orion", "Orion", "Library/Application Support/Orion", "Library/Caches/com.kagi.kagimacOS", "safari", []string{"Orion"}},
}

// chromiumParts explains each folder of a Chromium profile. Safety says what removing that part costs.
var chromiumParts = []struct {
	name, rel, explain string
	safety             model.Safety
}{
	{"Code cache", "Code Cache", "Compiled JavaScript of sites. Rebuilt on the next visit.", model.Safe},
	{"GPU caches", "GPUCache", "Compiled graphics shaders. Rebuilt by itself.", model.Safe},
	{"Service worker storage", "Service Worker", "Offline copies of web apps (Gmail, Docs, Slack web). Removing it breaks offline mode until you visit again.", model.Review},
	{"Site databases (IndexedDB)", "IndexedDB", "Data that sites keep on this Mac: offline mail, documents, drafts. It can be the only copy of unsent work.", model.Risky},
	{"Site storage (Local Storage)", "Local Storage", "Small key-value data of sites: settings and logins.", model.Risky},
	{"Session storage", "Session Storage", "Data of open tabs.", model.Review},
	{"Site file systems", "File System", "Files that web apps store with the File System API.", model.Risky},
	{"Extensions", "Extensions", "Installed extensions. They download again, but their settings live in Local Extension Settings.", model.Keep},
	{"Extension settings", "Local Extension Settings", "Data and settings of extensions (password managers, wallets). Can be unique.", model.Risky},
	{"History", "History", "Your browsing history database.", model.Keep},
	{"Favicons", "Favicons", "Site icons. Rebuilt on visits.", model.Safe},
	{"Top sites and thumbnails", "Top Sites", "New-tab page tiles.", model.Safe},
	{"Cookies", "Cookies", "Logins. Removing it signs you out of every site.", model.Risky},
	{"Sessions", "Sessions", "Tabs to restore after a restart.", model.Review},
	{"Web data (autofill)", "Web Data", "Saved addresses and autofill entries.", model.Keep},
	{"Login data", "Login Data", "Saved passwords (also synced, if sync is on).", model.Keep},
	{"Shared dictionary", "Shared Dictionary", "Compression dictionaries from sites. Rebuilt by itself.", model.Safe},
	{"Network data", "Network", "Cookies and network state on recent versions.", model.Risky},
}

var chromiumRoot = []struct {
	name, rel, explain string
	safety             model.Safety
}{
	{"On-device AI model", "OptGuideOnDeviceModel", "Gemini Nano for built-in AI features. Turn off On-device AI in Settings > System to remove it.", model.Review},
	{"Profile snapshots", "Snapshots", "Copies of profiles that the browser keeps before a major update, for rollback.", model.Review},
	{"Component downloads", "component_crx_cache", "Downloaded browser components. They download again.", model.Safe},
	{"Speech packs (SODA)", "SODALanguagePacks", "Live caption speech models.", model.Review},
	{"Safe Browsing lists", "Safe Browsing", "Phishing and malware lists. They update by themselves.", model.Safe},
	{"Crash reports", "Crashpad", "Old crash reports.", model.Safe},
	{"Graphics shader cache", "GrShaderCache", "Compiled shaders. Rebuilt by itself.", model.Safe},
	{"Graphics cache", "GraphiteDawnCache", "Compiled shaders. Rebuilt by itself.", model.Safe},
}

func (e *Env) browserInventory() model.Inventory {
	inv := model.Inventory{Key: "browsers", Title: "Browsers and profiles",
		Intro: "Every browser that is installed or has data here, with each profile and what its folders hold. Caches rebuild by themselves; site data, cookies and extension settings can hold logins and unique work."}
	seen := map[string]bool{}
	for _, b := range browsers {
		data := filepath.Join(e.Home, b.data)
		appPath := ""
		for _, d := range []string{"/Applications", filepath.Join(e.Home, "Applications")} {
			if fsx.Exists(filepath.Join(d, b.app+".app")) {
				appPath = filepath.Join(d, b.app+".app")
			}
		}
		if b.kind == "firefox-dev" {
			if appPath == "" {
				continue
			}
			b.kind = "firefox"
		}
		if seen[data] && b.kind == "firefox" {
			continue // Firefox and its Developer Edition share one profile folder
		}
		if appPath == "" && !fsx.Exists(data) {
			continue
		}
		seen[data] = true
		it := model.InvItem{Name: b.name, Path: data, Installed: appPath != "", App: appPath}
		if r := e.AppRunning(b.proc...); r != "" {
			it.Running = true
		}
		switch b.kind {
		case "chromium":
			e.chromium(&it, b)
		case "firefox":
			e.firefox(&it, b)
		case "safari":
			e.webkit(&it, b)
		}
		for _, g := range it.Groups {
			it.Bytes += g.Bytes
		}
		it.Bytes += sumParts(it.Parts)
		if appPath != "" {
			if u := fsx.MeasureWithin(appPath, invStall); u.Exists {
				it.AppBytes = u.Bytes
			}
		}
		if !it.Installed && it.Bytes < 1<<20 {
			continue // an empty data folder of a browser that is not installed
		}
		if !it.Installed && it.Bytes > 0 {
			it.Notes = append(it.Notes, "The app is not installed, but its data is still here. If you do not use it again, its whole data folder is leftover.")
		}
		if it.Running {
			it.Notes = append(it.Notes, "The browser runs now. Quit it before you clear any of its folders.")
		}
		inv.Items = append(inv.Items, it)
		inv.Bytes += it.Bytes
	}
	sort.Slice(inv.Items, func(i, j int) bool { return inv.Items[i].Bytes > inv.Items[j].Bytes })
	return inv
}

// chromiumProfiles reads profile folders and their display names from Local State.
func chromiumProfiles(data string) [][2]string {
	names := map[string]string{}
	if b, err := os.ReadFile(filepath.Join(data, "Local State")); err == nil {
		var ls struct {
			Profile struct {
				InfoCache map[string]struct {
					Name     string `json:"name"`
					UserName string `json:"user_name"`
				} `json:"info_cache"`
			} `json:"profile"`
		}
		if json.Unmarshal(b, &ls) == nil {
			for dir, v := range ls.Profile.InfoCache {
				n := v.Name
				if v.UserName != "" && v.UserName != n {
					n += " (" + v.UserName + ")"
				}
				names[dir] = n
			}
		}
	}
	var out [][2]string
	ents, _ := os.ReadDir(data)
	for _, en := range ents {
		n := en.Name()
		if en.IsDir() && (n == "Default" || strings.HasPrefix(n, "Profile ") || n == "Guest Profile") {
			out = append(out, [2]string{n, names[n]})
		}
	}
	return out
}

func (e *Env) chromium(it *model.InvItem, b browser) {
	data := filepath.Join(e.Home, b.data)
	cache := filepath.Join(e.Home, b.cache)
	for _, pr := range chromiumProfiles(data) {
		dir := filepath.Join(data, pr[0])
		g := model.InvGroup{Name: orDefault(pr[1], pr[0]), Path: dir, Note: "Folder: " + pr[0]}
		if p, ok := e.part("HTTP cache", filepath.Join(cache, pr[0], "Cache"), "Downloaded pages, images and scripts. Rebuilt on the next visit. Chromium on macOS keeps it in ~/Library/Caches.", model.Safe); ok {
			g.Parts = append(g.Parts, p)
		}
		if p, ok := e.part("Code cache (Caches)", filepath.Join(cache, pr[0], "Code Cache"), "Compiled JavaScript of sites. Rebuilt on the next visit.", model.Safe); ok {
			g.Parts = append(g.Parts, p)
		}
		var known int64
		for _, cp := range chromiumParts {
			if p, ok := e.part(cp.name, filepath.Join(dir, cp.rel), cp.explain, cp.safety); ok && p.Bytes > 0 {
				if cp.rel == "Extensions" {
					p.Top = extensionNames(filepath.Join(dir, "Extensions"), 6)
				}
				g.Parts = append(g.Parts, p)
				known += p.Bytes
			}
		}
		if u := fsx.MeasureWithin(dir, invStall); u.Exists && u.Bytes > known {
			g.Parts = append(g.Parts, model.Part{Name: "Other profile data", Path: dir, Bytes: u.Bytes - known, Explain: "Settings, bookmarks, permissions and smaller databases.", Safety: model.Keep})
		}
		sortParts(g.Parts)
		g.Bytes = sumParts(g.Parts)
		it.Groups = append(it.Groups, g)
	}
	sort.Slice(it.Groups, func(i, j int) bool { return it.Groups[i].Bytes > it.Groups[j].Bytes })
	for _, rp := range chromiumRoot {
		if p, ok := e.part(rp.name, filepath.Join(data, rp.rel), rp.explain, rp.safety); ok && p.Bytes > 0 {
			it.Parts = append(it.Parts, p)
		}
	}
	sortParts(it.Parts)
}

func (e *Env) firefox(it *model.InvItem, b browser) {
	data := filepath.Join(e.Home, b.data)
	names := map[string]string{}
	if f, err := os.Open(filepath.Join(data, "profiles.ini")); err == nil {
		sc := bufio.NewScanner(f)
		var name string
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if v, ok := strings.CutPrefix(l, "Name="); ok {
				name = v
			}
			if v, ok := strings.CutPrefix(l, "Path="); ok {
				names[filepath.Base(v)] = name
			}
		}
		f.Close()
	}
	profs, _ := filepath.Glob(filepath.Join(data, "Profiles", "*"))
	for _, dir := range profs {
		id := filepath.Base(dir)
		g := model.InvGroup{Name: orDefault(names[id], id), Path: dir, Note: "Folder: " + id}
		if p, ok := e.part("HTTP cache", filepath.Join(e.Home, b.cache, "Profiles", id, "cache2"), "Downloaded pages and images. Rebuilt on the next visit.", model.Safe); ok {
			g.Parts = append(g.Parts, p)
		}
		var known int64
		for _, fp := range []struct {
			name, rel, explain string
			s                  model.Safety
		}{
			{"Site data", "storage", "IndexedDB, cache storage and local storage of sites. Can hold offline work.", model.Risky},
			{"History and bookmarks", "places.sqlite", "Your history and bookmarks.", model.Keep},
			{"Favicons", "favicons.sqlite", "Site icons.", model.Safe},
			{"Extensions", "extensions", "Installed add-ons.", model.Keep},
			{"Session backups", "sessionstore-backups", "Tabs to restore.", model.Review},
			{"Crash reports", "crashes", "Old crash reports.", model.Safe},
			{"Telemetry", "datareporting", "Usage reports waiting to be sent.", model.Safe},
			{"Startup cache", "startupCache", "Rebuilt at start.", model.Safe},
		} {
			if p, ok := e.part(fp.name, filepath.Join(dir, fp.rel), fp.explain, fp.s); ok && p.Bytes > 0 {
				g.Parts = append(g.Parts, p)
				known += p.Bytes
			}
		}
		if u := fsx.MeasureWithin(dir, invStall); u.Exists && u.Bytes > known {
			g.Parts = append(g.Parts, model.Part{Name: "Other profile data", Path: dir, Bytes: u.Bytes - known, Explain: "Passwords (logins.json, key4.db), cookies, settings.", Safety: model.Keep})
		}
		sortParts(g.Parts)
		g.Bytes = sumParts(g.Parts)
		it.Groups = append(it.Groups, g)
	}
	sort.Slice(it.Groups, func(i, j int) bool { return it.Groups[i].Bytes > it.Groups[j].Bytes })
}

func (e *Env) webkit(it *model.InvItem, b browser) {
	for _, p := range []struct {
		name, rel, explain string
		s                  model.Safety
	}{
		{"History, bookmarks, reading list", b.data, "Safari's own data. macOS protects it: without Full Disk Access the size shows as small.", model.Keep},
		{"Cache", b.cache, "Downloaded pages. Use Develop > Empty Caches.", model.Safe},
		{"Sandboxed cache", "Library/Containers/com.apple.Safari/Data/Library/Caches", "Pages and previews.", model.Safe},
		{"Website data", "Library/Containers/com.apple.Safari/Data/Library/WebKit", "Site storage and databases. Remove per site in Settings > Privacy > Manage Website Data.", model.Risky},
		{"Profiles", "Library/Containers/com.apple.Safari/Data/Library/Safari/Profiles", "Data of Safari profiles (Safari 17 and later).", model.Keep},
	} {
		if part, ok := e.part(p.name, filepath.Join(e.Home, p.rel), p.explain, p.s); ok && part.Bytes > 0 {
			it.Parts = append(it.Parts, part)
		}
	}
	sortParts(it.Parts)
}

// ---------- AI tools ----------

type aiTool struct {
	name, kind string // kind: CLI agent, desktop app, editor, local models
	roots      []string
	explain    map[string]string // sub-folder -> what it holds
	proc       []string
}

var aiTools = []aiTool{
	{"Claude Code", "CLI agent", []string{".claude", ".local/share/claude", "Library/Caches/claude-cli-nodejs"}, map[string]string{
		"projects": "review|Session transcripts (.jsonl) per project, and each project's memory/ folder. claude --resume needs them.",
		"versions": "review|Installed Claude Code binaries. Old versions stay after updates while a session still runs them.",
		"todos":    "Todo lists of past sessions.", "shell-snapshots": "review|Shell environment snapshots of sessions.", "plugins": "keep|Installed plugins and marketplaces.",
		"statsig": "safe|Feature flag cache.", "ide": "safe|IDE connection lock files.", "file-history": "review|Backups of files that Claude edited, for undo and rewind.", "debug": "safe|Debug logs.",
		"local": "keep|A local npm install of Claude Code.", "skills": "keep|Your skills.", "agents": "keep|Your subagent definitions.", "commands": "keep|Your slash commands.", "hooks": "keep|Your hooks.",
		"session-env": "review|Per-session environment.", "jobs": "review|Output of background jobs and tasks that sessions started.",
		"ClaudeCode.app": "keep|The native Claude Code app bundle that the installer keeps.", "backups": "review|Backups of ~/.claude.json.", "cache": "safe|Cache.", "paste-cache": "review|Text and images that you pasted into sessions.", "image-cache": "review|Images from sessions.", "telemetry": "safe|Telemetry waiting to be sent.",
	}, []string{"claude"}},
	{"Claude desktop", "desktop app", []string{"Library/Application Support/Claude", "Library/Logs/Claude", "Library/Caches/com.anthropic.claudefordesktop"}, map[string]string{
		"vm_bundles": "review|Virtual machine images for computer use.", "claude-code": "keep|The Claude Code that the desktop app bundles.", "Cache": "safe|Web cache.", "Code Cache": "safe|Compiled scripts cache.",
		"IndexedDB": "keep|Local app data.", "Local Storage": "keep|Local app settings.",
	}, []string{"Claude"}},
	{"Codex", "CLI agent", []string{".codex", "Library/Application Support/Codex"}, map[string]string{
		"sessions": "review|Session logs. codex resume needs them.", "packages": "review|Packaged runtimes and tools that Codex installed.", "plugins": "keep|Plugins.", ".tmp": "safe|Temporary files.",
		"cache": "safe|Cache.", "log": "safe|Logs.", "computer-use": "keep|Computer use helpers.", "generated_images": "keep|Images that Codex made.", "vendor_imports": "keep|Vendored imports.",
	}, []string{"codex"}},
	{"ChatGPT desktop", "desktop app", []string{"Library/Application Support/com.openai.chat", "Library/Caches/com.openai.chat"}, nil, []string{"ChatGPT"}},
	{"Cursor", "editor", []string{"Library/Application Support/Cursor", ".cursor", ".local/share/cursor-agent"}, map[string]string{
		"User": "review|Settings, chat history (globalStorage/state.vscdb) and per-workspace state.", "CachedData": "safe|Compiled code cache, also of old versions. The editor rebuilds it.", "logs": "safe|Logs.",
		"extensions": "keep|Installed extensions.", "versions": "review|cursor-agent CLI versions. Old versions stay after updates.", "CachedExtensionVSIXs": "safe|Copies of extension installers that are already installed.",
	}, []string{"Cursor"}},
	{"Windsurf", "editor", []string{"Library/Application Support/Windsurf", ".windsurf", ".codeium"}, nil, []string{"Windsurf"}},
	{"Kiro", "editor", []string{"Library/Application Support/Kiro", ".kiro"}, nil, []string{"Kiro"}},
	{"Zed", "editor", []string{"Library/Application Support/Zed", "Library/Caches/Zed"}, map[string]string{
		"languages": "safe|Language servers that Zed downloaded. It downloads them again.", "node": "safe|Node.js that Zed downloaded. It downloads it again.", "extensions": "keep|Extensions.", "conversations": "review|AI chat history.",
	}, []string{"zed"}},
	{"OpenCode", "CLI agent", []string{".local/share/opencode", ".config/opencode", ".cache/opencode"}, map[string]string{
		"storage": "review|Sessions and messages.", "log": "safe|Logs.", "bin": "keep|Downloaded tools.", "node_modules": "keep|Plugins and providers.",
	}, []string{"opencode"}},
	{"OpenClaw", "CLI agent", []string{".openclaw"}, map[string]string{"skills": "keep|Installed skills.", "sessions": "review|Session history.", "logs": "safe|Logs.", "workspace": "keep|Agent workspace files."}, []string{"openclaw"}},
	{"pi coding agent", "CLI agent", []string{".pi"}, map[string]string{"agent": "review|Sessions and settings."}, []string{"pi"}},
	{"Gemini CLI", "CLI agent", []string{".gemini"}, map[string]string{"tmp": "review|Chat checkpoints and session data.", "extensions": "keep|Extensions."}, []string{"gemini"}},
	{"Hermes agent", "CLI agent", []string{".hermes"}, map[string]string{"hermes-agent": "keep|The agent's code and its Python environment.", "skills": "keep|Installed skills.", "bin": "keep|Commands.", "sessions": "review|Session history.", "logs": "safe|Logs."}, []string{"hermes"}},
	{"Amp", "CLI agent", []string{".amp", ".config/amp", ".local/share/amp", ".cache/amp"}, nil, []string{"amp"}},
	{"Aider", "CLI agent", []string{".aider"}, map[string]string{"caches": "safe|Repository map caches."}, []string{"aider"}},
	{"Goose", "CLI agent", []string{".config/goose", ".local/share/goose"}, map[string]string{"sessions": "review|Session history."}, []string{"goose"}},
	{"Crush", "CLI agent", []string{".local/share/crush", ".config/crush"}, nil, []string{"crush"}},
	{"Continue", "editor extension", []string{".continue"}, map[string]string{"index": "safe|Code index for search. Continue rebuilds it.", "sessions": "review|Chat history."}, nil},
	{"GitHub Copilot", "editor extension", []string{".config/github-copilot"}, nil, nil},
	{"Ollama", "local models", []string{".ollama"}, map[string]string{"models": "review|Model weights. ollama rm removes one."}, []string{"ollama"}},
	{"LM Studio", "local models", []string{".lmstudio", ".cache/lm-studio"}, map[string]string{"models": "review|Model weights.", "extensions": "review|Runtimes (llama.cpp, MLX) that LM Studio downloaded."}, []string{"LM Studio"}},
	{"Jan", "local models", []string{"Library/Application Support/Jan"}, nil, []string{"Jan"}},
	{"Hugging Face cache", "local models", []string{".cache/huggingface"}, map[string]string{"hub": "review|Model and dataset downloads. Large to download again.", "xet": "safe|Xet transfer cache."}, nil},
}

// editorAgents are AI extensions inside VS Code-family editors, by globalStorage folder.
var editorAgents = map[string]string{
	"saoudrizwan.claude-dev": "Cline", "rooveterinaryinc.roo-cline": "Roo Code", "kilocode.kilo-code": "Kilo Code", "anthropic.claude-code": "Claude Code extension",
	"github.copilot": "GitHub Copilot", "github.copilot-chat": "GitHub Copilot Chat", "continue.continue": "Continue", "codeium.codeium": "Codeium",
	"openai.chatgpt": "Codex extension", "google.geminicodeassist": "Gemini Code Assist", "amazonwebservices.amazon-q-vscode": "Amazon Q",
}

func (e *Env) aiInventory() model.Inventory {
	inv := model.Inventory{Key: "ai", Title: "AI agents, editors and local models",
		Intro: "Every AI tool with data here, split into its folders. Session history is your record of past work; versions, caches and logs come back by themselves; model weights download again but are large."}
	for _, t := range aiTools {
		var parts []model.Part
		for _, r := range t.roots {
			root := filepath.Join(e.Home, r)
			st, err := os.Lstat(root)
			if err != nil {
				continue
			}
			if !st.IsDir() {
				if p, ok := e.part(e.Pretty(root), root, "", model.Keep); ok {
					parts = append(parts, p)
				}
				continue
			}
			ents, _ := os.ReadDir(root)
			var files int64
			for _, en := range ents {
				p := filepath.Join(root, en.Name())
				if !en.IsDir() {
					if info, err := en.Info(); err == nil {
						files += info.Size()
					}
					continue
				}
				s, ex := model.Keep, "No description for this folder yet. Treat it as data and check it before you change anything."
				if v, ok := t.explain[en.Name()]; ok {
					lvl, text, _ := strings.Cut(v, "|")
					s, ex = model.Safety(lvl), text
				}
				if part, ok := e.part(e.Pretty(p), p, ex, s); ok && part.Bytes > 0 {
					if part.Bytes >= 100<<20 {
						part.Top = e.largestChildren(p, 5)
					}
					parts = append(parts, part)
				}
			}
			if files > 0 {
				parts = append(parts, model.Part{Name: e.Pretty(root) + " (files)", Path: root, Bytes: files, Explain: "Settings and state files.", Safety: model.Keep})
			}
		}
		if len(parts) == 0 {
			continue
		}
		sortParts(parts)
		it := model.InvItem{Name: t.name, Kind: t.kind, Parts: parts, Bytes: sumParts(parts), Path: filepath.Join(e.Home, t.roots[0])}
		inUse := false
		for _, r := range t.roots {
			if len(e.UsersOf(filepath.Join(e.Home, r))) > 0 {
				inUse = true // a process holds a file open here, even when its name is a version number
			}
		}
		if inUse || (len(t.proc) > 0 && e.AppRunning(t.proc...) != "") {
			it.Running = true
			it.Notes = append(it.Notes, "It runs now. Do not touch its folders while it runs.")
		}
		inv.Items = append(inv.Items, it)
		inv.Bytes += it.Bytes
	}
	for _, ed := range editors {
		gs := filepath.Join(e.Home, "Library/Application Support", ed.support, "User/globalStorage")
		ents, _ := os.ReadDir(gs)
		for _, en := range ents {
			name, ok := editorAgents[strings.ToLower(en.Name())]
			if !ok {
				continue
			}
			p, ok2 := e.part(e.Pretty(filepath.Join(gs, en.Name())), filepath.Join(gs, en.Name()), "Task history, checkpoints and settings of this extension. Task history can be large: clear old tasks inside the extension.", model.Review)
			if !ok2 || p.Bytes == 0 {
				continue
			}
			it := model.InvItem{Name: name + " (in " + ed.name + ")", Kind: "editor extension", Parts: []model.Part{p}, Bytes: p.Bytes, Path: p.Path}
			inv.Items = append(inv.Items, it)
			inv.Bytes += it.Bytes
		}
	}
	sort.Slice(inv.Items, func(i, j int) bool { return inv.Items[i].Bytes > inv.Items[j].Bytes })
	return inv
}

// ---------- Languages ----------

type langStore struct {
	name, path, explain string
	s                   model.Safety
}

var languages = []struct {
	name, intro string
	stores      []langStore
	artifacts   []string
}{
	{"JavaScript / TypeScript", "Packages in each project, the package manager caches, and Node.js versions.", []langStore{
		{"npm cache", ".npm", "Package tarballs. npm cache clean --force.", model.Safe},
		{"Yarn cache", "Library/Caches/Yarn", "Yarn v1 cache.", model.Safe}, {"Yarn Berry cache", ".yarn/berry", "Yarn 2+ global cache.", model.Safe},
		{"pnpm store", "Library/pnpm", "Content-addressed store. Projects hard-link into it: use pnpm store prune.", model.Safe},
		{"Bun", ".bun", "Bun binary and install cache.", model.Review}, {"Corepack", ".cache/node/corepack", "Package manager binaries that Corepack downloaded.", model.Safe},
		{"nvm Node versions", ".nvm/versions", "Each Node version with its global packages.", model.Review}, {"fnm Node versions", ".local/share/fnm", "Node versions.", model.Review},
		{"Volta", ".volta", "Node versions and tools.", model.Review}, {"node-gyp headers", "Library/Caches/node-gyp", "Headers for native modules.", model.Safe},
		{"Electron downloads", "Library/Caches/electron", "Electron binaries.", model.Safe}, {"Playwright browsers", "Library/Caches/ms-playwright", "Test browsers.", model.Safe},
		{"Cypress", "Library/Caches/Cypress", "Test runners.", model.Safe}, {"Deno", "Library/Caches/deno", "Deno module cache.", model.Safe},
	}, []string{"node_modules", ".next", ".nuxt", ".svelte-kit", ".turbo", ".nx", ".parcel-cache", ".angular", ".expo", "dist", "out", "coverage", ".vercel", ".serverless"}},
	{"Python", "Virtual environments, caches and interpreter versions.", []langStore{
		{"pip cache", "Library/Caches/pip", "Downloaded wheels. pip3 cache purge.", model.Safe}, {"uv", ".cache/uv", "uv cache. uv cache prune.", model.Safe},
		{"uv Pythons", ".local/share/uv", "Python versions and tools that uv installed.", model.Review}, {"Poetry", "Library/Caches/pypoetry", "Poetry cache and virtualenvs.", model.Review},
		{"pyenv", ".pyenv/versions", "Python versions that pyenv built.", model.Review}, {"pipx", ".local/pipx", "Tools installed with pipx.", model.Keep},
		{"Conda (miniconda3)", "miniconda3", "Conda base, envs and package cache.", model.Review}, {"Conda (anaconda3)", "anaconda3", "Conda base, envs and package cache.", model.Review},
		{"Conda (miniforge3)", "miniforge3", "Conda base, envs and package cache.", model.Review}, {"Jupyter", "Library/Jupyter", "Kernels and runtime files.", model.Keep},
		{"PyTorch hub", ".cache/torch", "Downloaded models.", model.Review},
	}, []string{".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox"}},
	{"Go", "The module and build caches, and installed tools.", []langStore{
		{"Module cache", "go/pkg/mod", "Downloaded modules. go clean -modcache.", model.Review}, {"Build cache", "Library/Caches/go-build", "Compiled packages. go clean -cache.", model.Safe},
		{"Installed tools", "go/bin", "Commands from go install.", model.Keep}, {"Go SDKs", "sdk", "Extra Go versions from golang.org/dl.", model.Review},
		{"golangci-lint", "Library/Caches/golangci-lint", "Lint cache.", model.Safe},
	}, nil},
	{"Rust", "Toolchains, the crate registry and build output.", []langStore{
		{"Toolchains", ".rustup/toolchains", "Installed Rust toolchains.", model.Review}, {"Crate registry", ".cargo/registry", "Downloaded crates.", model.Safe},
		{"Git checkouts", ".cargo/git", "Git dependencies.", model.Safe}, {"Installed tools", ".cargo/bin", "Commands from cargo install.", model.Keep},
		{"sccache", "Library/Caches/Mozilla.sccache", "Compiler cache.", model.Safe},
	}, []string{"target"}},
	{"Java / Kotlin / Scala", "Build tool caches and JDKs.", []langStore{
		{"Maven repository", ".m2/repository", "Downloaded artifacts and your mvn install builds.", model.Review}, {"Gradle", ".gradle", "Gradle caches, wrappers and daemons.", model.Safe},
		{"Ivy", ".ivy2", "sbt and Ivy caches.", model.Safe}, {"sbt", ".sbt", "sbt boot and caches.", model.Safe}, {"Coursier", "Library/Caches/Coursier", "Scala dependency cache.", model.Safe},
		{"Kotlin/Native", ".konan", "Kotlin/Native toolchain.", model.Review}, {"JDKs (yours)", "Library/Java/JavaVirtualMachines", "JDKs that you installed for your user.", model.Review},
	}, []string{".gradle"}},
	{"Swift / Apple platforms", "Xcode build data, packages and simulators.", []langStore{
		{"DerivedData", "Library/Developer/Xcode/DerivedData", "Build output. Rebuilt by Xcode.", model.Safe}, {"Archives", "Library/Developer/Xcode/Archives", "Shipped builds with dSYMs.", model.Risky},
		{"Device support", "Library/Developer/Xcode/iOS DeviceSupport", "Symbols for connected devices.", model.Safe}, {"Simulators", "Library/Developer/CoreSimulator", "Simulator devices and data.", model.Review},
		{"SwiftPM", "Library/Caches/org.swift.swiftpm", "Package cache.", model.Safe}, {"CocoaPods", "Library/Caches/CocoaPods", "Pods cache.", model.Safe},
		{"Xcode caches", "Library/Caches/com.apple.dt.Xcode", "Xcode's own cache.", model.Safe},
	}, []string{"Pods", "DerivedData"}},
	{"Ruby", "Ruby versions and gems.", []langStore{
		{"rbenv", ".rbenv/versions", "Ruby versions with their gems.", model.Review}, {"RVM", ".rvm", "Ruby versions.", model.Review},
		{"Gems", ".gem", "User gems.", model.Review}, {"Bundler cache", ".bundle/cache", "Bundler downloads.", model.Safe},
	}, []string{"vendor"}},
	{"PHP", "Composer cache.", []langStore{{"Composer", ".composer/cache", "Composer downloads.", model.Safe}, {"Composer (Caches)", "Library/Caches/composer", "Composer downloads.", model.Safe}}, nil},
	{"Dart / Flutter", "Pub cache and SDKs.", []langStore{
		{"Pub cache", ".pub-cache", "Packages and global tools.", model.Review}, {"Flutter SDK", "flutter", "The Flutter SDK.", model.Keep}, {"Flutter SDK", "development/flutter", "The Flutter SDK.", model.Keep},
	}, []string{".dart_tool", "build"}},
	{".NET", "NuGet packages and SDKs.", []langStore{{"NuGet packages", ".nuget/packages", "Downloaded packages. dotnet nuget locals all --clear.", model.Safe}, {".NET SDKs", ".dotnet", "SDKs and tools.", model.Review}}, nil},
	{"Haskell", "GHC versions and build caches.", []langStore{{"ghcup", ".ghcup", "GHC, cabal and stack installs.", model.Review}, {"Stack", ".stack", "Stack snapshots and GHCs.", model.Review}, {"Cabal", ".cabal", "Cabal store.", model.Review}}, nil},
	{"Julia", "Packages and environments.", []langStore{{"Julia depot", ".julia", "Packages, artifacts, compiled cache and environments.", model.Review}}, nil},
	{"Elixir / Erlang", "Hex and Mix.", []langStore{{"Hex", ".hex", "Package cache.", model.Safe}, {"Mix", ".mix", "Archives and tools.", model.Keep}}, nil},
	{"C / C++", "Compiler caches and package managers.", []langStore{
		{"ccache", "Library/Caches/ccache", "Compiler cache.", model.Safe}, {"Conan", ".conan2", "Package cache.", model.Safe}, {"vcpkg", ".cache/vcpkg", "Binary cache.", model.Safe},
	}, nil},
}

func (e *Env) languageInventory(cands []candidate) model.Inventory {
	inv := model.Inventory{Key: "languages", Title: "Programming languages",
		Intro: "Space per language: dependency and build folders inside your projects (from the home walk), plus the caches, toolchains and versions of each ecosystem."}
	for _, l := range languages {
		it := model.InvItem{Name: l.name, Kind: l.intro}
		for _, s := range l.stores {
			if p, ok := e.part(s.name, filepath.Join(e.Home, s.path), s.explain, s.s); ok && p.Bytes > 0 {
				it.Parts = append(it.Parts, p)
			}
		}
		want := map[string]bool{}
		for _, a := range l.artifacts {
			want[a] = true
		}
		type proj struct {
			path  string
			bytes int64
		}
		byKind := map[string][]proj{}
		for _, c := range cands {
			if !want[c.kind] {
				continue
			}
			u := e.measure(c.path)
			if u.Bytes == 0 {
				continue
			}
			b := u.Freeable
			if b == 0 {
				b = u.Bytes
			}
			byKind[c.kind] = append(byKind[c.kind], proj{c.path, b})
		}
		for kind, ps := range byKind {
			sort.Slice(ps, func(i, j int) bool { return ps[i].bytes > ps[j].bytes })
			var total int64
			for _, p := range ps {
				total += p.bytes
			}
			ex := artifactByName[kind].Reason
			var top []string
			for _, p := range ps[:min(5, len(ps))] {
				top = append(top, fsx.Human(p.bytes)+"  "+e.Pretty(p.path))
			}
			it.Parts = append(it.Parts, model.Part{Name: kind + " in " + strconv.Itoa(len(ps)) + " projects", Bytes: total, Explain: ex, Safety: artifactByName[kind].Safety, Top: top})
		}
		if len(it.Parts) == 0 {
			continue
		}
		sortParts(it.Parts)
		it.Bytes = sumParts(it.Parts)
		inv.Items = append(inv.Items, it)
		inv.Bytes += it.Bytes
	}
	sort.Slice(inv.Items, func(i, j int) bool { return inv.Items[i].Bytes > inv.Items[j].Bytes })
	return inv
}

// ---------- Downloads ----------

var downloadKinds = []struct {
	name, explain string
	exts          []string
}{
	{"Installers and disk images", "Apps that you installed from these can go. A disk image can also hold your own files: open it first if you are not sure.", []string{".dmg", ".pkg", ".mpkg", ".iso", ".exe", ".msi", ".deb", ".rpm", ".apk", ".ipa", ".xip"}},
	{"Archives", "Check whether you already extracted them. An archive can be the only copy of what is inside.", []string{".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".zst"}},
	{"Videos", "Usually the largest files. Move the ones you keep to an external disk or cloud storage.", []string{".mp4", ".mov", ".mkv", ".avi", ".webm", ".m4v", ".wmv"}},
	{"Audio", "Music, recordings and podcasts.", []string{".mp3", ".m4a", ".wav", ".flac", ".aac", ".aiff", ".ogg"}},
	{"Images", "Photos, screenshots and graphics.", []string{".jpg", ".jpeg", ".png", ".gif", ".heic", ".webp", ".svg", ".tiff", ".tif", ".raw", ".cr2", ".nef", ".dng", ".psd"}},
	{"Documents", "PDFs, office files and e-books. Often small but important: keep or move to Documents.", []string{".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".key", ".pages", ".numbers", ".txt", ".md", ".rtf", ".csv", ".epub", ".odt"}},
	{"Code and data", "Exports, logs, datasets and scripts.", []string{".json", ".js", ".ts", ".py", ".go", ".sql", ".sh", ".ipynb", ".yaml", ".yml", ".xml", ".log", ".har", ".parquet", ".db", ".sqlite", ".jsonl"}},
}

func (e *Env) downloadsInventory() model.Inventory {
	dir := filepath.Join(e.Home, "Downloads")
	inv := model.Inventory{Key: "downloads", Title: "Downloads by type",
		Intro: "What is in your Downloads folder, grouped by type and age, with the largest items of each group. Nothing here is regenerated by itself: decide per file."}
	extKind := map[string]int{}
	for i, k := range downloadKinds {
		for _, x := range k.exts {
			extKind[x] = i
		}
	}
	type entry struct {
		path  string
		bytes int64
		mod   time.Time
	}
	groups := make([][]entry, len(downloadKinds)+2) // + folders, other
	ents, err := os.ReadDir(dir)
	if err != nil {
		return inv
	}
	for _, en := range ents {
		if strings.HasPrefix(en.Name(), ".") {
			continue
		}
		p := filepath.Join(dir, en.Name())
		info, err := en.Info()
		if err != nil {
			continue
		}
		idx := len(downloadKinds) + 1 // other
		var b int64
		if en.IsDir() {
			idx = len(downloadKinds)
			isBundle := false
			for _, ext := range bundleExt {
				if strings.HasSuffix(en.Name(), ext) {
					isBundle = true
				}
			}
			if isBundle {
				idx = 0
			}
			b = fsx.MeasureWithin(p, invStall).Bytes
		} else {
			if i, ok := extKind[strings.ToLower(filepath.Ext(en.Name()))]; ok {
				idx = i
			}
			b = fsx.Measure(p).Bytes
		}
		groups[idx] = append(groups[idx], entry{p, b, info.ModTime()})
	}
	names := append([]string{}, func() []string {
		var n []string
		for _, k := range downloadKinds {
			n = append(n, k.name)
		}
		return n
	}()...)
	names = append(names, "Folders", "Other files")
	explains := []string{}
	for _, k := range downloadKinds {
		explains = append(explains, k.explain)
	}
	explains = append(explains, "Folders that you saved or extracted here.", "Files of other types.")
	for i, g := range groups {
		if len(g) == 0 {
			continue
		}
		sort.Slice(g, func(a, b int) bool { return g[a].bytes > g[b].bytes })
		var total, old, mid int64
		for _, x := range g {
			total += x.bytes
			age := e.Now.Sub(x.mod)
			switch {
			case age > 180*24*time.Hour:
				old += x.bytes
			case age > 30*24*time.Hour:
				mid += x.bytes
			}
		}
		var top []string
		for _, x := range g[:min(8, len(g))] {
			top = append(top, fsx.Human(x.bytes)+"  "+filepath.Base(x.path)+"  ("+Ago(e.Now, x.mod)+")")
		}
		var buckets []model.Part
		for _, bk := range []model.Part{
			{Name: "Older than 6 months", Bytes: old, Explain: "Changed more than 180 days ago.", Safety: model.Review},
			{Name: "1 to 6 months old", Bytes: mid, Explain: "Changed 30 to 180 days ago.", Safety: model.Review},
			{Name: "Last 30 days", Bytes: total - old - mid, Explain: "Recent downloads.", Safety: model.Keep},
		} {
			if bk.Bytes > 0 {
				buckets = append(buckets, bk)
			}
		}
		if total == 0 {
			continue
		}
		it := model.InvItem{Name: names[i], Kind: strconv.Itoa(len(g)) + " items", Bytes: total, Path: dir,
			Parts: buckets,
			Notes: append([]string{explains[i], "Largest:"}, top...)}
		inv.Items = append(inv.Items, it)
		inv.Bytes += total
	}
	sort.Slice(inv.Items, func(i, j int) bool { return inv.Items[i].Bytes > inv.Items[j].Bytes })
	return inv
}

// largestChildren lists the biggest entries directly inside dir, for parts that need more detail.
func (e *Env) largestChildren(dir string, n int) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	type kv struct {
		name string
		b    int64
	}
	var all []kv
	for _, en := range ents {
		u := fsx.MeasureWithin(filepath.Join(dir, en.Name()), invStall)
		b := u.Freeable
		if b == 0 {
			b = u.Bytes
		}
		all = append(all, kv{en.Name(), b})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].b > all[j].b })
	var out []string
	for _, x := range all[:min(n, len(all))] {
		if x.b > 0 {
			out = append(out, fsx.Human(x.b)+"  "+x.name)
		}
	}
	return out
}

// extensionNames lists the largest Chromium extensions with the name from their manifest.
func extensionNames(dir string, n int) []string {
	ents, _ := os.ReadDir(dir)
	type ext struct {
		name string
		b    int64
	}
	var all []ext
	for _, en := range ents {
		if !en.IsDir() {
			continue
		}
		p := filepath.Join(dir, en.Name())
		name := en.Name()
		if vers, _ := os.ReadDir(p); len(vers) > 0 {
			vdir := filepath.Join(p, vers[len(vers)-1].Name())
			var m struct {
				Name          string `json:"name"`
				DefaultLocale string `json:"default_locale"`
			}
			if b, err := os.ReadFile(filepath.Join(vdir, "manifest.json")); err == nil && json.Unmarshal(b, &m) == nil && m.Name != "" {
				name = m.Name
				if key, ok := strings.CutPrefix(m.Name, "__MSG_"); ok {
					key = strings.TrimSuffix(key, "__")
					for _, loc := range []string{m.DefaultLocale, "en", "en_US"} {
						var msgs map[string]struct {
							Message string `json:"message"`
						}
						if b, err := os.ReadFile(filepath.Join(vdir, "_locales", loc, "messages.json")); err == nil && json.Unmarshal(b, &msgs) == nil {
							for k, v := range msgs {
								if strings.EqualFold(k, key) && v.Message != "" {
									name = v.Message
								}
							}
						}
					}
				}
			}
		}
		all = append(all, ext{name, fsx.Measure(p).Bytes})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].b > all[j].b })
	var out []string
	for _, x := range all[:min(n, len(all))] {
		out = append(out, fsx.Human(x.b)+"  "+x.name)
	}
	return out
}
