package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
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
		{"volta", "~/.volta/tools/image/node/*", "", "rm -rf (volta has no uninstall for a Node version)"},
	}
	current, _ := probe.Run(5*time.Second, "node", "--version")
	current = strings.TrimSpace(current)
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
			f := model.Finding{
				ID: id("node", d), Rule: "node-version", Category: catDev, Title: m.name + " Node.js " + v, Paths: []string{d},
				Bytes: u.Bytes, Files: u.Files, Safety: model.Review, Confidence: "high", Modified: u.Newest,
				Reasons:  []string{"It is not the default version (" + orNone(def) + ") and not the current version (" + orNone(current) + ")."},
				Risks:    []string{"A project with .nvmrc, .node-version or engines that names this version needs it."},
				Verify:   []string{"grep -rl --include=.nvmrc --include=.node-version " + strings.TrimPrefix(v, "v") + " ~ 2>/dev/null | head"},
				Commands: []string{m.uninstall + " " + v},
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
	for _, f := range files {
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
		extra := g[0].bytes * int64(len(g)-1)
		var cmds []string
		for _, p := range paths[1:] {
			cmds = append(cmds, e.Rm(false, p)+"   # keeps the oldest copy: "+e.Pretty(paths[0]))
		}
		quoted := make([]string, len(paths))
		for i, p := range paths {
			quoted[i] = e.Q(p)
		}
		out = append(out, model.Finding{
			ID: id("dup", strings.Join(paths, "|")), Rule: "duplicate-files", Category: catUser,
			Title: strconv.Itoa(len(g)) + " identical copies of " + filepath.Base(paths[0]), Paths: paths,
			Bytes: extra, Files: int64(len(g) - 1), Safety: model.Review, Confidence: "high", Modified: g[len(g)-1].mod,
			Reasons:  []string{"These files have the same size and the same SHA-256 hash, so their content is identical.", "The size shown is the space of the extra copies."},
			Risks:    []string{"APFS clones share disk blocks. If these copies are clones, a delete frees nothing.", "An app can expect a file at one of these paths. Keep the copy that the app uses."},
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
