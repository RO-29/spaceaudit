package scan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/RO-29/spaceaudit/internal/fsx"
	"github.com/RO-29/spaceaudit/internal/model"
	"github.com/RO-29/spaceaudit/internal/probe"
)

// Artifact is one kind of folder that a build tool makes inside a project.
type Artifact struct {
	Name       string
	Markers    []string // the project must have one of these next to the folder; "*.x" is a glob
	MustIgnore bool     // only when git ignores it, because the name can also be source code
	Safety     model.Safety
	Locks      []string // lock files that make a reinstall give the same versions
	Reason     string
	Restore    string
	Aggregate  bool // small and many: report as one finding
}

var artifacts = []Artifact{
	{Name: "node_modules", Markers: []string{"package.json"}, Safety: model.Safe,
		Locks:  []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock", "npm-shrinkwrap.json"},
		Reason: "npm, yarn or pnpm installs these packages again from the lock file.", Restore: "npm ci, yarn install or pnpm install"},
	{Name: "target", Markers: []string{"Cargo.toml", "pom.xml", "build.sbt"}, Safety: model.Safe, Reason: "Cargo, Maven or sbt writes build output here.", Restore: "cargo build, mvn package or sbt compile"},
	{Name: "build", Markers: []string{"build.gradle", "build.gradle.kts", "package.json", "CMakeLists.txt", "setup.py", "pyproject.toml", "*.xcodeproj", "Podfile", "pubspec.yaml"}, MustIgnore: true, Safety: model.Safe, Reason: "The build tool writes its output here.", Restore: "Run the build again."},
	{Name: "dist", Markers: []string{"package.json", "setup.py", "pyproject.toml"}, MustIgnore: true, Safety: model.Safe, Reason: "The bundler or packager writes its output here.", Restore: "Run the build again."},
	{Name: "out", Markers: []string{"package.json"}, MustIgnore: true, Safety: model.Safe, Reason: "A static export or compiler writes here.", Restore: "Run the build again."},
	{Name: ".next", Markers: []string{"package.json"}, Safety: model.Safe, Reason: "Next.js writes its build and dev cache here.", Restore: "next build or next dev"},
	{Name: ".nuxt", Markers: []string{"package.json"}, Safety: model.Safe, Reason: "Nuxt writes its build here.", Restore: "nuxt build"},
	{Name: ".svelte-kit", Markers: []string{"package.json"}, Safety: model.Safe, Reason: "SvelteKit writes generated files here.", Restore: "vite dev"},
	{Name: ".turbo", Markers: []string{"package.json", "turbo.json"}, Safety: model.Safe, Reason: "Turborepo keeps its local task cache here.", Restore: "The next turbo run fills it."},
	{Name: ".nx", Markers: []string{"nx.json", "package.json"}, Safety: model.Safe, Reason: "Nx keeps its local cache here.", Restore: "The next nx run fills it."},
	{Name: ".parcel-cache", Markers: []string{"package.json"}, Safety: model.Safe, Reason: "Parcel keeps its cache here.", Restore: "The next build fills it."},
	{Name: ".angular", Markers: []string{"angular.json"}, Safety: model.Safe, Reason: "Angular CLI keeps its build cache here.", Restore: "ng build"},
	{Name: ".expo", Markers: []string{"app.json", "package.json"}, Safety: model.Safe, Reason: "Expo keeps local state and caches here.", Restore: "expo start"},
	{Name: ".vercel", Markers: []string{"package.json"}, MustIgnore: true, Safety: model.Review, Reason: "Vercel keeps build output and the project link here.", Restore: "vercel link, then vercel build"},
	{Name: ".serverless", Markers: []string{"serverless.yml", "serverless.ts"}, Safety: model.Safe, Reason: "Serverless writes deploy packages here.", Restore: "serverless package"},
	{Name: "coverage", Markers: []string{"package.json", "pyproject.toml", "go.mod", "setup.py", "pom.xml"}, MustIgnore: true, Safety: model.Safe, Reason: "Test runs write coverage reports here.", Restore: "Run the tests with coverage again."},
	{Name: ".gradle", Markers: []string{"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}, Safety: model.Safe, Reason: "Gradle keeps project caches here.", Restore: "The next Gradle build fills it."},
	{Name: "Pods", Markers: []string{"Podfile"}, Safety: model.Review, Locks: []string{"Podfile.lock"}, Reason: "CocoaPods installs dependencies here.", Restore: "pod install"},
	{Name: "DerivedData", Markers: []string{"*.xcodeproj", "*.xcworkspace"}, Safety: model.Safe, Reason: "Xcode build output for this project.", Restore: "Build again in Xcode."},
	{Name: ".dart_tool", Markers: []string{"pubspec.yaml"}, Safety: model.Safe, Reason: "Dart and Flutter keep generated files here.", Restore: "flutter pub get"},
	{Name: ".venv", Markers: []string{"pyproject.toml", "requirements.txt", "setup.py", "Pipfile", "uv.lock", "poetry.lock"}, Safety: model.Review,
		Locks:  []string{"uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt", "pdm.lock"},
		Reason: "This is a Python virtual environment for the project.", Restore: "uv sync, poetry install, or python3 -m venv .venv && pip install -r requirements.txt"},
	{Name: "venv", Markers: []string{"pyproject.toml", "requirements.txt", "setup.py", "Pipfile"}, Safety: model.Review,
		Locks:  []string{"uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt", "pdm.lock"},
		Reason: "This is a Python virtual environment for the project.", Restore: "python3 -m venv venv && pip install -r requirements.txt"},
	{Name: ".tox", Markers: []string{"tox.ini", "pyproject.toml"}, Safety: model.Safe, Reason: "tox builds test environments here.", Restore: "tox"},
	{Name: ".terraform", Markers: []string{"*.tf"}, Safety: model.Review, Reason: "terraform init downloads providers and modules here.", Restore: "terraform init"},
	{Name: "vendor", Markers: []string{"go.mod", "composer.json", "Gemfile"}, MustIgnore: true, Safety: model.Review, Reason: "Vendored dependencies that the package manager can fetch again.", Restore: "go mod vendor, composer install or bundle install"},
	{Name: "__pycache__", Safety: model.Safe, Aggregate: true, Reason: "Python writes compiled bytecode here and makes it again on import.", Restore: "Nothing to restore."},
	{Name: ".pytest_cache", Safety: model.Safe, Aggregate: true, Reason: "pytest keeps run state here.", Restore: "Nothing to restore."},
	{Name: ".mypy_cache", Safety: model.Safe, Aggregate: true, Reason: "mypy keeps its type cache here.", Restore: "Nothing to restore."},
	{Name: ".ruff_cache", Safety: model.Safe, Aggregate: true, Reason: "ruff keeps its lint cache here.", Restore: "Nothing to restore."},
}

var artifactByName = func() map[string]Artifact {
	m := map[string]Artifact{}
	for _, a := range artifacts {
		m[a.Name] = a
	}
	return m
}()

// bundleExt are folders macOS shows as one file. The walk measures them as one item.
var bundleExt = []string{".photoslibrary", ".musiclibrary", ".tvlibrary", ".app", ".vmwarevm", ".pvm", ".utm", ".sparsebundle", ".fcpbundle", ".logicx", ".band", ".xcarchive", ".imovielibrary"}

type candidate struct{ path, kind string }

type large struct {
	path     string
	bytes    int64
	mod      time.Time
	apparent int64
}

const dupMin = 64 << 20 // files at or above this size are checked for duplicates

type walkResult struct {
	cands     []candidate
	worktrees []string
	larges    []large
	dups      []large
	bundles   []string
	top       map[string]int64 // first and second level folders of home
	denied    map[string]int
	total     int64
}

// walkHome makes one pass over the home folder. It prunes artifacts and bundles, so their content is not walked twice.
func (e *Env) walkHome() walkResult {
	res := walkResult{top: map[string]int64{}, denied: map[string]int{}}
	ents, err := os.ReadDir(e.Home)
	if err != nil {
		e.warn("cannot read the home folder: " + err.Error())
		return res
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, e.Opt.Jobs)
	rootDev := devOf(e.Home)
	var nFiles, nBytes atomic.Int64
	var where atomic.Value
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				w, _ := where.Load().(string)
				e.Opt.Progress(fmt.Sprintf("Walking the home folder: %d files, %s so far (%s)", nFiles.Load(), fsx.Human(nBytes.Load()), e.Pretty(w)))
			}
		}
	}()
	for _, en := range ents {
		p := filepath.Join(e.Home, en.Name())
		if !en.IsDir() {
			if info, err := en.Info(); err == nil {
				if sys, ok := info.Sys().(*syscall.Stat_t); ok {
					mu.Lock()
					res.top[p] += sys.Blocks * 512
					res.total += sys.Blocks * 512
					if sys.Blocks*512 >= e.Opt.LargeBytes {
						res.larges = append(res.larges, large{p, sys.Blocks * 512, info.ModTime(), info.Size()})
					}
					mu.Unlock()
				}
			}
			continue
		}
		wg.Add(1)
		go func(top string, hidden bool) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			local := walkResult{top: map[string]int64{}, denied: map[string]int{}}
			inLibrary := top == filepath.Join(e.Home, "Library")
			seen := map[uint64]bool{}
			_ = filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					if d != nil && d.IsDir() {
						local.denied[top]++
						return fs.SkipDir
					}
					return nil
				}
				name := d.Name()
				if d.IsDir() && p != top {
					if devOf(p) != rootDev || fsx.Provider(p, e.Home) {
						return fs.SkipDir
					}
					if name == ".git" {
						return e.addTree(&local, p)
					}
					if !inLibrary && !hidden {
						if _, ok := artifactByName[name]; ok {
							local.cands = append(local.cands, candidate{p, name})
							return e.addTree(&local, p)
						}
					}
					for _, ext := range bundleExt {
						if strings.HasSuffix(name, ext) {
							local.bundles = append(local.bundles, p)
							return e.addTree(&local, p)
						}
					}
					return nil
				}
				if d.IsDir() {
					return nil
				}
				if name == ".git" && d.Type().IsRegular() {
					local.worktrees = append(local.worktrees, filepath.Dir(p))
				}
				info, err := d.Info()
				if err != nil {
					return nil
				}
				sys, ok := info.Sys().(*syscall.Stat_t)
				if !ok {
					return nil
				}
				if sys.Nlink > 1 {
					if seen[sys.Ino] {
						return nil
					}
					seen[sys.Ino] = true
				}
				b := sys.Blocks * 512
				if nFiles.Add(1)%2000 == 0 {
					where.Store(filepath.Dir(p))
				}
				nBytes.Add(b)
				local.total += b
				local.top[second(e.Home, p)] += b
				if b >= e.Opt.LargeBytes {
					local.larges = append(local.larges, large{p, b, info.ModTime(), info.Size()})
				}
				// iCloud placeholders are skipped: reading one to hash it would download it.
				if info.Size() >= dupMin && d.Type().IsRegular() && sys.Flags&0x40000000 == 0 {
					local.dups = append(local.dups, large{p, b, info.ModTime(), info.Size()})
				}
				return nil
			})
			mu.Lock()
			res.cands = append(res.cands, local.cands...)
			res.worktrees = append(res.worktrees, local.worktrees...)
			res.larges = append(res.larges, local.larges...)
			res.dups = append(res.dups, local.dups...)
			res.bundles = append(res.bundles, local.bundles...)
			res.total += local.total
			for k, v := range local.top {
				res.top[k] += v
			}
			for k, v := range local.denied {
				res.denied[k] += v
			}
			mu.Unlock()
		}(p, strings.HasPrefix(en.Name(), "."))
	}
	wg.Wait()
	return res
}

// addTree measures a pruned folder into the totals and stops the walk from entering it.
func (e *Env) addTree(r *walkResult, p string) error {
	u := fsx.Measure(p)
	e.sizes.Store(p, u)
	r.total += u.Bytes
	r.top[second(e.Home, p)] += u.Bytes
	return fs.SkipDir
}

// second returns the first two levels of p below home, for the breakdown view.
func second(home, p string) string {
	rel := strings.TrimPrefix(p, home+"/")
	parts := strings.SplitN(rel, "/", 3)
	if len(parts) >= 2 {
		return filepath.Join(home, parts[0], parts[1])
	}
	return filepath.Join(home, parts[0])
}

func devOf(p string) int32 {
	var st syscall.Stat_t
	if syscall.Lstat(p, &st) != nil {
		return -1
	}
	return st.Dev
}

// projectFindings judges each artifact folder in its project: git state, lock files, live use and age.
func (e *Env) projectFindings(cands []candidate) []model.Finding {
	var agg = map[string][]string{}
	var direct []candidate
	for _, c := range cands {
		if artifactByName[c.kind].Aggregate {
			agg[c.kind] = append(agg[c.kind], c.path)
		} else {
			direct = append(direct, c)
		}
	}
	out := parallel(e.Opt.Jobs, len(direct), func(i int) *model.Finding { return e.judgeArtifact(direct[i]) })
	kinds := make([]string, 0, len(agg))
	for k := range agg {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		paths := agg[k]
		u := measureAll(paths)
		if u.Bytes < e.Opt.MinBytes {
			continue
		}
		a := artifactByName[k]
		r := Rule{ID: "artifact-" + k, Category: catBuild, Title: k + " folders (" + strconv.Itoa(len(paths)) + ")", Safety: a.Safety,
			Reasons: []string{a.Reason}, Verify: []string{"find \"$HOME\" -name '" + k + "' -type d -prune -not -path '*/Library/*' -not -path '*/.*/*' | head"},
			Commands: []string{"find \"$HOME\" -name '" + k + "' -type d -prune -not -path '*/Library/*' -not -path '*/.*/*' -exec rm -rf -- {} +"}, Restore: a.Restore}
		f := e.build(r, paths, u)
		out = append(out, f)
	}
	return out
}

func (e *Env) judgeArtifact(c candidate) *model.Finding {
	a := artifactByName[c.kind]
	proj := filepath.Dir(c.path)
	if len(a.Markers) > 0 && !hasAny(proj, a.Markers) {
		return nil // a folder with this name but no project marker can be anything, so it is not reported
	}
	top := GitTop(proj, e.Home)
	safety := a.Safety
	reasons := []string{a.Reason}
	var risks, blockers []string
	if top != "" {
		if Tracked(top, c.path) {
			return nil // git tracks files here, so it is source code, not output
		}
		if !Ignored(top, c.path) {
			if a.MustIgnore {
				safety = model.Review
				risks = append(risks, "git does not ignore this folder, so it can be new source code that you did not commit yet.")
			}
		} else {
			reasons = append(reasons, "git ignores this folder, so the repository does not need it.")
		}
		r := e.repo(top)
		if !r.lastCommit.IsZero() {
			reasons = append(reasons, "Last commit in "+e.Pretty(top)+" was "+Ago(e.Now, r.lastCommit)+".")
		}
	} else if a.MustIgnore {
		safety = model.Review
		risks = append(risks, "The project is not in git, so the scan cannot prove that this folder is output and not source.")
	}
	if len(a.Locks) > 0 {
		if lock := findLock(proj, top, e.Home, a.Locks); lock != "" {
			reasons = append(reasons, "Lock file "+e.Pretty(lock)+" pins the versions, so a reinstall gives the same packages.")
		} else {
			risks = append(risks, "No lock file, so a reinstall can pick newer package versions.")
			if safety == model.Safe {
				safety = model.Review
			}
		}
	}
	if c.kind == "node_modules" {
		if links := linkedPackages(c.path); len(links) > 0 {
			risks = append(risks, "Has linked packages ("+strings.Join(limit(links, 3), ", ")+"). Run npm link or yarn link again after a reinstall.")
		}
		if hasAny(proj, []string{".npmrc"}) {
			risks = append(risks, "The project has an .npmrc, so a reinstall can need a private registry login.")
		}
	}
	if c.kind == ".venv" || c.kind == "venv" {
		risks = append(risks, "Packages that you installed by hand with pip and did not write to a requirements file are lost.")
	}
	activity := projectActivity(proj)
	if top != "" {
		if g := gitActivity(top); g.After(activity) {
			activity = g
		}
		if r := e.repo(top); r.dirty > 0 {
			blockers = append(blockers, strconv.Itoa(r.dirty)+" files in "+e.Pretty(top)+" have uncommitted changes, so you are probably still working on it.")
		}
	}
	if !activity.IsZero() {
		age := e.Now.Sub(activity)
		reasons = append(reasons, "Project files changed "+Ago(e.Now, activity)+".")
		if age < e.Opt.ActiveFor {
			blockers = append(blockers, "You edited this project "+Ago(e.Now, activity)+". It looks active.")
		} else if age > e.Opt.StaleAfter {
			reasons = append(reasons, "Untouched for more than "+strconv.Itoa(int(e.Opt.StaleAfter.Hours()/24))+" days.")
		}
	}
	scope := proj
	if top != "" {
		scope = top
	}
	if users := e.UsersOf(scope); len(users) > 0 {
		blockers = append(blockers, "Programs use this project now: "+strings.Join(limit(users, 4), ", ")+".")
	}
	if len(blockers) > 0 && safety == model.Safe {
		safety = model.Review
	}
	u := e.measure(c.path)
	if u.Bytes < e.Opt.MinBytes {
		return nil
	}
	cmds := []string{e.Rm(false, c.path)}
	if c.kind == "target" && hasAny(proj, []string{"Cargo.toml"}) && haveTool("cargo") {
		cmds = []string{"cargo clean --manifest-path " + e.Q(filepath.Join(proj, "Cargo.toml"))}
	}
	f := model.Finding{
		ID: id("artifact", c.path), Rule: "artifact-" + c.kind, Category: catBuild, Title: c.kind + " in " + e.Pretty(proj),
		Paths: []string{c.path}, Bytes: u.Bytes, Files: u.Files, Safety: safety, Confidence: "high", Modified: activity,
		Reasons: reasons, Risks: risks, Blockers: blockers, Commands: cmds,
		Verify:  []string{"ls " + e.Q(proj), "git --no-optional-locks -C " + e.Q(scope) + " status --short | head"},
		Restore: "cd " + e.Q(proj) + " && " + a.Restore,
	}
	if t := Trash(c.path); t != "" {
		f.Alternate = []string{t}
	}
	e.annotate(&f, u)
	return &f
}

func hasAny(dir string, names []string) bool {
	for _, n := range names {
		if strings.Contains(n, "*") {
			if m, _ := filepath.Glob(filepath.Join(dir, n)); len(m) > 0 {
				return true
			}
		} else if fsx.Exists(filepath.Join(dir, n)) {
			return true
		}
	}
	return false
}

// findLock looks for a lock file in the project and in its parents up to the repo root, for monorepos.
func findLock(proj, top, home string, locks []string) string {
	stop := top
	if stop == "" {
		stop = proj
	}
	for d := proj; fsx.Under(d, stop) && fsx.Under(d, home); d = filepath.Dir(d) {
		for _, l := range locks {
			if p := filepath.Join(d, l); fsx.Exists(p) {
				return p
			}
		}
		if d == stop {
			break
		}
	}
	return ""
}

func linkedPackages(nm string) []string {
	var links []string
	walkLinks := func(dir string) {
		ents, _ := os.ReadDir(dir)
		for _, en := range ents {
			if en.Type()&os.ModeSymlink != 0 {
				if t, err := os.Readlink(filepath.Join(dir, en.Name())); err == nil && !strings.Contains(t, "node_modules") {
					links = append(links, en.Name())
				}
			}
		}
	}
	walkLinks(nm)
	ents, _ := os.ReadDir(nm)
	for _, en := range ents {
		if strings.HasPrefix(en.Name(), "@") && en.IsDir() {
			walkLinks(filepath.Join(nm, en.Name()))
		}
	}
	return links
}

// junkIgnored are ignored names that hold only regenerable output.
var junkIgnored = map[string]bool{".DS_Store": true, ".idea": true, ".vscode": true, ".cache": true, "tmp": true, ".eslintcache": true, "logs": true, ".code-review-graph": true}

// precious lists git-ignored files in a worktree that are not regenerable output, such as .env or terraform.tfstate.
func precious(wt string) []string {
	out, err := probe.Run(60*time.Second, "git", "-C", wt, "status", "--porcelain", "--ignored", "--untracked-files=normal")
	if err != nil {
		return nil
	}
	var keep []string
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "!! ") {
			continue
		}
		p := strings.TrimSuffix(strings.Trim(line[3:], `"`), "/")
		base := filepath.Base(p)
		if _, art := artifactByName[base]; art || junkIgnored[base] || strings.HasSuffix(base, ".log") || strings.HasSuffix(base, ".tsbuildinfo") {
			continue
		}
		keep = append(keep, p)
	}
	return keep
}

// gitActivity is the newest change to git state: staging, checkout, commit or fetch.
func gitActivity(top string) time.Time {
	var newest time.Time
	gitDir := filepath.Join(top, ".git")
	if b, err := os.ReadFile(gitDir); err == nil {
		gitDir = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(b)), "gitdir:"))
	}
	for _, f := range []string{"index", "HEAD", "logs/HEAD", "FETCH_HEAD"} {
		if st, err := os.Stat(filepath.Join(gitDir, f)); err == nil && st.ModTime().After(newest) && st.ModTime().Before(time.Now().Add(time.Hour)) {
			newest = st.ModTime()
		}
	}
	return newest
}

// projectActivity is the newest change to a project file, outside artifact folders and .git.
func projectActivity(proj string) time.Time {
	var newest time.Time
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		ents, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, en := range ents {
			name := en.Name()
			if _, skip := artifactByName[name]; skip || name == ".git" || name == ".DS_Store" {
				continue
			}
			if en.IsDir() {
				if depth > 0 && en.Type()&os.ModeSymlink == 0 {
					walk(filepath.Join(dir, name), depth-1)
				}
				continue
			}
			if info, err := en.Info(); err == nil && info.ModTime().After(newest) && info.ModTime().Before(time.Now().Add(time.Hour)) {
				newest = info.ModTime()
			}
		}
	}
	walk(proj, 6)
	return newest
}

// worktreeFindings judges each linked git worktree: changes, unpushed commits and live use.
func (e *Env) worktreeFindings(dirs []string) []model.Finding {
	return parallel(e.Opt.Jobs, len(dirs), func(i int) *model.Finding {
		wt := dirs[i]
		b, err := os.ReadFile(filepath.Join(wt, ".git"))
		if err != nil {
			return nil
		}
		gitdir := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(b)), "gitdir:"))
		if !strings.Contains(gitdir, "/worktrees/") {
			return nil // a submodule, not a worktree
		}
		main := filepath.Dir(filepath.Dir(filepath.Dir(gitdir)))
		if !filepath.IsAbs(gitdir) {
			main = filepath.Clean(filepath.Join(wt, main))
		}
		u := fsx.Measure(wt)
		if u.Bytes < e.Opt.MinBytes {
			return nil
		}
		safety := model.Safe
		var reasons, risks, blockers []string
		branch, _ := probe.Run(5*time.Second, "git", "-C", wt, "rev-parse", "--abbrev-ref", "HEAD")
		branch = strings.TrimSpace(branch)
		reasons = append(reasons, "Linked worktree of "+e.Pretty(main)+" on branch "+branch+".")
		if !fsx.Exists(main) {
			risks = append(risks, "The main repository is gone, so git worktree remove cannot run. Check the folder by hand.")
			safety = model.Risky
		}
		st, err := probe.Run(30*time.Second, "git", "-C", wt, "status", "--porcelain")
		if err == nil && strings.TrimSpace(st) != "" {
			n := strings.Count(st, "\n")
			risks = append(risks, strconv.Itoa(n)+" files have uncommitted changes. They are lost on delete.")
			safety = model.Risky
		}
		ahead, err := probe.Run(10*time.Second, "git", "-C", wt, "rev-list", "--count", "@{u}..HEAD")
		if err != nil {
			remote, _ := probe.Run(10*time.Second, "git", "-C", wt, "branch", "-r", "--contains", "HEAD")
			if strings.TrimSpace(remote) == "" {
				risks = append(risks, "No remote branch has this commit, so it exists only on this Mac.")
				if safety == model.Safe {
					safety = model.Review
				}
			} else {
				reasons = append(reasons, "A remote branch has the current commit.")
			}
		} else if n, _ := strconv.Atoi(strings.TrimSpace(ahead)); n > 0 {
			risks = append(risks, strconv.Itoa(n)+" commits are not pushed.")
			if safety == model.Safe {
				safety = model.Review
			}
		} else {
			reasons = append(reasons, "Every commit is pushed.")
		}
		if keep := precious(wt); len(keep) > 0 {
			risks = append(risks, strconv.Itoa(len(keep))+" git-ignored files are not build output and are not in git, so a delete loses them: "+strings.Join(limit(keep, 5), ", ")+".")
			if safety == model.Safe {
				safety = model.Review
			}
		}
		if out, err := probe.Run(5*time.Second, "git", "-C", wt, "log", "-1", "--format=%ct"); err == nil {
			if ts, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64); err == nil {
				reasons = append(reasons, "Last commit "+Ago(e.Now, time.Unix(ts, 0))+".")
			}
		}
		if users := e.UsersOf(wt); len(users) > 0 {
			blockers = append(blockers, "Programs use this worktree now: "+strings.Join(limit(users, 4), ", ")+".")
			if safety == model.Safe {
				safety = model.Review
			}
		}
		f := model.Finding{
			ID: id("worktree", wt), Rule: "git-worktree", Category: catDev, Title: "Git worktree " + e.Pretty(wt),
			Paths: []string{wt}, Bytes: u.Bytes, Files: u.Files, Safety: safety, Confidence: "high", Modified: u.Newest,
			Reasons: reasons, Risks: risks, Blockers: blockers,
			Verify:   []string{"git --no-optional-locks -C " + e.Q(wt) + " status --short --ignored", "git -C " + e.Q(wt) + " log --oneline @{u}..HEAD"},
			Commands: []string{"git -C " + e.Q(main) + " worktree remove " + e.Q(wt)},
			Notes:    []string{"git worktree remove refuses when there are uncommitted changes. Do not use rm, because it leaves stale worktree records. Run git worktree prune after a manual delete."},
			Restore:  "git -C " + e.Q(main) + " worktree add " + e.Q(wt) + " " + branch,
		}
		e.annotate(&f, u)
		return &f
	})
}
