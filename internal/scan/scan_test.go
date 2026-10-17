package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/RO-29/spaceaudit/internal/fsx"
	"github.com/RO-29/spaceaudit/internal/model"
)

func testEnv(t *testing.T) (*Env, string) {
	t.Helper()
	home := t.TempDir()
	home, _ = filepath.EvalSymlinks(home)
	e := &Env{Opt: Options{Home: home, MinBytes: 0, ActiveFor: 48 * time.Hour, StaleAfter: 30 * 24 * time.Hour, Jobs: 2},
		Home: home, Now: time.Now(), procs: map[int]string{}, git: map[string]*repoInfo{}}
	return e, home
}

func write(t *testing.T, p string, size int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.email=t@t", "-c", "user.name=t"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
}

func TestArtifactJudgement(t *testing.T) {
	e, home := testEnv(t)
	proj := filepath.Join(home, "proj")
	write(t, filepath.Join(proj, "package.json"), 10)
	write(t, filepath.Join(proj, "node_modules/a/index.js"), 4096)
	write(t, filepath.Join(proj, "dist/out.js"), 4096)
	write(t, filepath.Join(proj, "build/keep.txt"), 4096)
	write(t, filepath.Join(proj, ".gitignore"), 0)
	os.WriteFile(filepath.Join(proj, ".gitignore"), []byte("node_modules\ndist\n"), 0o644)
	git(t, proj, "init", "-q")
	git(t, proj, "add", "package.json", ".gitignore", "build/keep.txt")
	git(t, proj, "commit", "-qm", "x")

	nm := e.judgeArtifact(candidate{filepath.Join(proj, "node_modules"), "node_modules"})
	if nm == nil {
		t.Fatal("node_modules was not reported")
	}
	if !contains(nm.Risks, "No lock file") {
		t.Errorf("missing lock-file risk: %v", nm.Risks)
	}
	if !contains(nm.Blockers, "edited this project") {
		t.Errorf("a project edited now must be blocked: %v", nm.Blockers)
	}
	if nm.Safety == model.Safe {
		t.Error("an active project with no lock file must not be safe")
	}
	if f := e.judgeArtifact(candidate{filepath.Join(proj, "build"), "build"}); f != nil {
		t.Error("a build folder that git tracks is source and must not be reported")
	}
	if f := e.judgeArtifact(candidate{filepath.Join(proj, "dist"), "dist"}); f == nil || !contains(f.Reasons, "git ignores") {
		t.Errorf("ignored dist must be reported with the ignore reason: %+v", f)
	}
	lone := filepath.Join(home, "notes/target")
	write(t, filepath.Join(lone, "x"), 10)
	if f := e.judgeArtifact(candidate{lone, "target"}); f != nil {
		t.Error("a target folder without Cargo.toml or pom.xml must not be reported")
	}
}

func TestStaleProjectIsSafe(t *testing.T) {
	e, home := testEnv(t)
	proj := filepath.Join(home, "old")
	write(t, filepath.Join(proj, "package.json"), 10)
	write(t, filepath.Join(proj, "yarn.lock"), 10)
	write(t, filepath.Join(proj, "node_modules/a.js"), 4096)
	old := time.Now().Add(-90 * 24 * time.Hour)
	filepath.Walk(proj, func(p string, _ os.FileInfo, _ error) error { return os.Chtimes(p, old, old) })
	f := e.judgeArtifact(candidate{filepath.Join(proj, "node_modules"), "node_modules"})
	if f == nil || f.Safety != model.Safe {
		t.Fatalf("an old project with a lock file must be safe: %+v", f)
	}
	if !contains(f.Reasons, "Untouched for more than 30 days") {
		t.Errorf("missing stale reason: %v", f.Reasons)
	}
}

func TestWorkspaceAndExtensions(t *testing.T) {
	_, home := testEnv(t)
	ws := filepath.Join(home, "ws/abc")
	write(t, filepath.Join(ws, "workspace.json"), 0)
	os.WriteFile(filepath.Join(ws, "workspace.json"), []byte(`{"folder":"file:///nope/My%20Project"}`), 0o644)
	if p, ok := workspaceTarget(ws); !ok || p != "/nope/My Project" {
		t.Fatalf("workspaceTarget = %q %v", p, ok)
	}
	ext := filepath.Join(home, "ext")
	write(t, filepath.Join(ext, "a.b-1.0.0/package.json"), 1)
	write(t, filepath.Join(ext, "a.b-2.0.0/package.json"), 1)
	os.WriteFile(filepath.Join(ext, "extensions.json"), []byte(`[{"relativeLocation":"a.b-2.0.0","location":{"path":"/x/a.b-2.0.0"}}]`), 0o644)
	stale := staleExtensions(ext)
	if len(stale) != 1 || filepath.Base(stale[0]) != "a.b-1.0.0" {
		t.Fatalf("stale = %v", stale)
	}
}

func TestTotalsSkipNested(t *testing.T) {
	fs := []model.Finding{
		{Paths: []string{"/h/wt"}, Bytes: 100, Safety: model.Safe},
		{Paths: []string{"/h/wt/node_modules"}, Bytes: 60, Safety: model.Safe},
		{Paths: []string{"/h/other"}, Bytes: 5, Safety: model.Review},
	}
	if got := totals(fs); got.Safe != 100 || got.Review != 5 {
		t.Fatalf("totals = %+v", got)
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"2.173GB": 2173000000, "563.2MB (98%)": 563200000, "0B": 0, "12kB": 12000} {
		if got := parseSize(in); got != want {
			t.Errorf("parseSize(%q) = %d, want %d", in, got, want)
		}
	}
}

func contains(xs []string, sub string) bool {
	for _, x := range xs {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}

func TestWorktreeIgnoredFilesAreReported(t *testing.T) {
	_, home := testEnv(t)
	repo := filepath.Join(home, "repo")
	write(t, filepath.Join(repo, "a.txt"), 1)
	os.WriteFile(filepath.Join(repo, ".gitignore"), []byte(".env\nnode_modules\n"), 0o644)
	git(t, repo, "init", "-q")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-qm", "x")
	write(t, filepath.Join(repo, ".env"), 10)
	write(t, filepath.Join(repo, "node_modules/x.js"), 10)
	keep := precious(repo)
	if len(keep) != 1 || keep[0] != ".env" {
		t.Fatalf("precious = %v, want [.env]", keep)
	}
}

// readOnlyVerify lists the command starts that only read. A verify step must never change anything.
var readOnlyVerify = []string{"du ", "sudo du ", "ls ", "find ", "cat ", "mdls ", "file ", "shasum ", "grep ", "git --no-optional-locks ", "git -C ",
	"docker system df", "brew cleanup -n", "brew autoremove --dry-run", "tmutil listlocalsnapshots", "xcrun simctl list", "go env", "yarn cache dir",
	"pnpm store status", "pip3 cache info", "uv cache dir", "poetry cache list", "conda clean --all --dry-run", "rustup toolchain list", "pod cache list",
	"ollama list", "huggingface-cli scan-cache", "lsof ", "pyenv versions", "vagrant box list", "minikube profile list",
	"nix-env --list-generations", "tart list", "rbenv versions", "conda env list", "xcrun simctl runtime list", "tmutil listlocalsnapshots"}

func checkVerify(t *testing.T, where string, cmds []string) {
	t.Helper()
	for _, c := range cmds {
		ok := false
		for _, p := range readOnlyVerify {
			if strings.HasPrefix(c, p) {
				ok = true
			}
		}
		bad := regexp.MustCompile(`-delete|-exec|\brm\b|--force|(^|\s)prune\b|clean(\s|$)|\bpurge\b|> `).MatchString(strings.Split(c, "|")[0])
		if !ok || (bad && !strings.Contains(c, "--dry-run") && !strings.HasPrefix(c, "brew cleanup -n")) {
			t.Errorf("%s: verify command is not read-only: %q", where, c)
		}
	}
}

func TestVerifyCommandsAreReadOnly(t *testing.T) {
	for _, r := range catalog {
		checkVerify(t, r.ID, r.Verify)
	}
	e, home := testEnv(t)
	proj := filepath.Join(home, "p")
	write(t, filepath.Join(proj, "package.json"), 1)
	write(t, filepath.Join(proj, "yarn.lock"), 1)
	write(t, filepath.Join(proj, "node_modules/x.js"), 4096)
	if f := e.judgeArtifact(candidate{filepath.Join(proj, "node_modules"), "node_modules"}); f != nil {
		checkVerify(t, "artifact", f.Verify)
	}
}

func TestDuplicates(t *testing.T) {
	e, home := testEnv(t)
	a, b, c, l := filepath.Join(home, "a.bin"), filepath.Join(home, "sub/b.bin"), filepath.Join(home, "c.bin"), filepath.Join(home, "link.bin")
	write(t, a, 3<<20)
	write(t, b, 3<<20)
	os.WriteFile(c, append(make([]byte, 3<<20-1), 1), 0o644) // same size, different content
	os.Link(a, l)
	var fs []large
	for _, p := range []string{a, b, c, l} {
		st, _ := os.Stat(p)
		fs = append(fs, large{p, st.Size(), st.ModTime(), st.Size()})
	}
	got := e.duplicates(fs)
	if len(got) != 1 {
		t.Fatalf("want 1 duplicate group, got %d: %+v", len(got), got)
	}
	if n := len(got[0].Paths); n != 3 {
		t.Errorf("group should hold a, b and the hard link (3 paths), got %v", got[0].Paths)
	}
	checkVerify(t, "dup", got[0].Verify)
	repo := filepath.Join(home, "r")
	write(t, filepath.Join(repo, "x.bin"), 3<<20)
	os.MkdirAll(filepath.Join(repo, ".git"), 0o755)
	write(t, filepath.Join(home, ".tool/x.bin"), 3<<20)
	var mixed []large
	for _, p := range []string{a, filepath.Join(repo, "x.bin"), filepath.Join(home, ".tool/x.bin")} {
		st, _ := os.Stat(p)
		mixed = append(mixed, large{p, st.Size(), st.ModTime(), st.Size()})
	}
	if got := e.duplicates(mixed); len(got) != 0 {
		t.Errorf("copies inside a git tree or a hidden tool folder must not count: %+v", got[0].Paths)
	}
	only := e.duplicates([]large{fs[0], fs[3]})
	if len(only) != 0 {
		t.Errorf("two hard links to one file are not duplicates: %+v", only)
	}
}

func TestNodeVersionsKeepsDefault(t *testing.T) {
	e, home := testEnv(t)
	for _, v := range []string{"v20.1.0", "v22.22.2"} {
		write(t, filepath.Join(home, ".nvm/versions/node", v, "bin/node"), 4096)
	}
	write(t, filepath.Join(home, ".nvm/versions/node/v20.1.0/lib/node_modules/typescript/package.json"), 10)
	os.WriteFile(filepath.Join(home, ".nvm/alias/default"), []byte("22.22.2\n"), 0o644)
	os.MkdirAll(filepath.Join(home, ".nvm/alias"), 0o755)
	os.WriteFile(filepath.Join(home, ".nvm/alias/default"), []byte("22.22.2\n"), 0o644)
	got := e.nodeVersions()
	for _, f := range got {
		if strings.Contains(f.Title, "v22.22.2") {
			t.Errorf("the default version must not be reported: %s", f.Title)
		}
	}
	found := false
	for _, f := range got {
		checkVerify(t, "node", f.Verify)
		if strings.Contains(f.Title, "v20.1.0") {
			found = true
			if !contains(f.Risks, "global npm packages") {
				t.Errorf("missing global package risk: %v", f.Risks)
			}
		}
	}
	if !found {
		t.Error("v20.1.0 should be reported")
	}
}

func TestCloudFoldersAreNeverOpened(t *testing.T) {
	_, home := testEnv(t)
	fsx.Home = home
	defer func() { fsx.Home = "" }()
	write(t, filepath.Join(home, "Library/Mobile Documents/com~apple~CloudDocs/big.bin"), 1<<20)
	write(t, filepath.Join(home, "Library/CloudStorage/GoogleDrive-x/f.bin"), 1<<20)
	write(t, filepath.Join(home, "Library/Other/f.bin"), 1<<20)
	if u := fsx.Measure(filepath.Join(home, "Library/Mobile Documents")); !u.Skipped || u.Bytes != 0 {
		t.Errorf("iCloud Drive was opened: %+v", u)
	}
	u := fsx.Measure(filepath.Join(home, "Library"))
	if u.Bytes == 0 || u.Bytes >= 2<<20 {
		t.Errorf("Library walk must count Other but skip both cloud folders, got %d bytes", u.Bytes)
	}
}

func TestMeasureWithinStops(t *testing.T) {
	start := time.Now()
	u := fsx.MeasureWithin("/", time.Millisecond)
	if !u.TimedOut || time.Since(start) > time.Second {
		t.Errorf("MeasureWithin did not stop on time: %+v after %s", u, time.Since(start))
	}
}

func TestHeldFileNames(t *testing.T) {
	if got := appName("/Applications/Visual Studio Code.app/Contents/Frameworks/x"); got != "Visual Studio Code" {
		t.Errorf("appName = %q", got)
	}
	if runFor(3*24*time.Hour+time.Hour) != "3 days" || runFor(5*time.Hour) != "5 hours" {
		t.Error("runFor formats wrong")
	}
}
