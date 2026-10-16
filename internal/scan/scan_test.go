package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestQuoting(t *testing.T) {
	e, home := testEnv(t)
	got := e.Q(filepath.Join(home, "it's a dir/x"))
	if got != `"$HOME"/'it'\''s a dir/x'` {
		t.Fatalf("Q = %s", got)
	}
	if Trash(`/a/b"c`) != "" || Trash(`/a/it's`) != "" {
		t.Fatal("Trash must refuse paths it cannot quote")
	}
	if !strings.HasPrefix(e.Rm(true, "/x"), "sudo rm -rf -- '/x'") {
		t.Fatal(e.Rm(true, "/x"))
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
