package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RO-29/spaceaudit/internal/model"
)

// One test per red-team finding, each built from the fixture that proved it.

func TestRTUsersOfSeesThroughSiblings(t *testing.T) {
	e := &Env{procs: map[int]string{7: "tail"}, open: []openFile{{"/c/Foo-x/a", 9}, {"/c/Foo.bar/x", 8}, {"/c/Foo/y", 7}}}
	if got := e.UsersOf("/c/Foo"); len(got) != 1 || !strings.Contains(got[0], "pid 7") {
		t.Fatalf("UsersOf(/c/Foo) = %v, want the tail process", got)
	}
}

func TestRTGitErrorIsNeverSafe(t *testing.T) {
	e, home := testEnv(t)
	proj := filepath.Join(home, "broken")
	write(t, filepath.Join(proj, "package.json"), 1)
	write(t, filepath.Join(proj, "yarn.lock"), 1)
	write(t, filepath.Join(proj, "node_modules", "committed.js"), 4096)
	git(t, proj, "init", "-q")
	git(t, proj, "add", ".")
	git(t, proj, "commit", "-qm", "x")
	git(t, proj, "config", "core.repositoryformatversion", "99")
	f := e.judgeArtifact(candidate{filepath.Join(proj, "node_modules"), "node_modules"})
	if f != nil && f.Safety == model.Safe {
		t.Fatalf("git could not read the repo, but the finding is safe: %+v", f.Risks)
	}
}

func TestRTCacheNamedFolderIsNotAWebCache(t *testing.T) {
	e, home := testEnv(t)
	write(t, filepath.Join(home, "Library/Application Support/MyNotes/Cache/notes.sqlite"), 1<<20)
	write(t, filepath.Join(home, "Library/Application Support/RealElectron/Cache/Cache_Data/f"), 1<<20)
	write(t, filepath.Join(home, "Library/Application Support/RealElectron/Preferences"), 10)
	os.MkdirAll(filepath.Join(home, "Library/Application Support/RealElectron/Local Storage"), 0o755)
	write(t, filepath.Join(home, "Library/Application Support/Signal/Cache/x"), 1<<20)
	write(t, filepath.Join(home, "Library/Application Support/Signal/Preferences"), 10)
	os.MkdirAll(filepath.Join(home, "Library/Application Support/Signal/Local Storage"), 0o755)
	var titles []string
	for _, f := range e.webCaches(nil) {
		titles = append(titles, f.Title)
	}
	got := strings.Join(titles, "|")
	if strings.Contains(got, "MyNotes") || strings.Contains(got, "Signal") || !strings.Contains(got, "RealElectron") {
		t.Fatalf("web caches = %q; want RealElectron only", got)
	}
}

func TestRTDiskImageIsNotSafeByName(t *testing.T) {
	if app := matchInstalled("Google Takeout photos 2019.dmg", []string{"Google Chrome"}); app != "" {
		t.Fatalf("a personal image matched %s", app)
	}
	if app := matchInstalled("GoogleChrome.dmg", []string{"Google Chrome"}); app == "" {
		t.Fatal("the real Chrome installer did not match")
	}
}

func TestRTWorktreeSecretsAreFound(t *testing.T) {
	_, home := testEnv(t)
	repo := filepath.Join(home, "wt")
	write(t, filepath.Join(repo, "a.txt"), 1)
	os.WriteFile(filepath.Join(repo, ".gitignore"), []byte("tmp/\n.vscode/\nbuild/\nnode_modules/\n"), 0o644)
	git(t, repo, "init", "-q")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-qm", "x")
	write(t, filepath.Join(repo, "tmp/prod-credentials.json"), 10)
	write(t, filepath.Join(repo, "build/release.keystore"), 10)
	write(t, filepath.Join(repo, "build/out.js"), 10)
	write(t, filepath.Join(repo, "node_modules/x.js"), 10)
	got := strings.Join(precious(repo), "|")
	if !strings.Contains(got, "tmp") || !strings.Contains(got, "build/release.keystore") || strings.Contains(got, "out.js") || strings.Contains(got, "node_modules") {
		t.Fatalf("precious = %q", got)
	}
}

func TestRTTotalsCountParentsOnce(t *testing.T) {
	fs := []model.Finding{
		{Paths: []string{"/h/wt/node_modules"}, Bytes: 5, Safety: model.Safe},
		{Paths: []string{"/h/wt"}, Bytes: 5, Safety: model.Review},
	}
	if got := totals(fs); got.Safe+got.Review != 5 {
		t.Fatalf("totals = %+v, want 5 bytes in all", got)
	}
}

func TestRTControlCharactersNeverReachScripts(t *testing.T) {
	in := []model.Finding{
		{Title: "ok", Paths: []string{"/h/evil\necho INJECTED #"}},
		{Title: "x", Paths: []string{"/h/fine"}, Reasons: []string{"a\nrm -rf ~"}},
	}
	out, dropped := sanitize(in)
	if dropped != 1 || len(out) != 1 || strings.Contains(out[0].Reasons[0], "\n") {
		t.Fatalf("sanitize = %d dropped, %+v", dropped, out)
	}
}

func TestRTCommandsUseAbsolutePaths(t *testing.T) {
	e, home := testEnv(t)
	if q := e.Q(filepath.Join(home, "x")); strings.Contains(q, "$HOME") || !strings.HasPrefix(q, "'/") {
		t.Fatalf("Q = %s, want an absolute quoted path", q)
	}
}

func TestRTLocalHistoryInCacheIsReview(t *testing.T) {
	e, home := testEnv(t)
	write(t, filepath.Join(home, "Library/Caches/Google/AndroidStudio2024.1/LocalHistory/changes.storageData"), 1<<20)
	for _, f := range e.cacheChildren(nil) {
		if strings.Contains(f.Title, "Google") && (f.Safety == model.Safe || len(f.Commands) == 0 || strings.Contains(f.Commands[0], "rm ")) {
			t.Fatalf("a cache that holds LocalHistory got %s %q", f.Safety, f.Commands)
		}
	}
}
