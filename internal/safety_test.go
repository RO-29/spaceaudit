package internal

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/RO-29/spaceaudit/internal/probe"
)

// The tool must not be able to delete, move or change a file. This test reads every Go source file and fails on any API that can.
func TestNoDestructiveCalls(t *testing.T) {
	banned := regexp.MustCompile(`\bos\.(Remove|RemoveAll|Rename|Truncate|Chmod|Chown|Chtimes|Link|Symlink|Mkdir|MkdirAll|WriteFile)\b|\bsyscall\.(Unlink|Rmdir|Rename|Unlinkat|Truncate)\b|\bexec\.Command(Context)?\(`)
	allowedExec := map[string]bool{
		filepath.Join("probe", "probe.go"):                  true,
		filepath.Join("..", "cmd", "spaceaudit", "main.go"): true, // only "/usr/bin/open <report>"
	}
	files := []string{}
	for _, root := range []string{".", filepath.Join("..", "cmd")} {
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err == nil && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
				files = append(files, p)
			}
			return nil
		})
	}
	if len(files) < 5 {
		t.Fatalf("found only %d source files; the test does not see the code", len(files))
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, m := range banned.FindAllString(string(b), -1) {
			if strings.HasPrefix(m, "exec.Command") && allowedExec[f] {
				continue
			}
			if m == "os.MkdirAll" && f == filepath.Join("state", "state.go") {
				continue // spaceaudit's own folder in Application Support, for the last scan
			}
			t.Errorf("%s uses %s, which can change files", f, m)
		}
	}
}

func TestOpenOnlyOpensTheReport(t *testing.T) {
	b, _ := os.ReadFile(filepath.Join("..", "cmd", "spaceaudit", "main.go"))
	for _, m := range regexp.MustCompile(`exec\.Command\([^)]*\)`).FindAllString(string(b), -1) {
		if m != `exec.Command("/usr/bin/open", path)` {
			t.Errorf("unexpected exec in main.go: %s", m)
		}
	}
}

func TestProbeRefusesWrites(t *testing.T) {
	refused := [][]string{
		{"rm", "-rf", "/tmp/x"}, {"docker", "system", "prune"}, {"docker", "image", "prune", "-a"}, {"brew", "cleanup"},
		{"brew", "cleanup", "--prune=all"}, {"git", "-C", "/tmp", "worktree", "remove", "x"}, {"git", "-C", "/tmp", "clean", "-fdx"},
		{"git", "-C", "/tmp", "checkout", "."}, {"tmutil", "deletelocalsnapshots", "/"}, {"xcrun", "simctl", "delete", "unavailable"},
		{"npm", "cache", "clean", "--force"}, {"go", "clean", "-cache"}, {"open", "/Applications/Calculator.app"}, {"sh", "-c", "ls"},
		{"git", "status"}, {"lsof", "-p", "1"},
	}
	for _, c := range refused {
		if probe.Allowed(c[0], c[1:]) {
			t.Errorf("probe allows %v", c)
		}
		if _, err := probe.Run(1, c[0], c[1:]...); err == nil {
			t.Errorf("probe ran %v", c)
		}
	}
	for _, c := range [][]string{{"docker", "system", "df"}, {"brew", "cleanup", "-n"}, {"git", "-C", "/tmp", "status", "--porcelain"}, {"open", "-R", "/tmp"}} {
		if !probe.Allowed(c[0], c[1:]) {
			t.Errorf("probe refuses read-only %v", c)
		}
	}
}
