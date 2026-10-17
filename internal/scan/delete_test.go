package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// These tests run the generated delete commands for real, inside a temporary folder, with traps around
// the target. A command must remove its target and nothing else, and it must do nothing when damaged.

func sandbox(t *testing.T) (*Env, string, string) {
	t.Helper()
	root, _ := filepath.EvalSymlinks(t.TempDir())
	home := filepath.Join(root, "home")
	e := &Env{Opt: Options{Home: home, Jobs: 1}, Home: home, Now: time.Now(), procs: map[int]string{}, git: map[string]*repoInfo{}}
	return e, home, root
}

func shells() []string {
	out := []string{"/bin/sh"}
	if _, err := os.Stat("/bin/zsh"); err == nil {
		out = append(out, "/bin/zsh")
	}
	return out
}

func run(t *testing.T, shell, cmd string) error {
	t.Helper()
	c := exec.Command(shell, "-c", cmd)
	c.Env = []string{"PATH=/usr/bin:/bin", "HOME="} // an empty HOME must not change what is deleted
	return c.Run()
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func TestDeleteRemovesOnlyTheTarget(t *testing.T) {
	for _, sh := range shells() {
		e, home, root := sandbox(t)
		target := filepath.Join(home, "it's a \"dir\" $x `y`", "node_modules")
		write(t, filepath.Join(target, "a.js"), 10)
		write(t, filepath.Join(target+".bak", "keep.js"), 10) // a sibling with a longer name
		write(t, filepath.Join(filepath.Dir(target), "src.js"), 10)
		write(t, filepath.Join(root, "outside", "precious"), 10)
		os.Symlink(filepath.Join(root, "outside"), filepath.Join(target, "link")) // a link inside the target
		cmd, ok := e.del(delAuto, target, false)
		if !ok {
			t.Fatalf("no command: %s", cmd)
		}
		if err := run(t, sh, cmd); err != nil {
			t.Fatalf("%s: %v\n%s", sh, err, cmd)
		}
		if exists(target) {
			t.Errorf("%s: target still exists", sh)
		}
		for _, keep := range []string{target + ".bak/keep.js", filepath.Join(filepath.Dir(target), "src.js"), filepath.Join(root, "outside", "precious")} {
			if !exists(keep) {
				t.Errorf("%s: deleted %s, which is not the target", sh, keep)
			}
		}
	}
}

func TestDeleteContentsKeepsTheFolderAndNeverFollowsLinks(t *testing.T) {
	for _, sh := range shells() {
		e, home, root := sandbox(t)
		dir := filepath.Join(home, "Library", "Caches", "App Name")
		write(t, filepath.Join(dir, "a"), 10)
		write(t, filepath.Join(dir, ".hidden"), 10)
		write(t, filepath.Join(dir, "sub", "b"), 10)
		write(t, filepath.Join(root, "outside", "precious"), 10)
		os.Symlink(filepath.Join(root, "outside"), filepath.Join(dir, "link"))
		write(t, filepath.Join(home, "Library", "Caches", "App Name 2", "keep"), 10)
		cmd, ok := e.del(delContents, dir, false)
		if !ok {
			t.Fatalf("no command: %s", cmd)
		}
		if err := run(t, sh, cmd); err != nil {
			t.Fatalf("%s: %v\n%s", sh, err, cmd)
		}
		ents, _ := os.ReadDir(dir)
		if !exists(dir) || len(ents) != 0 {
			t.Errorf("%s: want an empty folder, got %d entries", sh, len(ents))
		}
		if !exists(filepath.Join(root, "outside", "precious")) {
			t.Errorf("%s: followed a symbolic link out of the target", sh)
		}
		if !exists(filepath.Join(home, "Library", "Caches", "App Name 2", "keep")) {
			t.Errorf("%s: deleted a neighbour folder", sh)
		}
	}
}

func TestDamagedCommandsDeleteNothing(t *testing.T) {
	for _, sh := range shells() {
		e, home, _ := sandbox(t)
		target := filepath.Join(home, "proj", "node_modules")
		write(t, filepath.Join(target, "a.js"), 10)
		write(t, filepath.Join(home, "proj", "keep.js"), 10)
		cmd, _ := e.del(delAuto, target, false)
		q := shq(target)
		damaged := map[string]string{
			"empty path":          strings.Replace(cmd, q, "''", 1),
			"cut after the path":  cmd[:strings.Index(cmd, ";")],
			"lost closing quote":  strings.Replace(cmd, q, q[:len(q)-1], 1),
			"path cut in half":    strings.Replace(cmd, q, shq(target[:len(target)/2]), 1),
			"missing folder name": strings.Replace(cmd, q, shq(filepath.Join(home, "proj", "nope")), 1),
			"path cut to parent":  strings.Replace(cmd, q, shq(filepath.Join(home, "proj")), 1),
			"path cut to home":    strings.Replace(cmd, q, shq(home), 1),
		}
		for name, c := range damaged {
			_ = run(t, sh, c)
			if !exists(filepath.Join(target, "a.js")) || !exists(filepath.Join(home, "proj", "keep.js")) {
				t.Fatalf("%s: damaged command (%s) deleted files: %s", sh, name, c)
			}
		}
	}
}

func TestRefusedTargets(t *testing.T) {
	e, home, root := sandbox(t)
	os.MkdirAll(filepath.Join(home, "Desktop"), 0o755)
	write(t, filepath.Join(root, "real", "x"), 1)
	os.Symlink(filepath.Join(root, "real"), filepath.Join(home, "proj-link"))
	os.MkdirAll(filepath.Join(home, "proj"), 0o755)
	os.Symlink(filepath.Join(root, "real"), filepath.Join(home, "proj", "cache-link"))
	refused := []string{"/", "/Users", "/Library", "/System", "/Applications", "/usr/local", "/opt/homebrew", home,
		filepath.Join(home, "Desktop"), filepath.Join(home, "Library"), filepath.Join(home, "Library", "Caches"), filepath.Join(home, "Documents"),
		filepath.Join(home, "proj", "cache-link"), filepath.Join(home, "Library", "Mobile Documents", "x"), filepath.Join(home, "Library", "CloudStorage", "Drive", "f"),
		"relative/path", filepath.Join(home, "a", "..", "b"), filepath.Join(home, "a") + "/", filepath.Join(home, "bad\nname"), "/etc", "/tmp", "/Volumes"}
	for _, p := range refused {
		if err := e.refuse(p); err == nil {
			t.Errorf("refuse(%q) = nil, want a refusal", p)
		}
		if c, ok := e.del(delAuto, p, false); ok || !strings.HasPrefix(c, "No delete command") {
			t.Errorf("del(%q) gave a command: %s", p, c)
		}
	}
	for _, p := range []string{filepath.Join(home, "Library", "Caches", "com.x"), filepath.Join(home, "proj", "node_modules"), filepath.Join(home, ".konan"), "/Applications/NoSuchApp.app", "/Library/Developer/CoreSimulator/Caches"} {
		if err := e.refuse(p); err != nil {
			t.Errorf("refuse(%q) = %v, want allowed", p, err)
		}
	}
}

func TestEveryCatalogDeleteIsGuarded(t *testing.T) {
	for _, r := range catalog {
		for _, c := range r.Commands {
			raw := regexp.MustCompile(`(^|[;&|]\s*)(sudo\s+)?rm\s|(^|\s)-delete(\s|$)`).MatchString(strings.Split(c, "#")[0])
			if raw && !strings.Contains(c, "{rm}") && !strings.Contains(c, "{contents}") {
				t.Errorf("%s: raw delete command bypasses the guard: %q", r.ID, c)
			}
		}
	}
}

func TestCatalogCommandsParse(t *testing.T) {
	e, home, _ := sandbox(t)
	sample := filepath.Join(home, "Library", "Caches", "it's a dir")
	ph := regexp.MustCompile(`<[a-zA-Z][a-zA-Z0-9 _-]*>`)
	for _, r := range catalog {
		for _, tmpl := range append(append([]string{}, r.Commands...), r.Verify...) {
			c := e.expand(tmpl, sample, r.Sudo)
			if ph.MatchString(c) {
				t.Errorf("%s: placeholder with < > can act as a redirection: %q", r.ID, c)
			}
			if !strings.ContainsAny(c[:1], "abcdefghijklmnopqrstuvwxyzp") || strings.Contains(c, " > ") && !strings.Contains(c, "env export") {
				continue // prose advice such as "Use the app's settings", not a shell line
			}
			if out, err := exec.Command("/bin/sh", "-n", "-c", c).CombinedOutput(); err != nil {
				t.Errorf("%s: command does not parse: %q: %s", r.ID, c, out)
			}
		}
	}
}
