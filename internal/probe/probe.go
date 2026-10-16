// Package probe runs external commands, but only the read-only ones on an allowlist.
package probe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// allowed maps a binary to the argument prefixes it may run with. Anything else is refused.
var allowed = map[string][][]string{
	"ps":           {{"-axo"}},
	"lsof":         {{"-nP", "-u"}, {"-nP", "+L1"}},
	"docker":       {{"system", "df"}, {"context", "ls"}, {"info"}},
	"brew":         {{"cleanup", "-n"}, {"--cache"}, {"--prefix"}, {"autoremove", "--dry-run"}},
	"tmutil":       {{"listlocalsnapshots"}},
	"mdls":         {{"-raw", "-name"}},
	"xcode-select": {{"-p"}},
	"xcrun":        {{"simctl", "list"}},
	"diskutil":     {{"info"}},
	"df":           {{"-k"}},
	"go":           {{"env"}},
	"npm":          {{"config", "get", "cache"}},
	"yarn":         {{"cache", "dir"}},
	"pnpm":         {{"store", "path"}},
	"sw_vers":      {{"-productVersion"}},
	"plutil":       {{"-extract", "CFBundleIdentifier", "raw", "-o", "-"}},
	"pbcopy":       {{}},
	"open":         {{"-R"}},
}

// gitAllowed lists the git subcommands allowed after "-C <dir>".
var gitAllowed = [][]string{
	{"rev-parse"}, {"check-ignore"}, {"ls-files"}, {"log"}, {"status", "--porcelain"},
	{"rev-list", "--count"}, {"branch", "-r", "--contains"}, {"worktree", "list"},
}

// ErrRefused is returned for a command that is not on the allowlist.
var ErrRefused = errors.New("probe: command is not on the read-only allowlist")

// Allowed reports whether name+args is a permitted read-only command.
func Allowed(name string, args []string) bool {
	if name == "git" {
		if len(args) < 3 || args[0] != "-C" {
			return false
		}
		return hasPrefix(args[2:], gitAllowed)
	}
	prefixes, ok := allowed[name]
	if !ok {
		return false
	}
	return hasPrefix(args, prefixes)
}

func hasPrefix(args []string, prefixes [][]string) bool {
	for _, p := range prefixes {
		if len(args) < len(p) {
			continue
		}
		match := true
		for i := range p {
			if args[i] != p[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Look finds a binary. A Finder-launched app has a short PATH, so common tool folders are added.
func Look(name string) (string, bool) {
	if p, err := exec.LookPath(name); err == nil {
		return p, true
	}
	home, _ := os.UserHomeDir()
	for _, dir := range []string{"/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
		filepath.Join(home, "go/bin"), "/usr/local/go/bin", filepath.Join(home, ".cargo/bin"), filepath.Join(home, ".local/bin")} {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}

// Have reports whether a tool is installed.
func Have(name string) bool { _, ok := Look(name); return ok }

// Run executes an allowlisted command with a timeout and returns stdout.
func Run(timeout time.Duration, name string, args ...string) (string, error) {
	return RunInput(timeout, nil, name, args...)
}

// RunInput is Run with stdin, used only for pbcopy.
func RunInput(timeout time.Duration, stdin []byte, name string, args ...string) (string, error) {
	if !Allowed(name, args) {
		return "", fmt.Errorf("%w: %s %s", ErrRefused, name, strings.Join(args, " "))
	}
	bin, ok := Look(name)
	if !ok {
		return "", fmt.Errorf("probe: %s is not installed", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C", "GIT_OPTIONAL_LOCKS=0")
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return out.String(), fmt.Errorf("probe: %s timed out after %s", name, timeout)
	}
	if err != nil {
		return out.String(), fmt.Errorf("probe: %s: %v: %s", name, err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}
