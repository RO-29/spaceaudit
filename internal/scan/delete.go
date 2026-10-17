package scan

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/RO-29/spaceaudit/internal/fsx"
)

// Every delete command that spaceaudit prints is built here, so one set of guards protects all of them.
// The command carries its own checks: an empty, missing or symlinked path makes it do nothing.

type delKind int

const (
	delAuto     delKind = iota // the folder or file itself
	delContents                // everything inside the folder, but not the folder
)

// protectedRoots are never a delete target, whatever a rule says.
var protectedRoots = []string{"/", "/Users", "/System", "/Library", "/Applications", "/usr", "/bin", "/sbin", "/etc", "/var",
	"/private", "/private/var", "/private/etc", "/private/tmp", "/tmp", "/opt", "/opt/homebrew", "/usr/local", "/Volumes", "/cores", "/nix", "/nix/store",
	"/Library/Developer", "/Library/Application Support", "/System/Volumes", "/System/Volumes/Data"}

// homeDotAllowed are tool folders directly in the home folder that a rule may delete as a whole.
var homeDotAllowed = map[string]bool{".konan": true, ".ccache": true}

var errNoDelete = errors.New("no delete command")

// refuse explains why p must never be a delete target, or returns nil.
func (e *Env) refuse(p string) error {
	why := func(s string) error { return errors.Join(errNoDelete, errors.New(s)) }
	switch {
	case p == "" || !filepath.IsAbs(p):
		return why("the path is not absolute")
	case filepath.Clean(p) != p:
		return why("the path is not in clean form (it has //, /./, /../ or a trailing /)")
	case strings.IndexFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0:
		return why("the path holds a control character")
	case fsx.Provider(p, e.Home) || strings.Contains(p, "/Library/Application Support/Google/DriveFS") || strings.Contains(p, ".com.getdropbox.dropbox.sync"):
		return why("it is a cloud folder; a delete there also deletes the file in the cloud")
	}
	for _, r := range protectedRoots {
		if p == r {
			return why(p + " is a system or top-level folder")
		}
	}
	if p == e.Home {
		return why("it is your home folder")
	}
	if rel, ok := strings.CutPrefix(p, e.Home+"/"); ok {
		parts := strings.Split(rel, "/")
		if len(parts) == 1 && !homeDotAllowed[parts[0]] {
			return why("~/" + parts[0] + " is a top-level folder of your home")
		}
		if parts[0] == "Library" && len(parts) == 2 {
			return why("~/" + rel + " is a top-level folder of your Library")
		}
	} else if !strings.HasPrefix(p, "/Applications/") && strings.Count(p, "/") < 3 {
		return why("the path is too close to the root of the disk")
	}
	if st, err := os.Lstat(p); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return why("it is a symbolic link; deleting through a link can reach another folder")
	}
	return nil
}

// del returns a guarded delete command for p, or a refusal text and false.
func (e *Env) del(kind delKind, p string, sudo bool) (string, bool) {
	if err := e.refuse(p); err != nil {
		return "No delete command: " + strings.TrimPrefix(err.Error(), errNoDelete.Error()+"\n") + ". Clean it by hand, carefully.", false
	}
	s := ""
	if sudo {
		s = "sudo "
	}
	q := shq(p)
	// n is the expected last component: if the path is cut or edited, the name check fails and nothing runs.
	g := "p=" + q + "; n=" + shq(filepath.Base(p)) + "; [ \"${p##*/}\" = \"$n\" ] && "
	isDir := true
	if st, err := os.Lstat(p); err == nil && !st.IsDir() {
		isDir = false
	}
	switch {
	case kind == delContents:
		return g + "[ -d \"$p\" ] && [ ! -L \"$p\" ] && " + s + "find -P \"$p\" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +", true
	case !isDir:
		return g + "[ -f \"$p\" ] && [ ! -L \"$p\" ] && " + s + "rm -f -- \"$p\"", true
	}
	return g + "[ -d \"$p\" ] && [ ! -L \"$p\" ] && " + s + "rm -rf -- \"$p\"", true
}

func (e *Env) delOnly(p string) string { c, _ := e.del(delAuto, p, false); return c }
