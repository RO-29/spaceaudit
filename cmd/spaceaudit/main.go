// Command spaceaudit audits disk space on a Mac and recommends cleanups. It never deletes anything.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mattn/go-isatty"

	"github.com/RO-29/spaceaudit/internal/fsx"
	"github.com/RO-29/spaceaudit/internal/model"
	"github.com/RO-29/spaceaudit/internal/report"
	"github.com/RO-29/spaceaudit/internal/scan"
	"github.com/RO-29/spaceaudit/internal/tui"
)

const usage = `spaceaudit: read-only disk space audit for macOS. It recommends; it never deletes.

Usage:
  spaceaudit [scan]            terminal summary (add -v for reasons, risks and commands)
  spaceaudit tui               interactive browser
  spaceaudit html  [-o file]   designed HTML report (default: spaceaudit-report.html, then opens it)
  spaceaudit md    [-o file]   Markdown report
  spaceaudit json  [-o file]   machine-readable report (the Mac app reads this)
  spaceaudit script [-o file]  review script: every command is commented out
  spaceaudit plan  [-o file]   plan for --level items: runs only verify lines, cleanup lines stay comments
  spaceaudit rules             print the rule catalog as Markdown
  spaceaudit version

Flags (all commands):
`

func main() {
	cmd := "scan"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	home, _ := os.UserHomeDir()
	if su := os.Getenv("SUDO_USER"); su != "" && os.Geteuid() == 0 {
		home = "/Users/" + su
	}
	out := fs.String("o", "", "write to this file instead of the default")
	verbose := fs.Bool("v", false, "show reasons, risks and commands in the terminal summary")
	quick := fs.Bool("quick", false, "skip the full home walk (no project folders, worktrees or large files)")
	minMB := fs.Int("min", 50, "hide findings smaller than this many MB")
	largeGB := fs.Float64("large", 1, "list single files and bundles at or above this many GB")
	active := fs.Duration("active", 48*time.Hour, "a project edited within this time counts as active")
	stale := fs.Int("stale-days", 30, "a project untouched for this many days counts as stale")
	noDocker := fs.Bool("no-docker", false, "do not ask the Docker daemon")
	jobs := fs.Int("jobs", 8, "parallel workers")
	noOpen := fs.Bool("no-open", false, "do not open the HTML report after writing it")
	levels := fs.String("level", "", "only these levels, comma separated: safe,review,risky,keep (plan defaults to safe)")
	fs.StringVar(&home, "home", home, "home folder to scan")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	_ = fs.Parse(args)

	switch cmd {
	case "help", "-h", "--help":
		fs.Usage()
		return
	case "version":
		fmt.Println("spaceaudit", scan.Version)
		return
	case "rules":
		rulesMarkdown(os.Stdout)
		return
	}

	tty := isatty.IsTerminal(os.Stderr.Fd())
	o := scan.Options{Home: home, MinBytes: int64(*minMB) << 20, LargeBytes: int64(*largeGB * (1 << 30)),
		ActiveFor: *active, StaleAfter: time.Duration(*stale) * 24 * time.Hour, Quick: *quick, NoDocker: *noDocker, Jobs: *jobs}
	o.Progress = func(s string) {
		if tty {
			fmt.Fprintf(os.Stderr, "\r\033[K• %s", s)
		} else if cmd == "json" {
			fmt.Fprintln(os.Stderr, "progress: "+s)
		}
	}

	if cmd == "tui" {
		if err := tui.Run(o); err != nil {
			fail(err)
		}
		return
	}
	known := map[string]string{"scan": "", "html": "spaceaudit-report.html", "md": "spaceaudit-report.md", "json": "", "script": "spaceaudit-review.sh", "plan": "spaceaudit-plan.sh"}
	def, ok := known[cmd]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		fs.Usage()
		os.Exit(2)
	}
	r := scan.Run(o)
	if tty {
		fmt.Fprint(os.Stderr, "\r\033[K")
	}
	if *levels == "" && cmd == "plan" {
		*levels = "safe"
	}
	if *levels != "" {
		want := map[string]bool{}
		for _, l := range strings.Split(*levels, ",") {
			want[strings.TrimSpace(l)] = true
		}
		var keep []model.Finding
		for _, f := range r.Findings {
			if want[string(f.Safety)] && (cmd != "plan" || len(f.Blockers) == 0) {
				keep = append(keep, f)
			}
		}
		r.Findings = keep
		r.Totals = scan.Totals(keep)
	}
	path := *out
	if path == "" {
		path = def
	}
	var w io.Writer = os.Stdout
	if path != "" && path != "-" {
		if err := safeTarget(path); err != nil {
			fail(err)
		}
		f, err := os.Create(path) // the only file the tool writes is the report the user asked for
		if err != nil {
			fail(err)
		}
		defer f.Close()
		w = f
	}
	switch cmd {
	case "scan":
		report.Text(w, r, *verbose, w == os.Stdout && isatty.IsTerminal(os.Stdout.Fd()))
	case "json":
		if err := report.JSON(w, r); err != nil {
			fail(err)
		}
	case "md":
		report.Markdown(w, r)
	case "script":
		report.Script(w, r)
	case "plan":
		report.Plan(w, r)
	case "html":
		if err := report.HTML(w, r); err != nil {
			fail(err)
		}
	}
	if w != os.Stdout {
		fmt.Fprintf(os.Stderr, "Wrote %s. Safe %s, review %s, risky %s. Nothing was deleted.\n", path, fsx.Human(r.Totals.Safe), fsx.Human(r.Totals.Review), fsx.Human(r.Totals.Risky))
		if cmd == "html" && !*noOpen && tty {
			_ = exec.Command("/usr/bin/open", path).Start()
		}
	}
}

// safeTarget refuses to overwrite a file that an earlier spaceaudit run did not write.
func safeTarget(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	if !strings.Contains(string(buf[:n]), "spaceaudit") {
		return fmt.Errorf("%s exists and spaceaudit did not write it, so it is not overwritten. Choose another -o path", path)
	}
	return nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "spaceaudit:", err)
	os.Exit(1)
}

func rulesMarkdown(w io.Writer) {
	fmt.Fprint(w, "# Rule catalog\n\nGenerated by `spaceaudit rules`. Each rule is a recommendation, never an action.\n\n")
	fmt.Fprintln(w, "## Known locations\n\n| Rule | Level | Paths | Why | Risks | Restore |\n|---|---|---|---|---|---|")
	cell := func(s []string) string { return strings.ReplaceAll(strings.Join(s, " "), "|", "\\|") }
	for _, r := range scan.Catalog() {
		fmt.Fprintf(w, "| `%s` %s | %s | %s | %s | %s | %s |\n", r.ID, r.Title, r.Safety, "`"+strings.Join(r.Paths, "`<br>`")+"`", cell(r.Reasons), cell(r.Risks), strings.ReplaceAll(r.Restore, "|", "\\|"))
	}
	fmt.Fprint(w, "\n## Project build folders\n\nFound by one walk of the home folder. Each one is checked against its project: marker file, git tracked or ignored, lock file, last edit, and programs that use it now.\n\n")
	fmt.Fprintln(w, "| Folder | Base level | Needs marker | Must be git-ignored | Why | Restore |\n|---|---|---|---|---|---|")
	for _, a := range scan.Artifacts() {
		fmt.Fprintf(w, "| `%s` | %s | %s | %v | %s | %s |\n", a.Name, a.Safety, strings.Join(a.Markers, ", "), a.MustIgnore, a.Reason, a.Restore)
	}
	fmt.Fprintln(w, "\n## Dynamic checks\n\n- Every folder in `~/Library/Caches` and `~/.cache` that no rule above claims.\n- Chromium and Electron caches inside each app in `~/Library/Application Support` (HTTP, code, GPU and shader caches are safe; service worker storage is review).\n- Editor workspace state for folders that no longer exist, and extension versions that `extensions.json` does not list.\n- Git worktrees: uncommitted changes, unpushed commits, missing main repository.\n- Apps over 200 MB not opened for 90 days (Spotlight), with the Xcode and `xcode-select` dependency.\n- Downloads over 100 MB: age, source URL, installers that are already installed, archives already extracted.\n- Container runtimes: VM disk images, and `docker system df` when a daemon answers.\n- Homebrew `cleanup -n`, APFS local snapshots, deleted files that programs still hold open, the temporary folder.\n- Large single files and bundles that no other finding explains.")
}
