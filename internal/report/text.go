// Package report renders a scan as terminal text, Markdown, a review script, JSON or HTML.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/RO-29/spaceaudit/internal/fsx"
	"github.com/RO-29/spaceaudit/internal/model"
)

const disclaimer = "spaceaudit never deletes anything. It only recommends. Check every path and every command yourself before you run it, and keep a backup of anything you cannot download again."

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

var badge = map[model.Safety]string{model.Safe: "SAFE  ", model.Review: "REVIEW", model.Risky: "RISKY ", model.Keep: "KEEP  "}
var color = map[model.Safety]string{model.Safe: "\033[32m", model.Review: "\033[33m", model.Risky: "\033[31m", model.Keep: "\033[36m"}

// Text writes a terminal summary. detail adds reasons, risks and commands for each finding.
func Text(w io.Writer, r model.Report, detail, ansi bool) {
	c := func(s model.Safety, t string) string {
		if !ansi {
			return t
		}
		return color[s] + t + "\033[0m"
	}
	b := func(t string) string {
		if !ansi {
			return t
		}
		return "\033[1m" + t + "\033[0m"
	}
	v := r.Volume
	fmt.Fprintf(w, "%s  %s  macOS %s  %s\n", b("spaceaudit "+r.Version), r.Host, r.MacOS, r.GeneratedAt.Format("2006-01-02 15:04"))
	if v.Total > 0 {
		fmt.Fprintf(w, "Disk %s: %s used of %s, %s free (%.0f%% used)\n", v.Mount, fsx.Human(v.Used), fsx.Human(v.Total), fsx.Human(v.Available), 100*float64(v.Used)/float64(v.Total))
	}
	t := r.Totals
	fmt.Fprintf(w, "Can free: %s safe, %s after review, %s risky. Scan took %.0fs.\n\n",
		c(model.Safe, fsx.Human(t.Safe)), c(model.Review, fsx.Human(t.Review)), c(model.Risky, fsx.Human(t.Risky)), r.DurationSec)
	for _, f := range r.Findings {
		fmt.Fprintf(w, "%s %9s  %s\n", c(f.Safety, badge[f.Safety]), fsx.Human(f.Bytes), f.Title)
		if !detail {
			continue
		}
		for _, p := range first(f.Paths, 3) {
			fmt.Fprintf(w, "         path     %s\n", p)
		}
		for _, x := range f.Blockers {
			fmt.Fprintf(w, "         %s %s\n", c(model.Risky, "BLOCKER "), x)
		}
		for _, x := range f.Reasons {
			fmt.Fprintf(w, "         why      %s\n", x)
		}
		for _, x := range f.Risks {
			fmt.Fprintf(w, "         risk     %s\n", x)
		}
		for _, x := range first(f.Verify, 3) {
			fmt.Fprintf(w, "         verify   %s\n", x)
		}
		for _, x := range first(f.Commands, 3) {
			fmt.Fprintf(w, "         command  %s\n", x)
		}
		if f.Restore != "" {
			fmt.Fprintf(w, "         restore  %s\n", f.Restore)
		}
		for _, x := range f.Notes {
			fmt.Fprintf(w, "         note     %s\n", x)
		}
		fmt.Fprintln(w)
	}
	if len(r.Facts) > 0 {
		fmt.Fprintln(w, b("\nFacts that change the advice"))
		for _, f := range r.Facts {
			fmt.Fprintf(w, "  %-18s %s  %s\n", f.Key, f.Value, f.Note)
		}
	}
	fmt.Fprintln(w)
	for _, x := range r.Warnings {
		fmt.Fprintln(w, "! "+x)
	}
	fmt.Fprintln(w, "! "+disclaimer)
}

func first(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], fmt.Sprintf("... %d more (see the review script)", len(s)-n))
}

// Script writes a shell file where every command is a comment, so running the file does nothing.
func Script(w io.Writer, r model.Report) {
	fmt.Fprintf(w, "#!/bin/sh\n# spaceaudit review script, generated %s on %s.\n", r.GeneratedAt.Format(time.RFC3339), r.Host)
	fmt.Fprintln(w, "# Every command below is commented out. Read the reason, run the verify line, then uncomment only what you choose.")
	fmt.Fprintln(w, "# "+disclaimer)
	fmt.Fprintln(w, "echo 'This file runs nothing. Open it in an editor and uncomment the commands you choose.'; exit 0")
	for _, s := range []model.Safety{model.Safe, model.Review, model.Risky} {
		fmt.Fprintf(w, "\n# ================= %s =================\n", strings.ToUpper(string(s)))
		for _, f := range r.Findings {
			if f.Safety != s {
				continue
			}
			fmt.Fprintf(w, "\n# --- %s  (%s)  [%s]\n", f.Title, fsx.Human(f.Bytes), f.Rule)
			for _, x := range f.Blockers {
				fmt.Fprintf(w, "# BLOCKER: %s\n", x)
			}
			for _, x := range f.Reasons {
				fmt.Fprintf(w, "# why:    %s\n", x)
			}
			for _, x := range f.Risks {
				fmt.Fprintf(w, "# risk:   %s\n", x)
			}
			for _, x := range f.Verify {
				fmt.Fprintf(w, "# verify: %s\n", x)
			}
			if f.Restore != "" {
				fmt.Fprintf(w, "# restore: %s\n", f.Restore)
			}
			for _, x := range f.Commands {
				fmt.Fprintf(w, "# %s\n", strings.ReplaceAll(x, "\n", "\n# "))
			}
			for _, x := range f.Alternate {
				fmt.Fprintf(w, "#   or: %s\n", x)
			}
		}
	}
}

// Markdown writes a readable report.
func Markdown(w io.Writer, r model.Report) {
	v := r.Volume
	fmt.Fprintf(w, "# Disk space audit: %s\n\n", r.Host)
	fmt.Fprintf(w, "Generated %s by spaceaudit %s on macOS %s.\n\n", r.GeneratedAt.Format("2006-01-02 15:04 MST"), r.Version, r.MacOS)
	fmt.Fprintf(w, "> %s\n\n", disclaimer)
	if v.Total > 0 {
		fmt.Fprintf(w, "**Disk:** %s used of %s. %s free.\n\n", fsx.Human(v.Used), fsx.Human(v.Total), fsx.Human(v.Available))
	}
	t := r.Totals
	fmt.Fprintf(w, "| Level | Space | Meaning |\n|---|---|---|\n")
	fmt.Fprintf(w, "| Safe | %s | Regenerated automatically. No user data. |\n", fsx.Human(t.Safe))
	fmt.Fprintf(w, "| Review | %s | Regenerable, but has a cost or a blocker. |\n", fsx.Human(t.Review))
	fmt.Fprintf(w, "| Risky | %s | Can hold your data or break a tool. |\n\n", fsx.Human(t.Risky))
	for _, s := range []model.Safety{model.Safe, model.Review, model.Risky, model.Keep} {
		var rows []model.Finding
		for _, f := range r.Findings {
			if f.Safety == s {
				rows = append(rows, f)
			}
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(w, "## %s\n\n", strings.ToUpper(string(s[:1]))+string(s[1:]))
		for _, f := range rows {
			fmt.Fprintf(w, "### %s (%s)\n\n", f.Title, fsx.Human(f.Bytes))
			for _, p := range first(f.Paths, 5) {
				fmt.Fprintf(w, "- Path: `%s`\n", p)
			}
			for _, x := range f.Blockers {
				fmt.Fprintf(w, "- **Blocker:** %s\n", x)
			}
			for _, x := range f.Reasons {
				fmt.Fprintf(w, "- Why: %s\n", x)
			}
			for _, x := range f.Risks {
				fmt.Fprintf(w, "- Risk: %s\n", x)
			}
			if f.Restore != "" {
				fmt.Fprintf(w, "- Restore: %s\n", f.Restore)
			}
			fmt.Fprintln(w, "\n```sh\n# verify")
			for _, x := range f.Verify {
				fmt.Fprintln(w, x)
			}
			fmt.Fprintln(w, "# command (run only after you verify)")
			for _, x := range first(f.Commands, 5) {
				fmt.Fprintln(w, x)
			}
			fmt.Fprint(w, "```\n\n")
		}
	}
	if len(r.Facts) > 0 {
		fmt.Fprintf(w, "## Facts\n\n| Fact | Value | Note |\n|---|---|---|\n")
		for _, f := range r.Facts {
			fmt.Fprintf(w, "| %s | %s | %s |\n", f.Key, f.Value, f.Note)
		}
	}
}
