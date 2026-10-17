// Package scan finds reclaimable disk space and explains each finding. It never changes a file.
package scan

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/RO-29/spaceaudit/internal/fsx"
	"github.com/RO-29/spaceaudit/internal/model"
	"github.com/RO-29/spaceaudit/internal/probe"
)

// Version is set by the build.
var Version = "dev"

// Run performs one full read-only scan.
func Run(o Options) model.Report {
	start := time.Now()
	if o.Jobs <= 0 {
		o.Jobs = 8
	}
	if o.Progress == nil {
		o.Progress = func(string) {}
	}
	fsx.Home = o.Home
	steps := []string{"Snapshot of open files (lsof)", "Known caches and tool folders", "App and browser caches", "Homebrew and Docker (dry run)", "Snapshots, open deleted files, simulators", "Applications and Downloads"}
	if !o.Quick {
		steps = append(steps, "Walking the home folder", "Project build folders and worktrees", "Duplicate files")
	}
	steps = append(steps, "Inventory: browsers, AI tools, languages, Downloads")
	if o.Events != nil {
		o.Events(model.Event{Step: 1, Steps: len(steps), Title: steps[0], Titles: steps})
	}
	o.Progress(steps[0])
	e := newEnv(o)
	for _, r := range []string{"Library/Mobile Documents", "Library/CloudStorage"} {
		if fsx.Exists(filepath.Join(o.Home, r)) {
			e.fact("not opened", "~/"+r, "Cloud folders (iCloud Drive, Google Drive, Dropbox, OneDrive) are not read, because reading them can download files. Manage them in their apps.")
		}
	}
	if os.Geteuid() == 0 {
		e.warn("The scan runs as root. Commands in this report use $HOME, so check that HOME points at the right user.")
	}
	host, _ := os.Hostname()
	mac, _ := probe.Run(5*time.Second, "sw_vers", "-productVersion")
	rep := model.Report{Tool: "spaceaudit", Version: Version, GeneratedAt: start, Host: host, MacOS: strings.TrimSpace(mac), Home: o.Home}
	rep.Volume = volume(o.Home)

	var findings []model.Finding
	cur := 0
	var fb int64
	step := func(i int, detail string) {
		cur = i
		fb = 0
		for _, f := range findings {
			fb += f.Bytes
		}
		o.Progress(steps[i])
		if o.Events != nil {
			o.Events(model.Event{Step: i + 1, Steps: len(steps), Title: steps[i], Detail: detail, Found: len(findings), FoundBytes: fb, Titles: steps})
		}
	}
	e.onWalk = func(files, bytes int64, where string) {
		if o.Events != nil {
			o.Events(model.Event{Step: cur + 1, Steps: len(steps), Title: steps[cur], Detail: where, Files: files, Bytes: bytes, Found: len(findings), FoundBytes: fb})
		}
	}
	step(1, "")
	st, claimed := e.staticRules()
	findings = append(findings, st...)
	step(2, "")
	findings = append(findings, e.cacheChildren(claimed)...)
	findings = append(findings, e.webCaches(claimed)...)
	findings = append(findings, e.sandboxWebCaches(claimed)...)
	findings = append(findings, e.sandboxCaches(claimed)...)
	findings = append(findings, e.editorLeftovers()...)
	findings = append(findings, e.nodeVersions()...)
	step(3, "")
	findings = append(findings, e.homebrew()...)
	findings = append(findings, e.containers()...)
	step(4, "")
	findings = append(findings, e.systemFacts()...)
	step(5, "")
	findings = append(findings, e.apps()...)
	findings = append(findings, e.downloads()...)

	var cands []candidate
	if !o.Quick {
		step(6, "")
		w := e.walkHome()
		cands = w.cands
		step(7, strconv.Itoa(len(w.cands))+" build folders, "+strconv.Itoa(len(w.worktrees))+" worktrees")
		findings = append(findings, e.projectFindings(w.cands)...)
		findings = append(findings, e.worktreeFindings(w.worktrees)...)
		step(8, strconv.Itoa(len(w.dups))+" large files")
		findings = append(findings, e.duplicates(w.dups)...)
		var covered []string
		for _, f := range findings {
			covered = append(covered, f.Paths...)
		}
		findings = append(findings, e.largeFiles(w.larges, w.bundles, covered)...)
		rep.Areas = areas(o.Home, w)
		rep.Unexplained = unexplained(rep.Volume, w.total, e)
	}

	findings, dropped := sanitize(findings)
	if dropped > 0 {
		e.warn(strconv.Itoa(dropped) + " findings were dropped because their paths hold control characters (such as a line break). Commands for such paths are unsafe to copy. Inspect them by hand.")
	}
	step(len(steps)-1, "")
	rep.Inventories = []model.Inventory{e.browserInventory(), e.aiInventory(), e.languageInventory(cands), e.downloadsInventory()}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Safety.Rank() != findings[j].Safety.Rank() {
			return findings[i].Safety.Rank() < findings[j].Safety.Rank()
		}
		return findings[i].Bytes > findings[j].Bytes
	})
	for i := range findings {
		for _, k := range []*[]string{&findings[i].Reasons, &findings[i].Risks, &findings[i].Blockers, &findings[i].Verify, &findings[i].Commands} {
			if *k == nil {
				*k = []string{}
			}
		}
		if findings[i].Paths == nil {
			findings[i].Paths = []string{}
		}
	}
	rep.Findings = findings
	rep.Totals = totals(findings)
	rep.Facts = e.Facts
	rep.Warnings = append(e.Warn, "This tool only recommends. Check every path and command yourself before you run it.")
	rep.DurationSec = time.Since(start).Seconds()
	if o.Events != nil {
		o.Events(model.Event{Step: len(steps), Steps: len(steps), Title: "Done", Found: len(findings)})
	}
	return rep
}

// sanitize drops findings with control characters in a path and makes every text field one line,
// so no generated script line can be broken out of its comment.
func sanitize(fs []model.Finding) ([]model.Finding, int) {
	bad := func(s string) bool {
		return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
	}
	flat := func(s string) string {
		return strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return ' '
			}
			return r
		}, s)
	}
	var out []model.Finding
	dropped := 0
	for _, f := range fs {
		skip := bad(f.Title)
		for _, p := range f.Paths {
			skip = skip || bad(p)
		}
		if skip {
			dropped++
			continue
		}
		for _, list := range []*[]string{&f.Reasons, &f.Risks, &f.Blockers, &f.Notes, &f.Verify, &f.Commands, &f.Alternate} {
			for i := range *list {
				(*list)[i] = flat((*list)[i])
			}
		}
		f.Restore = flat(f.Restore)
		out = append(out, f)
	}
	return out, dropped
}

// totals adds sizes per safety level without double counting. Findings with shorter paths go first,
// so a parent (a worktree) is counted and the child inside it (its node_modules) is skipped.
func totals(in []model.Finding) model.Totals {
	fs := append([]model.Finding(nil), in...)
	depth := func(f model.Finding) int {
		if len(f.Paths) == 0 {
			return -1
		}
		d := 1 << 30
		for _, p := range f.Paths {
			d = min(d, strings.Count(p, "/"))
		}
		return d
	}
	sort.SliceStable(fs, func(i, j int) bool { return depth(fs[i]) < depth(fs[j]) })
	var t model.Totals
	var counted []string
	for _, f := range fs {
		inside := false
		for _, p := range f.Paths {
			for _, c := range counted {
				if fsx.Under(p, c) {
					inside = true
				}
			}
		}
		if inside {
			continue
		}
		counted = append(counted, f.Paths...)
		switch f.Safety {
		case model.Safe:
			t.Safe += f.Bytes
		case model.Review:
			t.Review += f.Bytes
		case model.Risky:
			t.Risky += f.Bytes
		default:
			t.Keep += f.Bytes
		}
	}
	return t
}

func areas(home string, w walkResult) []model.Area {
	first := map[string]*model.Area{}
	for p, b := range w.top {
		rel := strings.TrimPrefix(p, home+"/")
		top := filepath.Join(home, strings.SplitN(rel, "/", 2)[0])
		a, ok := first[top]
		if !ok {
			a = &model.Area{Path: top}
			first[top] = a
		}
		a.Bytes += b
		if p != top {
			a.Children = append(a.Children, model.Area{Path: p, Bytes: b})
		}
	}
	var out []model.Area
	for top, a := range first {
		a.Denied = w.denied[top]
		sort.Slice(a.Children, func(i, j int) bool { return a.Children[i].Bytes > a.Children[j].Bytes })
		if len(a.Children) > 12 {
			var rest int64
			for _, c := range a.Children[12:] {
				rest += c.Bytes
			}
			a.Children = append(a.Children[:12], model.Area{Path: filepath.Join(top, "(other)"), Bytes: rest})
		}
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	var small int64
	var keep []model.Area
	for i, a := range out {
		if i < 20 {
			keep = append(keep, a)
		} else {
			small += a.Bytes
		}
	}
	if small > 0 {
		keep = append(keep, model.Area{Path: filepath.Join(home, "(other)"), Bytes: small})
	}
	return keep
}

// unexplained is volume use that neither the home walk nor the main system folders account for.
func unexplained(v model.Volume, home int64, e *Env) int64 {
	if v.Used == 0 {
		return 0
	}
	sum := home
	for _, p := range []string{"/Applications", "/Library", "/opt", "/usr/local", "/private/var", "/Users/Shared"} {
		u := fsx.MeasureWithin(p, time.Minute)
		sum += u.Bytes
		e.fact("size "+p, fsx.Human(u.Bytes), denyNote(u))
	}
	gap := v.Used - sum
	if gap > 1<<30 {
		e.fact("not explained", fsx.Human(gap), "Root-only folders, other users, APFS snapshots and purgeable space. Run sudo du -xhd1 /System/Volumes/Data to see it.")
	}
	if gap < 0 {
		return 0
	}
	return gap
}

func denyNote(u fsx.Usage) string {
	if u.Denied > 0 {
		return "some folders were not readable"
	}
	return ""
}

func parallel(jobs, n int, fn func(int) *model.Finding) []model.Finding {
	res := make([]*model.Finding, n)
	var wg sync.WaitGroup
	sem := make(chan struct{}, jobs)
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			res[i] = fn(i)
		}(i)
	}
	wg.Wait()
	var out []model.Finding
	for _, f := range res {
		if f != nil {
			out = append(out, *f)
		}
	}
	return out
}

func parallelMulti(jobs, n int, fn func(int) []model.Finding) []model.Finding {
	res := make([][]model.Finding, n)
	var wg sync.WaitGroup
	sem := make(chan struct{}, jobs)
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			res[i] = fn(i)
		}(i)
	}
	wg.Wait()
	var out []model.Finding
	for _, r := range res {
		out = append(out, r...)
	}
	return out
}

func probeHave(n string) bool { return probe.Have(n) }

func ownerIsMe(st os.FileInfo) bool {
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(sys.Uid) == os.Getuid()
}

// Totals is the exported form of totals, for filtered reports.
func Totals(fs []model.Finding) model.Totals { return totals(fs) }

// Catalog exposes the static rules for documentation.
func Catalog() []Rule { return catalog }

// Artifacts exposes the project artifact kinds for documentation.
func Artifacts() []Artifact { return artifacts }
