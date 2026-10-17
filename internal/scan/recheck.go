package scan

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RO-29/spaceaudit/internal/fsx"
	"github.com/RO-29/spaceaudit/internal/model"
)

// Recheck measures again only the paths of an earlier report, so you can see what a cleanup changed.
// Items are measured in parallel; progress gets (done, total, title, freed so far) after each one.
func Recheck(base model.Report, ids map[string]bool, progress func(done, total int, title string, freed int64)) model.RecheckReport {
	out := model.RecheckReport{Tool: "spaceaudit", Version: Version, CheckedAt: time.Now(), BaseScanAt: base.GeneratedAt, Home: base.Home,
		VolumeBefore: base.Volume, VolumeNow: volume(base.Home)}
	fsx.Home = base.Home
	fsx.NoPrompt = !fsx.FullDiskAccess() // the same rule as a scan: never cause a privacy prompt
	var todo []model.Finding
	for _, f := range base.Findings {
		if len(ids) == 0 || ids[f.ID] {
			todo = append(todo, f)
		}
	}
	// The largest items take longest, so they start first; the total time is then close to the slowest one.
	sort.SliceStable(todo, func(i, j int) bool { return todo[i].Bytes > todo[j].Bytes })
	items := make([]model.RecheckItem, len(todo))
	var mu sync.Mutex
	running := map[int]string{}
	now := func() string { // the items still being measured, so a slow one is visible
		var t []string
		for _, v := range running {
			t = append(t, v)
		}
		sort.Strings(t)
		if len(t) > 3 {
			t = append(t[:3], "+"+strconv.Itoa(len(t)-3)+" more")
		}
		return "measuring now: " + strings.Join(t, ", ")
	}
	done := 0
	var freed int64
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i := range todo {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			mu.Lock()
			running[i] = todo[i].Title
			d0, f0, n0 := done, freed, now()
			mu.Unlock()
			if progress != nil {
				progress(d0, len(todo), n0, f0)
			}
			it := checkItem(todo[i])
			items[i] = it
			mu.Lock()
			delete(running, i)
			done++
			if it.Before > it.Now && it.Status != "not checked" {
				freed += it.Before - it.Now
			}
			d, fr, n := done, freed, now()
			if len(running) == 0 {
				n = "done"
			}
			mu.Unlock()
			if progress != nil {
				progress(d, len(todo), n, fr)
			}
		}(i)
	}
	wg.Wait()
	out.Items, out.Freed = items, freed
	return out
}

func checkItem(f model.Finding) model.RecheckItem {
	it := model.RecheckItem{ID: f.ID, Title: f.Title, Safety: f.Safety, Category: f.Category, Before: f.Bytes, Paths: f.Paths}
	if len(f.Paths) == 0 {
		it.Status = "not checked"
		it.Note = "This finding has no path (for example Docker or open deleted files). Run a new scan to check it."
		return it
	}
	if f.Rule == "duplicate-files" {
		left := 0
		for _, p := range f.Paths {
			if _, err := os.Lstat(p); err == nil {
				left++
			}
		}
		it.Now = f.Bytes * int64(max(0, left-1)) / int64(max(1, len(f.Paths)-1))
		switch {
		case left <= 1:
			it.Status, it.Now = "gone", 0
			it.Note = "Only one copy is left."
		case left < len(f.Paths):
			it.Status = "partly gone"
		default:
			it.Status = "unchanged"
		}
		return it
	}
	// Compare the same measure as the scan: allocated bytes, with the same age filter.
	before := f.Allocated
	if before == 0 {
		before = f.Bytes // a report from before v0.4 stored only this
	}
	it.Before = before
	gone := 0
	var now int64
	stalled := false
	for _, p := range f.Paths {
		if fsx.Blocked(p) != "" {
			stalled = true // not readable without a prompt now
			continue
		}
		if _, err := os.Lstat(p); err != nil {
			gone++
			continue
		}
		var u fsx.Usage
		if f.OlderDays > 0 {
			u = measureOlder([]string{p}, time.Now().Add(-time.Duration(f.OlderDays)*24*time.Hour))
		} else {
			u = fsx.MeasureWithin(p, time.Minute)
		}
		stalled = stalled || u.TimedOut
		now += u.Bytes
	}
	it.Now = now
	switch {
	case stalled:
		it.Status = "not checked"
		it.Note = "A folder gave no answer while it was measured, so the size now is not known."
	case f.Partial:
		it.Status = "not checked"
		it.Note = "The scan could not measure this item fully, so a comparison would not be fair."
	case gone == len(f.Paths):
		it.Status = "gone"
	case gone > 0:
		it.Status = "partly gone"
	case now < before*9/10:
		it.Status = "smaller"
	case now > before*11/10+(1<<20):
		it.Status = "larger"
	default:
		it.Status = "unchanged"
	}
	return it
}
