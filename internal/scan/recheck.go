package scan

import (
	"os"
	"time"

	"github.com/RO-29/spaceaudit/internal/fsx"
	"github.com/RO-29/spaceaudit/internal/model"
)

// Recheck measures again only the paths of an earlier report, so you can see what a cleanup changed.
func Recheck(base model.Report, ids map[string]bool) model.RecheckReport {
	out := model.RecheckReport{Tool: "spaceaudit", Version: Version, CheckedAt: time.Now(), BaseScanAt: base.GeneratedAt, Home: base.Home,
		VolumeBefore: base.Volume, VolumeNow: volume(base.Home)}
	fsx.Home = base.Home
	for _, f := range base.Findings {
		if len(ids) > 0 && !ids[f.ID] {
			continue
		}
		it := model.RecheckItem{ID: f.ID, Title: f.Title, Safety: f.Safety, Category: f.Category, Before: f.Bytes, Paths: f.Paths}
		if len(f.Paths) == 0 {
			it.Status = "not checked"
			it.Note = "This finding has no path (for example Docker or open deleted files). Run a new scan to check it."
			out.Items = append(out.Items, it)
			continue
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
			if it.Before > it.Now {
				out.Freed += it.Before - it.Now
			}
			out.Items = append(out.Items, it)
			continue
		}
		// Compare the same measure as the scan: allocated bytes, with the same age filter.
		before := f.Allocated
		if before == 0 {
			before = f.Bytes // a report from before v0.4 stored only this
		}
		it.Before = before
		gone := 0
		var now int64
		for _, p := range f.Paths {
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
			now += u.Bytes
		}
		it.Now = now
		switch {
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
		if it.Before > it.Now {
			out.Freed += it.Before - it.Now
		}
		out.Items = append(out.Items, it)
	}
	return out
}
