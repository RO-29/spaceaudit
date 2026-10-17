// Package state keeps the last scan so a recheck can compare against it. It writes only in its own folder.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/RO-29/spaceaudit/internal/model"
)

// Dir is spaceaudit's own folder. Nothing outside it is ever written by this package.
func Dir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Application Support", "spaceaudit")
}

// LastPath is where the most recent full report is kept.
func LastPath() string { return filepath.Join(Dir(), "last-scan.json") }

// Save stores r as the last scan.
func Save(r model.Report) error {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	f, err := os.Create(LastPath())
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(r)
}

// HistoryPath holds one line per full scan.
func HistoryPath() string { return filepath.Join(Dir(), "history.jsonl") }

// AppendHistory adds r to the history and returns its run number.
func AppendHistory(r model.Report) (int, error) {
	prev := LoadHistory(0)
	run := 1
	if len(prev) > 0 {
		run = prev[len(prev)-1].Run + 1
	}
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return run, err
	}
	f, err := os.OpenFile(HistoryPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return run, err
	}
	defer f.Close()
	p := model.HistoryPoint{Run: run, At: r.GeneratedAt, Version: r.Version, Total: r.Volume.Total, Used: r.Volume.Used, Available: r.Volume.Available,
		Safe: r.Totals.Safe, Review: r.Totals.Review, Risky: r.Totals.Risky, Findings: len(r.Findings), Seconds: r.DurationSec}
	b, _ := json.Marshal(p)
	_, err = f.Write(append(b, '\n'))
	return run, err
}

// LoadHistory returns the last n points (all when n is 0), oldest first.
func LoadHistory(n int) []model.HistoryPoint {
	b, err := os.ReadFile(HistoryPath())
	if err != nil {
		return nil
	}
	var out []model.HistoryPoint
	for _, line := range strings.Split(string(b), "\n") {
		var p model.HistoryPoint
		if json.Unmarshal([]byte(line), &p) == nil && p.Run > 0 {
			out = append(out, p)
		}
	}
	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

var htmlData = regexp.MustCompile(`(?s)<script id="data" type="application/json">(.*?)</script>`)

// Load reads a report from a JSON file or from a spaceaudit HTML report.
func Load(path string) (model.Report, error) {
	var r model.Report
	b, err := os.ReadFile(path)
	if err != nil {
		return r, err
	}
	if m := htmlData.FindSubmatch(b); m != nil {
		b = m[1]
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	if r.Tool != "spaceaudit" {
		return r, errors.New(path + " is not a spaceaudit report")
	}
	return r, nil
}
