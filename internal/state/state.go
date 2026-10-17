// Package state keeps the last scan so a recheck can compare against it. It writes only in its own folder.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"

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
