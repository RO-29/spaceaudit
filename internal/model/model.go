// Package model holds the report types shared by the scanner and every front end.
package model

import "time"

// Safety is the recommendation level for one finding.
type Safety string

const (
	Safe   Safety = "safe"   // regenerated automatically, holds no user data
	Review Safety = "review" // regenerable, but has a cost or a blocker
	Risky  Safety = "risky"  // can hold user data or break a tool
	Keep   Safety = "keep"   // information only, no command is offered
)

// Rank orders safety levels for sorting.
func (s Safety) Rank() int {
	switch s {
	case Safe:
		return 0
	case Review:
		return 1
	case Risky:
		return 2
	}
	return 3
}

// Finding is one thing the user can choose to clean, with the evidence for the advice.
type Finding struct {
	ID         string    `json:"id"`
	Rule       string    `json:"rule"`
	Category   string    `json:"category"`
	Title      string    `json:"title"`
	Paths      []string  `json:"paths"`
	Bytes      int64     `json:"bytes"`
	Files      int64     `json:"files"`
	Safety     Safety    `json:"safety"`
	Confidence string    `json:"confidence"`
	Modified   time.Time `json:"modified,omitzero"`
	LastUsed   time.Time `json:"lastUsed,omitzero"`
	UsedSource string    `json:"lastUsedSource,omitempty"`
	Reasons    []string  `json:"reasons"`
	Risks      []string  `json:"risks"`
	Blockers   []string  `json:"blockers"`
	Verify     []string  `json:"verify"`
	Commands   []string  `json:"commands"`
	Alternate  []string  `json:"alternate,omitempty"`
	Restore    string    `json:"restore,omitempty"`
	NeedsSudo  bool      `json:"needsSudo,omitempty"`
	Partial    bool      `json:"partial,omitempty"`
	Notes      []string  `json:"notes,omitempty"`
}

// Volume describes the disk that holds the home folder.
type Volume struct {
	Mount     string `json:"mount"`
	Total     int64  `json:"total"`
	Used      int64  `json:"used"`
	Available int64  `json:"available"`
}

// Area is one measured folder used for the "where the space goes" view.
type Area struct {
	Path     string `json:"path"`
	Bytes    int64  `json:"bytes"`
	Denied   int    `json:"denied,omitempty"`
	Children []Area `json:"children,omitempty"`
}

// Fact is one environment observation that changes the advice.
type Fact struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Note  string `json:"note,omitempty"`
}

// Report is the full scan output.
type Report struct {
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	GeneratedAt time.Time `json:"generatedAt"`
	Host        string    `json:"host"`
	MacOS       string    `json:"macos"`
	Home        string    `json:"home"`
	DurationSec float64   `json:"durationSec"`
	Volume      Volume    `json:"volume"`
	Areas       []Area    `json:"areas"`
	Unexplained int64     `json:"unexplained"`
	Facts       []Fact    `json:"facts"`
	Totals      Totals    `json:"totals"`
	Findings    []Finding `json:"findings"`
	Warnings    []string  `json:"warnings"`
}

// Totals sums findings per safety level without double counting nested paths.
type Totals struct {
	Safe   int64 `json:"safe"`
	Review int64 `json:"review"`
	Risky  int64 `json:"risky"`
	Keep   int64 `json:"keep"`
}
