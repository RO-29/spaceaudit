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
	Allocated  int64     `json:"allocated,omitempty"` // allocated bytes at scan time; recheck compares this, so versions agree
	OlderDays  int       `json:"olderDays,omitempty"` // only files older than this were counted
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
	Tool        string         `json:"tool"`
	Version     string         `json:"version"`
	GeneratedAt time.Time      `json:"generatedAt"`
	Host        string         `json:"host"`
	MacOS       string         `json:"macos"`
	Home        string         `json:"home"`
	DurationSec float64        `json:"durationSec"`
	Volume      Volume         `json:"volume"`
	Areas       []Area         `json:"areas"`
	Unexplained int64          `json:"unexplained"`
	Facts       []Fact         `json:"facts"`
	Totals      Totals         `json:"totals"`
	Findings    []Finding      `json:"findings"`
	Inventories []Inventory    `json:"inventories,omitempty"`
	Run         int            `json:"run,omitempty"`   // this report's number in the history
	Every       string         `json:"every,omitempty"` // the schedule, when a scheduled job made this report
	History     []HistoryPoint `json:"history,omitempty"`
	Warnings    []string       `json:"warnings"`
}

// Part is one measured folder inside an inventory item, with what it holds.
type Part struct {
	Name    string   `json:"name"`
	Path    string   `json:"path,omitempty"`
	Bytes   int64    `json:"bytes"`
	Explain string   `json:"explain,omitempty"`
	Safety  Safety   `json:"safety,omitempty"`
	Partial bool     `json:"partial,omitempty"`
	Top     []string `json:"top,omitempty"` // largest members, for aggregated parts
}

// InvGroup is a sub-unit of an item, such as one browser profile.
type InvGroup struct {
	Name  string `json:"name"`
	Path  string `json:"path,omitempty"`
	Note  string `json:"note,omitempty"`
	Bytes int64  `json:"bytes"`
	Parts []Part `json:"parts"`
}

// InvItem is one browser, AI tool, language or Downloads category.
type InvItem struct {
	Name      string     `json:"name"`
	Kind      string     `json:"kind,omitempty"`
	Path      string     `json:"path,omitempty"`
	App       string     `json:"app,omitempty"`
	AppBytes  int64      `json:"appBytes,omitempty"`
	Installed bool       `json:"installed,omitempty"`
	Running   bool       `json:"running,omitempty"`
	Bytes     int64      `json:"bytes"`
	Groups    []InvGroup `json:"groups,omitempty"`
	Parts     []Part     `json:"parts,omitempty"`
	Notes     []string   `json:"notes,omitempty"`
}

// Inventory explains where space goes in one area. It holds no commands.
type Inventory struct {
	Key   string    `json:"key"`
	Title string    `json:"title"`
	Intro string    `json:"intro"`
	Bytes int64     `json:"bytes"`
	Items []InvItem `json:"items"`
}

// Event is one structured progress update. Front ends use it to draw the scan screen.
type Event struct {
	Step       int      `json:"step"`
	Steps      int      `json:"steps"`
	Title      string   `json:"title"`
	Detail     string   `json:"detail,omitempty"`
	Files      int64    `json:"files,omitempty"`
	Bytes      int64    `json:"bytes,omitempty"`
	Found      int      `json:"found"`
	FoundBytes int64    `json:"foundBytes"`
	Titles     []string `json:"titles,omitempty"` // every step, so a front end can list the steps that are still to come
}

// RecheckItem is one earlier finding measured again.
type RecheckItem struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Safety   Safety   `json:"safety"`
	Category string   `json:"category"`
	Paths    []string `json:"paths"`
	Before   int64    `json:"before"`
	Now      int64    `json:"now"`
	Status   string   `json:"status"` // gone, partly gone, smaller, unchanged, larger, not checked
	Note     string   `json:"note,omitempty"`
}

// RecheckReport compares an earlier scan with the disk now.
type RecheckReport struct {
	Tool         string        `json:"tool"`
	Version      string        `json:"version"`
	CheckedAt    time.Time     `json:"checkedAt"`
	BaseScanAt   time.Time     `json:"baseScanAt"`
	Home         string        `json:"home"`
	VolumeBefore Volume        `json:"volumeBefore"`
	VolumeNow    Volume        `json:"volumeNow"`
	Freed        int64         `json:"freed"`
	Items        []RecheckItem `json:"items"`
}

// HistoryPoint is the summary of one full scan, kept so a report can show the trend.
type HistoryPoint struct {
	Run       int       `json:"run"`
	At        time.Time `json:"at"`
	Version   string    `json:"version"`
	Total     int64     `json:"total"`
	Used      int64     `json:"used"`
	Available int64     `json:"available"`
	Safe      int64     `json:"safe"`
	Review    int64     `json:"review"`
	Risky     int64     `json:"risky"`
	Findings  int       `json:"findings"`
	Seconds   float64   `json:"seconds"`
}

// Totals sums findings per safety level without double counting nested paths.
type Totals struct {
	Safe   int64 `json:"safe"`
	Review int64 `json:"review"`
	Risky  int64 `json:"risky"`
	Keep   int64 `json:"keep"`
}
