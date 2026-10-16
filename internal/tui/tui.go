// Package tui is an interactive terminal browser for a scan. It copies commands; it never runs them.
package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/RO-29/spaceaudit/internal/fsx"
	"github.com/RO-29/spaceaudit/internal/model"
	"github.com/RO-29/spaceaudit/internal/probe"
	"github.com/RO-29/spaceaudit/internal/report"
	"github.com/RO-29/spaceaudit/internal/scan"
)

var (
	cSafe      = lipgloss.Color("#3ccf7d")
	cReview    = lipgloss.Color("#f0b44c")
	cRisky     = lipgloss.Color("#ff6b6b")
	cKeep      = lipgloss.Color("#7aa2ff")
	cDim       = lipgloss.Color("#7f8796")
	levelColor = map[model.Safety]lipgloss.Color{model.Safe: cSafe, model.Review: cReview, model.Risky: cRisky, model.Keep: cKeep}
	title      = lipgloss.NewStyle().Bold(true)
	dim        = lipgloss.NewStyle().Foreground(cDim)
	sel        = lipgloss.NewStyle().Background(lipgloss.Color("#2a2f3a")).Bold(true)
	box        = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#3a4050")).Padding(0, 1)
	levels     = []string{"all", "safe", "review", "risky", "keep"}
)

type scanDone model.Report
type progressMsg string
type flash string

type Model struct {
	opt      scan.Options
	rep      *model.Report
	progress string
	start    time.Time
	view     []model.Finding
	cur, top int
	level    int
	search   string
	typing   bool
	detail   bool
	scroll   int
	w, h     int
	msg      string
	ch       chan string
	marked   map[string]bool
	sortBy   int
	help     bool
}

var sorts = []string{"safety", "size", "oldest"}

// New makes the TUI model. The scan starts when the program starts.
func New(o scan.Options) Model {
	return Model{opt: o, start: time.Now(), ch: make(chan string, 16), marked: map[string]bool{}}
}

func (m Model) Init() tea.Cmd {
	o := m.opt
	ch := m.ch
	o.Progress = func(s string) {
		select {
		case ch <- s:
		default:
		}
	}
	return tea.Batch(func() tea.Msg { r := scan.Run(o); return scanDone(r) }, wait(ch), tick())
}

func wait(ch chan string) tea.Cmd { return func() tea.Msg { return progressMsg(<-ch) } }
func tick() tea.Cmd               { return tea.Tick(time.Second, func(time.Time) tea.Msg { return progressMsg("") }) }

func (m *Model) filter() {
	m.view = m.view[:0]
	for _, f := range m.rep.Findings {
		if m.level > 0 && string(f.Safety) != levels[m.level] {
			continue
		}
		if m.search != "" && !strings.Contains(strings.ToLower(f.Title+" "+strings.Join(f.Paths, " ")), strings.ToLower(m.search)) {
			continue
		}
		m.view = append(m.view, f)
	}
	switch sorts[m.sortBy] {
	case "size":
		sort.SliceStable(m.view, func(i, j int) bool { return m.view[i].Bytes > m.view[j].Bytes })
	case "oldest":
		sort.SliceStable(m.view, func(i, j int) bool { return m.view[i].Modified.Before(m.view[j].Modified) })
	}
	if m.cur >= len(m.view) {
		m.cur = max(0, len(m.view)-1)
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
	case progressMsg:
		if m.rep != nil {
			return m, nil
		}
		if msg != "" {
			m.progress = string(msg)
			return m, wait(m.ch)
		}
		return m, tick()
	case scanDone:
		r := model.Report(msg)
		m.rep = &r
		m.filter()
	case flash:
		m.msg = string(msg)
	case tea.KeyMsg:
		if m.rep == nil {
			if msg.String() == "ctrl+c" || msg.String() == "q" {
				return m, tea.Quit
			}
			return m, nil
		}
		if m.typing {
			switch msg.Type {
			case tea.KeyEnter, tea.KeyEsc:
				m.typing = false
			case tea.KeyBackspace:
				if len(m.search) > 0 {
					m.search = m.search[:len(m.search)-1]
				}
			case tea.KeyRunes, tea.KeySpace:
				m.search += msg.String()
			}
			m.filter()
			return m, nil
		}
		if m.help {
			m.help = false
			return m, nil
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "?":
			m.help = true
		case " ", "x":
			if f, ok := m.current(); ok && f.Safety != model.Keep && len(f.Commands) > 0 {
				m.marked[f.ID] = !m.marked[f.ID]
				if !m.marked[f.ID] {
					delete(m.marked, f.ID)
				}
				if m.cur < len(m.view)-1 {
					m.cur++
				}
			}
		case "A":
			for _, f := range m.view {
				if f.Safety == model.Safe && len(f.Blockers) == 0 && len(f.Commands) > 0 {
					m.marked[f.ID] = true
				}
			}
		case "u":
			m.marked = map[string]bool{}
		case "s":
			m.sortBy = (m.sortBy + 1) % len(sorts)
			m.filter()
		case "p":
			plan := m.planText()
			if plan == "" {
				return m, func() tea.Msg { return flash("Mark items with space first.") }
			}
			return m, func() tea.Msg {
				if _, err := probe.RunInput(5*time.Second, []byte(plan), "pbcopy"); err != nil {
					return flash("Copy failed: " + err.Error())
				}
				return flash("Copied the plan. The cleanup commands in it are comments.")
			}
		case "w":
			plan := m.planText()
			if plan == "" {
				return m, func() tea.Msg { return flash("Mark items with space first.") }
			}
			return m, func() tea.Msg { return flash(writePlan(plan)) }
		case "j", "down":
			if m.detail {
				m.scroll++
			} else if m.cur < len(m.view)-1 {
				m.cur++
			}
		case "k", "up":
			if m.detail {
				m.scroll = max(0, m.scroll-1)
			} else if m.cur > 0 {
				m.cur--
			}
		case "g":
			m.cur = 0
		case "G":
			m.cur = max(0, len(m.view)-1)
		case "enter", "l", "right":
			m.detail = !m.detail
			m.scroll = 0
		case "esc", "h", "left":
			m.detail = false
		case "tab":
			m.level = (m.level + 1) % len(levels)
			m.filter()
		case "1", "2", "3", "4", "5":
			m.level = int(msg.String()[0] - '1')
			m.filter()
		case "/":
			m.typing = true
		case "c":
			return m, m.copy(func(f model.Finding) []string { return f.Commands }, "command")
		case "v":
			return m, m.copy(func(f model.Finding) []string { return f.Verify }, "verify command")
		case "o":
			if f, ok := m.current(); ok && len(f.Paths) > 0 {
				p := f.Paths[0]
				return m, func() tea.Msg {
					if _, err := probe.Run(5*time.Second, "open", "-R", p); err != nil {
						return flash("Cannot open Finder: " + err.Error())
					}
					return flash("Shown in Finder.")
				}
			}
		}
	}
	return m, nil
}

func (m Model) selected() []model.Finding {
	var out []model.Finding
	for _, f := range m.rep.Findings {
		if m.marked[f.ID] {
			out = append(out, f)
		}
	}
	return out
}

// planText runs verify lines and keeps every cleanup command as a comment.
func (m Model) planText() string {
	fs := m.selected()
	if len(fs) == 0 {
		return ""
	}
	r := *m.rep
	r.Findings = fs
	var b strings.Builder
	report.Plan(&b, r)
	return b.String()
}

// writePlan creates a new file and never replaces one.
func writePlan(plan string) string {
	name := "spaceaudit-plan-" + time.Now().Format("20060102-150405") + ".sh"
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "Cannot write the plan: " + err.Error()
	}
	defer f.Close()
	if _, err := f.WriteString(plan); err != nil {
		return "Cannot write the plan: " + err.Error()
	}
	wd, _ := os.Getwd()
	return "Wrote " + filepath.Join(wd, name) + ". Read it before you run it."
}

func (m Model) current() (model.Finding, bool) {
	if m.cur < len(m.view) {
		return m.view[m.cur], true
	}
	return model.Finding{}, false
}

func (m Model) copy(get func(model.Finding) []string, what string) tea.Cmd {
	f, ok := m.current()
	if !ok || len(get(f)) == 0 {
		return func() tea.Msg { return flash("Nothing to copy.") }
	}
	text := strings.Join(get(f), "\n")
	return func() tea.Msg {
		if _, err := probe.RunInput(5*time.Second, []byte(text), "pbcopy"); err != nil {
			return flash("Copy failed: " + err.Error())
		}
		return flash("Copied the " + what + ". Read it before you paste it into a terminal.")
	}
}

func (m Model) View() string {
	if m.rep == nil {
		spin := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}[int(time.Since(m.start).Seconds())%10]
		return fmt.Sprintf("\n  %s %s\n  %s\n\n  %s\n", spin, title.Render("spaceaudit is scanning (read-only)"), m.progress,
			dim.Render(fmt.Sprintf("%.0fs elapsed. A full scan of a large home folder takes some minutes. q quits.", time.Since(m.start).Seconds())))
	}
	r := m.rep
	head := title.Render("spaceaudit") + dim.Render("  read-only · nothing is deleted · verify every command yourself")
	v := r.Volume
	disk := ""
	if v.Total > 0 {
		disk = fmt.Sprintf("Disk %s free of %s   ", fsx.Human(v.Available), fsx.Human(v.Total))
	}
	tot := disk + lipgloss.NewStyle().Foreground(cSafe).Render("safe "+fsx.Human(r.Totals.Safe)) + "   " +
		lipgloss.NewStyle().Foreground(cReview).Render("review "+fsx.Human(r.Totals.Review)) + "   " +
		lipgloss.NewStyle().Foreground(cRisky).Render("risky "+fsx.Human(r.Totals.Risky))
	var tabs []string
	for i, l := range levels {
		s := " " + l + " "
		if i == m.level {
			s = sel.Render(s)
		} else {
			s = dim.Render(s)
		}
		tabs = append(tabs, s)
	}
	search := ""
	if m.typing || m.search != "" {
		search = "  /" + m.search
		if m.typing {
			search += "█"
		}
	}
	bodyH := max(5, m.h-7)
	var body string
	if m.help {
		body = box.Render(strings.Join([]string{
			title.Render("Keys"), "",
			"↑ ↓ / j k     move            enter  details      esc  back",
			"space / x     mark for plan   A      mark visible safe items   u  unmark all",
			"tab / 1-5     level filter    /      search       s    sort (safety, size, oldest)",
			"c             copy command    v      copy verify  o    show in Finder",
			"p             copy plan       w      write plan file (a new file, never overwritten)",
			"", dim.Render("spaceaudit runs no cleanup command. A plan runs only the verify lines; the cleanup lines are comments."),
			dim.Render("Press any key to close."),
		}, "\n"))
	} else if m.detail {
		body = m.detailView(bodyH)
	} else {
		body = m.listView(bodyH)
	}
	sel := m.selected()
	var selBytes int64
	for _, f := range sel {
		selBytes += f.Bytes
	}
	help := dim.Render("space mark  p copy plan  w write plan  enter details  tab level  / search  s sort:" + sorts[m.sortBy] + "  ? help  q quit")
	if len(sel) > 0 {
		help = lipgloss.NewStyle().Foreground(cKeep).Bold(true).Render(fmt.Sprintf("%d marked · %s", len(sel), fsx.Human(selBytes))) + "  " + help
	}
	if m.msg != "" {
		help = lipgloss.NewStyle().Foreground(cReview).Render(m.msg)
	}
	return strings.Join([]string{head, tot, strings.Join(tabs, "") + search, body, help}, "\n")
}

func (m *Model) listView(h int) string {
	if len(m.view) == 0 {
		return dim.Render("\n  No finding matches.\n")
	}
	if m.cur < m.top {
		m.top = m.cur
	}
	if m.cur >= m.top+h {
		m.top = m.cur - h + 1
	}
	var lines []string
	for i := m.top; i < len(m.view) && i < m.top+h; i++ {
		f := m.view[i]
		b := lipgloss.NewStyle().Foreground(levelColor[f.Safety]).Bold(true).Width(7).Render(strings.ToUpper(string(f.Safety)))
		flag := " "
		if len(f.Blockers) > 0 {
			flag = lipgloss.NewStyle().Foreground(cRisky).Render("!")
		}
		mark := "  "
		if m.marked[f.ID] {
			mark = lipgloss.NewStyle().Foreground(cKeep).Bold(true).Render("● ")
		}
		w := max(20, m.w-36)
		t := f.Title
		if len([]rune(t)) > w {
			t = string([]rune(t)[:w-1]) + "…"
		}
		bar := sizeBar(f.Bytes, m.view[0].Bytes, 8)
		line := fmt.Sprintf("%s%s %9s %s %s %s", mark, b, fsx.Human(f.Bytes), dim.Render(bar), flag, t)
		if i == m.cur {
			line = sel.Render(line)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func sizeBar(b, maxB int64, w int) string {
	if maxB <= 0 {
		return strings.Repeat(" ", w)
	}
	n := int(float64(w) * float64(b) / float64(maxB))
	if n < 1 && b > 0 {
		n = 1
	}
	return strings.Repeat("▇", min(n, w)) + strings.Repeat(" ", w-min(n, w))
}

func (m Model) detailView(h int) string {
	f, ok := m.current()
	if !ok {
		return ""
	}
	var b strings.Builder
	sec := func(name string, xs []string, c lipgloss.Color) {
		if len(xs) == 0 {
			return
		}
		b.WriteString(lipgloss.NewStyle().Foreground(c).Bold(true).Render(name) + "\n")
		for _, x := range xs {
			b.WriteString("  " + x + "\n")
		}
	}
	b.WriteString(lipgloss.NewStyle().Foreground(levelColor[f.Safety]).Bold(true).Render(strings.ToUpper(string(f.Safety))) + "  " + title.Render(f.Title) + "  " + fsx.Human(f.Bytes) + "\n")
	b.WriteString(dim.Render(f.Category+" · confidence "+f.Confidence) + "\n\n")
	sec("Paths", f.Paths, cDim)
	sec("Blockers", f.Blockers, cRisky)
	sec("Why", f.Reasons, cSafe)
	sec("Risks", f.Risks, cReview)
	sec("1. Verify first", f.Verify, cKeep)
	sec("2. Command (run only after you verify)", f.Commands, cKeep)
	sec("Undo-friendly alternative", f.Alternate, cKeep)
	if f.Restore != "" {
		sec("How to get it back", []string{f.Restore}, cDim)
	}
	sec("Notes", f.Notes, cDim)
	lines := strings.Split(b.String(), "\n")
	s := min(m.scroll, max(0, len(lines)-h))
	end := min(len(lines), s+h)
	return box.Width(max(40, m.w-2)).Render(strings.Join(lines[s:end], "\n"))
}

// Run starts the TUI.
func Run(o scan.Options) error {
	_, err := tea.NewProgram(New(o), tea.WithAltScreen()).Run()
	return err
}
