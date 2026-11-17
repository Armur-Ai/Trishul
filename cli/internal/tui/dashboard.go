package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ToolStatus represents the state of a single analyzer in the scan.
type ToolStatus struct {
	Name     string
	Status   string // "queued", "running", "completed", "failed", "skipped"
	Detail   string // honest reason, e.g. "not installed" for skipped tools
	Findings int
	Started  time.Time
	Duration time.Duration
}

// SeverityCounts tracks finding counts by severity.
type SeverityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

func (s SeverityCounts) Total() int {
	return s.Critical + s.High + s.Medium + s.Low + s.Info
}

// DashboardModel is the Bubbletea model for the live scan dashboard.
type DashboardModel struct {
	Target    string
	Language  string
	Mode      string // "quick" or "deep"
	Tools     []ToolStatus
	Counts    SeverityCounts
	StartedAt time.Time
	Done      bool
	Failed    bool
	ErrMsg    string
	spinner   spinner.Model
	width     int
	height    int
}

// TickMsg triggers a time update.
type TickMsg time.Time

// ScanDoneMsg signals scan completion.
type ScanDoneMsg struct {
	Results map[string]interface{}
}

// ScanFailedMsg signals scan failure.
type ScanFailedMsg struct {
	Error string
}

// ToolUpdateMsg updates a specific tool's status. Detail carries an honest
// reason (for example "not installed") so skipped tools can explain themselves.
type ToolUpdateMsg struct {
	Tool     string
	Status   string
	Detail   string
	Findings int
}

// CountsUpdateMsg refreshes the running severity tally.
type CountsUpdateMsg struct {
	Counts SeverityCounts
}

func NewDashboard(target, language, mode string, tools []string) DashboardModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(ColAccent)

	statuses := make([]ToolStatus, len(tools))
	for i, t := range tools {
		statuses[i] = ToolStatus{Name: t, Status: "queued"}
	}

	return DashboardModel{
		Target:    target,
		Language:  language,
		Mode:      mode,
		Tools:     statuses,
		StartedAt: time.Now(),
		spinner:   s,
	}
}

func (m DashboardModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, tickCmd())
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func (m DashboardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case TickMsg:
		return m, tickCmd()

	case CountsUpdateMsg:
		m.Counts = msg.Counts

	case ToolUpdateMsg:
		for i := range m.Tools {
			if m.Tools[i].Name == msg.Tool {
				m.Tools[i].Status = msg.Status
				m.Tools[i].Findings = msg.Findings
				if msg.Detail != "" {
					m.Tools[i].Detail = msg.Detail
				}
				if msg.Status == "running" && m.Tools[i].Started.IsZero() {
					m.Tools[i].Started = time.Now()
				}
				if msg.Status == "completed" || msg.Status == "failed" {
					if !m.Tools[i].Started.IsZero() {
						m.Tools[i].Duration = time.Since(m.Tools[i].Started)
					}
				}
			}
		}

	case ScanDoneMsg:
		m.Done = true
		return m, tea.Quit

	case ScanFailedMsg:
		m.Failed = true
		m.ErrMsg = msg.Error
		return m, tea.Quit

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

// progress returns (finished, total) tool counts. A tool is "finished" once it
// has completed, been skipped, or failed — i.e. it will not run again.
func (m DashboardModel) progress() (int, int) {
	done := 0
	for _, t := range m.Tools {
		switch t.Status {
		case "completed", "skipped", "failed":
			done++
		}
	}
	return done, len(m.Tools)
}

func (m DashboardModel) View() string {
	if m.width == 0 {
		return MutedStyle.Render("  " + m.spinnerString() + " Preparing scan…")
	}

	cw := clampWidth(m.width-2, 72, 78)
	var b strings.Builder

	// Banner.
	b.WriteString(TridentBanner(cw))
	b.WriteString("\n")

	// Context line.
	ctx := fmt.Sprintf("%s  %s  %s %s  %s %s scan",
		AccentStyle.Render(m.Target),
		FaintStyle.Render(GlyphBullet),
		MutedStyle.Render("lang"),
		TextStyle.Render(upperOr(m.Language, "auto")),
		FaintStyle.Render(GlyphBullet),
		TextStyle.Render(m.Mode),
	)
	b.WriteString("  " + ctx + "\n\n")

	// Progress bar.
	done, total := m.progress()
	elapsed := time.Since(m.StartedAt).Truncate(time.Second)
	b.WriteString("  " + m.progressBar(cw-2, done, total))
	status := m.spinnerString()
	if done >= total && total > 0 {
		status = AccentStyle.Render(GlyphDone)
	}
	b.WriteString(fmt.Sprintf("  %s  %s  %s\n\n",
		status,
		MutedStyle.Render(fmt.Sprintf("%d/%d analyzers", done, total)),
		FaintStyle.Render(elapsed.String()),
	))

	// Tool rows.
	b.WriteString(SubtitleStyle.Bold(true).Render(fmt.Sprintf("  %-22s %-24s %7s", "ANALYZER", "STATUS", "FOUND")))
	b.WriteString("\n")
	b.WriteString("  " + RuleStyle.Render(strings.Repeat("─", min(cw-2, 66))) + "\n")

	for _, t := range m.Tools {
		b.WriteString(m.toolRow(t))
		b.WriteString("\n")
	}

	// Severity tally.
	b.WriteString("\n")
	b.WriteString("  " + RuleStyle.Render(strings.Repeat("─", min(cw-2, 66))) + "\n")
	b.WriteString("  " + m.tallyLine() + "\n\n")

	// Help.
	b.WriteString(renderHelp([2]string{"q", "quit"}))
	b.WriteString("\n")

	return b.String()
}

func (m DashboardModel) toolRow(t ToolStatus) string {
	icon, iconStyle := statusDisplay(t.Status)

	// Status cell with honest detail / timing.
	statusWord := iconStyle.Render(t.Status)
	suffix := ""
	switch t.Status {
	case "running":
		if !t.Started.IsZero() {
			suffix = " " + FaintStyle.Render(time.Since(t.Started).Truncate(time.Second).String())
		}
	case "completed":
		if t.Duration > 0 {
			suffix = " " + FaintStyle.Render(t.Duration.Truncate(time.Second).String())
		}
	case "skipped":
		reason := t.Detail
		if reason == "" {
			reason = "not installed"
		}
		suffix = " " + FaintStyle.Render("("+reason+")")
	case "failed":
		if t.Detail != "" {
			suffix = " " + FaintStyle.Render("("+t.Detail+")")
		}
	}

	findings := FaintStyle.Render("—")
	if t.Status == "completed" || t.Status == "failed" {
		if t.Findings > 0 {
			findings = lipgloss.NewStyle().Foreground(ColHigh).Bold(true).Render(fmt.Sprintf("%d", t.Findings))
		} else {
			findings = lipgloss.NewStyle().Foreground(ColLow).Render("0")
		}
	}

	name := TextStyle.Render(fmt.Sprintf("%-20s", truncate(t.Name, 20)))
	statusCell := statusWord + suffix
	// Pad the visible status content to a stable column width.
	pad := 24 - lipgloss.Width(statusCell)
	if pad < 1 {
		pad = 1
	}
	return fmt.Sprintf("  %s %s %s%s%7s",
		iconStyle.Render(icon), name, statusCell, strings.Repeat(" ", pad), findings)
}

func (m DashboardModel) tallyLine() string {
	c := m.Counts
	cell := func(label string, n int, col lipgloss.Color) string {
		return lipgloss.NewStyle().Foreground(col).Bold(true).Render(fmt.Sprintf("%s %d", label, n))
	}
	parts := []string{
		cell("CRIT", c.Critical, ColCritical),
		cell("HIGH", c.High, ColHigh),
		cell("MED", c.Medium, ColMedium),
		cell("LOW", c.Low, ColLow),
		cell("INFO", c.Info, ColInfo),
	}
	total := MutedStyle.Render(fmt.Sprintf("%d total", c.Total()))
	return strings.Join(parts, FaintStyle.Render("  ")) + FaintStyle.Render("   ") + total
}

func (m DashboardModel) progressBar(width, done, total int) string {
	if width < 10 {
		width = 10
	}
	if total == 0 {
		return RuleStyle.Render(strings.Repeat("░", width))
	}
	filled := width * done / total
	if filled > width {
		filled = width
	}
	bar := lipgloss.NewStyle().Foreground(ColBrand).Render(strings.Repeat("█", filled))
	rest := RuleStyle.Render(strings.Repeat("░", width-filled))
	return bar + rest
}

func (m DashboardModel) spinnerString() string {
	return m.spinner.View()
}

func statusDisplay(status string) (string, lipgloss.Style) {
	switch status {
	case "running":
		return GlyphRunning, lipgloss.NewStyle().Foreground(ColAccent)
	case "completed":
		return GlyphDone, lipgloss.NewStyle().Foreground(ColLow)
	case "failed":
		return GlyphFailed, lipgloss.NewStyle().Foreground(ColCritical)
	case "skipped":
		return GlyphSkipped, lipgloss.NewStyle().Foreground(ColMedium)
	default: // queued
		return GlyphQueued, lipgloss.NewStyle().Foreground(ColFaint)
	}
}

func upperOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return strings.ToUpper(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
