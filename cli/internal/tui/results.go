package tui

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ResultItem represents a single finding in the results browser. It carries the
// union of fields across all finding categories; only the relevant ones are
// rendered per item. Secrets are stored already-redacted — a raw secret value
// must never reach this struct.
type ResultItem struct {
	Severity string
	File     string
	Line     int
	RuleID   string
	Message  string
	Category string
	CWE      string
	Tool     string

	// Agent Supply-Chain Security (agent_security)
	CheckID       string
	Confidence    string
	TrustBoundary string
	Remediation   string
	IsChain       bool // AGENT-CHAIN-00x cross-file attack chain

	// Dependencies / SCA (sca)
	Package string
	Version string

	// Secrets (secret_detection) — redacted display only, never the raw value
	Redacted string
}

// SkippedTool records an analyzer that did not run, so the browser can be
// honest that its findings are absent (not a clean result).
type SkippedTool struct {
	Tool   string
	Reason string
}

// ResultsModel is the interactive results browser TUI.
type ResultsModel struct {
	Items   []ResultItem
	Skipped []SkippedTool
	Cursor  int
	Offset  int // scroll offset
	Width   int
	Height  int

	sevFilter string   // "", "critical", "high", "medium", "low", "info"
	catFilter string   // "" = all, else a raw category key
	cats      []string // distinct categories present, in display order
	filtered  []ResultItem
}

func NewResults(items []ResultItem) ResultsModel {
	// Sort by severity (desc) then category so the worst findings surface first.
	sort.SliceStable(items, func(i, j int) bool {
		if r := SeverityRank(items[i].Severity) - SeverityRank(items[j].Severity); r != 0 {
			return r > 0
		}
		return items[i].Category < items[j].Category
	})
	m := ResultsModel{Items: items}
	m.cats = distinctCategories(items)
	m.applyFilter()
	return m
}

func distinctCategories(items []ResultItem) []string {
	seen := map[string]bool{}
	var out []string
	for _, it := range items {
		if !seen[it.Category] {
			seen[it.Category] = true
			out = append(out, it.Category)
		}
	}
	// Agent-Chain first — it's the flagship category.
	sort.SliceStable(out, func(i, j int) bool {
		return catPriority(out[i]) < catPriority(out[j])
	})
	return out
}

func catPriority(cat string) int {
	switch cat {
	case "agent_security":
		return 0
	case "secret_detection":
		return 1
	case "sca":
		return 2
	case "infra_security":
		return 3
	case "security_issues":
		return 4
	default:
		return 9
	}
}

func (m *ResultsModel) applyFilter() {
	var out []ResultItem
	for _, item := range m.Items {
		if m.sevFilter != "" && !strings.EqualFold(item.Severity, m.sevFilter) {
			continue
		}
		if m.catFilter != "" && item.Category != m.catFilter {
			continue
		}
		out = append(out, item)
	}
	m.filtered = out
	if m.Cursor >= len(m.filtered) {
		m.Cursor = max(0, len(m.filtered)-1)
	}
	if m.Offset > m.Cursor {
		m.Offset = m.Cursor
	}
}

func (m ResultsModel) Init() tea.Cmd { return nil }

func (m ResultsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "up", "k":
			if m.Cursor > 0 {
				m.Cursor--
				if m.Cursor < m.Offset {
					m.Offset = m.Cursor
				}
			}
		case "down", "j":
			if m.Cursor < len(m.filtered)-1 {
				m.Cursor++
				maxVisible := m.visibleRows()
				if m.Cursor >= m.Offset+maxVisible {
					m.Offset = m.Cursor - maxVisible + 1
				}
			}
		case "g", "home":
			m.Cursor, m.Offset = 0, 0
		case "G", "end":
			m.Cursor = max(0, len(m.filtered)-1)
			maxVisible := m.visibleRows()
			m.Offset = max(0, m.Cursor-maxVisible+1)
		case "f":
			m.cycleSeverity()
			m.applyFilter()
		case "c":
			m.cycleCategory()
			m.applyFilter()
		}

	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
	}

	return m, nil
}

func (m *ResultsModel) cycleSeverity() {
	order := []string{"", "critical", "high", "medium", "low", "info"}
	for i, s := range order {
		if s == m.sevFilter {
			m.sevFilter = order[(i+1)%len(order)]
			return
		}
	}
	m.sevFilter = ""
}

func (m *ResultsModel) cycleCategory() {
	if len(m.cats) == 0 {
		return
	}
	ring := append([]string{""}, m.cats...)
	for i, c := range ring {
		if c == m.catFilter {
			m.catFilter = ring[(i+1)%len(ring)]
			return
		}
	}
	m.catFilter = ""
}

func (m ResultsModel) View() string {
	if m.Width == 0 {
		return MutedStyle.Render("  Loading results…")
	}

	// Empty states.
	if len(m.Items) == 0 {
		return m.emptyState()
	}
	if len(m.filtered) == 0 {
		return m.header() + "\n\n" +
			MutedStyle.Render("  No findings match the current filter.") + "\n" +
			renderHelp([2]string{"f", "severity"}, [2]string{"c", "category"}, [2]string{"q", "quit"}) + "\n"
	}

	var b strings.Builder
	b.WriteString(m.header())
	b.WriteString("\n\n")

	// Column header.
	cw := clampWidth(m.Width-2, 88, 110)
	b.WriteString(SubtitleStyle.Bold(true).Render(fmt.Sprintf("  %-6s %-13s %-34s %-6s", "SEV", "CATEGORY", "LOCATION", "LINE")))
	b.WriteString("\n")
	b.WriteString("  " + RuleStyle.Render(strings.Repeat("─", min(cw, 100))) + "\n")

	// Rows.
	maxRows := m.visibleRows()
	end := min(m.Offset+maxRows, len(m.filtered))
	for i := m.Offset; i < end; i++ {
		b.WriteString(m.row(m.filtered[i], i == m.Cursor))
		b.WriteString("\n")
	}

	// Scroll indicator.
	if len(m.filtered) > maxRows {
		b.WriteString(FaintStyle.Render(fmt.Sprintf("  %d–%d of %d", m.Offset+1, end, len(m.filtered))))
		b.WriteString("\n")
	}

	// Detail pane.
	if m.Cursor >= 0 && m.Cursor < len(m.filtered) {
		b.WriteString("\n")
		b.WriteString(m.detail(m.filtered[m.Cursor], cw))
	}

	// Skipped-tools honesty note.
	if len(m.Skipped) > 0 {
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(ColMedium).Render(
			fmt.Sprintf("  %s %d analyzer(s) skipped — their findings are absent, not clean. Run 'trishul doctor'.",
				GlyphSkipped, len(m.Skipped))))
		b.WriteString("\n")
	}

	// Help.
	b.WriteString("\n")
	b.WriteString(renderHelp(
		[2]string{"↑↓/jk", "move"},
		[2]string{"f", "severity"},
		[2]string{"c", "category"},
		[2]string{"g/G", "top/end"},
		[2]string{"q", "quit"},
	))
	b.WriteString("\n")

	return b.String()
}

func (m ResultsModel) header() string {
	title := TitleStyle.Render(Trident + " Trishul findings")
	count := MutedStyle.Render(fmt.Sprintf("%d of %d", len(m.filtered), len(m.Items)))

	sev := "all"
	if m.sevFilter != "" {
		sev = m.sevFilter
	}
	cat := "all"
	if m.catFilter != "" {
		cat = CategoryLabel(m.catFilter)
	}
	filters := FaintStyle.Render("severity ") + AccentStyle.Render(sev) +
		FaintStyle.Render("  category ") + AccentStyle.Render(cat)

	return "  " + title + "   " + count + "   " + filters
}

func (m ResultsModel) row(item ResultItem, selected bool) string {
	loc := item.File
	if item.Category == "sca" && item.Package != "" {
		loc = item.Package
		if item.Version != "" {
			loc += "@" + item.Version
		}
	}
	loc = truncate(loc, 34)

	lineStr := "—"
	if item.Line > 0 {
		lineStr = fmt.Sprintf("%d", item.Line)
	}

	chainMark := " "
	if item.IsChain {
		chainMark = lipgloss.NewStyle().Foreground(ColCritical).Render(GlyphChain)
	}

	line := fmt.Sprintf("  %s %s %-13s %-34s %-6s",
		SeverityBadge(item.Severity),
		chainMark,
		truncate(CategoryLabel(item.Category), 13),
		loc,
		lineStr,
	)

	if selected {
		return SelectedRowStyle.Render(line)
	}
	return line
}

func (m ResultsModel) detail(item ResultItem, cw int) string {
	var b strings.Builder
	b.WriteString("  " + RuleStyle.Render(strings.Repeat("─", min(cw, 100))) + "\n")

	label := func(s string) string { return MutedStyle.Render(fmt.Sprintf("  %-11s", s)) }

	// Attack-chain banner for the flagship finding type.
	if item.IsChain {
		b.WriteString("  " + ChainStyle.Render(GlyphChain+" AGENT SUPPLY-CHAIN ATTACK CHAIN") + "\n")
	}

	// Title + severity.
	b.WriteString(label("Severity") + SeverityBadge(item.Severity) + "  " + SeverityText(item.Severity) + "\n")
	if item.Message != "" {
		b.WriteString(label("Finding") + TextStyle.Render(wrapInline(item.Message, cw-13)) + "\n")
	}

	// Location.
	loc := item.File
	if item.Line > 0 {
		loc = fmt.Sprintf("%s:%d", item.File, item.Line)
	}
	if loc != "" && loc != "-" {
		b.WriteString(label("Location") + AccentStyle.Render(loc) + "\n")
	}

	// Category-specific detail.
	switch item.Category {
	case "agent_security":
		if item.CheckID != "" {
			b.WriteString(label("Check-ID") + lipgloss.NewStyle().Foreground(ColBrand).Bold(true).Render(item.CheckID) + "\n")
		}
		if item.Confidence != "" {
			b.WriteString(label("Confidence") + TextStyle.Render(item.Confidence) + "\n")
		}
		if item.TrustBoundary != "" {
			b.WriteString(label("Trust bnd") + lipgloss.NewStyle().Foreground(ColHigh).Render("crosses "+item.TrustBoundary) + "\n")
		}
	case "secret_detection":
		shown := item.Redacted
		if shown == "" {
			shown = Redact("")
		}
		b.WriteString(label("Secret") + lipgloss.NewStyle().Foreground(ColHigh).Render(shown) +
			FaintStyle.Render("  (redacted)") + "\n")
	case "sca":
		if item.Package != "" {
			pkg := item.Package
			if item.Version != "" {
				pkg += "@" + item.Version
			}
			b.WriteString(label("Package") + TextStyle.Render(pkg) + "\n")
		}
	}

	// Common optional fields.
	if item.RuleID != "" {
		b.WriteString(label("Rule") + FaintStyle.Render(item.RuleID) + "\n")
	}
	if item.CWE != "" {
		b.WriteString(label("CWE") + FaintStyle.Render(item.CWE) + "\n")
	}
	if item.Tool != "" {
		b.WriteString(label("Tool") + FaintStyle.Render(item.Tool) + "\n")
	}
	if item.Remediation != "" {
		b.WriteString(label("Fix") + lipgloss.NewStyle().Foreground(ColLow).Render(wrapInline(item.Remediation, cw-13)) + "\n")
	}

	return b.String()
}

func (m ResultsModel) emptyState() string {
	ok := lipgloss.NewStyle().Foreground(ColLow).Bold(true)
	return "\n  " + ok.Render(GlyphDone+" No findings returned by this scan.") + "\n  " +
		MutedStyle.Render("Trishul renders only what the analyzers reported.") + "\n\n" +
		renderHelp([2]string{"q", "quit"}) + "\n"
}

func (m ResultsModel) visibleRows() int {
	// Reserve lines for header, column header, detail pane, help.
	available := m.Height - 18
	if available < 4 {
		return 4
	}
	if available > 14 {
		return 14
	}
	return available
}

// wrapInline collapses whitespace and truncates to width with an ellipsis.
func wrapInline(s string, width int) string {
	s = strings.Join(strings.Fields(s), " ")
	if width < 8 {
		width = 8
	}
	return truncate(s, width)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
