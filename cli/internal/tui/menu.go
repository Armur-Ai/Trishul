package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// MenuItem represents a single option in the interactive menu.
type MenuItem struct {
	ID          string
	Title       string
	Description string
	Icon        string
}

// MenuModel is the full-screen interactive menu TUI.
type MenuModel struct {
	Items    []MenuItem
	Cursor   int
	Selected string
	Quit     bool
	Width    int
	Height   int
}

func NewMenu() MenuModel {
	return MenuModel{
		Items: []MenuItem{
			{ID: "scan", Title: "Scan Project", Description: "Analyze your code for security vulnerabilities", Icon: ""},
			{ID: "run", Title: "Interactive Scan", Description: "Guided wizard with live dashboard and results browser", Icon: ""},
			{ID: "review", Title: "Review Pull Request", Description: "Security review a GitHub/GitLab PR", Icon: ""},
			{ID: "history", Title: "View History", Description: "Browse past scan results and compare scans", Icon: ""},
			{ID: "report", Title: "Generate Report", Description: "Create HTML, CSV, OWASP, or SANS reports", Icon: ""},
			{ID: "explain", Title: "Explain Finding", Description: "Get an AI explanation of a security finding", Icon: ""},
			{ID: "fix", Title: "Fix Finding", Description: "Generate an AI-powered code patch", Icon: ""},
			{ID: "doctor", Title: "Check Health", Description: "Verify tools, server, and configuration", Icon: ""},
			{ID: "init", Title: "Initialize Project", Description: "Create .trishul.yml config for this project", Icon: ""},
			{ID: "setup", Title: "Setup AI / MCP", Description: "Configure Claude API, Ollama, or editor integration", Icon: ""},
		},
	}
}

func (m MenuModel) Init() tea.Cmd {
	return nil
}

func (m MenuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			m.Quit = true
			return m, tea.Quit
		case "up", "k":
			if m.Cursor > 0 {
				m.Cursor--
			}
		case "down", "j":
			if m.Cursor < len(m.Items)-1 {
				m.Cursor++
			}
		case "enter":
			m.Selected = m.Items[m.Cursor].ID
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
	}
	return m, nil
}

func (m MenuModel) View() string {
	var b strings.Builder

	width := clampWidth(m.Width, 80, 90)

	// Banner.
	b.WriteString("\n")
	b.WriteString(lipgloss.PlaceHorizontal(width, lipgloss.Center, TridentBanner(min(width, 56))))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(ColMuted).Align(lipgloss.Center).Width(width).
		Render("SAST  ·  Dependencies  ·  Secrets  ·  IaC  ·  Agent Supply-Chain"))
	b.WriteString("\n\n")

	// Separator.
	b.WriteString("  " + RuleStyle.Render(strings.Repeat("─", width-4)))
	b.WriteString("\n\n")

	// Prompt.
	b.WriteString(TextStyle.Bold(true).PaddingLeft(2).Render("What would you like to do?"))
	b.WriteString("\n\n")

	// Menu items.
	for i, item := range m.Items {
		selected := i == m.Cursor

		cursor := "   "
		if selected {
			cursor = lipgloss.NewStyle().Foreground(ColBrand).Bold(true).Render(" " + GlyphArrow + " ")
		}

		titleStyle := lipgloss.NewStyle().Foreground(ColText)
		descStyle := lipgloss.NewStyle().Foreground(ColFaint)
		if selected {
			titleStyle = titleStyle.Foreground(ColBrand).Bold(true)
			descStyle = descStyle.Foreground(ColMuted)
		}

		line := fmt.Sprintf("%s%s  %s",
			cursor,
			titleStyle.Render(fmt.Sprintf("%-20s", item.Title)),
			descStyle.Render(item.Description),
		)

		if selected {
			b.WriteString(lipgloss.NewStyle().Background(ColSelBg).Width(width - 2).Render(line))
		} else {
			b.WriteString(line)
		}
		b.WriteString("\n")
	}

	// Footer.
	b.WriteString("\n")
	b.WriteString("  " + RuleStyle.Render(strings.Repeat("─", width-4)))
	b.WriteString("\n")
	b.WriteString(renderHelp(
		[2]string{"↑↓", "navigate"},
		[2]string{"enter", "select"},
		[2]string{"q", "quit"},
	))
	b.WriteString("\n")
	b.WriteString(FaintStyle.PaddingLeft(2).Render(Trident + " trishul — security scanner for AI-era codebases"))
	b.WriteString("\n")

	return b.String()
}
