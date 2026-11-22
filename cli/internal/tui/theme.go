package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Trishul's visual identity.
//
// The trident (त्रिशूल) is the mark: a dark, electric-indigo brand accent with a
// cyan secondary highlight, severity badges in a fixed, distinct palette, and a
// muted scale for chrome. Everything in the TUI pulls its colours and styles
// from here so the experience reads as one cohesive product.

// Glyphs — kept ASCII-width-safe so layouts stay aligned across terminals.
const (
	Trident      = "Ψ" // trident mark used throughout the UI
	GlyphRunning = "◈"
	GlyphDone    = "✓"
	GlyphFailed  = "✗"
	GlyphSkipped = "⊘"
	GlyphQueued  = "○"
	GlyphChain   = "⛓"
	GlyphBullet  = "•"
	GlyphArrow   = "▸"
)

// Palette — the full set of colours used anywhere in the TUI. Truecolor hex so
// the identity is consistent on capable terminals; lipgloss degrades gracefully
// on 256/16-colour terminals.
var (
	ColBrand     = lipgloss.Color("#7C5CFF") // electric indigo — Trishul's signature
	ColBrandDeep = lipgloss.Color("#4C3FA3") // dim brand for borders/rules
	ColAccent    = lipgloss.Color("#22D3EE") // cyan secondary highlight
	ColText      = lipgloss.Color("#E6E6EB")
	ColMuted     = lipgloss.Color("#9A9AB0")
	ColFaint     = lipgloss.Color("#5A5A70")
	ColPanelBg   = lipgloss.Color("#16161F")
	ColSelBg     = lipgloss.Color("#262637")

	// Severity palette — each level has its own, deliberately distinct hue.
	ColCritical = lipgloss.Color("#FF4D6D") // hot red/magenta
	ColHigh     = lipgloss.Color("#FF8C42") // orange
	ColMedium   = lipgloss.Color("#FFD166") // amber
	ColLow      = lipgloss.Color("#06D6A0") // teal-green
	ColInfo     = lipgloss.Color("#4CC9F0") // cyan-blue

	ColOnDark  = lipgloss.Color("#FFFFFF")
	ColOnLight = lipgloss.Color("#0B0B12")
)

// Shared styles.
var (
	TitleStyle = lipgloss.NewStyle().Bold(true).Foreground(ColBrand)

	SubtitleStyle = lipgloss.NewStyle().Foreground(ColMuted)

	AccentStyle = lipgloss.NewStyle().Foreground(ColAccent)

	TextStyle = lipgloss.NewStyle().Foreground(ColText)

	MutedStyle = lipgloss.NewStyle().Foreground(ColMuted)

	FaintStyle = lipgloss.NewStyle().Foreground(ColFaint)

	HelpStyle = lipgloss.NewStyle().Foreground(ColFaint)

	HelpKeyStyle = lipgloss.NewStyle().Foreground(ColAccent).Bold(true)

	RuleStyle = lipgloss.NewStyle().Foreground(ColFaint)

	// PanelStyle is a bordered box in the brand accent for banners and cards.
	PanelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColBrandDeep).
			Padding(0, 2)

	SelectedRowStyle = lipgloss.NewStyle().Background(ColSelBg).Bold(true)

	// Attack-chain emphasis — the flagship Agent Supply-Chain finding type.
	ChainStyle = lipgloss.NewStyle().
			Foreground(ColOnDark).
			Background(ColCritical).
			Bold(true).
			Padding(0, 1)
)

// ---- Severity helpers -------------------------------------------------------

// NormalizeSeverity upper-cases and trims a severity string, defaulting to INFO.
func NormalizeSeverity(sev string) string {
	s := strings.ToUpper(strings.TrimSpace(sev))
	switch s {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO":
		return s
	case "":
		return "INFO"
	default:
		return s
	}
}

// SeverityRank gives a sortable weight (higher = more severe).
func SeverityRank(sev string) int {
	switch NormalizeSeverity(sev) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

// SeverityColor returns the hue for a severity.
func SeverityColor(sev string) lipgloss.Color {
	switch NormalizeSeverity(sev) {
	case "CRITICAL":
		return ColCritical
	case "HIGH":
		return ColHigh
	case "MEDIUM":
		return ColMedium
	case "LOW":
		return ColLow
	default:
		return ColInfo
	}
}

// SeverityLabel returns a fixed-width (4-char) upper label for a severity.
func SeverityLabel(sev string) string {
	switch NormalizeSeverity(sev) {
	case "CRITICAL":
		return "CRIT"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MED "
	case "LOW":
		return "LOW "
	case "INFO":
		return "INFO"
	default:
		return "UNKN"
	}
}

// SeverityBadge renders a padded, coloured severity pill.
func SeverityBadge(sev string) string {
	fg := ColOnDark
	switch NormalizeSeverity(sev) {
	case "MEDIUM", "LOW":
		fg = ColOnLight // dark text reads better on the lighter amber/teal
	}
	return lipgloss.NewStyle().
		Background(SeverityColor(sev)).
		Foreground(fg).
		Bold(true).
		Padding(0, 1).
		Render(strings.TrimSpace(SeverityLabel(sev)))
}

// SeverityText renders the severity word in its hue, no background.
func SeverityText(sev string) string {
	return lipgloss.NewStyle().Foreground(SeverityColor(sev)).Bold(true).
		Render(NormalizeSeverity(sev))
}

// ---- Category helpers -------------------------------------------------------

// CategoryLabel maps a raw scan category key to a human label.
func CategoryLabel(cat string) string {
	switch cat {
	case "security_issues":
		return "Security"
	case "antipatterns_bugs":
		return "Anti-patterns"
	case "complex_functions":
		return "Complexity"
	case "dockstring_absent", "docstring_absent":
		return "Docs"
	case "dead_code":
		return "Dead code"
	case "duplicate_code":
		return "Duplication"
	case "secret_detection":
		return "Secrets"
	case "sca":
		return "Dependencies"
	case "infra_security":
		return "IaC"
	case "agent_security":
		return "Agent-Chain"
	case "exploitability":
		return "Exploitable"
	default:
		return cat
	}
}

// CategoryColor gives a chip colour per category family.
func CategoryColor(cat string) lipgloss.Color {
	switch cat {
	case "agent_security":
		return ColBrand
	case "secret_detection":
		return ColHigh
	case "sca":
		return ColAccent
	case "infra_security":
		return ColInfo
	case "security_issues":
		return ColCritical
	case "exploitability":
		return ColCritical
	default:
		return ColMuted
	}
}

// CategoryChip renders a small category tag.
func CategoryChip(cat string) string {
	return lipgloss.NewStyle().Foreground(CategoryColor(cat)).Bold(true).
		Render(CategoryLabel(cat))
}

// ---- Secret redaction -------------------------------------------------------

// Redact masks a secret so it is never shown in full. It keeps at most the
// first two characters for recognisability and replaces the rest with dots.
// A short or empty secret is fully masked.
func Redact(secret string) string {
	s := strings.TrimSpace(secret)
	if s == "" {
		return "••••••••"
	}
	runes := []rune(s)
	if len(runes) <= 4 {
		return strings.Repeat("•", 8)
	}
	prefix := string(runes[:2])
	return prefix + strings.Repeat("•", 10)
}

// ---- Banner -----------------------------------------------------------------

// TridentBanner renders the Trishul brand banner, sized to width.
func TridentBanner(width int) string {
	if width < 20 {
		width = 20
	}
	inner := width - 4
	if inner < 16 {
		inner = 16
	}

	mark := lipgloss.NewStyle().Foreground(ColAccent).Bold(true).Render(Trident)
	name := lipgloss.NewStyle().Foreground(ColBrand).Bold(true).Render("T R I S H U L")
	tagline := lipgloss.NewStyle().Foreground(ColMuted).
		Render("Security scanner for AI-era codebases")

	line1 := lipgloss.PlaceHorizontal(inner, lipgloss.Center,
		mark+"  "+name+"  "+mark)
	line2 := lipgloss.PlaceHorizontal(inner, lipgloss.Center, tagline)

	return PanelStyle.
		BorderForeground(ColBrand).
		Width(inner).
		Render(line1 + "\n" + line2)
}

// renderHelp joins key/description pairs into a single muted help line.
func renderHelp(pairs ...[2]string) string {
	var parts []string
	for _, p := range pairs {
		parts = append(parts, HelpKeyStyle.Render(p[0])+" "+HelpStyle.Render(p[1]))
	}
	return HelpStyle.Render("  ") + strings.Join(parts, HelpStyle.Render("   "))
}

// clampWidth returns a sensible content width given a terminal width.
func clampWidth(w, fallback, maxW int) int {
	if w <= 0 {
		return fallback
	}
	if w > maxW {
		return maxW
	}
	return w
}
