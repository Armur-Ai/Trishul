package sharecard

import (
	"strings"
	"testing"
)

func TestSVG_ContainsGradeAndCounts(t *testing.T) {
	c := Card{Title: "My AI setup", Grade: "C", Counts: map[string]int{"HIGH": 1, "MEDIUM": 3}}
	svg := c.SVG()
	if !strings.HasPrefix(svg, "<svg") || !strings.Contains(svg, "</svg>") {
		t.Fatal("not a well-formed svg")
	}
	if !strings.Contains(svg, ">C<") {
		t.Error("grade not rendered")
	}
	if !strings.Contains(svg, "High") || !strings.Contains(svg, "Medium") {
		t.Errorf("severity rows missing:\n%s", svg)
	}
}

func TestSVG_NeverLeaksPathsOrSecrets(t *testing.T) {
	c := Card{
		Title:  "scan of /Users/alice/secret-project token=ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		Grade:  "F",
		Counts: map[string]int{"CRITICAL": 1},
	}
	svg := c.SVG()
	if strings.Contains(svg, "/Users/alice") || strings.Contains(svg, "secret-project") {
		t.Errorf("path leaked into card:\n%s", svg)
	}
	if strings.Contains(svg, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		t.Errorf("long/secret token leaked into card:\n%s", svg)
	}
}

func TestSanitizeTitle(t *testing.T) {
	if got := sanitizeTitle(""); got != "My AI setup" {
		t.Errorf("empty title=%q", got)
	}
	if got := sanitizeTitle("/etc/passwd"); got != "My AI setup" {
		t.Errorf("path-only title should fall back, got %q", got)
	}
}

func TestCountsFromSeverities(t *testing.T) {
	m := CountsFromSeverities([]string{"high", "HIGH", "low"})
	if m["HIGH"] != 2 || m["LOW"] != 1 {
		t.Errorf("counts=%v", m)
	}
}

func TestSVG_EscapesText(t *testing.T) {
	svg := Card{Title: "a&b", Grade: "A"}.SVG()
	if strings.Contains(svg, "a&b") || !strings.Contains(svg, "a&amp;b") {
		t.Errorf("title not escaped:\n%s", svg)
	}
}
