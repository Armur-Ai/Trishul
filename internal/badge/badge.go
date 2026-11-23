// Package badge renders a shields.io "endpoint" JSON that the GitHub Action
// writes into the user's own repo (plan D-ARCH.3), e.g. .trishul/badge.json.
// shields.io reads it from raw.githubusercontent.com and renders the badge —
// no Armur server is involved, so the badge works entirely from the user's
// infrastructure. This fits the local-first model: we serve nothing.
package badge

import "encoding/json"

// Endpoint is the shields.io endpoint-badge schema (the subset we emit).
type Endpoint struct {
	SchemaVersion int    `json:"schemaVersion"`
	Label         string `json:"label"`
	Message       string `json:"message"`
	Color         string `json:"color"`
}

// gradeColor maps an A–F grade to a shields color.
var gradeColor = map[string]string{
	"A": "brightgreen", "B": "green", "C": "yellow", "D": "orange", "F": "red",
}

// ForGrade builds a badge for a letter grade.
func ForGrade(grade string) Endpoint {
	color := gradeColor[grade]
	if color == "" {
		color = "lightgrey"
	}
	return Endpoint{SchemaVersion: 1, Label: "trishul", Message: "grade " + grade, Color: color}
}

// ForFindings builds a badge from a new-finding count and whether the gate
// passed: "passing" (green) with no new issues, otherwise "N issues" colored by
// whether the gate blocked.
func ForFindings(newCount int, blocked bool) Endpoint {
	if newCount == 0 {
		return Endpoint{SchemaVersion: 1, Label: "trishul", Message: "passing", Color: "brightgreen"}
	}
	color := "yellow"
	if blocked {
		color = "red"
	}
	return Endpoint{SchemaVersion: 1, Label: "trishul", Message: plural(newCount), Color: color}
}

// JSON renders the endpoint as compact JSON (what gets committed to the repo).
func (e Endpoint) JSON() ([]byte, error) {
	return json.Marshal(e)
}

func plural(n int) string {
	s := itoa(n) + " issue"
	if n != 1 {
		s += "s"
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
