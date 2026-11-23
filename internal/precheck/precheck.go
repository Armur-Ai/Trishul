// Package precheck evaluates a package / MCP server / plugin BEFORE a user
// installs it (plan D5): typosquat distance to popular names, risky install
// scripts, and poisoned tool descriptions, combined into a safe/caution/risky
// verdict. It operates on already-fetched, local content — the hermetic network
// fetch (internal/fetchsafe) and the `trishul check` command wire it later.
package precheck

import (
	"encoding/json"
	"sort"
	"strings"
)

// Verdict is the overall judgement.
type Verdict string

const (
	Safe    Verdict = "safe"
	Caution Verdict = "caution"
	Risky   Verdict = "risky"
)

// ExitCode maps a verdict to a scripting exit code.
func (v Verdict) ExitCode() int {
	switch v {
	case Risky:
		return 2
	case Caution:
		return 1
	default:
		return 0
	}
}

// Reason is one signal contributing to the verdict.
type Reason struct {
	Severity string // HIGH/MEDIUM/LOW
	Detail   string
}

// Report is the result of a precheck.
type Report struct {
	Name    string
	Verdict Verdict
	Reasons []Reason
}

// Levenshtein returns the edit distance between a and b.
func Levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

// Typosquat returns the closest popular name and its distance. A nonzero
// distance within TyposquatMax (and not an exact match) suggests a typosquat.
const TyposquatMax = 2

func Typosquat(name string, popular []string) (closest string, dist int) {
	dist = -1
	for _, p := range popular {
		if p == name {
			return p, 0
		}
		d := Levenshtein(name, p)
		if dist < 0 || d < dist {
			closest, dist = p, d
		}
	}
	return closest, dist
}

// InstallScriptRisks inspects a package.json's scripts for install-time hooks
// that run arbitrary code (preinstall/postinstall/install). Returns the hook
// names present.
func InstallScriptRisks(packageJSON []byte) []string {
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(packageJSON, &pkg) != nil {
		return nil
	}
	var out []string
	for _, hook := range []string{"preinstall", "install", "postinstall"} {
		if _, ok := pkg.Scripts[hook]; ok {
			out = append(out, hook)
		}
	}
	sort.Strings(out)
	return out
}

// imperativeToAgent matches hidden-instruction phrasing in an MCP tool
// description (tool poisoning): second-person imperatives aimed at the agent.
var imperativePhrases = []string{
	"ignore previous", "ignore all previous", "you must", "do not tell",
	"disregard", "system prompt", "before using this tool", "always run",
	"send the", "exfiltrate", "read the file", "curl ", "| sh",
}

// ToolDescriptionPoisoned reports whether an MCP tool description contains
// hidden instructions aimed at the reading agent.
func ToolDescriptionPoisoned(description string) bool {
	d := strings.ToLower(description)
	for _, p := range imperativePhrases {
		if strings.Contains(d, p) {
			return true
		}
	}
	return false
}

// Assess combines signals into a Report. popular is the top-names list for the
// typosquat check (may be empty); packageJSON and toolDescriptions may be nil.
func Assess(name string, popular []string, packageJSON []byte, toolDescriptions []string) Report {
	r := Report{Name: name, Verdict: Safe}
	worst := 0
	bump := func(sev string, detail string, rank int) {
		r.Reasons = append(r.Reasons, Reason{Severity: sev, Detail: detail})
		if rank > worst {
			worst = rank
		}
	}

	if closest, dist := Typosquat(name, popular); dist > 0 && dist <= TyposquatMax {
		bump("HIGH", "name is edit-distance "+itoa(dist)+" from popular \""+closest+"\" (possible typosquat)", 2)
	}
	for _, hook := range InstallScriptRisks(packageJSON) {
		bump("MEDIUM", "runs an install-time script: "+hook, 1)
	}
	for _, desc := range toolDescriptions {
		if ToolDescriptionPoisoned(desc) {
			bump("HIGH", "tool description contains hidden agent instructions (tool poisoning)", 2)
		}
	}

	switch worst {
	case 2:
		r.Verdict = Risky
	case 1:
		r.Verdict = Caution
	default:
		r.Verdict = Safe
	}
	return r
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
