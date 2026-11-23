// Package sarif converts Armur scan results to SARIF 2.1.0 format.
// SARIF (Static Analysis Results Interchange Format) is an OASIS standard
// used by GitHub Code Scanning and many other CI security dashboards.
package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	common "github.com/Armur-Ai/Trishul/pkg/common"
)

// --- SARIF 2.1.0 schema types ---

// Log is the top-level SARIF document.
type Log struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single tool execution.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool describes the scanner that produced the results.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver describes the scanning tool.
type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []Rule `json:"rules"`
}

// Rule describes a single analysis rule.
type Rule struct {
	ID               string                    `json:"id"`
	Name             string                    `json:"name,omitempty"`
	ShortDescription *MultiformatMessageString `json:"shortDescription,omitempty"`
	FullDescription  *MultiformatMessageString `json:"fullDescription,omitempty"`
	Help             *MultiformatMessageString `json:"help,omitempty"`
	HelpURI          string                    `json:"helpUri,omitempty"`
	Properties       map[string]interface{}    `json:"properties,omitempty"`
}

// Result represents a single finding.
type Result struct {
	RuleID              string                 `json:"ruleId"`
	Level               string                 `json:"level"` // error, warning, note, none
	Message             Message                `json:"message"`
	Locations           []Location             `json:"locations,omitempty"`
	PartialFingerprints map[string]string      `json:"partialFingerprints,omitempty"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
	Fixes               []Fix                  `json:"fixes,omitempty"`
}

// Fix is a suggested change for a result (SARIF fixes[]), which GitHub code
// scanning can offer to apply.
type Fix struct {
	Description     *Message         `json:"description,omitempty"`
	ArtifactChanges []ArtifactChange `json:"artifactChanges"`
}

// ArtifactChange is the set of replacements in one file.
type ArtifactChange struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Replacements     []Replacement    `json:"replacements"`
}

// Replacement deletes a region and inserts content in its place.
type Replacement struct {
	DeletedRegion   Region                    `json:"deletedRegion"`
	InsertedContent *MultiformatMessageString `json:"insertedContent,omitempty"`
}

// fingerprint computes a stable, line-insensitive identity for a finding so
// GitHub Code Scanning can track it across runs. Deliberately excludes the line
// number so an unrelated edit above the finding does not churn its identity.
func fingerprint(ruleID, filePath, message string) string {
	sum := sha256.Sum256([]byte(ruleID + "|" + filePath + "|" + message))
	return hex.EncodeToString(sum[:])[:16]
}

// stableRuleID derives a deterministic rule id from whatever identifying
// fields are available, so findings that lack a canonical id (CVE/CWE/check)
// still get a stable, per-rule identity rather than all collapsing onto one
// generic bucket. Empty parts are skipped so the id only reflects real data.
func stableRuleID(prefix string, parts ...string) string {
	var nonEmpty []string
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	if len(nonEmpty) == 0 {
		return prefix
	}
	sum := sha256.Sum256([]byte(strings.Join(nonEmpty, "|")))
	return prefix + "-" + hex.EncodeToString(sum[:])[:10]
}

// registerCWERule registers a CWE-backed security rule once, linking to the
// MITRE CWE definition.
func registerCWERule(rulesSeen map[string]Rule, cwe string) {
	if _, seen := rulesSeen[cwe]; seen {
		return
	}
	rulesSeen[cwe] = Rule{
		ID:   cwe,
		Name: cwe,
		ShortDescription: &MultiformatMessageString{
			Text: fmt.Sprintf("Security issue: %s", cwe),
		},
		HelpURI: fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html",
			strings.TrimPrefix(cwe, "CWE-")),
	}
}

// flattenIssues normalizes a category value into a flat list of issue maps.
// Reformatted categories nest the real issues under an "issues" key (grouped
// by path, message, etc.); raw categories are already flat. Supporting both
// keeps the SARIF generator robust to either shape.
func flattenIssues(raw interface{}) []map[string]interface{} {
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	var out []map[string]interface{}
	for _, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if nested, ok := m["issues"].([]interface{}); ok {
			for _, ni := range nested {
				if nm, ok := ni.(map[string]interface{}); ok {
					out = append(out, nm)
				}
			}
			continue
		}
		out = append(out, m)
	}
	return out
}

// getSeverity extracts a severity string, tolerating scanners (e.g. osv-scanner)
// that emit severity as a list rather than a scalar.
func getSeverity(m map[string]interface{}, key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case []interface{}:
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				return s
			}
		}
	case []string:
		for _, s := range v {
			if s != "" {
				return s
			}
		}
	}
	return ""
}

// firstString returns the first non-empty string among the given keys.
func firstString(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if s := getString(m, k); s != "" {
			return s
		}
	}
	return ""
}

// Location pinpoints where a finding was observed.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation holds the file and region.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

// ArtifactLocation holds the file URI.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// Region specifies line/column range.
type Region struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// Message holds the human-readable finding text.
type Message struct {
	Text string `json:"text"`
}

// MultiformatMessageString holds a plain-text and/or markdown description.
type MultiformatMessageString struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// severityToLevel converts Armur severity strings to SARIF levels.
func severityToLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	default:
		return "warning"
	}
}

// FromScanResults converts Trishul scan results (map[string]interface{}) to a SARIF Log.
// It expects the standard Armur output structure with a "security_issues" key.
func FromScanResults(results map[string]interface{}, toolVersion string) *Log {
	if toolVersion == "" {
		toolVersion = common.Version
	}

	var sarifResults []Result
	rulesSeen := make(map[string]Rule)

	// Process security_issues
	if rawIssues, ok := results["security_issues"]; ok {
		issues, _ := rawIssues.([]interface{})
		for _, rawGroup := range issues {
			group, ok := rawGroup.(map[string]interface{})
			if !ok {
				continue
			}

			// A real CWE drives a shared, well-described rule. When it is
			// missing (empty or the "unknown" placeholder the reformatter
			// uses), we derive a stable per-finding rule id from the
			// finding's own fields instead of collapsing every CWE-less
			// finding into a single "UNKNOWN" bucket.
			cwe := getString(group, "cwe")
			hasCWE := cwe != "" && !strings.EqualFold(cwe, "unknown")
			groupRuleID := cwe
			if hasCWE {
				registerCWERule(rulesSeen, cwe)
			}

			// Iterate over file groups.
			filesRaw, _ := group["files"].([]interface{})
			for _, rawFile := range filesRaw {
				fileGroup, ok := rawFile.(map[string]interface{})
				if !ok {
					continue
				}
				filePath := getString(fileGroup, "path")

				issuesRaw, _ := fileGroup["issues"].([]interface{})
				for _, rawIssue := range issuesRaw {
					issue, ok := rawIssue.(map[string]interface{})
					if !ok {
						continue
					}

					line := getInt(issue, "line")
					col := getInt(issue, "column")
					msg := getString(issue, "message")
					sev := getString(issue, "severity")

					ruleID := groupRuleID
					if !hasCWE {
						ruleID = stableRuleID("ARMUR", getString(issue, "check_id"), msg)
						if _, seen := rulesSeen[ruleID]; !seen {
							rulesSeen[ruleID] = Rule{
								ID:   ruleID,
								Name: ruleID,
								ShortDescription: &MultiformatMessageString{
									Text: fmt.Sprintf("Security issue: %s", ruleID),
								},
							}
						}
					}

					result := Result{
						RuleID:     ruleID,
						Level:      severityToLevel(sev),
						Properties: sevProps(sev),
						Message:    Message{Text: msg},
						PartialFingerprints: map[string]string{
							"trishul/v1": fingerprint(ruleID, filePath, msg),
						},
					}

					if filePath != "" {
						loc := Location{
							PhysicalLocation: PhysicalLocation{
								ArtifactLocation: ArtifactLocation{URI: filePath},
							},
						}
						if line > 0 || col > 0 {
							loc.PhysicalLocation.Region = &Region{
								StartLine:   line,
								StartColumn: col,
							}
						}
						result.Locations = []Location{loc}
					}

					sarifResults = append(sarifResults, result)
				}
			}
		}
	}

	// Secret findings (already redacted upstream) — include them so they reach
	// GitHub Code Scanning. We only ever emit the masked preview, never a raw
	// secret value.
	if rawSecrets, ok := results["secret_detection"]; ok {
		if secrets, ok := rawSecrets.([]interface{}); ok && len(secrets) > 0 {
			const secretRule = "CWE-798"
			if _, seen := rulesSeen[secretRule]; !seen {
				rulesSeen[secretRule] = Rule{
					ID:               secretRule,
					Name:             secretRule,
					ShortDescription: &MultiformatMessageString{Text: "Use of hard-coded credentials (CWE-798)"},
					HelpURI:          "https://cwe.mitre.org/data/definitions/798.html",
				}
			}
			for _, rawS := range secrets {
				s, ok := rawS.(map[string]interface{})
				if !ok {
					continue
				}
				filePath := getString(s, "path")
				line := getInt(s, "line")
				msg := getString(s, "message")
				if msg == "" {
					msg = "Hard-coded secret detected"
				}
				if prev := getString(s, "secret_preview"); prev != "" {
					msg = msg + " (" + prev + ")"
				}
				fp := getString(s, "fingerprint")
				if fp == "" {
					fp = fingerprint(secretRule, filePath, msg)
				}
				res := Result{
					RuleID:              secretRule,
					Level:               severityToLevel(getString(s, "severity")),
					Properties:          sevProps(getString(s, "severity")),
					Message:             Message{Text: msg},
					PartialFingerprints: map[string]string{"trishul/v1": fp},
				}
				if filePath != "" {
					loc := Location{PhysicalLocation: PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: filePath}}}
					if line > 0 {
						loc.PhysicalLocation.Region = &Region{StartLine: line}
					}
					res.Locations = []Location{loc}
				}
				sarifResults = append(sarifResults, res)
			}
		}
	}

	// Dependency / SCA findings — vulnerable third-party packages reported by
	// osv-scanner, trivy, and friends. The reformatter groups these by manifest
	// path; flattenIssues descends into those groups to the individual advisories.
	for _, issue := range flattenIssues(results["sca"]) {
		// Prefer the advisory/CVE id as the rule id so Code Scanning can dedupe
		// and link out; otherwise fall back to a single stable DEPENDENCY rule.
		adv := getString(issue, "check_id")
		ruleID := adv
		if ruleID == "" {
			ruleID = "DEPENDENCY"
		}
		if _, seen := rulesSeen[ruleID]; !seen {
			rule := Rule{
				ID:               ruleID,
				Name:             ruleID,
				ShortDescription: &MultiformatMessageString{Text: fmt.Sprintf("Vulnerable dependency: %s", ruleID)},
			}
			if strings.HasPrefix(adv, "CVE-") {
				rule.HelpURI = "https://nvd.nist.gov/vuln/detail/" + adv
			} else if strings.HasPrefix(adv, "GHSA-") {
				rule.HelpURI = "https://github.com/advisories/" + adv
			}
			rulesSeen[ruleID] = rule
		}

		filePath := getString(issue, "path")
		pkg := getString(issue, "package")
		version := firstString(issue, "version", "installed_version")

		// Build a human-readable message from whatever fields are present.
		msg := getString(issue, "message")
		pkgRef := pkg
		if pkg != "" && version != "" {
			pkgRef = pkg + "@" + version
		}
		switch {
		case msg != "" && pkgRef != "":
			msg = msg + " (" + pkgRef + ")"
		case msg == "" && pkgRef != "":
			msg = "Vulnerable dependency " + pkgRef
		case msg == "":
			msg = "Vulnerable dependency"
		}
		if adv != "" {
			msg = adv + ": " + msg
		}

		res := Result{
			RuleID:              ruleID,
			Level:               severityToLevel(getSeverity(issue, "severity")),
			Properties:          sevProps(getSeverity(issue, "severity")),
			Message:             Message{Text: msg},
			PartialFingerprints: map[string]string{"trishul/v1": fingerprint(ruleID, filePath, msg)},
		}
		if filePath != "" {
			loc := Location{PhysicalLocation: PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: filePath}}}
			if line := getInt(issue, "line"); line > 0 {
				loc.PhysicalLocation.Region = &Region{StartLine: line}
			}
			res.Locations = []Location{loc}
		}
		sarifResults = append(sarifResults, res)
	}

	// Infrastructure-as-Code / infra security findings — misconfigurations
	// reported by checkov, tfsec, trivy, etc. The reformatter groups these by
	// message; flattenIssues descends to the individual checks, each of which
	// carries its own file path.
	for _, issue := range flattenIssues(results["infra_security"]) {
		// Prefer the scanner's check id (e.g. CKV_AWS_..., AVD-...); otherwise a
		// CWE if the scanner attached one; otherwise a stable IAC rule.
		checkID := getString(issue, "check_id")
		cwe := getSeverity(issue, "cwe") // tolerant of string / list cwe values
		ruleID := checkID
		if ruleID == "" {
			ruleID = cwe
		}
		if ruleID == "" {
			ruleID = "IAC"
		}
		if _, seen := rulesSeen[ruleID]; !seen {
			rule := Rule{
				ID:               ruleID,
				Name:             ruleID,
				ShortDescription: &MultiformatMessageString{Text: fmt.Sprintf("Infrastructure misconfiguration: %s", ruleID)},
			}
			if strings.HasPrefix(ruleID, "CWE-") {
				rule.HelpURI = "https://cwe.mitre.org/data/definitions/" + strings.TrimPrefix(ruleID, "CWE-") + ".html"
			}
			rulesSeen[ruleID] = rule
		}

		filePath := getString(issue, "path")
		msg := getString(issue, "message")
		if msg == "" {
			msg = "Infrastructure misconfiguration"
		}
		if checkID != "" {
			msg = checkID + ": " + msg
		}

		res := Result{
			RuleID:              ruleID,
			Level:               severityToLevel(getSeverity(issue, "severity")),
			Properties:          sevProps(getSeverity(issue, "severity")),
			Message:             Message{Text: msg},
			PartialFingerprints: map[string]string{"trishul/v1": fingerprint(ruleID, filePath, msg)},
		}
		if filePath != "" {
			loc := Location{PhysicalLocation: PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: filePath}}}
			// Line may come as an int ("line") or as the start of a
			// "start:end" range string ("file_line_range", from checkov).
			line := getInt(issue, "line")
			if line == 0 {
				if lr := getString(issue, "file_line_range"); lr != "" {
					if start, err := strconv.Atoi(strings.SplitN(lr, ":", 2)[0]); err == nil {
						line = start
					}
				}
			}
			if line > 0 {
				loc.PhysicalLocation.Region = &Region{StartLine: line}
			}
			res.Locations = []Location{loc}
		}
		sarifResults = append(sarifResults, res)
	}

	// Agent supply-chain security findings — suspicious agent instructions,
	// MCP/permission changes, install hooks, encoded instructions, and cross-file
	// attack chains. The check_id is the rule.
	for _, issue := range flattenIssues(results["agent_security"]) {
		ruleID := getString(issue, "check_id")
		if ruleID == "" {
			ruleID = "AGENT-SECURITY"
		}
		if _, seen := rulesSeen[ruleID]; !seen {
			rulesSeen[ruleID] = Rule{
				ID:               ruleID,
				Name:             ruleID,
				ShortDescription: &MultiformatMessageString{Text: "AI agent supply-chain risk: " + ruleID},
			}
		}
		filePath := getString(issue, "path")
		msg := getString(issue, "message")
		if tb := getString(issue, "trust_boundary"); tb != "" {
			msg = msg + " [trust boundary: " + tb + "]"
		}
		if conf := getString(issue, "confidence"); conf != "" {
			msg = msg + " (confidence: " + conf + ")"
		}
		res := Result{
			RuleID:              ruleID,
			Level:               severityToLevel(getSeverity(issue, "severity")),
			Properties:          sevProps(getSeverity(issue, "severity")),
			Message:             Message{Text: msg},
			PartialFingerprints: map[string]string{"trishul/v1": fingerprint(ruleID, filePath, msg)},
		}
		if filePath != "" {
			loc := Location{PhysicalLocation: PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: filePath}}}
			if line := getInt(issue, "line"); line > 0 {
				loc.PhysicalLocation.Region = &Region{StartLine: line}
			}
			res.Locations = []Location{loc}
		}
		sarifResults = append(sarifResults, res)
	}

	// Built-in Vibe Top 10 analyzer findings (missing authz, placeholder
	// security, unsafe LLM, …). The check_id is the rule.
	for _, issue := range flattenIssues(results["vibe_security"]) {
		ruleID := getString(issue, "check_id")
		if ruleID == "" {
			ruleID = "VIBE-SECURITY"
		}
		if _, seen := rulesSeen[ruleID]; !seen {
			rulesSeen[ruleID] = Rule{
				ID:               ruleID,
				Name:             ruleID,
				ShortDescription: &MultiformatMessageString{Text: "Vibe-coding security issue: " + ruleID},
			}
		}
		filePath := getString(issue, "path")
		msg := getString(issue, "message")
		res := Result{
			RuleID:              ruleID,
			Level:               severityToLevel(getSeverity(issue, "severity")),
			Properties:          sevProps(getSeverity(issue, "severity")),
			Message:             Message{Text: msg},
			PartialFingerprints: map[string]string{"trishul/v1": fingerprint(ruleID, filePath, msg)},
		}
		if filePath != "" {
			loc := Location{PhysicalLocation: PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: filePath}}}
			if line := getInt(issue, "line"); line > 0 {
				loc.PhysicalLocation.Region = &Region{StartLine: line}
			}
			res.Locations = []Location{loc}
		}
		sarifResults = append(sarifResults, res)
	}

	// Process exploitability — the exploitability engine's live-exploitability
	// findings (prefers the finding's own check_id / CVE as the SARIF rule id).
	for _, issue := range flattenIssues(results["exploitability"]) {
		ruleID := firstString(issue, "check_id", "cve")
		if ruleID == "" {
			ruleID = "EXPLOITABILITY"
		}
		if _, seen := rulesSeen[ruleID]; !seen {
			rulesSeen[ruleID] = Rule{
				ID:               ruleID,
				Name:             ruleID,
				ShortDescription: &MultiformatMessageString{Text: "Exploitability: " + ruleID},
			}
		}
		filePath := getString(issue, "path")
		msg := getString(issue, "message")
		res := Result{
			RuleID:              ruleID,
			Level:               severityToLevel(getSeverity(issue, "severity")),
			Properties:          sevProps(getSeverity(issue, "severity")),
			Message:             Message{Text: msg},
			PartialFingerprints: map[string]string{"trishul/v1": fingerprint(ruleID, filePath, msg)},
		}
		if filePath != "" {
			loc := Location{PhysicalLocation: PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: filePath}}}
			if line := getInt(issue, "line"); line > 0 {
				loc.PhysicalLocation.Region = &Region{StartLine: line}
			}
			res.Locations = []Location{loc}
		}
		sarifResults = append(sarifResults, res)
	}

	// Build the rules list in a deterministic order (map iteration is random,
	// which otherwise churns the SARIF output and its diffs run to run).
	var rules []Rule
	for _, r := range rulesSeen {
		rules = append(rules, r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	log := &Log{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           "Armur Code Scanner",
						Version:        toolVersion,
						InformationURI: "https://armur.ai",
						Rules:          rules,
					},
				},
				Results: sarifResults,
			},
		},
	}

	return log
}

// Marshal returns the SARIF log as indented JSON.
func (l *Log) Marshal() ([]byte, error) {
	return json.MarshalIndent(l, "", "  ")
}

// Timestamp returns an ISO-8601 timestamp for SARIF invocation records.
func Timestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case float64:
			return int(n)
		}
	}
	return 0
}

// sevProps records the original Trishul severity on a result. SARIF levels are
// coarser (critical and high both map to "error"), so consumers such as the PR
// gate read the precise severity from here.
func sevProps(severity string) map[string]interface{} {
	s := strings.ToLower(strings.TrimSpace(severity))
	if s == "" {
		s = "medium"
	}
	return map[string]interface{}{"severity": s}
}
