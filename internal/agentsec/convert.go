package agentsec

// ToFindingMaps converts agent-security findings into the generic finding-map
// shape used by the scan pipeline and reporting (a flat list placed under one
// category). Evidence is already trimmed/redacted by the analyzers; this does
// not expose anything new.
func ToFindingMaps(findings []AgentFinding) []interface{} {
	out := make([]interface{}, 0, len(findings))
	for _, f := range findings {
		out = append(out, map[string]interface{}{
			"path":              f.File,
			"line":              f.Line,
			"message":           f.Title,
			"severity":          f.Severity,
			"check_id":          f.CheckID,
			"cwe":               f.CWE,
			"confidence":        f.Confidence,
			"entry_point":       f.EntryPoint,
			"trust_boundary":    f.TrustBoundary,
			"affected_workflow": f.AffectedWorkflow,
			"enabled_action":    f.EnabledAction,
			"evidence":          f.Evidence,
			"limitations":       f.Limitations,
			"remediation":       f.Remediation,
		})
	}
	return out
}
