package sarifenrich

import (
	"github.com/Armur-Ai/Trishul/internal/findings"
	"github.com/Armur-Ai/Trishul/internal/rules"
	"github.com/Armur-Ai/Trishul/pkg/sarif"
)

// FromFindings builds a SARIF log directly from v2 findings (P1.1), then enriches
// rules[] from the catalog. This is the forward path that lets analyzers emit
// findings.Finding and get SARIF without round-tripping through the legacy
// models.ScanResult shim. driverName/version/uri describe the tool run.
func FromFindings(fs []findings.Finding, catalog *rules.Catalog, precisionByRule map[string]float64, driverName, version, uri string) *sarif.Log {
	run := sarif.Run{
		Tool: sarif.Tool{Driver: sarif.Driver{
			Name:           driverName,
			Version:        version,
			InformationURI: uri,
		}},
	}
	for _, f := range fs {
		run.Results = append(run.Results, resultFor(f))
	}
	log := &sarif.Log{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs:    []sarif.Run{run},
	}
	Enrich(log, catalog, precisionByRule)
	return log
}

func resultFor(f findings.Finding) sarif.Result {
	var region *sarif.Region
	if f.Location.StartLine > 0 || f.Location.StartCol > 0 {
		region = &sarif.Region{StartLine: f.Location.StartLine, StartColumn: f.Location.StartCol}
	}
	msg := f.Message
	if msg == "" {
		msg = f.Title
	}
	res := sarif.Result{
		RuleID:  f.RuleID,
		Level:   levelFor(f.Severity),
		Message: sarif.Message{Text: msg},
		Locations: []sarif.Location{{
			PhysicalLocation: sarif.PhysicalLocation{
				ArtifactLocation: sarif.ArtifactLocation{URI: f.Location.Path},
				Region:           region,
			},
		}},
	}
	if f.FingerprintV2 != "" {
		res.PartialFingerprints = map[string]string{"trishulFingerprintV2": f.FingerprintV2}
	}
	res.Properties = map[string]interface{}{
		"confidence": f.Confidence,
		"analyzer":   f.Analyzer,
	}
	return res
}

// levelFor maps a v2 severity to a SARIF result level.
func levelFor(sev findings.Severity) string {
	switch sev {
	case findings.SeverityCritical, findings.SeverityHigh:
		return "error"
	case findings.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
