// Package findings defines Trishul's v2 finding model: a single, analyzer-
// agnostic representation that every analyzer (agentsec, the Vibe rules,
// clientsecrets, supabase, firebase, exploitability) adapts to, and that the
// PR gate and SARIF writer consume directly.
//
// The v2 model is richer and more honest than the legacy
// map[string]interface{} / models.Finding shapes it supersedes:
//
//   - confidence is a number in [0,1] with a derived band, set from evidence
//     strength rather than a bare "high/medium/low" string;
//   - evidence is an ordered list of located notes, so a comment can show the
//     reasoning steps instead of a single opaque message;
//   - location carries start/end line and column;
//   - fingerprint_v2 is message-independent (see fingerprint.go), so reworded
//     messages and edits above a finding keep its identity stable.
//
// Adapters from the existing analyzers live in adapt.go; nothing here imports
// an analyzer package, so this stays a leaf dependency.
package findings

// Severity is the impact band of a finding. Values match the legacy
// models.Severity strings so SARIF and the gate need no translation table.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// ConfidenceBand is the coarse bucket derived from the numeric Confidence.
type ConfidenceBand string

const (
	BandHigh   ConfidenceBand = "high"
	BandMedium ConfidenceBand = "medium"
	BandLow    ConfidenceBand = "low"
)

// Location points at the code a finding is about. Columns are 1-based and
// optional (0 means "unknown"); EndLine defaults to StartLine when unset.
type Location struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line,omitempty"`
	StartCol  int    `json:"start_col,omitempty"`
	EndCol    int    `json:"end_col,omitempty"`
}

// EvidenceStep is one located note in the chain of reasoning that justifies a
// finding. Notes are redacted (no secret values) and ordered most-relevant
// first. A step may omit Path/Line when it is a general observation.
type EvidenceStep struct {
	Path string `json:"path,omitempty"`
	Line int    `json:"line,omitempty"`
	Note string `json:"note"`
}

// Remediation is advice plus, when available, a concrete patch (unified diff).
type Remediation struct {
	Text  string `json:"text,omitempty"`
	Patch string `json:"patch,omitempty"`
}

// Finding is the v2 finding record. Zero values are valid; use New to get a
// finding with its confidence band and fingerprint filled in.
type Finding struct {
	RuleID      string `json:"rule_id"`
	RuleVersion string `json:"rule_version,omitempty"`
	Analyzer    string `json:"analyzer"`
	VibeID      string `json:"vibe_id,omitempty"`

	Title   string `json:"title"`
	Message string `json:"message"`

	Severity   Severity       `json:"severity"`
	Confidence float64        `json:"confidence"`      // [0,1]
	Band       ConfidenceBand `json:"confidence_band"` // derived from Confidence
	Category   string         `json:"category,omitempty"`

	CWE   []string `json:"cwe,omitempty"`
	OWASP []string `json:"owasp,omitempty"`

	Location Location       `json:"location"`
	Snippet  string         `json:"snippet,omitempty"` // redacted, <= 5 lines
	Evidence []EvidenceStep `json:"evidence,omitempty"`

	Remediation Remediation `json:"remediation,omitempty"`
	References  []string    `json:"references,omitempty"`
	Tags        []string    `json:"tags,omitempty"`

	FingerprintV2 string `json:"fingerprint_v2,omitempty"`
}

// BandFor maps a numeric confidence to its coarse band. The thresholds match
// the priority model in P1.3: >= 0.8 high, >= 0.5 medium, else low.
func BandFor(confidence float64) ConfidenceBand {
	switch {
	case confidence >= 0.8:
		return BandHigh
	case confidence >= 0.5:
		return BandMedium
	default:
		return BandLow
	}
}

// New returns a finding with its Band derived from confidence and its
// fingerprint computed from (rule_id, path, normalized snippet window). Callers
// that mutate Severity/Location/Snippet afterwards should call Finalize again.
func New(f Finding) Finding {
	return f.Finalize()
}

// Finalize derives the confidence band and fingerprint from the current field
// values and returns the updated finding. It is idempotent.
func (f Finding) Finalize() Finding {
	if f.Confidence < 0 {
		f.Confidence = 0
	}
	if f.Confidence > 1 {
		f.Confidence = 1
	}
	f.Band = BandFor(f.Confidence)
	if f.Location.EndLine == 0 {
		f.Location.EndLine = f.Location.StartLine
	}
	f.FingerprintV2 = FingerprintV2(f.RuleID, f.Location.Path, f.Snippet)
	return f
}
