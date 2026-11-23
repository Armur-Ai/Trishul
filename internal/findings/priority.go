package findings

import "sort"

// Priority scoring (P1.3). Everything the gate shows or blocks on is ordered by
// priority, so the highest-impact, highest-confidence findings in real source
// come first and noise in tests/docs/generated files sinks.
//
//	priority = severity_weight × confidence × context_multiplier
//
// The context multiplier is supplied by the caller (it comes from the file's
// classification — see internal/fileclass); ContextMultiplier maps a file-kind
// name to the weight so callers don't hard-code the table.

// SeverityWeight is the impact term of the priority score.
func SeverityWeight(s Severity) float64 {
	switch s {
	case SeverityCritical:
		return 1.0
	case SeverityHigh:
		return 0.8
	case SeverityMedium:
		return 0.5
	case SeverityLow:
		return 0.25
	case SeverityInfo:
		return 0.1
	default:
		return 0.5
	}
}

// ContextMultiplier weights a finding by where it lives. Issues in real source
// and on the agent surface count fully; issues in tests, examples, docs, locale
// and generated/vendored/minified files are progressively discounted because a
// finding there is far less likely to be a real, shippable vulnerability.
func ContextMultiplier(fileKind string) float64 {
	switch fileKind {
	case "source", "agent-surface", "ci", "migration", "config":
		return 1.0
	case "example", "fixture":
		return 0.5
	case "test":
		return 0.4
	case "docs", "locale":
		return 0.3
	case "generated", "vendored", "minified":
		return 0.15
	default:
		return 1.0
	}
}

// Priority returns the finding's priority given its context multiplier.
func (f Finding) Priority(contextMultiplier float64) float64 {
	return SeverityWeight(f.Severity) * f.Confidence * contextMultiplier
}

// Scored pairs a finding with its computed priority, for ordering.
type Scored struct {
	Finding  Finding
	Priority float64
}

// Rank computes each finding's priority using multiplierFor(path) for its file
// and returns them sorted by priority descending (stable; ties keep CRITICAL>...
// then path, then line). multiplierFor may be nil, meaning multiplier 1.0 for
// every finding.
func Rank(fs []Finding, multiplierFor func(path string) float64) []Scored {
	out := make([]Scored, len(fs))
	for i, f := range fs {
		m := 1.0
		if multiplierFor != nil {
			m = multiplierFor(f.Location.Path)
		}
		out[i] = Scored{Finding: f, Priority: f.Priority(m)}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		if out[i].Finding.Location.Path != out[j].Finding.Location.Path {
			return out[i].Finding.Location.Path < out[j].Finding.Location.Path
		}
		return out[i].Finding.Location.StartLine < out[j].Finding.Location.StartLine
	})
	return out
}
