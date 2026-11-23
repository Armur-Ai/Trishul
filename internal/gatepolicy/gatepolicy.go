// Package gatepolicy decides where a rule's findings may surface, combining the
// rule's declared maturity (from the catalog) with its measured precision (from
// the bench). This is the P1.3 visibility policy:
//
//   - experimental rules never appear inline or in the gate — only in full
//     reports run with --experimental;
//   - a stable rule whose measured precision is below the demotion threshold is
//     treated as beta and is not shown inline (it is auto-demoted until its
//     precision recovers);
//   - beta rules appear in reports but not inline.
//
// Keeping this in one place means the gate, the App and the SARIF writer all
// make the same call.
package gatepolicy

import "github.com/Armur-Ai/Trishul/internal/rules"

// DemotionThreshold is the precision below which a stable rule is auto-demoted
// to beta (and so dropped from inline comments).
const DemotionThreshold = 0.70

// EffectiveMaturity returns the maturity a rule is treated as, after applying
// auto-demotion. A stable rule with measured precision below DemotionThreshold
// becomes beta. hasPrecision is false when the rule has no bench data yet, in
// which case the declared maturity stands (we don't demote on missing data).
func EffectiveMaturity(declared rules.Maturity, precision float64, hasPrecision bool) rules.Maturity {
	if declared == rules.MaturityStable && hasPrecision && precision < DemotionThreshold {
		return rules.MaturityBeta
	}
	return declared
}

// ShowInline reports whether a rule's findings may appear as inline PR comments
// and count toward the gate. Only effectively-stable rules qualify.
func ShowInline(declared rules.Maturity, precision float64, hasPrecision bool) bool {
	return EffectiveMaturity(declared, precision, hasPrecision) == rules.MaturityStable
}

// ShowInReport reports whether a rule may appear in a full report. Experimental
// rules only show when the caller opts in via includeExperimental.
func ShowInReport(declared rules.Maturity, includeExperimental bool) bool {
	if declared == rules.MaturityExperimental {
		return includeExperimental
	}
	return true
}

// Decision is the resolved visibility for a rule, handy for logging why a rule
// was or wasn't shown.
type Decision struct {
	Effective   rules.Maturity
	Inline      bool
	InReport    bool
	AutoDemoted bool
}

// Resolve computes the full visibility decision for a rule.
func Resolve(declared rules.Maturity, precision float64, hasPrecision, includeExperimental bool) Decision {
	eff := EffectiveMaturity(declared, precision, hasPrecision)
	return Decision{
		Effective:   eff,
		Inline:      eff == rules.MaturityStable,
		InReport:    ShowInReport(declared, includeExperimental),
		AutoDemoted: declared == rules.MaturityStable && eff == rules.MaturityBeta,
	}
}
