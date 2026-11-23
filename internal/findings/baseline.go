package findings

// Baseline diffing with rename awareness (P1.4). A PR gate shows only findings
// that are *new* relative to a baseline (the set of fingerprints already present
// on the base branch). Two things make this honest:
//
//   - rename tracking: when a PR renames a file, a pre-existing finding moves to
//     the new path and would get a new fingerprint; we re-key it to the old path
//     so it is still recognised as not-new.
//   - fingerprint migration: a baseline may hold both v1 and v2 fingerprints, so
//     Baseline accepts opaque fingerprint strings and callers add whichever
//     scheme(s) they computed (the v1 value is computed by the legacy model).

// Baseline is a set of known fingerprints.
type Baseline struct {
	fps map[string]struct{}
}

// NewBaseline builds a baseline from fingerprint strings (any scheme).
func NewBaseline(fps []string) *Baseline {
	b := &Baseline{fps: make(map[string]struct{}, len(fps))}
	for _, fp := range fps {
		if fp != "" {
			b.fps[fp] = struct{}{}
		}
	}
	return b
}

// Add records a fingerprint.
func (b *Baseline) Add(fp string) {
	if fp != "" {
		b.fps[fp] = struct{}{}
	}
}

// Has reports whether a fingerprint is in the baseline.
func (b *Baseline) Has(fp string) bool {
	_, ok := b.fps[fp]
	return ok
}

// Len reports how many fingerprints are in the baseline.
func (b *Baseline) Len() int { return len(b.fps) }

// FingerprintUnderRenames computes the finding's fingerprint as if it were still
// at its previous path. renames maps a current path to its previous path (as a
// PR's rename detection reports, e.g. git similarity >= 50%). When the finding's
// file was not renamed the result equals its normal FingerprintV2.
func (f Finding) FingerprintUnderRenames(renames map[string]string) string {
	p := f.Location.Path
	if prev, ok := renames[p]; ok {
		p = prev
	}
	return FingerprintV2(f.RuleID, p, f.Snippet)
}

// IsNew reports whether a finding is new relative to the baseline, accounting
// for renames and any extra fingerprints the caller knows (e.g. the legacy v1
// fingerprint). A finding is NOT new if any of these is in the baseline:
//   - its v2 fingerprint,
//   - its rename-adjusted v2 fingerprint,
//   - any fingerprint in extra.
func (f Finding) IsNew(b *Baseline, renames map[string]string, extra ...string) bool {
	if b == nil {
		return true
	}
	if b.Has(f.FingerprintV2) {
		return false
	}
	if len(renames) > 0 && b.Has(f.FingerprintUnderRenames(renames)) {
		return false
	}
	for _, fp := range extra {
		if b.Has(fp) {
			return false
		}
	}
	return true
}

// New returns only the findings that are new relative to the baseline.
func NewOnly(fs []Finding, b *Baseline, renames map[string]string) []Finding {
	out := make([]Finding, 0, len(fs))
	for _, f := range fs {
		if f.IsNew(b, renames) {
			out = append(out, f)
		}
	}
	return out
}
