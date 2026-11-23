package prgate

import (
	"os"
	"path/filepath"

	"github.com/Armur-Ai/Trishul/internal/suppress"
)

// Suppression integration (P2.3): drop findings that carry an inline suppression
// marker at their location, and report what was suppressed (with the required
// reason) so the gate summary can show "N suppressed in this PR" rather than
// hiding them silently.

// Suppressed pairs a dropped finding with the marker that suppressed it.
type Suppressed struct {
	Finding Finding
	Marker  suppress.Marker
	Reason  string
}

// ApplySuppressions removes findings suppressed by an inline marker in their
// source file (root-relative) and returns the kept findings plus the suppressed
// ones. Files are read once and cached; a finding whose file cannot be read is
// kept (fail-open — we never hide a finding because of an IO error).
func ApplySuppressions(fs []Finding, root string) (kept []Finding, suppressed []Suppressed) {
	indexByFile := map[string]*suppress.Index{}
	indexFor := func(path string) *suppress.Index {
		if ix, ok := indexByFile[path]; ok {
			return ix
		}
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			indexByFile[path] = nil
			return nil
		}
		ix := suppress.NewIndex(suppress.ScanFile(path, data))
		indexByFile[path] = ix
		return ix
	}

	for _, f := range fs {
		ix := indexFor(f.Path)
		if ix == nil {
			kept = append(kept, f)
			continue
		}
		if s, ok := ix.Suppressed(f.Path, f.Line, f.RuleID); ok {
			suppressed = append(suppressed, Suppressed{Finding: f, Marker: s.Marker, Reason: s.Reason})
			continue
		}
		kept = append(kept, f)
	}
	return kept, suppressed
}
