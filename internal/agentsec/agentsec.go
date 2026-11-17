package agentsec

import "sort"

// Analyzer inspects a directory (read-only) and returns agent-security findings.
// Each component registers itself via register() in an init() so new components
// are added without editing any central list.
type Analyzer func(dir string) ([]AgentFinding, error)

var analyzers []Analyzer

func register(a Analyzer) { analyzers = append(analyzers, a) }

// Registered returns how many component analyzers are active (for diagnostics).
func Registered() int { return len(analyzers) }

// AnalyzePath runs every registered component analyzer over dir and returns the
// aggregated, deterministically-ordered findings. A failing component is skipped
// (logged by the caller), never aborting the whole analysis.
func AnalyzePath(dir string) ([]AgentFinding, error) {
	return runAnalyzers(dir, analyzers)
}

func runAnalyzers(dir string, list []Analyzer) ([]AgentFinding, error) {
	var all []AgentFinding
	for _, a := range list {
		fs, err := a(dir)
		if err != nil {
			continue
		}
		all = append(all, fs...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].File != all[j].File {
			return all[i].File < all[j].File
		}
		if all[i].Line != all[j].Line {
			return all[i].Line < all[j].Line
		}
		return all[i].CheckID < all[j].CheckID
	})
	return all, nil
}
