// Package advisory models and matches agent-extension security advisories (plan
// D7): an OSV-schema-subset feed covering npm/PyPI packages plus the custom
// ecosystems MCP and ClaudePlugin, so Trishul can flag a known-bad MCP server,
// skill or plugin offline. The feed is published separately (D-HUMAN); this
// package loads a local snapshot and answers match queries.
package advisory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Ecosystem identifiers. npm/PyPI match OSV; MCP/ClaudePlugin are Trishul's own.
const (
	EcosystemNPM          = "npm"
	EcosystemPyPI         = "PyPI"
	EcosystemMCP          = "MCP"
	EcosystemClaudePlugin = "ClaudePlugin"
)

// Advisory is an OSV-subset record.
type Advisory struct {
	ID       string    `json:"id"` // e.g. TRISHUL-MCP-2026-0001
	Summary  string    `json:"summary"`
	Details  string    `json:"details,omitempty"`
	Severity string    `json:"severity,omitempty"` // CRITICAL/HIGH/MEDIUM/LOW
	Affected []Package `json:"affected"`
	Aliases  []string  `json:"aliases,omitempty"`
}

// Package is one affected package + the version ranges hit.
type Package struct {
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	Versions  []string `json:"versions,omitempty"` // exact affected versions; empty = all
}

// Feed is a loaded set of advisories indexed for lookup.
type Feed struct {
	advisories []Advisory
	byPkg      map[string][]int // "ecosystem\x00name" -> advisory indices
}

// Load parses a single advisories JSON array.
func Load(data []byte) (*Feed, error) {
	var adv []Advisory
	if err := json.Unmarshal(data, &adv); err != nil {
		return nil, err
	}
	return index(adv), nil
}

// LoadDir loads every *.json file in dir (each an array of advisories) and merges
// them. A missing dir yields an empty feed, not an error (the snapshot is optional).
func LoadDir(dir string) (*Feed, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return index(nil), nil
		}
		return nil, err
	}
	var all []Advisory
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var adv []Advisory
		if err := json.Unmarshal(data, &adv); err != nil {
			return nil, err
		}
		all = append(all, adv...)
	}
	return index(all), nil
}

func index(adv []Advisory) *Feed {
	f := &Feed{advisories: adv, byPkg: map[string][]int{}}
	for i, a := range adv {
		for _, p := range a.Affected {
			k := key(p.Ecosystem, p.Name)
			f.byPkg[k] = append(f.byPkg[k], i)
		}
	}
	return f
}

// Match returns advisories affecting a given package@version. An advisory whose
// affected package lists no versions matches every version. Version comparison is
// exact (the feed lists concrete affected versions); version "" matches
// version-agnostic advisories only.
func (f *Feed) Match(ecosystem, name, version string) []Advisory {
	var out []Advisory
	seen := map[string]bool{}
	for _, i := range f.byPkg[key(ecosystem, name)] {
		a := f.advisories[i]
		for _, p := range a.Affected {
			if !strings.EqualFold(p.Ecosystem, ecosystem) || p.Name != name {
				continue
			}
			if len(p.Versions) == 0 || containsVersion(p.Versions, version) {
				if !seen[a.ID] {
					out = append(out, a)
					seen[a.ID] = true
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Len reports how many advisories are loaded.
func (f *Feed) Len() int { return len(f.advisories) }

func containsVersion(vs []string, v string) bool {
	for _, x := range vs {
		if x == v {
			return true
		}
	}
	return false
}

func key(ecosystem, name string) string {
	return strings.ToLower(ecosystem) + "\x00" + name
}
