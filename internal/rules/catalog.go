package rules

// This file implements the per-rule metadata catalog (P1.2): the single source
// of truth for what each rule means, how severe/confident it is by default, what
// file kinds and languages it applies to, and how it renders in docs and SARIF.
// It is distinct from registry.go, which indexes downloadable rule *packs*.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Maturity gates where a rule is allowed to surface. Only stable rules appear
// inline in PR comments and the gate (see P1.3).
type Maturity string

const (
	MaturityStable       Maturity = "stable"
	MaturityBeta         Maturity = "beta"
	MaturityExperimental Maturity = "experimental"
)

// Mode is a rule's default action in the PR gate.
type Mode string

const (
	ModeBlock   Mode = "block"
	ModeComment Mode = "comment"
	ModeMonitor Mode = "monitor"
)

// Examples holds a minimal triggering (bad) and non-triggering (good) snippet.
type Examples struct {
	Bad  string `yaml:"bad" json:"bad,omitempty"`
	Good string `yaml:"good" json:"good,omitempty"`
}

// RuleDef is one rule's registry entry.
type RuleDef struct {
	ID                string   `yaml:"id" json:"id"`
	Title             string   `yaml:"title" json:"title"`
	Short             string   `yaml:"short" json:"short"`
	Description       string   `yaml:"description" json:"description"`
	DefaultSeverity   string   `yaml:"default_severity" json:"default_severity"`
	DefaultConfidence float64  `yaml:"default_confidence" json:"default_confidence"`
	Maturity          Maturity `yaml:"maturity" json:"maturity"`
	Languages         []string `yaml:"languages" json:"languages,omitempty"`
	FileKinds         []string `yaml:"file_kinds" json:"file_kinds,omitempty"`
	CWE               []string `yaml:"cwe" json:"cwe,omitempty"`
	OWASP             []string `yaml:"owasp" json:"owasp,omitempty"`
	References        []string `yaml:"references" json:"references,omitempty"`
	Fix               string   `yaml:"fix" json:"fix,omitempty"`
	Examples          Examples `yaml:"examples" json:"examples,omitempty"`
	ModeDefault       Mode     `yaml:"mode_default" json:"mode_default"`
}

// catalogFile is the on-disk shape: either a top-level `rules:` list, or a
// single rule document (detected by a non-empty id).
type catalogFile struct {
	Rules   []RuleDef `yaml:"rules"`
	RuleDef `yaml:",inline"`
}

// Catalog is the loaded set of rule definitions, indexed by ID.
type Catalog struct {
	byID  map[string]RuleDef
	order []string
}

// LoadCatalog reads every *.yaml/*.yml file under dir (non-recursively) and
// returns the merged catalog. Duplicate IDs are an error.
func LoadCatalog(dir string) (*Catalog, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir: %w", err)
	}
	c := &Catalog{byID: map[string]RuleDef{}}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		var cf catalogFile
		if err := yaml.Unmarshal(data, &cf); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		defs := cf.Rules
		if len(defs) == 0 && cf.RuleDef.ID != "" {
			defs = []RuleDef{cf.RuleDef}
		}
		for _, d := range defs {
			if d.ID == "" {
				return nil, fmt.Errorf("%s: rule with empty id", name)
			}
			if _, dup := c.byID[d.ID]; dup {
				return nil, fmt.Errorf("duplicate rule id %q (in %s)", d.ID, name)
			}
			c.byID[d.ID] = d
			c.order = append(c.order, d.ID)
		}
	}
	sort.Strings(c.order)
	return c, nil
}

// Get returns the definition for id.
func (c *Catalog) Get(id string) (RuleDef, bool) {
	d, ok := c.byID[id]
	return d, ok
}

// IDs returns all rule IDs, sorted.
func (c *Catalog) IDs() []string {
	out := make([]string, len(c.order))
	copy(out, c.order)
	return out
}

// All returns every definition in sorted-ID order.
func (c *Catalog) All() []RuleDef {
	out := make([]RuleDef, 0, len(c.order))
	for _, id := range c.order {
		out = append(out, c.byID[id])
	}
	return out
}

// Len reports how many rules are loaded.
func (c *Catalog) Len() int { return len(c.order) }

var validSeverity = map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFO": true}
var validMaturity = map[Maturity]bool{MaturityStable: true, MaturityBeta: true, MaturityExperimental: true}
var validMode = map[Mode]bool{ModeBlock: true, ModeComment: true, ModeMonitor: true}

// Validate checks required fields and enum values for every rule, returning all
// problems (not just the first) so a contributor can fix them in one pass.
func (c *Catalog) Validate() []error {
	var errs []error
	for _, id := range c.order {
		d := c.byID[id]
		if strings.TrimSpace(d.Title) == "" {
			errs = append(errs, fmt.Errorf("%s: missing title", id))
		}
		if !validSeverity[strings.ToUpper(d.DefaultSeverity)] {
			errs = append(errs, fmt.Errorf("%s: invalid default_severity %q", id, d.DefaultSeverity))
		}
		if d.DefaultConfidence < 0 || d.DefaultConfidence > 1 {
			errs = append(errs, fmt.Errorf("%s: default_confidence %v out of [0,1]", id, d.DefaultConfidence))
		}
		if !validMaturity[d.Maturity] {
			errs = append(errs, fmt.Errorf("%s: invalid maturity %q", id, d.Maturity))
		}
		if d.ModeDefault != "" && !validMode[d.ModeDefault] {
			errs = append(errs, fmt.Errorf("%s: invalid mode_default %q", id, d.ModeDefault))
		}
	}
	return errs
}
