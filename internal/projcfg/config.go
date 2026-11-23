// Package projcfg loads and resolves the .trishul.yml v2 project configuration
// (P2.3): the profile, comment budget, gate policy, per-rule overrides (by id
// or glob), path ignores and the experimental toggle.
//
// Policy that decides blocking (the Gate) must always be read from the base
// branch so a PR cannot weaken the gate on itself; suppressions may come from
// the head. Enforcing that is the caller's job — this package just loads and
// resolves a single config file.
package projcfg

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// RuleOverride tweaks a rule's severity, mode or enabled state. Enabled is a
// pointer so "unset" is distinguishable from "false".
type RuleOverride struct {
	Severity string `yaml:"severity" json:"severity,omitempty"`
	Mode     string `yaml:"mode" json:"mode,omitempty"`
	Enabled  *bool  `yaml:"enabled" json:"enabled,omitempty"`
}

// CommentCfg bounds PR output.
type CommentCfg struct {
	MaxInline  int `yaml:"max_inline" json:"max_inline"`
	MaxSummary int `yaml:"max_summary" json:"max_summary"`
}

// GateCfg is the blocking policy.
type GateCfg struct {
	BlockOn   []string `yaml:"block_on" json:"block_on"` // severities that block, e.g. [CRITICAL, HIGH]
	FailOnNew bool     `yaml:"fail_on_new" json:"fail_on_new"`
}

// PathCfg lists ignore globs.
type PathCfg struct {
	Ignore []string `yaml:"ignore" json:"ignore,omitempty"`
}

// Config is the resolved .trishul.yml.
type Config struct {
	Profile      string                  `yaml:"profile" json:"profile"`
	Comments     CommentCfg              `yaml:"comments" json:"comments"`
	Gate         GateCfg                 `yaml:"gate" json:"gate"`
	Rules        map[string]RuleOverride `yaml:"rules" json:"rules,omitempty"`
	Paths        PathCfg                 `yaml:"paths" json:"paths,omitempty"`
	Experimental bool                    `yaml:"experimental" json:"experimental"`
}

// Default returns the baseline config applied when no file is present or as the
// base under any file's overrides.
func Default() Config {
	return Config{
		Profile:  "default",
		Comments: CommentCfg{MaxInline: 10, MaxSummary: 25},
		Gate:     GateCfg{BlockOn: []string{"CRITICAL", "HIGH"}, FailOnNew: true},
	}
}

// Load reads a .trishul.yml from path and layers it over Default(). A missing
// file is not an error — it returns Default(). Unknown keys are rejected so a
// typo in policy fails loudly rather than silently doing nothing.
func Load(path string) (Config, error) {
	c := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	if c.Comments.MaxInline <= 0 {
		c.Comments.MaxInline = 10
	}
	if c.Comments.MaxSummary <= 0 {
		c.Comments.MaxSummary = 25
	}
	return c, nil
}

// ResolveRule returns the effective override for a rule id, applying an exact
// match if present, otherwise the most specific glob match (longest non-wildcard
// prefix wins, e.g. "EXPLOIT-AZURE-*" beats "EXPLOIT-*"). Returns the zero
// override when nothing matches.
func (c Config) ResolveRule(id string) RuleOverride {
	if o, ok := c.Rules[id]; ok {
		return o
	}
	type cand struct {
		pat string
		ov  RuleOverride
	}
	var cands []cand
	for pat, ov := range c.Rules {
		if strings.ContainsAny(pat, "*?[") {
			if ok, _ := path.Match(pat, id); ok {
				cands = append(cands, cand{pat, ov})
			}
		}
	}
	if len(cands) == 0 {
		return RuleOverride{}
	}
	sort.Slice(cands, func(i, j int) bool {
		return specificity(cands[i].pat) > specificity(cands[j].pat)
	})
	return cands[0].ov
}

// specificity scores a glob by the length of its leading non-wildcard run, so a
// more specific pattern wins.
func specificity(pat string) int {
	i := strings.IndexAny(pat, "*?[")
	if i < 0 {
		return len(pat)
	}
	return i
}

// RuleEnabled reports whether a rule is enabled (default true unless an override
// disables it).
func (c Config) RuleEnabled(id string) bool {
	if o := c.ResolveRule(id); o.Enabled != nil {
		return *o.Enabled
	}
	return true
}

// PathIgnored reports whether a path matches any ignore glob. Globs match either
// the full path or any path segment prefix (so "node_modules" and
// "test/**" style entries both work via path.Match on the full path, and a bare
// token matches a leading path component).
func (c Config) PathIgnored(p string) bool {
	for _, g := range c.Paths.Ignore {
		if ok, _ := path.Match(g, p); ok {
			return true
		}
		// bare token: match it as a path segment anywhere
		if !strings.ContainsAny(g, "*?[/") {
			for _, seg := range strings.Split(p, "/") {
				if seg == g {
					return true
				}
			}
		}
		// prefix glob like "vendor/**"
		if strings.HasSuffix(g, "/**") {
			prefix := strings.TrimSuffix(g, "/**")
			if p == prefix || strings.HasPrefix(p, prefix+"/") {
				return true
			}
		}
	}
	return false
}

// Blocks reports whether a finding of the given severity should block the gate.
func (c Config) Blocks(severity string) bool {
	up := strings.ToUpper(severity)
	for _, s := range c.Gate.BlockOn {
		if strings.ToUpper(s) == up {
			return true
		}
	}
	return false
}

// Explain renders the effective config for `trishul-ci --explain-config`.
func (c Config) Explain() string {
	var b strings.Builder
	fmt.Fprintf(&b, "profile: %s\n", c.Profile)
	fmt.Fprintf(&b, "experimental: %v\n", c.Experimental)
	fmt.Fprintf(&b, "comments: max_inline=%d max_summary=%d\n", c.Comments.MaxInline, c.Comments.MaxSummary)
	fmt.Fprintf(&b, "gate: block_on=%s fail_on_new=%v\n", strings.Join(c.Gate.BlockOn, ","), c.Gate.FailOnNew)
	if len(c.Paths.Ignore) > 0 {
		fmt.Fprintf(&b, "paths.ignore: %s\n", strings.Join(c.Paths.Ignore, ", "))
	}
	if len(c.Rules) > 0 {
		ids := make([]string, 0, len(c.Rules))
		for id := range c.Rules {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		b.WriteString("rules:\n")
		for _, id := range ids {
			o := c.Rules[id]
			fmt.Fprintf(&b, "  %s: severity=%q mode=%q enabled=%v\n", id, o.Severity, o.Mode, o.Enabled)
		}
	}
	return b.String()
}
