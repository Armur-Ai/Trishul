package prgate

import (
	"path"
	"strings"

	"github.com/Armur-Ai/Trishul/internal/config"
)

// testPathMarkers identify test and fixture code. Pattern-matching analyzers
// legitimately fire on vulnerable snippets kept as test fixtures; reporting
// those on every PR is the fastest way to get a gate uninstalled.
var testPathMarkers = []string{
	"/testdata/", "/test/", "/tests/", "/__tests__/", "/__mocks__/", "/fixtures/", "/fixture/", "/spec/",
}

var testFileSuffixes = []string{
	"_test.go", "_test.py", ".test.js", ".test.ts", ".test.jsx", ".test.tsx",
	".spec.js", ".spec.ts", ".spec.jsx", ".spec.tsx", "_spec.rb", "Test.java", "Tests.java", "_test.rs",
}

// IsTestPath reports whether p (repo-relative) looks like test/fixture code.
func IsTestPath(p string) bool {
	slashed := "/" + strings.TrimPrefix(p, "/")
	for _, m := range testPathMarkers {
		if strings.Contains(slashed, m) {
			return true
		}
	}
	base := path.Base(p)
	if strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py") {
		return true
	}
	for _, s := range testFileSuffixes {
		if strings.HasSuffix(base, s) {
			return true
		}
	}
	return false
}

// alwaysRelevant findings are reported even in test code: a real secret or an
// agent-instruction attack is just as dangerous in a fixture file.
func alwaysRelevant(f Finding) bool {
	return f.RuleID == "CWE-798" || strings.HasPrefix(f.RuleID, "AGENT-") || strings.HasPrefix(f.RuleID, "SECRET")
}

// FilterOptions controls Filter.
type FilterOptions struct {
	IncludeTests bool
}

// Filter drops findings in paths excluded by the project's .trishul.yml
// `exclude:` globs and, unless IncludeTests, findings in test/fixture code
// (secrets and agent-security findings are always kept).
func Filter(fs []Finding, root string, opts FilterOptions) []Finding {
	var excludes []string
	if cfg, err := config.LoadProjectConfig(root); err == nil && cfg != nil {
		excludes = cfg.Exclude
	}
	var out []Finding
	for _, f := range fs {
		if Excluded(f.Path, excludes) {
			continue
		}
		if !opts.IncludeTests && IsTestPath(f.Path) && !alwaysRelevant(f) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// Excluded matches a repo-relative path against glob patterns. Supports
// path.Match globs against the full path or its base name, and "dir/**" /
// "dir/" prefixes.
func Excluded(p string, patterns []string) bool {
	for _, pat := range patterns {
		pat = strings.TrimPrefix(strings.TrimSpace(pat), "./")
		if pat == "" {
			continue
		}
		if prefix := strings.TrimSuffix(strings.TrimSuffix(pat, "**"), "/"); prefix != pat || strings.HasSuffix(pat, "/") {
			if p == prefix || strings.HasPrefix(p, prefix+"/") {
				return true
			}
		}
		// "**/x" matches x at any depth.
		if rest := strings.TrimPrefix(pat, "**/"); rest != pat {
			if ok, _ := path.Match(rest, path.Base(p)); ok {
				return true
			}
			if ok, _ := path.Match(rest, p); ok {
				return true
			}
		}
		if ok, _ := path.Match(pat, p); ok {
			return true
		}
		if ok, _ := path.Match(pat, path.Base(p)); ok {
			return true
		}
	}
	return false
}
