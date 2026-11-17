package internal

// Dependency-provenance analyzer (Vibe-security class: "risky dependency
// provenance" in JS/TS manifests). A conservative, deterministic, read-only
// static detector that inspects package.json manifests for WHERE dependencies
// come from and HOW they are pinned.
//
// It is intentionally scoped: this analyzer is about provenance and pinning —
// non-registry sources, floating/unpinned specs, and overrides/resolutions
// redirections. It deliberately does NOT analyze install-script execution
// (postinstall/preinstall/prepare); that concern is handled by a separate
// analyzer and is not duplicated here.
//
// Detected checks:
//
//	VIBE-DEP-001  MEDIUM / CWE-1104  a dependency sourced from a non-registry
//	              location (git/git+/http(s)/github:/gitlab:/file:/link:/raw URL)
//	              that bypasses registry integrity.
//	VIBE-DEP-002  LOW    / CWE-1357  an unpinned spec that floats (*, latest, x,
//	              or a bare range) while NO lockfile is present anywhere in the
//	              project. Suppressed entirely when a lockfile pins the tree.
//	VIBE-DEP-003  MEDIUM / CWE-494   an overrides/resolutions entry that repoints
//	              a package to a non-registry (git/url/file) source — a
//	              supply-chain redirection.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Armur-Ai/Trishul/internal/logger"
	utils "github.com/Armur-Ai/Trishul/pkg"
)

// RunDependencyProvenance statically scans a project (read-only) for risky
// dependency provenance in package.json manifests. It never writes, deletes, or
// executes anything in the target. Findings are returned under the
// vibe_security category.
func RunDependencyProvenance(dir string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "dep-provenance").Str("dir", dir).Msg("running")

	findings := []interface{}{}

	result, err := depScan(dir)
	if err != nil {
		logger.Error().Str("tool", "dep-provenance").Err(err).Msg("failed to scan project")
		return map[string]interface{}{utils.VIBE_SECURITY: findings}, nil
	}
	for _, f := range result {
		findings = append(findings, f)
	}

	return map[string]interface{}{utils.VIBE_SECURITY: findings}, nil
}

// depManifest is the subset of package.json we parse.
type depManifest struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Overrides            json.RawMessage   `json:"overrides"`
	Resolutions          json.RawMessage   `json:"resolutions"`
}

// depOverrideHit is one overrides/resolutions leaf that repoints a package.
type depOverrideHit struct {
	pkg  string
	spec string
}

// depSkipDirs are directories never worth walking.
var depSkipDirs = map[string]bool{
	"node_modules": true, ".git": true, "dist": true, "build": true,
	"vendor": true, "__pycache__": true, ".venv": true, "venv": true,
	".next": true, "coverage": true, "out": true, "bower_components": true,
}

// depLockfiles are the lockfile basenames whose presence anywhere in the
// project means the dependency tree is pinned (suppresses VIBE-DEP-002).
var depLockfiles = map[string]bool{
	"package-lock.json": true,
	"npm-shrinkwrap.json": true,
	"yarn.lock":           true,
	"pnpm-lock.yaml":      true,
}

// depExactVersionRe matches an exact, fully-pinned semver (optionally v-prefixed,
// with pre-release / build metadata). Anything that is not an exact pin is
// treated as floating.
var depExactVersionRe = regexp.MustCompile(`^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)*$`)

// depNonRegistryPrefixes are spec prefixes that denote a non-registry source.
var depNonRegistryPrefixes = []string{
	"git:", "git+", "git@", "git://",
	"github:", "gitlab:", "bitbucket:",
	"file:", "link:",
	"http://", "https://",
}

// depScan walks dir (read-only) and returns deterministic findings.
func depScan(dir string) ([]map[string]interface{}, error) {
	var manifests []string
	lockfilePresent := false

	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries rather than aborting the whole scan
		}
		if d.IsDir() {
			if depSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if depLockfiles[name] {
			lockfilePresent = true
			return nil
		}
		if name == "package.json" {
			manifests = append(manifests, path)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	// Deterministic processing order across manifests.
	sort.Strings(manifests)

	var findings []map[string]interface{}
	for _, m := range manifests {
		findings = append(findings, depScanManifest(dir, m, lockfilePresent)...)
	}

	depSortFindings(findings)
	return findings, nil
}

// depScanManifest parses one package.json and returns its findings.
func depScanManifest(dir, path string, lockfilePresent bool) []map[string]interface{} {
	content, readErr := os.ReadFile(path)
	if readErr != nil {
		logger.Debug().Str("tool", "dep-provenance").Str("file", path).Err(readErr).Msg("skip unreadable manifest")
		return nil
	}

	var mf depManifest
	if err := json.Unmarshal(content, &mf); err != nil {
		logger.Debug().Str("tool", "dep-provenance").Str("file", path).Err(err).Msg("skip malformed manifest")
		return nil
	}

	relPath := path
	if rel, relErr := filepath.Rel(dir, path); relErr == nil {
		relPath = rel
	}

	lines := strings.Split(string(content), "\n")
	used := map[int]bool{}
	var findings []map[string]interface{}

	// Process dependency sections in a fixed order with sorted keys so line
	// assignment (and output) is deterministic.
	sections := []map[string]string{mf.Dependencies, mf.DevDependencies, mf.OptionalDependencies}
	for _, section := range sections {
		for _, name := range depSortedKeys(section) {
			spec := section[name]
			if depIsNonRegistry(spec) {
				line := depFindLine(lines, name, spec, used)
				findings = append(findings, depFinding(
					relPath, line, "MEDIUM", "VIBE-DEP-001", "MEDIUM",
					fmt.Sprintf("Dependency %q is sourced from a non-registry location (%q), bypassing npm registry integrity checks.", name, spec),
					"CWE-1104",
					"Pin this dependency to a published registry version (or an `npm:` alias), or vendor-review the git/URL source and lock it to an immutable commit SHA before trusting it.",
				))
				continue
			}
			// Registry-sourced: flag only if it floats AND nothing pins it.
			if !lockfilePresent && depIsFloating(spec) {
				line := depFindLine(lines, name, spec, used)
				findings = append(findings, depFinding(
					relPath, line, "LOW", "VIBE-DEP-002", "MEDIUM",
					fmt.Sprintf("Dependency %q uses an unpinned/floating version spec (%q) and the project has no lockfile, so installs are not reproducible and can silently pull new code.", name, spec),
					"CWE-1357",
					"Pin to an exact registry version and/or commit a lockfile (package-lock.json / yarn.lock / pnpm-lock.yaml) to freeze the dependency tree.",
				))
			}
		}
	}

	// overrides / resolutions redirections.
	var hits []depOverrideHit
	depCollectOverrides(mf.Overrides, "", &hits)
	depCollectOverrides(mf.Resolutions, "", &hits)
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].pkg != hits[j].pkg {
			return hits[i].pkg < hits[j].pkg
		}
		return hits[i].spec < hits[j].spec
	})
	for _, h := range hits {
		line := depFindLine(lines, h.pkg, h.spec, used)
		findings = append(findings, depFinding(
			relPath, line, "MEDIUM", "VIBE-DEP-003", "MEDIUM",
			fmt.Sprintf("An overrides/resolutions entry repoints package %q to a non-registry source (%q); a supply-chain redirection can replace a trusted package with arbitrary code.", h.pkg, h.spec),
			"CWE-494",
			"Remove the override or point it at a published registry version; if a git/URL source is required, vendor-review it and pin it to an immutable commit SHA.",
		))
	}

	return findings
}

// depCollectOverrides recursively walks an overrides/resolutions tree and
// records every leaf whose spec repoints a package to a non-registry source.
func depCollectOverrides(raw json.RawMessage, key string, out *[]depOverrideHit) {
	if len(raw) == 0 {
		return
	}
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return
	}
	depWalkOverrides(v, key, out)
}

func depWalkOverrides(v interface{}, key string, out *[]depOverrideHit) {
	switch t := v.(type) {
	case string:
		if key != "" && depIsNonRegistry(t) {
			*out = append(*out, depOverrideHit{pkg: key, spec: t})
		}
	case map[string]interface{}:
		for k, child := range t {
			childKey := k
			// "." (and the nested version key "") denote the package itself.
			if k == "." || k == "" {
				childKey = key
			}
			depWalkOverrides(child, childKey, out)
		}
	}
}

// depIsNonRegistry reports whether a spec points outside the npm registry.
// A normal semver / range, a dist-tag, an `npm:` alias, or a `workspace:` /
// `portal:` protocol are all considered registry/local-workspace and NOT flagged
// here.
func depIsNonRegistry(spec string) bool {
	s := strings.TrimSpace(spec)
	if s == "" {
		return false
	}
	ls := strings.ToLower(s)
	// `npm:` aliases resolve against the registry — never a provenance risk.
	if strings.HasPrefix(ls, "npm:") {
		return false
	}
	for _, p := range depNonRegistryPrefixes {
		if strings.HasPrefix(ls, p) {
			return true
		}
	}
	// Any other URL scheme (ssh://, git+ssh://, etc.) is a raw URL source.
	if strings.Contains(ls, "://") {
		return true
	}
	return false
}

// depIsFloating reports whether a registry spec is unpinned/floating. It must be
// called only for specs that are NOT non-registry.
func depIsFloating(spec string) bool {
	s := strings.ToLower(strings.TrimSpace(spec))
	// Resolve `npm:` aliases to their version component before judging the pin.
	if strings.HasPrefix(s, "npm:") {
		if at := strings.LastIndex(s, "@"); at > len("npm:")-1 {
			s = strings.TrimSpace(s[at+1:])
		} else {
			return true // aliased with no version → floats
		}
	}
	if s == "" || s == "*" || s == "latest" || s == "x" {
		return true
	}
	// An exact, fully-pinned semver is clean; everything else (ranges, carets,
	// tildes, wildcards, dist-tags) floats.
	return !depExactVersionRe.MatchString(s)
}

// depFindLine returns the 1-indexed line of the manifest where a given
// dependency key (and, where possible, its value) appears, consuming matched
// lines via `used` so duplicate keys across sections resolve to distinct lines.
func depFindLine(lines []string, name, value string, used map[int]bool) int {
	quoted := `"` + name + `"`
	// First pass: a line containing both the quoted key and its value.
	for i, ln := range lines {
		if used[i+1] {
			continue
		}
		if strings.Contains(ln, quoted) && value != "" && strings.Contains(ln, value) {
			used[i+1] = true
			return i + 1
		}
	}
	// Second pass: a line with the quoted key used as an object key.
	for i, ln := range lines {
		if used[i+1] {
			continue
		}
		idx := strings.Index(ln, quoted)
		if idx >= 0 && strings.Contains(ln[idx+len(quoted):], ":") {
			used[i+1] = true
			return i + 1
		}
	}
	return 1
}

// depSortedKeys returns the keys of a dependency section in sorted order.
func depSortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func depFinding(relPath string, line int, severity, checkID, confidence, message, cwe, remediation string) map[string]interface{} {
	return map[string]interface{}{
		"path":        relPath,
		"line":        line,
		"severity":    severity,
		"check_id":    checkID,
		"message":     message,
		"cwe":         cwe,
		"confidence":  confidence,
		"remediation": remediation,
	}
}

// depSortFindings makes output deterministic regardless of walk ordering.
func depSortFindings(findings []map[string]interface{}) {
	sort.SliceStable(findings, func(i, j int) bool {
		pi, _ := findings[i]["path"].(string)
		pj, _ := findings[j]["path"].(string)
		if pi != pj {
			return pi < pj
		}
		li, _ := findings[i]["line"].(int)
		lj, _ := findings[j]["line"].(int)
		if li != lj {
			return li < lj
		}
		ci, _ := findings[i]["check_id"].(string)
		cj, _ := findings[j]["check_id"].(string)
		return ci < cj
	})
}
