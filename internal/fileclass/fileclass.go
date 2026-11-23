// Package fileclass provides a small, dependency-free file-classification
// layer. Given a repository-relative path (and optionally the file's content),
// Classify reports the file's Kind so that downstream analyzers can apply the
// right treatment: scan real code, skip vendored or generated noise, and still
// let agent-surface rules fire inside documentation-shaped files.
//
// Classification is deterministic and allocation-light. Content is consulted
// only for the generated-header and minified line-length heuristics, and never
// beyond the first maxScan bytes.
package fileclass

import (
	"bufio"
	"bytes"
	"strings"
)

// Kind is the classification of a file.
type Kind string

// The set of known file kinds.
const (
	KindSource       Kind = "source"
	KindTest         Kind = "test"
	KindFixture      Kind = "fixture"
	KindExample      Kind = "example"
	KindDocs         Kind = "docs"
	KindGenerated    Kind = "generated"
	KindVendored     Kind = "vendored"
	KindMinified     Kind = "minified"
	KindLocale       Kind = "locale"
	KindMigration    Kind = "migration"
	KindConfig       Kind = "config"
	KindCI           Kind = "ci"
	KindAgentSurface Kind = "agent-surface"
)

// maxScan caps how much of a file's content the heuristics inspect, so that a
// pathological (e.g. minified) file never forces a large scan.
const maxScan = 64 * 1024

// docExts are the extensions treated as documentation when under a docs/ dir.
var docExts = map[string]bool{
	".md": true, ".mdx": true, ".rst": true, ".adoc": true, ".txt": true,
}

// rootDocExts are extensions that mark a repo-root file as documentation.
var rootDocExts = map[string]bool{
	".md": true, ".mdx": true, ".rst": true, ".adoc": true,
}

// configExts are extensions that identify a configuration file.
var configExts = map[string]bool{
	".yaml": true, ".yml": true, ".toml": true, ".ini": true,
	".cfg": true, ".conf": true, ".env": true,
}

// lockfiles are basenames that are machine-maintained dependency lockfiles.
var lockfiles = map[string]bool{
	"go.sum": true, "package-lock.json": true, "yarn.lock": true,
	"pnpm-lock.yaml": true, "Cargo.lock": true, "poetry.lock": true,
	"composer.lock": true,
}

// agentBasenames are basenames that always denote an agent-surface file.
var agentBasenames = map[string]bool{
	"CLAUDE.md": true, "AGENTS.md": true, ".cursorrules": true,
	".windsurfrules": true, "mcp.json": true,
}

// langCodes is a curated set of 2-3 letter language codes used to recognise
// localized docs (README.<lang>.md, docs/<lang>/...) without misfiring on
// non-language segments like "api", "cli" or "sdk".
var langCodes = map[string]bool{
	"en": true, "zh": true, "fr": true, "de": true, "es": true, "ja": true,
	"ko": true, "ru": true, "pt": true, "it": true, "nl": true, "pl": true,
	"tr": true, "ar": true, "hi": true, "vi": true, "th": true, "id": true,
	"cs": true, "sv": true, "da": true, "fi": true, "no": true, "hu": true,
	"ro": true, "uk": true, "el": true, "he": true, "fa": true, "bn": true,
	"ta": true, "te": true, "ml": true, "kn": true, "mr": true, "gu": true,
	"ur": true, "sk": true, "sl": true, "hr": true, "sr": true, "bg": true,
	"lt": true, "lv": true, "et": true, "ca": true, "gl": true, "eu": true,
	"ms": true, "fil": true, "swa": true,
}

// Classify returns the Kind of the file at path. content may be nil or empty;
// when provided it is used only for the generated-header and minified
// heuristics. The first matching rule wins, in the precedence encoded below.
func Classify(path string, content []byte) Kind {
	p := normalize(path)
	base := baseName(p)
	ext := extOf(base)
	segs := strings.Split(p, "/")

	switch {
	case isAgentSurface(base, segs):
		return KindAgentSurface
	case isVendored(segs):
		return KindVendored
	case isGenerated(p, base, segs, content):
		return KindGenerated
	case isMinified(base, segs, content):
		return KindMinified
	case isLocale(base, ext, segs):
		return KindLocale
	case isMigration(segs):
		return KindMigration
	case isCI(base, segs):
		return KindCI
	case isConfig(base, ext):
		return KindConfig
	case isTest(base, segs):
		return KindTest
	case isFixture(segs):
		return KindFixture
	case isExample(base, segs):
		return KindExample
	case isDocs(p, ext, segs):
		return KindDocs
	default:
		return KindSource
	}
}

// IsCodeLike reports whether k denotes a file where real logic or configuration
// can live (and therefore warrants deeper inspection).
func (k Kind) IsCodeLike() bool {
	switch k {
	case KindSource, KindTest, KindExample, KindConfig, KindCI,
		KindMigration, KindAgentSurface:
		return true
	default:
		return false
	}
}

// --- rule helpers ---

func isAgentSurface(base string, segs []string) bool {
	if agentBasenames[base] {
		return true
	}
	// Any path under .cursor/, .claude/, or a skills/ dir (covers
	// .github/skills/ too). .vscode/mcp.json is already covered by the
	// basename check above.
	return containsSeg(segs, ".cursor", ".claude", "skills")
}

func isVendored(segs []string) bool {
	return containsSeg(segs, "vendor", "node_modules", "third_party", "external", ".yarn")
}

func isGenerated(p, base string, segs []string, content []byte) bool {
	if lockfiles[base] {
		return true
	}
	if strings.HasSuffix(base, ".pb.go") || strings.HasSuffix(base, "_gen.go") {
		return true
	}
	if containsSeg(segs, "dist", "build", ".next") {
		return true
	}
	return hasGeneratedHeader(content)
}

func isMinified(base string, segs []string, content []byte) bool {
	if strings.Contains(base, ".min.") {
		return true
	}
	if containsSeg(segs, "assets") &&
		strings.HasPrefix(base, "index-") && strings.HasSuffix(base, ".js") {
		return true
	}
	return looksMinified(content)
}

func isLocale(base, ext string, segs []string) bool {
	if containsSeg(segs, "locales", "i18n") {
		return true
	}
	if ext == ".po" || ext == ".xliff" {
		return true
	}
	if isReadmeLang(base) {
		return true
	}
	// docs/<lang>/ — two consecutive segments.
	for i := 0; i+1 < len(segs); i++ {
		if segs[i] == "docs" && langCodes[strings.ToLower(segs[i+1])] {
			return true
		}
	}
	return false
}

func isMigration(segs []string) bool {
	// Covers supabase/migrations/... as well.
	return containsSeg(segs, "migrations", "migration")
}

func isCI(base string, segs []string) bool {
	// .github/workflows/ — two consecutive segments.
	for i := 0; i+1 < len(segs); i++ {
		if segs[i] == ".github" && segs[i+1] == "workflows" {
			return true
		}
	}
	if base == ".gitlab-ci.yml" || base == ".travis.yml" || base == "Jenkinsfile" {
		return true
	}
	return containsSeg(segs, ".circleci")
}

func isConfig(base, ext string) bool {
	if configExts[ext] {
		return true
	}
	if base == "tsconfig.json" || base == "Dockerfile" || base == "Makefile" {
		return true
	}
	if strings.HasPrefix(base, ".eslintrc") {
		return true
	}
	return isConfigJSBasename(base)
}

func isTest(base string, segs []string) bool {
	if strings.HasSuffix(base, "_test.go") {
		return true
	}
	if strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") {
		return true
	}
	if strings.HasSuffix(base, ".py") &&
		(strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py")) {
		return true
	}
	return containsSeg(segs, "__tests__")
}

func isFixture(segs []string) bool {
	return containsSeg(segs, "testdata", "fixtures", "__fixtures__", "__snapshots__")
}

func isExample(base string, segs []string) bool {
	if containsSeg(segs, "examples", "example") {
		return true
	}
	return strings.HasPrefix(base, "example.") || strings.HasSuffix(base, ".example")
}

func isDocs(p, ext string, segs []string) bool {
	if docExts[ext] && hasSegment(p, "docs") {
		return true
	}
	// A .md/.rst/.mdx/.adoc file at the repository root (README, CHANGELOG,
	// CONTRIBUTING, ...). agent-surface and locale have already been checked.
	if len(segs) == 1 && rootDocExts[ext] {
		return true
	}
	return false
}

// --- content heuristics ---

// hasGeneratedHeader reports whether any of the first few lines carry a
// well-known "do not edit" / generated marker.
func hasGeneratedHeader(content []byte) bool {
	if len(content) == 0 {
		return false
	}
	limit := content
	if len(limit) > maxScan {
		limit = limit[:maxScan]
	}
	sc := bufio.NewScanner(bytes.NewReader(limit))
	sc.Buffer(make([]byte, 0, 4096), maxScan+1)
	for i := 0; i < 5 && sc.Scan(); i++ {
		line := strings.ToLower(sc.Text())
		if strings.Contains(line, "@generated") ||
			strings.Contains(line, "auto-generated") ||
			strings.Contains(line, "<!-- auto generated") {
			return true
		}
		if g := strings.Index(line, "code generated"); g >= 0 {
			if d := strings.Index(line, "do not edit"); d > g {
				return true
			}
		}
	}
	return false
}

// looksMinified reports whether the (non-empty) content reads like a minified
// bundle: a very long single line, or a high average line length.
func looksMinified(content []byte) bool {
	if len(content) == 0 {
		return false
	}
	limit := content
	if len(limit) > maxScan {
		limit = limit[:maxScan]
	}
	sc := bufio.NewScanner(bytes.NewReader(limit))
	sc.Buffer(make([]byte, 0, 4096), maxScan+1)
	var total, lines int
	for sc.Scan() {
		n := len(sc.Bytes())
		if n > 2000 {
			return true
		}
		total += n
		lines++
	}
	if lines == 0 {
		return false
	}
	return total/lines > 300
}

// --- path helpers ---

// hasSegment reports whether seg appears as a whole path segment of p, so
// "vendor" matches "a/vendor/b" but not "avendored/b".
func hasSegment(path, seg string) bool {
	seg = strings.Trim(seg, "/")
	if seg == "" {
		return false
	}
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || path[i] == '/' {
			if path[start:i] == seg {
				return true
			}
			start = i + 1
		}
	}
	return false
}

// containsSeg reports whether any of segs equals one of the given candidates.
func containsSeg(segs []string, candidates ...string) bool {
	for _, s := range segs {
		for _, c := range candidates {
			if s == c {
				return true
			}
		}
	}
	return false
}

// normalize converts a path to forward slashes and strips a leading "./".
func normalize(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "./")
	return p
}

// baseName returns the final path segment of p.
func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// extOf returns the lower-cased extension of base (including the dot), or "".
func extOf(base string) string {
	if i := strings.LastIndex(base, "."); i >= 0 {
		return strings.ToLower(base[i:])
	}
	return ""
}

// isReadmeLang reports whether base is README.<lang>.md for a known lang code.
func isReadmeLang(base string) bool {
	lb := strings.ToLower(base)
	const pre, suf = "readme.", ".md"
	if !strings.HasPrefix(lb, pre) || !strings.HasSuffix(lb, suf) {
		return false
	}
	start, end := len(pre), len(lb)-len(suf)
	if end <= start {
		return false
	}
	return langCodes[lb[start:end]]
}

// isConfigJSBasename reports whether base is a *.config.{js,ts,mjs,cjs} file.
func isConfigJSBasename(base string) bool {
	if !strings.Contains(base, ".config.") {
		return false
	}
	return strings.HasSuffix(base, ".js") ||
		strings.HasSuffix(base, ".ts") ||
		strings.HasSuffix(base, ".mjs") ||
		strings.HasSuffix(base, ".cjs")
}
