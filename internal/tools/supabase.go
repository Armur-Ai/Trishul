package internal

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Armur-Ai/Trishul/internal/logger"
	utils "github.com/Armur-Ai/Trishul/pkg"
)

// RunSupabaseRLS statically scans SQL migration files for insecure Supabase
// Row-Level-Security (RLS) configuration — the "open data layer" vulnerability
// class common in AI-generated apps. It is a read-only defensive detector: it
// only FLAGS insecure configuration, it never writes, deletes, or exploits the
// target. Findings are emitted under the IaC/infra category, matching the other
// IaC adapters (e.g. checkov).
func RunSupabaseRLS(directory string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "supabase-rls").Str("dir", directory).Msg("running")

	categorized := utils.InitAdvancedCategorizedResults()

	// Context gate: only run the Supabase checks when the repo is actually a
	// Supabase project. Scanning arbitrary SQL in a non-Supabase codebase is a
	// precision problem — plenty of projects have `CREATE TABLE` statements with
	// no intention of ever touching the Supabase anon/public data layer. If none
	// of the Supabase signals are present we emit nothing.
	if !isSupabaseProject(directory) {
		logger.Debug().Str("tool", "supabase-rls").Str("dir", directory).Msg("not a supabase project; skipping")
		return utils.ConvertCategorizedResults(categorized), nil
	}

	findings, err := scanSupabaseMigrations(directory)
	if err != nil {
		logger.Error().Str("tool", "supabase-rls").Err(err).Msg("failed to scan migrations")
		return utils.ConvertCategorizedResults(categorized), nil
	}

	for _, f := range findings {
		categorized[utils.INFRA_SECURITY] = append(categorized[utils.INFRA_SECURITY], f)
	}

	return utils.ConvertCategorizedResults(categorized), nil
}

// errSupabaseSignal is a sentinel used to short-circuit the context-gate walk
// as soon as any Supabase signal is found.
var errSupabaseSignal = errors.New("supabase signal")

// reSupabaseSQLToken matches SQL constructs that only appear in a Supabase
// (PostgREST/GoTrue/Storage) project: the auth helper functions, the storage
// object table, or the anon/authenticated roles.
var reSupabaseSQLToken = regexp.MustCompile(`(?i)auth\.uid\s*\(\s*\)|auth\.jwt\s*\(\s*\)|storage\.objects|\banon\b|\bauthenticated\b`)

// reSupabaseDep matches a `@supabase/*` dependency entry in a package.json.
var reSupabaseDep = regexp.MustCompile(`"@supabase/[^"]+"`)

// isSupabaseProject reports whether directory looks like a Supabase project.
// Any one of the following signals qualifies it:
//   - a `supabase/` directory exists;
//   - `supabase/config.toml` exists;
//   - a `@supabase/*` dependency appears in a package.json;
//   - SQL in scope references auth.uid()/auth.jwt()/storage.objects or the
//     anon/authenticated roles.
//
// It is read-only and skips vendored trees (node_modules, .git, vendor) so that
// a dependency's own files do not mask the project's real intent.
func isSupabaseProject(directory string) bool {
	// Fast path: the canonical `supabase/config.toml` at the repo root.
	if _, err := os.Stat(filepath.Join(directory, "supabase", "config.toml")); err == nil {
		return true
	}

	walkErr := filepath.WalkDir(directory, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "vendor":
				return filepath.SkipDir
			case "supabase":
				return errSupabaseSignal
			}
			return nil
		}

		name := d.Name()
		switch {
		case name == "config.toml" && filepath.Base(filepath.Dir(path)) == "supabase":
			return errSupabaseSignal
		case name == "package.json":
			if content, readErr := os.ReadFile(path); readErr == nil && reSupabaseDep.Match(content) {
				return errSupabaseSignal
			}
		case strings.EqualFold(filepath.Ext(name), ".sql"):
			if content, readErr := os.ReadFile(path); readErr == nil && reSupabaseSQLToken.Match(content) {
				return errSupabaseSignal
			}
		}
		return nil
	})

	return errors.Is(walkErr, errSupabaseSignal)
}

// sqlStmt is a single SQL statement with the 1-based line on which it starts.
type sqlStmt struct {
	line int
	text string // comment-stripped, newlines preserved for accurate line maths
}

// createdTable records a CREATE TABLE occurrence for the missing-RLS pass.
type createdTable struct {
	name    string
	relPath string
	line    int
}

var (
	reCreateTable   = regexp.MustCompile(`(?s)create\s+table\s+(?:if\s+not\s+exists\s+)?(?:("?[a-z0-9_]+"?)\.)?("?[a-z0-9_]+"?)`)
	reEnableRLS     = regexp.MustCompile(`(?s)alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?(?:"?[a-z0-9_]+"?\.)?("?[a-z0-9_]+"?)\s+enable\s+row\s+level\s+security`)
	reCreatePolicy  = regexp.MustCompile(`(?s)create\s+policy`)
	reUsingTrue     = regexp.MustCompile(`(?s)using\s*\(\s*true\s*\)`)
	reWithCheckTrue = regexp.MustCompile(`(?s)with\s+check\s*\(\s*true\s*\)`)
	reToAnon        = regexp.MustCompile(`(?s)\bto\b[^;]*\banon\b`)
	reForWrite      = regexp.MustCompile(`(?s)\bfor\s+(all|insert|update|delete)\b`)
	reForAny        = regexp.MustCompile(`(?s)\bfor\s+(all|insert|update|delete|select)\b`)
	reCreateFunc    = regexp.MustCompile(`(?s)create\s+(?:or\s+replace\s+)?function`)
	reSecDefiner    = regexp.MustCompile(`(?s)security\s+definer`)
	reSearchPath    = regexp.MustCompile(`(?s)set\s+search_path`)
	reStorageBucket = regexp.MustCompile(`(?s)insert\s+into\s+storage\.buckets`)
	rePublicCol     = regexp.MustCompile(`(?s)\bpublic\b`)
	reTrueTok       = regexp.MustCompile(`(?s)\btrue\b`)
)

// scanSupabaseMigrations walks directory (read-only) for SQL files and returns
// deterministic findings for insecure RLS configuration. It is exported for
// testing via a temp dir of sample migrations.
func scanSupabaseMigrations(directory string) ([]map[string]interface{}, error) {
	var findings []map[string]interface{}

	// Aggregated across all files so that RLS enabled in a later migration (or a
	// different file) does not produce a false "missing RLS" finding.
	var created []createdTable
	enabled := map[string]bool{}

	walkErr := filepath.WalkDir(directory, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries rather than aborting the whole scan
		}
		if d.IsDir() {
			return nil
		}
		if !strings.EqualFold(filepath.Ext(d.Name()), ".sql") {
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			logger.Debug().Str("tool", "supabase-rls").Str("file", path).Err(readErr).Msg("skip unreadable file")
			return nil
		}

		relPath := path
		if rel, relErr := filepath.Rel(directory, path); relErr == nil {
			relPath = rel
		}

		stmts := splitSQLStatements(stripSQLComments(string(content)))
		fileFindings, fileCreated, fileEnabled := scanStatements(stmts, relPath)

		findings = append(findings, fileFindings...)
		created = append(created, fileCreated...)
		for k := range fileEnabled {
			enabled[k] = true
		}
		return nil
	})
	if walkErr != nil {
		return findings, walkErr
	}

	// Missing-RLS pass (SUPABASE-RLS-001): a created public table with no later
	// ENABLE ROW LEVEL SECURITY anywhere in the scanned migrations.
	for _, t := range created {
		if enabled[t.name] {
			continue
		}
		findings = append(findings, supabaseFinding(
			t.relPath, t.line, "HIGH", "SUPABASE-RLS-001",
			"Table \""+t.name+"\" is created without `ENABLE ROW LEVEL SECURITY`; the data layer is open to any client using the anon/public API key.",
			[]string{"CWE-284"},
		))
	}

	sortFindings(findings)
	return findings, nil
}

// scanStatements inspects one file's statements and returns its findings plus
// the tables it created and the tables on which it enabled RLS.
func scanStatements(stmts []sqlStmt, relPath string) ([]map[string]interface{}, []createdTable, map[string]bool) {
	var findings []map[string]interface{}
	var created []createdTable
	enabled := map[string]bool{}

	for _, s := range stmts {
		lower := strings.ToLower(s.text)

		// CREATE TABLE — record for missing-RLS correlation.
		if m := reCreateTable.FindStringSubmatchIndex(lower); m != nil {
			schema := captureAt(lower, m, 2)
			name := unquote(captureAt(lower, m, 4))
			schema = unquote(schema)
			// Only public-schema tables are RLS-relevant; auth/storage/etc. are
			// managed by Supabase. Unqualified defaults to public.
			if name != "" && (schema == "" || schema == "public") {
				created = append(created, createdTable{name: name, relPath: relPath, line: s.line})
			}
		}

		// ALTER TABLE ... ENABLE ROW LEVEL SECURITY.
		if m := reEnableRLS.FindStringSubmatch(lower); m != nil {
			enabled[unquote(m[1])] = true
		}

		// Policy-level checks.
		if reCreatePolicy.MatchString(lower) {
			// SUPABASE-RLS-002: effectively public predicate.
			if idx := reUsingTrue.FindStringIndex(lower); idx != nil {
				findings = append(findings, supabaseFinding(
					relPath, lineOfOffset(s, idx[0]), "CRITICAL", "SUPABASE-RLS-002",
					"RLS policy uses `USING (true)`, which matches every row for every caller; the table is effectively public.",
					[]string{"CWE-862"},
				))
			} else if idx := reWithCheckTrue.FindStringIndex(lower); idx != nil {
				findings = append(findings, supabaseFinding(
					relPath, lineOfOffset(s, idx[0]), "CRITICAL", "SUPABASE-RLS-002",
					"RLS policy uses `WITH CHECK (true)`, allowing any caller to write arbitrary rows.",
					[]string{"CWE-862"},
				))
			}

			// SUPABASE-RLS-003: anon role on a sensitive operation. A policy with
			// no FOR clause defaults to ALL, which is also sensitive.
			if reToAnon.MatchString(lower) {
				sensitive := reForWrite.MatchString(lower) || !reForAny.MatchString(lower)
				if sensitive {
					findings = append(findings, supabaseFinding(
						relPath, s.line, "HIGH", "SUPABASE-RLS-003",
						"RLS policy grants a write/ALL operation to the `anon` role, exposing the data layer to unauthenticated callers.",
						[]string{"CWE-862"},
					))
				}
			}
		}

		// SUPABASE-RLS-004: SECURITY DEFINER function without a pinned search_path.
		if reCreateFunc.MatchString(lower) && reSecDefiner.MatchString(lower) && !reSearchPath.MatchString(lower) {
			findings = append(findings, supabaseFinding(
				relPath, s.line, "HIGH", "SUPABASE-RLS-004",
				"SECURITY DEFINER function does not pin `SET search_path`; a mutable search_path can let a caller hijack resolution and run code as the definer.",
				[]string{"CWE-284"},
			))
		}

		// SUPABASE-RLS-005: public storage bucket.
		if reStorageBucket.MatchString(lower) && rePublicCol.MatchString(lower) && reTrueTok.MatchString(lower) {
			findings = append(findings, supabaseFinding(
				relPath, s.line, "HIGH", "SUPABASE-RLS-005",
				"Storage bucket is created with `public = true`; its objects are readable by anyone without authorization.",
				[]string{"CWE-284"},
			))
		}
	}

	return findings, created, enabled
}

func supabaseFinding(relPath string, line int, severity, checkID, message string, cwes []string) map[string]interface{} {
	return map[string]interface{}{
		"path":       relPath,
		"line":       line,
		"severity":   severity,
		"check_id":   checkID,
		"message":    message,
		"cwe":        cwes,
		"confidence": "HIGH",
	}
}

// sortFindings makes output deterministic regardless of walk/map ordering.
func sortFindings(findings []map[string]interface{}) {
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

// captureAt returns the substring for submatch group n (0-based pair index) of a
// FindStringSubmatchIndex result, or "" if that group did not participate.
func captureAt(s string, idx []int, n int) string {
	if n+1 >= len(idx) {
		return ""
	}
	start, end := idx[n], idx[n+1]
	if start < 0 || end < 0 {
		return ""
	}
	return s[start:end]
}

func unquote(s string) string {
	return strings.Trim(s, `"`)
}

// lineOfOffset maps a byte offset within a statement's text to an absolute
// 1-based line number.
func lineOfOffset(s sqlStmt, offset int) int {
	if offset < 0 || offset > len(s.text) {
		return s.line
	}
	return s.line + strings.Count(s.text[:offset], "\n")
}

// stripSQLComments removes `-- line` and `/* block */` comments while preserving
// newlines so that line numbers stay accurate. It is intentionally simple (it
// does not track string literals), which only ever suppresses findings — never
// invents them — keeping the detector conservative.
func stripSQLComments(content string) string {
	var sb strings.Builder
	n := len(content)
	for i := 0; i < n; {
		if i+1 < n && content[i] == '-' && content[i+1] == '-' {
			for i < n && content[i] != '\n' {
				i++
			}
			continue
		}
		if i+1 < n && content[i] == '/' && content[i+1] == '*' {
			i += 2
			for i+1 < n && !(content[i] == '*' && content[i+1] == '/') {
				if content[i] == '\n' {
					sb.WriteByte('\n')
				}
				i++
			}
			i += 2
			continue
		}
		sb.WriteByte(content[i])
		i++
	}
	return sb.String()
}

// splitSQLStatements splits text on `;`, recording the 1-based line on which each
// statement's first non-whitespace character appears.
func splitSQLStatements(content string) []sqlStmt {
	var stmts []sqlStmt
	var sb strings.Builder
	line := 1
	startLine := 0
	for i := 0; i < len(content); i++ {
		c := content[i]
		if startLine == 0 && c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			startLine = line
		}
		if c == ';' {
			if strings.TrimSpace(sb.String()) != "" {
				stmts = append(stmts, sqlStmt{line: startLine, text: sb.String()})
			}
			sb.Reset()
			startLine = 0
		} else {
			sb.WriteByte(c)
		}
		if c == '\n' {
			line++
		}
	}
	if strings.TrimSpace(sb.String()) != "" {
		stmts = append(stmts, sqlStmt{line: startLine, text: sb.String()})
	}
	return stmts
}
