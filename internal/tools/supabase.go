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

// orderedStmt is a single statement tagged with the file it came from, used to
// replay all migrations in a single global order.
type orderedStmt struct {
	relPath string
	stmt    sqlStmt
}

// tableState is the replayed final state of one table: whether it still exists,
// whether RLS is enabled, and where the current RLS-disabled state was
// introduced (so the finding points at the offending migration).
type tableState struct {
	display    string
	exists     bool
	rls        bool
	offendPath string
	offendLine int
}

// policyState holds the live insecure findings for one policy. A policy is keyed
// by table + policySep + policy-name; DROP POLICY / DROP TABLE remove it so only
// policies live in the final state are reported.
type policyState struct {
	predF map[string]interface{} // RLS-002 (USING/WITH CHECK (true)), or nil
	anonF map[string]interface{} // RLS-003 (anon on a write/ALL op), or nil
}

// policySep separates a table key from a policy name in the policy map key.
const policySep = "\x1f"

// sqlIdent is the identifier sub-pattern shared by the table/policy parsers: a
// double-quoted name (which may contain spaces) or a bare snake_case name. It is
// a string so it can be composed into larger patterns.
const sqlIdent = `"[^"]+"|[a-z0-9_]+`

var (
	// Statement classifiers (anchored to the statement's leading keyword).
	reStmtCreateTable  = regexp.MustCompile(`(?s)^\s*create\s+table\b`)
	reStmtAlterTable   = regexp.MustCompile(`(?s)^\s*alter\s+table\b`)
	reStmtDropTable    = regexp.MustCompile(`(?s)^\s*drop\s+table\b`)
	reStmtCreatePolicy = regexp.MustCompile(`(?s)^\s*create\s+policy\b`)
	reStmtAlterPolicy  = regexp.MustCompile(`(?s)^\s*alter\s+policy\b`)
	reStmtDropPolicy   = regexp.MustCompile(`(?s)^\s*drop\s+policy\b`)

	// reCreateTable captures an optional schema (group 1) and the table name
	// (group 2), supporting IF NOT EXISTS, quoted names and schema qualification.
	reCreateTable     = regexp.MustCompile(`(?s)create\s+table\s+(?:if\s+not\s+exists\s+)?(?:(` + sqlIdent + `)\s*\.\s*)?(` + sqlIdent + `)`)
	reAlterTableTgt   = regexp.MustCompile(`(?s)^\s*alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?(?:(` + sqlIdent + `)\s*\.\s*)?(` + sqlIdent + `)`)
	reDropTablePrefix = regexp.MustCompile(`(?s)^\s*drop\s+table\s+(?:if\s+exists\s+)?`)
	reDropOneTgt      = regexp.MustCompile(`(?s)^\s*(?:(` + sqlIdent + `)\s*\.\s*)?(` + sqlIdent + `)`)
	rePolicyTgt       = regexp.MustCompile(`(?s)policy\s+(?:if\s+exists\s+)?(` + sqlIdent + `)\s+on\s+(?:(` + sqlIdent + `)\s*\.\s*)?(` + sqlIdent + `)`)
	reRenameTgt       = regexp.MustCompile(`(?s)\brename\s+to\s+(` + sqlIdent + `)`)

	// RLS enable/disable/force actions within an ALTER TABLE.
	reEnableRLSAction  = regexp.MustCompile(`(?s)enable\s+row\s+level\s+security`)
	reDisableRLSAction = regexp.MustCompile(`(?s)disable\s+row\s+level\s+security`)
	reForceRLSAction   = regexp.MustCompile(`(?s)\bforce\s+row\s+level\s+security`)
	reNoForceRLSAction = regexp.MustCompile(`(?s)no\s+force\s+row\s+level\s+security`)

	// Policy clause/predicate detectors.
	reUsingTrue       = regexp.MustCompile(`(?s)using\s*\(\s*true\s*\)`)
	reWithCheckTrue   = regexp.MustCompile(`(?s)with\s+check\s*\(\s*true\s*\)`)
	reUsingClause     = regexp.MustCompile(`(?s)\busing\s*\(`)
	reWithCheckClause = regexp.MustCompile(`(?s)\bwith\s+check\s*\(`)
	reToClause        = regexp.MustCompile(`(?s)\bto\b`)
	reToAnon          = regexp.MustCompile(`(?s)\bto\b[^;]*\banon\b`)
	reForWrite        = regexp.MustCompile(`(?s)\bfor\s+(all|insert|update|delete)\b`)
	reForAny          = regexp.MustCompile(`(?s)\bfor\s+(all|insert|update|delete|select)\b`)

	// Stateless (per-statement) detectors.
	reCreateFunc    = regexp.MustCompile(`(?s)create\s+(?:or\s+replace\s+)?function`)
	reSecDefiner    = regexp.MustCompile(`(?s)security\s+definer`)
	reSearchPath    = regexp.MustCompile(`(?s)set\s+search_path`)
	reStorageBucket = regexp.MustCompile(`(?s)insert\s+into\s+storage\.buckets`)
	rePublicCol     = regexp.MustCompile(`(?s)\bpublic\b`)
	reTrueTok       = regexp.MustCompile(`(?s)\btrue\b`)
)

// scanSupabaseMigrations walks directory (read-only) for SQL files, replays
// every statement in filename order, and returns deterministic findings for the
// FINAL state of the schema. It is exported for testing via a temp dir of sample
// migrations.
func scanSupabaseMigrations(directory string) ([]map[string]interface{}, error) {
	type sqlFile struct {
		relPath string
		content string
	}
	var files []sqlFile

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
		files = append(files, sqlFile{relPath: relPath, content: string(content)})
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	// Replay in filename/timestamp order. Supabase migration filenames are
	// timestamp-prefixed, so lexical order is chronological order.
	sort.Slice(files, func(i, j int) bool { return files[i].relPath < files[j].relPath })

	var ordered []orderedStmt
	for _, f := range files {
		for _, s := range splitSQLStatements(stripSQLComments(f.content)) {
			ordered = append(ordered, orderedStmt{relPath: f.relPath, stmt: s})
		}
	}

	return replayMigrations(ordered), nil
}

// replayMigrations applies every statement in order, computing the final state
// of each table and policy, then emits findings from that final state.
func replayMigrations(stmts []orderedStmt) []map[string]interface{} {
	var findings []map[string]interface{}
	tables := map[string]*tableState{}
	policies := map[string]*policyState{}

	for _, o := range stmts {
		relPath := o.relPath
		s := o.stmt
		lower := strings.ToLower(s.text)

		switch {
		case reStmtCreateTable.MatchString(lower):
			applyCreateTable(lower, s, relPath, tables)
		case reStmtAlterTable.MatchString(lower):
			applyAlterTable(lower, s, relPath, tables, policies)
		case reStmtDropTable.MatchString(lower):
			applyDropTable(lower, tables, policies)
		case reStmtCreatePolicy.MatchString(lower):
			applyCreatePolicy(lower, s, relPath, policies)
		case reStmtAlterPolicy.MatchString(lower):
			applyAlterPolicy(lower, s, relPath, policies)
		case reStmtDropPolicy.MatchString(lower):
			applyDropPolicy(lower, policies)
		default:
			// Non-stateful, per-statement checks (functions, storage buckets).
			findings = append(findings, statelessFindings(lower, s, relPath)...)
		}
	}

	// SUPABASE-RLS-001: a public table whose FINAL state still lacks RLS. The
	// evidence points at the statement that introduced the gap (the CREATE TABLE,
	// or a later DISABLE ROW LEVEL SECURITY).
	for _, key := range sortedKeys(tables) {
		st := tables[key]
		if st.exists && !st.rls {
			findings = append(findings, supabaseFinding(
				st.offendPath, st.offendLine, "HIGH", "SUPABASE-RLS-001",
				"Table \""+st.display+"\" is created without `ENABLE ROW LEVEL SECURITY`; the data layer is open to any client using the anon/public API key.",
				[]string{"CWE-284"},
			))
		}
	}

	// Insecure policies that are still live in the FINAL state (a later DROP
	// POLICY clears an earlier finding).
	for _, key := range sortedKeys(policies) {
		ps := policies[key]
		if ps.predF != nil {
			findings = append(findings, ps.predF)
		}
		if ps.anonF != nil {
			findings = append(findings, ps.anonF)
		}
	}

	sortFindings(findings)
	return findings
}

// applyCreateTable records a freshly created public table with RLS off.
func applyCreateTable(lower string, s sqlStmt, relPath string, tables map[string]*tableState) {
	m := reCreateTable.FindStringSubmatchIndex(lower)
	if m == nil {
		return
	}
	schema := captureAt(lower, m, 2)
	name := captureAt(lower, m, 4)
	if name == "" || !isPublicSchema(schema) {
		// Only public-schema tables are RLS-relevant; auth/storage/etc. are
		// managed by Supabase.
		return
	}
	key, display := canonicalTable(schema, name)
	if st, ok := tables[key]; ok && st.exists {
		// CREATE TABLE IF NOT EXISTS on a live table is a no-op in Postgres;
		// keep the already-computed state.
		return
	}
	tables[key] = &tableState{
		display:    display,
		exists:     true,
		rls:        false,
		offendPath: relPath,
		offendLine: s.line,
	}
}

// applyAlterTable toggles RLS state (ENABLE/DISABLE/FORCE) or renames a table.
func applyAlterTable(lower string, s sqlStmt, relPath string, tables map[string]*tableState, policies map[string]*policyState) {
	m := reAlterTableTgt.FindStringSubmatchIndex(lower)
	if m == nil {
		return
	}
	if !isPublicSchema(captureAt(lower, m, 2)) {
		return
	}
	key, _ := canonicalTable("", captureAt(lower, m, 4))
	st := tables[key]
	if st == nil {
		return // table created out of scope; nothing to track
	}

	if rm := reRenameTgt.FindStringSubmatch(lower); rm != nil {
		newKey, newDisplay := canonicalTable("", rm[1])
		renameTable(tables, policies, key, newKey, newDisplay)
		return
	}

	switch {
	case reDisableRLSAction.MatchString(lower):
		st.rls = false
		st.offendPath = relPath
		st.offendLine = s.line
	case reEnableRLSAction.MatchString(lower):
		st.rls = true
	case reForceRLSAction.MatchString(lower) && !reNoForceRLSAction.MatchString(lower):
		st.rls = true
	}
}

// renameTable moves a table's state (and its policies) to a new key.
func renameTable(tables map[string]*tableState, policies map[string]*policyState, oldKey, newKey, newDisplay string) {
	st := tables[oldKey]
	if st == nil {
		return
	}
	st.display = newDisplay
	delete(tables, oldKey)
	tables[newKey] = st

	oldPrefix := oldKey + policySep
	newPrefix := newKey + policySep
	for pk, pv := range policies {
		if strings.HasPrefix(pk, oldPrefix) {
			delete(policies, pk)
			policies[newPrefix+strings.TrimPrefix(pk, oldPrefix)] = pv
		}
	}
}

// applyDropTable marks dropped tables as gone and removes their policies.
func applyDropTable(lower string, tables map[string]*tableState, policies map[string]*policyState) {
	for _, key := range dropTableKeys(lower) {
		if st := tables[key]; st != nil {
			st.exists = false
		}
		prefix := key + policySep
		for pk := range policies {
			if strings.HasPrefix(pk, prefix) {
				delete(policies, pk)
			}
		}
	}
}

// dropTableKeys parses the (possibly comma-separated) target list of a DROP
// TABLE statement into canonical public-table keys.
func dropTableKeys(lower string) []string {
	loc := reDropTablePrefix.FindStringIndex(lower)
	if loc == nil {
		return nil
	}
	var keys []string
	for _, part := range strings.Split(lower[loc[1]:], ",") {
		m := reDropOneTgt.FindStringSubmatchIndex(part)
		if m == nil {
			continue
		}
		schema := captureAt(part, m, 2)
		name := captureAt(part, m, 4)
		if name == "" || !isPublicSchema(schema) {
			continue
		}
		key, _ := canonicalTable(schema, name)
		keys = append(keys, key)
	}
	return keys
}

// applyCreatePolicy (re)creates a policy, capturing any insecure findings.
func applyCreatePolicy(lower string, s sqlStmt, relPath string, policies map[string]*policyState) {
	key := policyKeyOf(lower)
	if key == "" {
		return
	}
	policies[key] = &policyState{
		predF: predicateFinding(lower, s, relPath),
		anonF: anonFinding(lower, s, relPath),
	}
}

// applyAlterPolicy renames a policy or updates the clauses it re-specifies.
func applyAlterPolicy(lower string, s sqlStmt, relPath string, policies map[string]*policyState) {
	key := policyKeyOf(lower)
	if key == "" {
		return
	}
	if rm := reRenameTgt.FindStringSubmatch(lower); rm != nil {
		ps := policies[key]
		if ps == nil {
			ps = &policyState{}
		}
		delete(policies, key)
		tkey := strings.SplitN(key, policySep, 2)[0]
		policies[tkey+policySep+strings.ToLower(unquote(rm[1]))] = ps
		return
	}
	ps := policies[key]
	if ps == nil {
		ps = &policyState{}
		policies[key] = ps
	}
	// ALTER POLICY re-specifies whole clauses; re-evaluate only those present so
	// that a safe ALTER clears a prior finding and an insecure one adds it.
	if reUsingClause.MatchString(lower) || reWithCheckClause.MatchString(lower) {
		ps.predF = predicateFinding(lower, s, relPath)
	}
	if reToClause.MatchString(lower) {
		ps.anonF = anonFinding(lower, s, relPath)
	}
}

// applyDropPolicy removes a policy from the live set.
func applyDropPolicy(lower string, policies map[string]*policyState) {
	if key := policyKeyOf(lower); key != "" {
		delete(policies, key)
	}
}

// policyKeyOf parses `policy <name> on [schema.]<table>` into a map key.
func policyKeyOf(lower string) string {
	m := rePolicyTgt.FindStringSubmatchIndex(lower)
	if m == nil {
		return ""
	}
	pname := strings.ToLower(unquote(captureAt(lower, m, 2)))
	tname := captureAt(lower, m, 6)
	if pname == "" || tname == "" {
		return ""
	}
	tkey, _ := canonicalTable(captureAt(lower, m, 4), tname)
	return tkey + policySep + pname
}

// predicateFinding returns a SUPABASE-RLS-002 finding if the policy's predicate
// is the effectively-public `(true)`, else nil.
func predicateFinding(lower string, s sqlStmt, relPath string) map[string]interface{} {
	if idx := reUsingTrue.FindStringIndex(lower); idx != nil {
		return supabaseFinding(relPath, lineOfOffset(s, idx[0]), "CRITICAL", "SUPABASE-RLS-002",
			"RLS policy uses `USING (true)`, which matches every row for every caller; the table is effectively public.",
			[]string{"CWE-862"})
	}
	if idx := reWithCheckTrue.FindStringIndex(lower); idx != nil {
		return supabaseFinding(relPath, lineOfOffset(s, idx[0]), "CRITICAL", "SUPABASE-RLS-002",
			"RLS policy uses `WITH CHECK (true)`, allowing any caller to write arbitrary rows.",
			[]string{"CWE-862"})
	}
	return nil
}

// anonFinding returns a SUPABASE-RLS-003 finding if the policy grants a write/ALL
// operation to the anon role, else nil. A policy with no FOR clause defaults to
// ALL, which is also sensitive.
func anonFinding(lower string, s sqlStmt, relPath string) map[string]interface{} {
	if reToAnon.MatchString(lower) {
		if reForWrite.MatchString(lower) || !reForAny.MatchString(lower) {
			return supabaseFinding(relPath, s.line, "HIGH", "SUPABASE-RLS-003",
				"RLS policy grants a write/ALL operation to the `anon` role, exposing the data layer to unauthenticated callers.",
				[]string{"CWE-862"})
		}
	}
	return nil
}

// statelessFindings runs the per-statement (non-replayed) detectors.
func statelessFindings(lower string, s sqlStmt, relPath string) []map[string]interface{} {
	var out []map[string]interface{}

	// SUPABASE-RLS-004: SECURITY DEFINER function without a pinned search_path.
	if reCreateFunc.MatchString(lower) && reSecDefiner.MatchString(lower) && !reSearchPath.MatchString(lower) {
		out = append(out, supabaseFinding(relPath, s.line, "HIGH", "SUPABASE-RLS-004",
			"SECURITY DEFINER function does not pin `SET search_path`; a mutable search_path can let a caller hijack resolution and run code as the definer.",
			[]string{"CWE-284"}))
	}

	// SUPABASE-RLS-005: public storage bucket.
	if reStorageBucket.MatchString(lower) && rePublicCol.MatchString(lower) && reTrueTok.MatchString(lower) {
		out = append(out, supabaseFinding(relPath, s.line, "HIGH", "SUPABASE-RLS-005",
			"Storage bucket is created with `public = true`; its objects are readable by anyone without authorization.",
			[]string{"CWE-284"}))
	}
	return out
}

// sortedKeys returns the keys of m in ascending order for deterministic output.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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

// isPublicSchema reports whether a parsed schema qualifier refers to the public
// schema. The unqualified form (empty) defaults to public in Postgres.
func isPublicSchema(schema string) bool {
	s := strings.ToLower(unquote(strings.TrimSpace(schema)))
	return s == "" || s == "public"
}

// canonicalTable reduces a (schema, name) identifier pair to a key used to
// correlate statements across migrations, plus a human-readable display name.
// Quotes are stripped and the public schema (and the unqualified form) collapse
// to the bare table name, so `public.users`, `"users"` and `users` are one
// table; a non-public schema is kept in the key to avoid cross-schema
// collisions.
func canonicalTable(schema, name string) (key, display string) {
	s := strings.ToLower(unquote(strings.TrimSpace(schema)))
	n := strings.ToLower(unquote(strings.TrimSpace(name)))
	if s == "" || s == "public" {
		return n, n
	}
	return s + "." + n, n
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
