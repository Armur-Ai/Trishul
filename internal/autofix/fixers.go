package autofix

import (
	"regexp"
	"strings"

	"github.com/Armur-Ai/Trishul/internal/findings"
)

// Concrete deterministic fixers (P4.2). Each is registered under its rule id and
// returns a local patch. Fixers are intentionally conservative: if they can't
// derive a safe, complete fix from the finding they return ok=false and no
// suggestion is offered.

// Matches the quoted table name in the RLS finding message, e.g. Table "profiles".
var reSupabaseTable = regexp.MustCompile(`[Tt]able\s+"([A-Za-z0-9_.]+)"`)

func init() {
	Register("SUPABASE-RLS-001", fixSupabaseEnableRLS)
}

// fixSupabaseEnableRLS appends an ENABLE ROW LEVEL SECURITY statement for the
// table named in the finding. The table name is taken from the finding message
// (e.g. `Table "profiles" is created without ...`). Appending is safe and local:
// it doesn't modify the existing CREATE statement.
func fixSupabaseEnableRLS(f findings.Finding, src string) (Patch, bool) {
	m := reSupabaseTable.FindStringSubmatch(f.Message)
	if m == nil {
		return Patch{}, false
	}
	table := m[1]
	lines := strings.Split(src, "\n")
	n := len(lines)
	stmt := "\nALTER TABLE " + table + " ENABLE ROW LEVEL SECURITY;"
	return Patch{
		Path:        f.Location.Path,
		StartLine:   n + 1,
		EndLine:     n,
		Replacement: strings.TrimPrefix(stmt, "\n"),
	}, true
}
