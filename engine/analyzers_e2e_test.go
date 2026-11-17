package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end: a repo containing an insecure Supabase migration must surface a
// SUPABASE-RLS finding through the in-process engine (proves the built-in
// analyzer is actually wired into the scan pipeline and runs with no external
// tools installed).
func TestScanLocal_FlagsInsecureSupabaseMigration(t *testing.T) {
	dir := t.TempDir()
	mig := filepath.Join(dir, "supabase", "migrations")
	if err := os.MkdirAll(mig, 0o755); err != nil {
		t.Fatal(err)
	}
	sql := `create table public.secrets (id int primary key, val text);
create policy "open" on public.secrets for select using (true);
`
	if err := os.WriteFile(filepath.Join(mig, "001_init.sql"), []byte(sql), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := ScanLocal(dir, "")
	if err != nil {
		t.Fatalf("ScanLocal: %v", err)
	}
	blob, _ := json.Marshal(res.Findings)
	if !strings.Contains(string(blob), "SUPABASE-RLS") {
		t.Errorf("expected a SUPABASE-RLS finding for an insecure migration; got: %s", string(blob))
	}
}
