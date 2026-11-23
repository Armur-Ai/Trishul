package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	utils "github.com/Armur-Ai/Trishul/pkg"
)

// writeMigration writes a SQL file at supabase/migrations/<name> under dir.
func writeMigration(t *testing.T, dir, name, body string) {
	t.Helper()
	mdir := filepath.Join(dir, "supabase", "migrations")
	if err := os.MkdirAll(mdir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mdir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// findingsByCheck groups findings by their check_id.
func findingsByCheck(findings []map[string]interface{}) map[string][]map[string]interface{} {
	out := map[string][]map[string]interface{}{}
	for _, f := range findings {
		id, _ := f["check_id"].(string)
		out[id] = append(out[id], f)
	}
	return out
}

func TestScanSupabase_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	findings, err := scanSupabaseMigrations(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty dir, got %d: %v", len(findings), findings)
	}
}

func TestScanSupabase_UsingTrueAndMissingRLS(t *testing.T) {
	dir := t.TempDir()
	writeMigration(t, dir, "0001_insecure.sql", `
create table public.profiles (
	id uuid primary key,
	email text
);

create policy "public read" on public.profiles
	for select
	using (true);
`)

	findings, err := scanSupabaseMigrations(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	byCheck := findingsByCheck(findings)

	if len(byCheck["SUPABASE-RLS-002"]) == 0 {
		t.Errorf("expected a SUPABASE-RLS-002 (using (true)) finding, got none: %v", findings)
	} else {
		f := byCheck["SUPABASE-RLS-002"][0]
		if f["severity"] != "CRITICAL" {
			t.Errorf("expected CRITICAL severity for using(true), got %v", f["severity"])
		}
		if p, _ := f["path"].(string); filepath.IsAbs(p) {
			t.Errorf("expected relativized path, got absolute %q", p)
		}
	}

	if len(byCheck["SUPABASE-RLS-001"]) == 0 {
		t.Errorf("expected a SUPABASE-RLS-001 (missing RLS) finding, got none: %v", findings)
	}
}

func TestScanSupabase_AnonFunctionAndBucket(t *testing.T) {
	dir := t.TempDir()
	writeMigration(t, dir, "0002_more.sql", `
create table public.secrets (id uuid primary key, value text);
alter table public.secrets enable row level security;

create policy "anon writes" on public.secrets
	for insert
	to anon
	with check (user_id = auth.uid());

create or replace function public.do_admin()
returns void
language plpgsql
security definer
as $$ begin end; $$;

insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
`)

	findings, err := scanSupabaseMigrations(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byCheck := findingsByCheck(findings)

	for _, id := range []string{"SUPABASE-RLS-003", "SUPABASE-RLS-004", "SUPABASE-RLS-005"} {
		if len(byCheck[id]) == 0 {
			t.Errorf("expected a %s finding, got none: %v", id, findings)
		}
	}

	// secrets has RLS enabled, so no missing-RLS finding should be raised.
	for _, f := range byCheck["SUPABASE-RLS-001"] {
		t.Errorf("unexpected missing-RLS finding for RLS-enabled table: %v", f)
	}
}

func TestScanSupabase_SecureMigrationNoFalsePositives(t *testing.T) {
	dir := t.TempDir()
	writeMigration(t, dir, "0003_secure.sql", `
-- A correctly secured migration. A comment mentioning using (true) must be ignored.
create table public.notes (
	id uuid primary key default gen_random_uuid(),
	owner uuid not null references auth.users (id),
	body text
);

alter table public.notes enable row level security;

create policy "owner can read" on public.notes
	for select
	to authenticated
	using (owner = auth.uid());

create policy "owner can write" on public.notes
	for insert
	to authenticated
	with check (owner = auth.uid());

create or replace function public.touch()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$ begin return new; end; $$;

insert into storage.buckets (id, name, public) values ('private', 'private', false);
`)

	findings, err := scanSupabaseMigrations(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for secure migration, got %d: %v", len(findings), findings)
	}
}

func TestRunSupabaseRLS_CategoryShapeAndReadOnly(t *testing.T) {
	dir := t.TempDir()
	body := `create table public.leaky (id int);
create policy "p" on public.leaky for select using (true);`
	writeMigration(t, dir, "0004.sql", body)

	infoBefore, _ := os.Stat(filepath.Join(dir, "supabase", "migrations", "0004.sql"))

	res, err := RunSupabaseRLS(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	raw, ok := res[utils.INFRA_SECURITY]
	if !ok {
		t.Fatalf("expected results under %q category key", utils.INFRA_SECURITY)
	}
	list, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("expected %q to be a slice, got %T", utils.INFRA_SECURITY, raw)
	}
	if len(list) == 0 {
		t.Errorf("expected findings under infra category, got none")
	}

	// Read-only invariant: the target file must be untouched.
	infoAfter, _ := os.Stat(filepath.Join(dir, "supabase", "migrations", "0004.sql"))
	if infoBefore != nil && infoAfter != nil {
		if !infoBefore.ModTime().Equal(infoAfter.ModTime()) || infoBefore.Size() != infoAfter.Size() {
			t.Errorf("scan must not modify target files")
		}
	}

	// Verify the first finding carries the expected finding-map keys.
	first, _ := list[0].(map[string]interface{})
	for _, key := range []string{"path", "line", "severity", "check_id", "message", "cwe"} {
		if _, has := first[key]; !has {
			t.Errorf("finding missing key %q: %v", key, first)
		}
	}
}

// infraFindings runs the public entry point and returns the flattened list of
// findings emitted under the infra-security category.
func infraFindings(t *testing.T, dir string) []interface{} {
	t.Helper()
	res, err := RunSupabaseRLS(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	raw, ok := res[utils.INFRA_SECURITY]
	if !ok {
		return nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("expected %q to be a slice, got %T", utils.INFRA_SECURITY, raw)
	}
	return list
}

func TestRunSupabaseRLS_ContextGate_NonSupabaseRepoEmitsNothing(t *testing.T) {
	// A plain SQL file with a CREATE TABLE in a repo that has none of the
	// Supabase signals must not produce any Supabase findings.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "schema.sql"),
		[]byte("create table public.widgets (id int);"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := infraFindings(t, dir); len(got) != 0 {
		t.Errorf("expected 0 findings for non-Supabase repo, got %d: %v", len(got), got)
	}
}

func TestRunSupabaseRLS_ContextGate_Signals(t *testing.T) {
	// The same insecure migration body; each subtest adds exactly one Supabase
	// signal and must then surface findings.
	body := "create table public.widgets (id int);\ncreate policy \"p\" on public.widgets for select using (true);"

	t.Run("supabase config.toml", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "schema.sql"), []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "supabase"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "supabase", "config.toml"), []byte("project_id = \"x\"\n"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got := infraFindings(t, dir); len(got) == 0 {
			t.Errorf("expected findings when supabase/config.toml present, got none")
		}
	})

	t.Run("package.json @supabase dep", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "schema.sql"), []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		pkg := `{"dependencies": {"@supabase/supabase-js": "^2.0.0"}}`
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got := infraFindings(t, dir); len(got) == 0 {
			t.Errorf("expected findings when @supabase dep present, got none")
		}
	})

	t.Run("sql references auth.uid", func(t *testing.T) {
		dir := t.TempDir()
		sql := "create table public.widgets (id int, owner uuid default auth.uid());\n" +
			"create policy \"p\" on public.widgets for select using (true);"
		if err := os.WriteFile(filepath.Join(dir, "schema.sql"), []byte(sql), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got := infraFindings(t, dir); len(got) == 0 {
			t.Errorf("expected findings when SQL references auth.uid(), got none")
		}
	})
}

func TestCreateTableParsing_Forms(t *testing.T) {
	// Each form should parse to the expected canonical table key and produce a
	// single missing-RLS finding whose message names that table. The historical
	// bug produced a table named "if" for IF NOT EXISTS; it must not recur.
	cases := []struct {
		name     string
		stmt     string
		wantName string // canonical (unquoted, unqualified) name in the message
	}{
		{"if not exists", "create table if not exists widgets (id int);", "widgets"},
		{"if not exists schema-qualified", "create table if not exists public.widgets (id int);", "widgets"},
		{"quoted with space", `create table "My Table" (id int);`, "my table"},
		{"schema qualified public", "create table public.users (id int);", "users"},
		{"public prefix bare match", "create table public.users (id int);", "users"},
		{"unqualified", "create table users (id int);", "users"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeMigration(t, dir, "0001.sql", tc.stmt)
			findings, err := scanSupabaseMigrations(dir)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			byCheck := findingsByCheck(findings)
			rls := byCheck["SUPABASE-RLS-001"]
			if len(rls) != 1 {
				t.Fatalf("expected exactly 1 missing-RLS finding, got %d: %v", len(rls), findings)
			}
			msg, _ := rls[0]["message"].(string)
			want := "\"" + tc.wantName + "\""
			if !strings.Contains(msg, want) {
				t.Errorf("expected message to name table %s, got: %q", want, msg)
			}
			if strings.Contains(msg, "\"if\"") {
				t.Errorf("parser produced bogus table name \"if\": %q", msg)
			}
		})
	}
}

func TestCreateTableParsing_NonPublicSchemaSkipped(t *testing.T) {
	// A table in a non-public schema (e.g. app.users) is not part of the
	// Supabase anon/public data layer, so no missing-RLS finding is expected.
	dir := t.TempDir()
	writeMigration(t, dir, "0001.sql", "create table app.users (id int);\n-- auth.uid()\n")
	findings, err := scanSupabaseMigrations(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if byCheck := findingsByCheck(findings); len(byCheck["SUPABASE-RLS-001"]) != 0 {
		t.Errorf("expected no missing-RLS finding for non-public schema, got: %v", byCheck["SUPABASE-RLS-001"])
	}
}

func TestReplay_EnableInLaterMigrationClearsFinding(t *testing.T) {
	// Migration A creates a table without RLS; migration B enables it. The FINAL
	// state has RLS on, so there must be no missing-RLS finding.
	dir := t.TempDir()
	writeMigration(t, dir, "0001_create.sql", "create table public.foo (id int);")
	writeMigration(t, dir, "0002_enable.sql", "alter table public.foo enable row level security;")

	findings, err := scanSupabaseMigrations(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if byCheck := findingsByCheck(findings); len(byCheck["SUPABASE-RLS-001"]) != 0 {
		t.Errorf("expected no missing-RLS finding after later ENABLE, got: %v", byCheck["SUPABASE-RLS-001"])
	}
}

func TestReplay_DisableInLaterMigrationReintroducesFinding(t *testing.T) {
	// Migration A creates and enables RLS; migration B disables it. The FINAL
	// state lacks RLS, so a finding must be raised, and its evidence must point
	// at migration B (the DISABLE that introduced the problem).
	dir := t.TempDir()
	writeMigration(t, dir, "0001_create.sql",
		"create table public.foo (id int);\nalter table public.foo enable row level security;")
	writeMigration(t, dir, "0002_disable.sql", "alter table public.foo disable row level security;")

	findings, err := scanSupabaseMigrations(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rls := findingsByCheck(findings)["SUPABASE-RLS-001"]
	if len(rls) != 1 {
		t.Fatalf("expected exactly 1 missing-RLS finding after later DISABLE, got %d: %v", len(rls), findings)
	}
	if p, _ := rls[0]["path"].(string); !strings.Contains(p, "0002_disable") {
		t.Errorf("expected evidence to point at the disabling migration (0002_disable), got path %q", p)
	}
}

func TestReplay_DropPolicyClearsInsecurePolicyFinding(t *testing.T) {
	dir := t.TempDir()
	writeMigration(t, dir, "0001_setup.sql",
		"create table public.foo (id int);\n"+
			"alter table public.foo enable row level security;\n"+
			"create policy \"wide open\" on public.foo for select using (true);")

	// Without a drop, the insecure USING (true) policy is flagged.
	before, err := scanSupabaseMigrations(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findingsByCheck(before)["SUPABASE-RLS-002"]) == 0 {
		t.Fatalf("expected a SUPABASE-RLS-002 finding for the live using(true) policy, got none")
	}

	// A later migration drops the policy; it is no longer live, so no finding.
	writeMigration(t, dir, "0002_drop.sql", "drop policy \"wide open\" on public.foo;")
	after, err := scanSupabaseMigrations(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := findingsByCheck(after)["SUPABASE-RLS-002"]; len(got) != 0 {
		t.Errorf("expected no SUPABASE-RLS-002 after DROP POLICY, got: %v", got)
	}
}

func TestReplay_DropTableClearsMissingRLSFinding(t *testing.T) {
	dir := t.TempDir()
	writeMigration(t, dir, "0001_create.sql", "create table public.foo (id int);")
	writeMigration(t, dir, "0002_drop.sql", "drop table public.foo;")

	findings, err := scanSupabaseMigrations(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := findingsByCheck(findings)["SUPABASE-RLS-001"]; len(got) != 0 {
		t.Errorf("expected no missing-RLS finding for a dropped table, got: %v", got)
	}
}

func TestScanSupabase_TopLevelSQLFile(t *testing.T) {
	// SQL files outside supabase/migrations should still be scanned.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "schema.sql"),
		[]byte("create table public.widgets (id int);"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	findings, err := scanSupabaseMigrations(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byCheck := findingsByCheck(findings)
	if len(byCheck["SUPABASE-RLS-001"]) == 0 {
		t.Errorf("expected missing-RLS finding for top-level sql file, got none")
	}
}
