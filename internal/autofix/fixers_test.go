package autofix

import (
	"strings"
	"testing"

	"github.com/Armur-Ai/Trishul/internal/findings"
)

func TestFixSupabaseEnableRLS(t *testing.T) {
	src := "create table profiles (id uuid primary key);\n"
	f := findings.Finding{
		RuleID:   "SUPABASE-RLS-001",
		Message:  `Table "profiles" is created without ENABLE ROW LEVEL SECURITY`,
		Location: findings.Location{Path: "supabase/migrations/0001.sql", StartLine: 1},
	}
	p, ok := FixFor(f, src)
	if !ok {
		t.Fatal("expected a fix")
	}
	patched, err := p.Apply(src)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(patched, "ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;") {
		t.Errorf("patch did not append ENABLE RLS:\n%s", patched)
	}
	// original create statement is preserved
	if !strings.Contains(patched, "create table profiles") {
		t.Errorf("original statement lost:\n%s", patched)
	}
}

func TestFixSupabaseEnableRLS_NoTableNoFix(t *testing.T) {
	f := findings.Finding{RuleID: "SUPABASE-RLS-001", Message: "something without a table name"}
	if _, ok := FixFor(f, "x\n"); ok {
		t.Error("should not fix when no table can be derived")
	}
}

func TestSupabaseFixerRegistered(t *testing.T) {
	if _, ok := FixFor(findings.Finding{RuleID: "SUPABASE-RLS-001", Message: `Table "t" x`, Location: findings.Location{StartLine: 1}}, "a\n"); !ok {
		t.Error("SUPABASE-RLS-001 fixer should be registered")
	}
}
