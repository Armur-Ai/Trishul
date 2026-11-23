package autofix

import (
	"strings"
	"testing"

	"github.com/Armur-Ai/Trishul/internal/findings"
)

func TestPatch_Apply_Replace(t *testing.T) {
	src := "a\nb\nc\n"
	p := Patch{StartLine: 2, EndLine: 2, Replacement: "B"}
	out, err := p.Apply(src)
	if err != nil || out != "a\nB\nc\n" {
		t.Fatalf("replace: %q err=%v", out, err)
	}
}

func TestPatch_Apply_Insert(t *testing.T) {
	src := "a\nc"
	// insert before line 2 (EndLine = StartLine-1)
	p := Patch{StartLine: 2, EndLine: 1, Replacement: "b"}
	out, err := p.Apply(src)
	if err != nil || out != "a\nb\nc" {
		t.Fatalf("insert: %q err=%v", out, err)
	}
}

func TestPatch_Apply_Delete(t *testing.T) {
	src := "a\nb\nc"
	p := Patch{StartLine: 2, EndLine: 2, Replacement: ""}
	out, err := p.Apply(src)
	if err != nil || out != "a\nc" {
		t.Fatalf("delete: %q err=%v", out, err)
	}
}

func TestPatch_Apply_OutOfRange(t *testing.T) {
	if _, err := (Patch{StartLine: 9, EndLine: 9}).Apply("a\nb"); err == nil {
		t.Error("out-of-range patch should error")
	}
}

func TestRegisterAndFixFor(t *testing.T) {
	// isolate the registry for this test
	old := registry
	registry = map[string]Fixer{}
	defer func() { registry = old }()

	Register("R", func(f findings.Finding, src string) (Patch, bool) {
		return Patch{Path: f.Location.Path, StartLine: f.Location.StartLine, EndLine: f.Location.StartLine, Replacement: "FIXED"}, true
	})
	f := findings.Finding{RuleID: "R", Location: findings.Location{Path: "a.go", StartLine: 1}}
	p, ok := FixFor(f, "bad\nok\n")
	if !ok || p.Replacement != "FIXED" {
		t.Fatalf("FixFor: %+v ok=%v", p, ok)
	}
	// unknown rule -> no fix
	if _, ok := FixFor(findings.Finding{RuleID: "NONE"}, "x"); ok {
		t.Error("unknown rule should have no fix")
	}
}

func TestValidate(t *testing.T) {
	src := "danger\n"
	p := Patch{StartLine: 1, EndLine: 1, Replacement: "safe"}
	// rescan: a finding persists only while "danger" is still present
	rescan := func(patched string) int {
		if strings.Contains(patched, "danger") {
			return 1
		}
		return 0
	}
	if !Validate(p, src, 1, rescan) {
		t.Error("valid fix should pass (findings dropped)")
	}
	// a patch that doesn't reduce findings fails validation
	noop := Patch{StartLine: 1, EndLine: 1, Replacement: "danger"}
	if Validate(noop, src, 1, func(string) int { return 1 }) {
		t.Error("non-reducing patch should fail validation")
	}
}
