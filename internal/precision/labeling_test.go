package precision

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	line := `token = "AKIAIOSFODNN7EXAMPLEKEY123456"`
	out := Redact(line)
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLEKEY123456") {
		t.Errorf("secret not redacted: %s", out)
	}
	if !strings.Contains(out, "…") {
		t.Errorf("expected redaction marker: %s", out)
	}
	// short tokens untouched
	if Redact("port = 5432") != "port = 5432" {
		t.Errorf("short token redacted: %q", Redact("port = 5432"))
	}
}

func TestContext_MarksTargetAndRedacts(t *testing.T) {
	src := "line1\napiKey = \"SECRETVALUE0123456789ABCDEF\"\nline3"
	ctx := Context(src, 2, 1)
	if !strings.Contains(ctx, "> 2:") {
		t.Errorf("target line not marked:\n%s", ctx)
	}
	if strings.Contains(ctx, "SECRETVALUE0123456789ABCDEF") {
		t.Errorf("secret leaked into context:\n%s", ctx)
	}
	if !strings.Contains(ctx, "1: line1") || !strings.Contains(ctx, "3: line3") {
		t.Errorf("context window wrong:\n%s", ctx)
	}
}

func TestAppendLabel(t *testing.T) {
	var b strings.Builder
	l := Label{RuleID: "R", Verdict: FP, FingerprintV2: "fp1", Reason: "safe"}
	if err := AppendLabel(&b, l); err != nil {
		t.Fatal(err)
	}
	ls, err := LoadLabels(strings.NewReader(b.String()))
	if err != nil || len(ls) != 1 || ls[0].RuleID != "R" {
		t.Fatalf("round-trip failed: %v %+v", err, ls)
	}
}

func TestValidVerdict(t *testing.T) {
	for _, v := range []string{"tp", "tp_benign", "fp", "unclear"} {
		if !ValidVerdict(v) {
			t.Errorf("%q should be valid", v)
		}
	}
	if ValidVerdict("maybe") {
		t.Error("bogus verdict accepted")
	}
}
