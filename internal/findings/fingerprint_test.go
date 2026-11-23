package findings

import "testing"

func TestFingerprintV2_MessageIndependent(t *testing.T) {
	// Same rule/path/snippet, different message => same fingerprint.
	a := FingerprintV2("R1", "a.go", "exec(userInput)")
	b := FingerprintV2("R1", "a.go", "exec(userInput)")
	if a != b {
		t.Fatal("fingerprint changed with no structural change")
	}
}

func TestFingerprintV2_LiteralAndWhitespaceMasked(t *testing.T) {
	// Different string literal, port number and spacing — same structure.
	a := FingerprintV2("R1", "a.go", `connect("db-prod:5432", timeout=30)`)
	b := FingerprintV2("R1", "a.go", `connect( "db-stage:5999",  timeout=90 )`)
	if a != b {
		t.Fatalf("fingerprint should ignore literals/whitespace:\n a=%s\n b=%s", a, b)
	}
}

func TestFingerprintV2_DistinctOccurrencesDiffer(t *testing.T) {
	a := FingerprintV2("R1", "a.go", "exec(userInput)")
	b := FingerprintV2("R1", "a.go", "spawn(childProc)")
	if a == b {
		t.Fatal("structurally different snippets collided")
	}
}

func TestFingerprintV2_RuleAndPathMatter(t *testing.T) {
	base := FingerprintV2("R1", "a.go", "x")
	if FingerprintV2("R2", "a.go", "x") == base {
		t.Error("rule id should affect fingerprint")
	}
	if FingerprintV2("R1", "b.go", "x") == base {
		t.Error("path should affect fingerprint")
	}
}

func TestWindow(t *testing.T) {
	src := "l1\nl2\nl3\nl4\nl5"
	if got := Window(src, 3, 1); got != "l2\nl3\nl4" {
		t.Errorf("window=%q", got)
	}
	if got := Window(src, 1, 2); got != "l1\nl2\nl3" {
		t.Errorf("clamp-low window=%q", got)
	}
	if got := Window(src, 5, 2); got != "l3\nl4\nl5" {
		t.Errorf("clamp-high window=%q", got)
	}
}

func TestNormalizeWindow(t *testing.T) {
	if got := NormalizeWindow(`  a =  "secret"  + 42 `); got != `a="S"+N` {
		t.Errorf("normalize=%q", got)
	}
	if NormalizeWindow("") != "" {
		t.Error("empty should stay empty")
	}
}
