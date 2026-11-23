package suppress

import "testing"

func TestTrishulMarker_RequiresReason(t *testing.T) {
	withReason := []byte("doThing() // trishul-ignore[VIBE-007]: accepted, see TICKET-1\n")
	s := ScanFile("a.go", withReason)
	if len(s) != 1 || s[0].RuleID != "VIBE-007" || s[0].Reason == "" {
		t.Fatalf("expected one reasoned suppression: %+v", s)
	}

	noReason := []byte("doThing() // trishul-ignore[VIBE-007]:\n")
	if got := ScanFile("a.go", noReason); len(got) != 0 {
		t.Errorf("reasonless marker must not suppress: %+v", got)
	}
}

func TestTrishulWildcard(t *testing.T) {
	s := ScanFile("a.go", []byte("x // trishul-ignore: blanket reason\n"))
	if len(s) != 1 || !s[0].Wildcard() {
		t.Fatalf("expected wildcard: %+v", s)
	}
}

func TestThirdPartyMarkers(t *testing.T) {
	src := []byte("a // nosec\nb // nosemgrep: rules.xss\nc // gitleaks:allow\nd # nosec G101,G102\n")
	s := ScanFile("f", src)
	// nosec(wildcard) + nosemgrep(rules.xss) + gitleaks + nosec(G101)+nosec(G102) = 5
	if len(s) != 5 {
		t.Fatalf("want 5 markers, got %d: %+v", len(s), s)
	}
}

func TestIndex_SameLineAndLineAbove(t *testing.T) {
	src := []byte("// trishul-ignore[R1]: above\nvulnerable()\nother() // trishul-ignore[R2]: same\n")
	ix := NewIndex(ScanFile("a.go", src))

	// R1 marker on line 1 should cover the finding on line 2.
	if _, ok := ix.Suppressed("a.go", 2, "R1"); !ok {
		t.Error("line-above suppression did not apply")
	}
	// R2 marker on line 3 covers a finding on line 3.
	if _, ok := ix.Suppressed("a.go", 3, "R2"); !ok {
		t.Error("same-line suppression did not apply")
	}
	// Wrong rule is not suppressed.
	if _, ok := ix.Suppressed("a.go", 2, "OTHER"); ok {
		t.Error("rule-specific marker suppressed a different rule")
	}
}

func TestIndex_Unused(t *testing.T) {
	ix := NewIndex(ScanFile("a.go", []byte("x // trishul-ignore[R1]: r\ny // trishul-ignore[R2]: r\n")))
	ix.Suppressed("a.go", 1, "R1") // use R1 only
	un := ix.Unused()
	if len(un) != 1 || un[0].RuleID != "R2" {
		t.Errorf("unused=%+v want just R2", un)
	}
}
