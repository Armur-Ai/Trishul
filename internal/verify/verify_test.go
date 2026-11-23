package verify

import (
	"encoding/json"
	"strings"
	"testing"
)

func sample() Claim {
	return NewClaim(Claim{
		Repo: "acme/app", CommitSHA: "abc123", Ref: "refs/heads/main",
		RulesVersion: "2026.11.23", ToolVersion: "v0.2.0", Grade: "A", Passed: true,
		NewFindings: 0, GeneratedAt: "2026-11-23T00:00:00Z",
	})
}

func TestNewClaim_SetsPredicate(t *testing.T) {
	if sample().PredicateType != PredicateType {
		t.Error("predicate type not set")
	}
}

func TestCanonicalAndDigest_Stable(t *testing.T) {
	c := sample()
	d1, err := c.Digest()
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := c.Digest()
	if d1 != d2 || len(d1) != 64 {
		t.Errorf("digest unstable or wrong length: %s / %s", d1, d2)
	}
	// a changed field changes the digest
	c2 := c
	c2.Grade = "F"
	if d3, _ := c2.Digest(); d3 == d1 {
		t.Error("digest should change with the grade")
	}
	// canonical has no code/snippet fields
	b, _ := c.Canonical()
	for _, forbidden := range []string{"snippet", "source", "path", "code"} {
		var m map[string]json.RawMessage
		_ = json.Unmarshal(b, &m)
		if _, ok := m[forbidden]; ok {
			t.Errorf("claim must not contain %q", forbidden)
		}
	}
}

func TestBadgeState(t *testing.T) {
	msg, color := sample().BadgeState()
	if !strings.Contains(msg, "Verified") || color != "brightgreen" {
		t.Errorf("passed claim should be verified: %s/%s", msg, color)
	}
	fail := sample()
	fail.Passed = false
	if m, c := fail.BadgeState(); m != "unverified" || c != "red" {
		t.Errorf("failed claim should be unverified: %s/%s", m, c)
	}
}

func TestVerifyCmd_NoArmur(t *testing.T) {
	cmd := sample().VerifyCmd("trishul-claim.json")
	joined := strings.Join(cmd, " ")
	if !strings.Contains(joined, "gh attestation verify") || !strings.Contains(joined, "--repo acme/app") {
		t.Errorf("verify cmd wrong: %v", cmd)
	}
	if strings.Contains(joined, "armur") {
		t.Error("verification must not involve an Armur service")
	}
}
