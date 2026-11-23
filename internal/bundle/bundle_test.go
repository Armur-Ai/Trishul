package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/Armur-Ai/Trishul/internal/advisory"
)

func testBundle() Bundle {
	return Bundle{
		SchemaVersion: 1,
		Version:       "2026.11.23",
		GeneratedAt:   "2026-11-23T00:00:00Z",
		RulesSHA256:   "abc123",
		Advisories: []advisory.Advisory{
			{ID: "TRISHUL-MCP-2026-0001", Summary: "bad server", Affected: []advisory.Package{{Ecosystem: "MCP", Name: "evil"}}},
		},
	}
}

func TestSignVerify_RoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	env, err := Sign(testBundle(), priv)
	if err != nil {
		t.Fatal(err)
	}
	data, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Verify(data, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if b.Version != "2026.11.23" || len(b.Advisories) != 1 {
		t.Errorf("round-trip lost data: %+v", b)
	}
}

func TestVerify_WrongKeyFails(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	env, _ := Sign(testBundle(), priv)
	data, _ := env.Marshal()
	if _, err := Verify(data, otherPub); err != ErrBadSignature {
		t.Errorf("wrong key should fail closed, got %v", err)
	}
}

func TestVerify_TamperedBundleFails(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	env, _ := Sign(testBundle(), priv)
	// tamper with the signed bundle bytes
	env.Bundle = append(env.Bundle[:len(env.Bundle)-1], []byte(`,"x":1}`)...)
	data, _ := env.Marshal()
	if _, err := Verify(data, pub); err != ErrBadSignature {
		t.Errorf("tampered bundle should fail closed, got %v", err)
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	got, err := ParsePublicKey(base64.StdEncoding.EncodeToString(pub))
	if err != nil || len(got) != ed25519.PublicKeySize {
		t.Fatalf("b64 parse: %v", err)
	}
	if _, err := ParsePublicKey("not-a-key"); err == nil {
		t.Error("garbage key should error")
	}
}

func TestRulesHash(t *testing.T) {
	if RulesHash([]byte("x")) == RulesHash([]byte("y")) {
		t.Error("different inputs should hash differently")
	}
}
