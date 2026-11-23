package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Armur-Ai/Trishul/internal/advisory"
	"github.com/Armur-Ai/Trishul/internal/bundle"
)

func signedBundle(t *testing.T) ([]byte, string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	env, err := bundle.Sign(bundle.Bundle{
		SchemaVersion: 1, Version: "2026.11.23", GeneratedAt: "2026-11-23T00:00:00Z",
		Advisories: []advisory.Advisory{
			{ID: "TRISHUL-MCP-2026-0001", Summary: "bad", Affected: []advisory.Package{{Ecosystem: "MCP", Name: "evil"}}},
		},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := env.Marshal()
	return data, base64.StdEncoding.EncodeToString(pub)
}

func TestRunUpdate_VerifiesAndStores(t *testing.T) {
	data, pubB64 := signedBundle(t)
	cache := t.TempDir()
	var b strings.Builder
	n, err := runUpdate(data, pubB64, cache, &b)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("advisory count=%d want 1", n)
	}
	if _, err := os.Stat(filepath.Join(cache, "advisories", "bundle.json")); err != nil {
		t.Errorf("bundle not stored: %v", err)
	}
	if !strings.Contains(b.String(), "verified") {
		t.Errorf("missing verified message: %s", b.String())
	}
}

func TestRunUpdate_FailsClosedOnWrongKey(t *testing.T) {
	data, _ := signedBundle(t)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	cache := t.TempDir()
	var b strings.Builder
	if _, err := runUpdate(data, base64.StdEncoding.EncodeToString(otherPub), cache, &b); err == nil {
		t.Error("wrong key must fail closed")
	}
	// nothing written on failure
	if _, err := os.Stat(filepath.Join(cache, "advisories", "bundle.json")); err == nil {
		t.Error("must not write anything on verification failure")
	}
}
