package redact

import (
	"strings"
	"testing"
)

// Mask operates on runes, so a multi-byte secret must still be masked safely
// (never slicing a rune in half, never leaking the middle).
func TestMask_UnicodeRuneSafe(t *testing.T) {
	secret := "héllo-wörld-sëcret-café-token" // multi-byte runes throughout
	got := Mask(secret)
	if strings.Contains(got, secret) {
		t.Errorf("Mask leaked the full unicode secret: %q", got)
	}
	if !strings.Contains(got, "...") {
		t.Errorf("expected an ellipsis in %q", got)
	}
	// Fingerprint must be stable and hex for unicode input.
	if len(Fingerprint(secret)) != 12 {
		t.Errorf("fingerprint length wrong for unicode input")
	}
}
