package internal

import (
	"encoding/json"
	"strings"
	"testing"

	utils "github.com/Armur-Ai/Trishul/pkg"
)

// canary is a synthetic, obviously-fake secret. The regression contract is that
// this exact plaintext must never survive serialization of a scan result, no
// matter which sink (API JSON, Redis, webhook) consumes it — they all receive
// the map that categorizeTrufflehogResults builds.
const canary = "CANARYsk-ABCDEFGHIJKLMNOP-1234567890-ENDCANARY"

// trufflehogCanaryJSON mimics a trufflehog3 JSON record carrying the canary.
const trufflehogCanaryJSON = `[{"path":"/tmp/app/config.py","line":7,` +
	`"rule":{"message":"Generic API Key","severity":"HIGH"},` +
	`"secret":"` + canary + `"}]`

func TestNoPlaintextSecretEscapesSerialization(t *testing.T) {
	categorized := categorizeTrufflehogResults(trufflehogCanaryJSON, "/tmp/app")
	result := utils.ConvertCategorizedResults(categorized)

	blob, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal scan result: %v", err)
	}
	if strings.Contains(string(blob), canary) {
		t.Fatalf("CANARY LEAK: the raw secret appears in the serialized scan result")
	}

	// A redacted preview and a fingerprint must still be present so the finding
	// remains actionable without exposing the value.
	if !strings.Contains(string(blob), "secret_preview") {
		t.Errorf("expected a secret_preview field in the serialized result")
	}
	if !strings.Contains(string(blob), "fingerprint") {
		t.Errorf("expected a fingerprint field in the serialized result")
	}
	// Defense in depth: even the middle of the secret must not leak.
	if strings.Contains(string(blob), "GHIJKLMNOP") {
		t.Fatalf("CANARY LEAK: an interior fragment of the secret appears in the result")
	}
}
