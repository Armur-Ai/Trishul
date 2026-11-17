package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end: a client-exposed secret must surface through the engine AND its
// raw value must never appear in the result (redaction holds end-to-end).
func TestScanLocal_FlagsClientSecret_NoLeak(t *testing.T) {
	dir := t.TempDir()
	rawSecret := "AbCdEf0123456789GhIjKl9876543210MnOpQrSt"
	env := "NEXT_PUBLIC_API_KEY=" + rawSecret + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := ScanLocal(dir, "")
	if err != nil {
		t.Fatalf("ScanLocal: %v", err)
	}
	blob, _ := json.Marshal(res.Findings)
	s := string(blob)
	if !strings.Contains(s, "CLIENT-SECRET") {
		t.Errorf("expected a CLIENT-SECRET finding; got: %s", s)
	}
	if strings.Contains(s, rawSecret) {
		t.Fatalf("LEAK: the raw secret appears in the scan result")
	}
}
