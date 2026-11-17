package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end: a placeholder/insecure-default issue must surface through the
// engine under the vibe_security category (validates the vibe analyzer wiring).
func TestScanLocal_SurfacesVibeSecurity(t *testing.T) {
	dir := t.TempDir()
	js := "const JWT_SECRET = \"changeme\";\nexport default JWT_SECRET;\n"
	if err := os.WriteFile(filepath.Join(dir, "config.js"), []byte(js), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := ScanLocal(dir, "")
	if err != nil {
		t.Fatalf("ScanLocal: %v", err)
	}
	blob, _ := json.Marshal(res.Findings)
	if !strings.Contains(string(blob), "VIBE-PLACEHOLDER") {
		t.Errorf("expected a VIBE-PLACEHOLDER finding in vibe_security; got: %s", string(blob))
	}
	// The weak secret value must be redacted, never emitted raw.
	if strings.Contains(string(blob), "\"changeme\"") {
		t.Errorf("raw placeholder secret leaked into the result")
	}
}
