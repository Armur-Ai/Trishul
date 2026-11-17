package internal

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempSBOM(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sbom.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write temp sbom: %v", err)
	}
	return path
}

func TestParseSBOMDependencies_WithComponents(t *testing.T) {
	content := `{
		"bomFormat": "CycloneDX",
		"components": [
			{"type": "library", "name": "express", "version": "4.17.1", "purl": "pkg:npm/express@4.17.1"},
			{"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21", "license": "MIT"}
		]
	}`
	path := writeTempSBOM(t, content)

	components, err := ParseSBOMDependencies(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(components))
	}
	if components[0].Name != "express" || components[0].Version != "4.17.1" {
		t.Errorf("unexpected first component: %+v", components[0])
	}
	if components[1].License != "MIT" {
		t.Errorf("expected license MIT, got %q", components[1].License)
	}
}

func TestParseSBOMDependencies_NoComponents(t *testing.T) {
	path := writeTempSBOM(t, `{"bomFormat": "CycloneDX", "components": []}`)
	components, err := ParseSBOMDependencies(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(components) != 0 {
		t.Errorf("expected 0 components, got %d", len(components))
	}
}

func TestParseSBOMDependencies_InvalidJSON(t *testing.T) {
	path := writeTempSBOM(t, `{not valid json`)
	_, err := ParseSBOMDependencies(path)
	if err == nil {
		t.Error("expected an error for invalid JSON SBOM, got nil")
	}
}
