package advisory

import (
	"os"
	"path/filepath"
	"testing"
)

const sample = `[
  {"id":"TRISHUL-MCP-2026-0001","summary":"malicious MCP server","severity":"CRITICAL",
   "affected":[{"ecosystem":"MCP","name":"evil-server","versions":["1.0.0","1.0.1"]}]},
  {"id":"TRISHUL-NPM-2026-0002","summary":"backdoored package","severity":"HIGH",
   "affected":[{"ecosystem":"npm","name":"left-pad-evil"}]}
]`

func TestLoadAndMatch(t *testing.T) {
	f, err := Load([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if f.Len() != 2 {
		t.Fatalf("len=%d", f.Len())
	}
	// exact affected version matches
	if m := f.Match("MCP", "evil-server", "1.0.0"); len(m) != 1 || m[0].ID != "TRISHUL-MCP-2026-0001" {
		t.Errorf("version match failed: %+v", m)
	}
	// non-affected version does not
	if m := f.Match("MCP", "evil-server", "2.0.0"); len(m) != 0 {
		t.Errorf("unaffected version matched: %+v", m)
	}
	// version-agnostic advisory (no versions) matches any version
	if m := f.Match("npm", "left-pad-evil", "9.9.9"); len(m) != 1 {
		t.Errorf("version-agnostic match failed: %+v", m)
	}
	// ecosystem is case-insensitive
	if m := f.Match("npm", "left-pad-evil", ""); len(m) != 1 {
		t.Errorf("empty version should match version-agnostic advisory: %+v", m)
	}
	// unknown package
	if m := f.Match("npm", "safe-pkg", "1.0.0"); len(m) != 0 {
		t.Errorf("unknown pkg matched: %+v", m)
	}
}

func TestLoadDir_MissingIsEmpty(t *testing.T) {
	f, err := LoadDir(filepath.Join(t.TempDir(), "nope"))
	if err != nil || f.Len() != 0 {
		t.Errorf("missing dir should be empty feed, got len=%d err=%v", f.Len(), err)
	}
}

func TestLoadDir_Merges(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.json"), []byte(sample), 0o644)
	os.WriteFile(filepath.Join(dir, "b.json"), []byte(`[{"id":"X","summary":"s","affected":[{"ecosystem":"PyPI","name":"p"}]}]`), 0o644)
	f, err := LoadDir(dir)
	if err != nil || f.Len() != 3 {
		t.Fatalf("merge len=%d err=%v", f.Len(), err)
	}
	if m := f.Match("PyPI", "p", "1.0"); len(m) != 1 {
		t.Errorf("merged advisory not matchable: %+v", m)
	}
}
