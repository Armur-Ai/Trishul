package mcpmeta

import "testing"

// expectedTools is the set of MCP tools Trishul registers in
// internal/mcp/server.go. The listing's _meta tool list must stay in sync.
var expectedTools = []string{
	"trishul_scan_path",
	"trishul_scan_code",
	"trishul_audit_mcp_config",
	"trishul_suggest_fix",
	"trishul_scan_diff",
	"trishul_explain_finding",
	"trishul_check_dependency",
	"trishul_get_history",
}

func load(t *testing.T) (*Server, string) {
	t.Helper()
	root, err := FindRepoRoot(".")
	if err != nil {
		t.Fatalf("FindRepoRoot: %v", err)
	}
	s, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return s, root
}

func TestServerJSONValid(t *testing.T) {
	s, _ := load(t)
	if err := s.Validate(); err != nil {
		t.Fatalf("server.json invalid: %v", err)
	}
}

// TestVersionMatchesRelease is the drift guard: the listing version must equal
// the actionVersion constant (minus the leading "v") so directories never point
// at a stale release. Bump both together. See packaging/mcp-registry/README.md.
func TestVersionMatchesRelease(t *testing.T) {
	s, root := load(t)
	want, err := ReleaseVersion(root)
	if err != nil {
		t.Fatalf("ReleaseVersion: %v", err)
	}
	if s.Version != want {
		t.Fatalf("server.json version = %q, but actionVersion (cli/cmd/init_github.go) = %q; keep them in sync", s.Version, want)
	}
}

func TestToolListComplete(t *testing.T) {
	s, _ := load(t)
	got := map[string]bool{}
	for _, tool := range s.Tools() {
		got[tool] = true
	}
	for _, want := range expectedTools {
		if !got[want] {
			t.Errorf("server.json _meta tools missing %q", want)
		}
	}
	if len(s.Tools()) != len(expectedTools) {
		t.Errorf("server.json advertises %d tools, want %d (%v)", len(s.Tools()), len(expectedTools), expectedTools)
	}
}
