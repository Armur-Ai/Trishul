package internal

import (
	"encoding/json"
	"strings"
	"testing"
)

// The reference vulnerable app (examples/vibe-coded-app) is Trishul's honesty
// target. This test pins which built-in analyzers now fire on it — in
// particular the classes the README used to list as "not yet reported":
// missing authorization, the exposed Supabase service-role key, and the table
// without row-level security.
func TestReferenceApp_ClosedGaps(t *testing.T) {
	const dir = "../../examples/vibe-coded-app"
	cases := []struct {
		name    string
		fn      func(string) (map[string]interface{}, error)
		wantID  string
		wantCat string
	}{
		{"missing authorization", RunRouteAuth, "VIBE-AUTHZ-001", "vibe_security"},
		{"exposed supabase key", RunClientSecretExposure, "CLIENT-SECRET-003", "secret_detection"},
		{"table without RLS", RunSupabaseRLS, "SUPABASE-RLS-001", "infra_security"},
		{"placeholder/CORS", RunPlaceholderSecurity, "VIBE-PLACEHOLDER", "vibe_security"},
		{"unsafe LLM prompt", RunUnsafeLLMIntegration, "VIBE-LLM-001", "vibe_security"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := c.fn(dir)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			items, _ := res[c.wantCat].([]interface{})
			if len(items) == 0 {
				t.Fatalf("expected %s findings in %s on the reference app", c.name, c.wantCat)
			}
			blob, _ := json.Marshal(items)
			if !strings.Contains(string(blob), c.wantID) {
				t.Errorf("expected %s on the reference app; got: %s", c.wantID, string(blob))
			}
			// The secret must be redacted — a masked preview (first/last chars
			// with the middle elided), never the full token.
			if c.wantCat == "secret_detection" {
				if !strings.Contains(string(blob), "...") {
					t.Errorf("expected a masked secret_preview; got: %s", string(blob))
				}
				for _, it := range items {
					if m, ok := it.(map[string]interface{}); ok {
						if p, _ := m["secret_preview"].(string); len(p) > 24 {
							t.Errorf("secret_preview too long to be masked: %q", p)
						}
					}
				}
			}
		})
	}
}
