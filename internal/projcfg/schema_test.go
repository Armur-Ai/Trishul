package projcfg

import (
	"encoding/json"
	"os"
	"testing"
)

// TestSchemaFileIsValidAndCoversConfig guards schemas/trishul-yml.schema.json:
// it must be valid JSON and declare a property for every top-level config key,
// so the editor-completion schema cannot silently drift from the loader.
func TestSchemaFileIsValidAndCoversConfig(t *testing.T) {
	data, err := os.ReadFile("../../schemas/trishul-yml.schema.json")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Type       string                     `json:"type"`
		Properties map[string]json.RawMessage `json:"properties"`
		Additional *bool                      `json:"additionalProperties"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	if schema.Type != "object" {
		t.Errorf("top-level type=%q want object", schema.Type)
	}
	if schema.Additional == nil || *schema.Additional {
		t.Error("schema should set additionalProperties:false to catch typos")
	}
	for _, key := range []string{"profile", "comments", "gate", "rules", "paths", "experimental"} {
		if _, ok := schema.Properties[key]; !ok {
			t.Errorf("schema missing property %q", key)
		}
	}
}
