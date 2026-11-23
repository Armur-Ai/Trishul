package cmd

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestTrishulWorkflow_ValidYAML(t *testing.T) {
	for _, failOn := range []string{"", "high"} {
		wf := trishulWorkflow(failOn)
		var m map[string]any
		if err := yaml.Unmarshal([]byte(wf), &m); err != nil {
			t.Fatalf("workflow (fail-on=%q) is not valid YAML: %v\n%s", failOn, err, wf)
		}
		if _, ok := m["jobs"]; !ok {
			t.Errorf("workflow missing jobs")
		}
		if !strings.Contains(wf, "Armur-Ai/Trishul@"+actionVersion) {
			t.Errorf("workflow missing pinned action ref")
		}
	}
}

func TestTrishulWorkflow_LocalFirstNoApp(t *testing.T) {
	wf := trishulWorkflow("high")
	if strings.Contains(wf, "trishul-app") || strings.Contains(strings.ToLower(wf), "install the trishul github app") {
		t.Error("workflow should not point at the deprecated hosted App")
	}
	// the opt-in badge block is present but commented (no active contents:write)
	if !strings.Contains(wf, "self-hosted status badge") {
		t.Error("badge guidance missing")
	}
}
