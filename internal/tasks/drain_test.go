package tasks

import (
	"fmt"
	"testing"

	utils "github.com/Armur-Ai/Trishul/pkg"
)

func TestCountFindings(t *testing.T) {
	r := map[string]interface{}{
		"security_issues": []interface{}{map[string]interface{}{}, map[string]interface{}{}},
		"secret_detection": []interface{}{map[string]interface{}{}},
		"status":           "ok", // non-list values are ignored
	}
	if got := countFindings(r); got != 3 {
		t.Errorf("countFindings = %d, want 3", got)
	}
	if got := countFindings(map[string]interface{}{}); got != 0 {
		t.Errorf("empty countFindings = %d, want 0", got)
	}
}

func TestDrainResults_RecordsErrorsAndMerges(t *testing.T) {
	ch := make(chan toolResult, 3)
	ch <- toolResult{name: "good", result: map[string]interface{}{
		"security_issues": []interface{}{map[string]interface{}{"message": "x"}},
	}}
	ch <- toolResult{name: "missing", err: fmt.Errorf("tool: %w", fmt.Errorf("not installed"))}
	close(ch)

	cat := utils.InitCategorizedResults()
	errs := drainResults(ch, cat)

	if len(errs) != 1 {
		t.Fatalf("expected exactly 1 scan error, got %d: %v", len(errs), errs)
	}
	if errs[0].Tool != "missing" {
		t.Errorf("expected the error to be from 'missing', got %q", errs[0].Tool)
	}
}
