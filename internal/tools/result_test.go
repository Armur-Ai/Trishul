package internal

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestClassifyOutcome(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		findings int
		want     ToolOutcome
	}{
		{"unavailable", fmt.Errorf("x: %w", ErrToolUnavailable), 0, OutcomeUnavailable},
		{"timeout", fmt.Errorf("x: %w", ErrToolTimeout), 0, OutcomeTimedOut},
		{"cancelled", context.Canceled, 0, OutcomeCancelled},
		{"failed", errors.New("boom"), 0, OutcomeFailed},
		{"findings", nil, 3, OutcomeFindings},
		{"clean", nil, 0, OutcomeClean},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyOutcome(c.err, c.findings); got != c.want {
				t.Errorf("ClassifyOutcome(%v, %d) = %q, want %q", c.err, c.findings, got, c.want)
			}
		})
	}
}

func TestOutcomeRan(t *testing.T) {
	if !OutcomeClean.Ran() || !OutcomeFindings.Ran() {
		t.Error("completed outcomes must report Ran() == true")
	}
	for _, o := range []ToolOutcome{OutcomeUnavailable, OutcomeFailed, OutcomeTimedOut, OutcomeCancelled} {
		if o.Ran() {
			t.Errorf("%q must report Ran() == false", o)
		}
	}
}
