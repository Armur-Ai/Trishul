package internal

import (
	"context"
	"errors"
)

// ToolOutcome is the structured outcome of a single scanner execution. It
// exists so that the runner and reports can distinguish, in particular, a
// scanner that was skipped because it is not installed from one that ran and
// found nothing — the two must never be conflated.
type ToolOutcome string

const (
	OutcomeFindings    ToolOutcome = "completed_with_findings"
	OutcomeClean       ToolOutcome = "completed_clean"
	OutcomeUnavailable ToolOutcome = "skipped_unavailable"
	OutcomeFailed      ToolOutcome = "failed"
	OutcomeTimedOut    ToolOutcome = "timed_out"
	OutcomeCancelled   ToolOutcome = "cancelled"
)

// Ran reports whether the tool actually executed to completion (with or without
// findings). A non-Ran outcome means the result is partial.
func (o ToolOutcome) Ran() bool {
	return o == OutcomeFindings || o == OutcomeClean
}

// ClassifyOutcome maps a tool's execution error and finding count to a
// structured outcome. It understands the sentinels returned by the exec
// helpers (ErrToolUnavailable, ErrToolTimeout) and cancellation.
func ClassifyOutcome(err error, findings int) ToolOutcome {
	switch {
	case errors.Is(err, ErrToolUnavailable):
		return OutcomeUnavailable
	case errors.Is(err, ErrToolTimeout):
		return OutcomeTimedOut
	case errors.Is(err, context.Canceled):
		return OutcomeCancelled
	case err != nil:
		return OutcomeFailed
	case findings > 0:
		return OutcomeFindings
	default:
		return OutcomeClean
	}
}
