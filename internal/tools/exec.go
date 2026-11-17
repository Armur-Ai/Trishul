package internal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// ErrToolUnavailable is returned when a scanner's executable is not on PATH.
// Callers must treat this as "skipped", never as a clean (zero-finding) result.
var ErrToolUnavailable = errors.New("tool not installed")

// ErrToolTimeout is returned when a scanner exceeds its execution budget and is
// killed. Unlike the previous goroutine+select approach, the OS process is
// actually terminated.
var ErrToolTimeout = errors.New("tool timed out")

// toolTimeout returns the per-tool execution budget, from TOOL_TIMEOUT_SECONDS
// (default 300s).
func toolTimeout() time.Duration {
	if v := os.Getenv("TOOL_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 300 * time.Second
}

// ToolAvailable reports whether name resolves to an executable on PATH.
func ToolAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func runWithTimeout(dir, name string, args ...string) ([]byte, error) {
	if !ToolAvailable(name) {
		return nil, fmt.Errorf("%s: %w", name, ErrToolUnavailable)
	}
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout())
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("%s: %w after %s", name, ErrToolTimeout, toolTimeout())
	}
	return out, err
}

// RunToolCommand runs an external scanner with a hard timeout that actually
// kills the process on expiry. It first checks the executable exists, returning
// ErrToolUnavailable if not — so a missing tool is reported as unavailable
// rather than silently yielding empty output. Returns combined stdout+stderr.
func RunToolCommand(name string, args ...string) ([]byte, error) {
	return runWithTimeout("", name, args...)
}

// RunToolCommandInDir is RunToolCommand with a working directory, for scanners
// that must be invoked from inside the target tree.
func RunToolCommandInDir(dir, name string, args ...string) ([]byte, error) {
	return runWithTimeout(dir, name, args...)
}
