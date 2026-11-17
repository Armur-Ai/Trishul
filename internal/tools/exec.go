package internal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
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

// ToolVersion returns a best-effort version string for a tool by invoking it
// with a common version flag. It is advisory only (tools differ widely) and
// returns ("", false) when the tool is absent or prints nothing useful. A short
// internal timeout keeps a misbehaving --version from hanging a scan.
func ToolVersion(name string) (string, bool) {
	if !ToolAvailable(name) {
		return "", false
	}
	for _, flag := range []string{"--version", "-version", "version", "-V"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, name, flag).CombinedOutput()
		cancel()
		if err == nil && len(out) > 0 {
			if line := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0]); line != "" {
				return line, true
			}
		}
	}
	return "", false
}

func runWithTimeout(dir, name string, combined bool, args ...string) ([]byte, error) {
	if !ToolAvailable(name) {
		return nil, fmt.Errorf("%s: %w", name, ErrToolUnavailable)
	}
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout())
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	var out []byte
	var err error
	if combined {
		out, err = cmd.CombinedOutput()
	} else {
		out, err = cmd.Output()
	}
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("%s: %w after %s", name, ErrToolTimeout, toolTimeout())
	}
	return out, err
}

// RunToolCommand runs an external scanner with a hard timeout that actually
// kills the process on expiry. It first checks the executable exists, returning
// ErrToolUnavailable if not — so a missing tool is reported as unavailable
// rather than silently yielding empty output. Returns combined stdout+stderr
// (use the Stdout variant when the caller parses machine-readable stdout).
func RunToolCommand(name string, args ...string) ([]byte, error) {
	return runWithTimeout("", name, true, args...)
}

// RunToolCommandInDir is RunToolCommand with a working directory, for scanners
// that must be invoked from inside the target tree.
func RunToolCommandInDir(dir, name string, args ...string) ([]byte, error) {
	return runWithTimeout(dir, name, true, args...)
}

// RunToolCommandStdout is like RunToolCommand but returns stdout only, for
// scanners whose stdout is machine-readable (JSON/SARIF) and must not be mixed
// with stderr diagnostics.
func RunToolCommandStdout(name string, args ...string) ([]byte, error) {
	return runWithTimeout("", name, false, args...)
}

// RunToolCommandStdoutInDir is RunToolCommandStdout with a working directory.
func RunToolCommandStdoutInDir(dir, name string, args ...string) ([]byte, error) {
	return runWithTimeout(dir, name, false, args...)
}
