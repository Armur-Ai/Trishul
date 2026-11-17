package internal

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestToolAvailable(t *testing.T) {
	if !ToolAvailable("go") {
		t.Skip("go not on PATH in this environment")
	}
	if ToolAvailable("this-tool-does-not-exist-xyzzy") {
		t.Errorf("expected a bogus tool to be unavailable")
	}
}

func TestRunToolCommand_Unavailable(t *testing.T) {
	_, err := RunToolCommand("this-tool-does-not-exist-xyzzy", "--version")
	if !errors.Is(err, ErrToolUnavailable) {
		t.Errorf("expected ErrToolUnavailable, got %v", err)
	}
}

func TestRunToolCommand_Output(t *testing.T) {
	if !ToolAvailable("echo") {
		t.Skip("echo not available")
	}
	out, err := RunToolCommand("echo", "hello-trishul")
	if err != nil {
		t.Fatalf("echo failed: %v", err)
	}
	if !strings.Contains(string(out), "hello-trishul") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestRunToolCommand_TimeoutKills(t *testing.T) {
	if !ToolAvailable("sleep") {
		t.Skip("sleep not available")
	}
	t.Setenv("TOOL_TIMEOUT_SECONDS", "1")
	start := time.Now()
	_, err := RunToolCommand("sleep", "10")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrToolTimeout) {
		t.Fatalf("expected ErrToolTimeout, got %v", err)
	}
	if elapsed.Seconds() > 5 {
		t.Errorf("timeout did not kill the process promptly (%.1fs)", elapsed.Seconds())
	}
}
