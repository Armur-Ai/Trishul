package tasks

import "testing"

func TestWeb3Enabled(t *testing.T) {
	// Default: off.
	t.Setenv("TRISHUL_PROFILE", "")
	t.Setenv("TRISHUL_WEB3", "")
	if web3Enabled() {
		t.Error("web3 must be off by default")
	}
	// Profile opt-in.
	t.Setenv("TRISHUL_PROFILE", "web3")
	if !web3Enabled() {
		t.Error("TRISHUL_PROFILE=web3 must enable web3")
	}
	t.Setenv("TRISHUL_PROFILE", "all")
	if !web3Enabled() {
		t.Error("TRISHUL_PROFILE=all must enable web3")
	}
	// Boolean opt-in.
	t.Setenv("TRISHUL_PROFILE", "")
	t.Setenv("TRISHUL_WEB3", "1")
	if !web3Enabled() {
		t.Error("TRISHUL_WEB3=1 must enable web3")
	}
	// A non-web3 profile stays off.
	t.Setenv("TRISHUL_WEB3", "")
	t.Setenv("TRISHUL_PROFILE", "security")
	if web3Enabled() {
		t.Error("TRISHUL_PROFILE=security must not enable web3")
	}
}
