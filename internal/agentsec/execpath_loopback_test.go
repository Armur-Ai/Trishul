package agentsec

import "testing"

func TestExecAllowedHostLoopback(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "localhost", "api.localhost"} {
		if !execAllowedHost(h) {
			t.Errorf("%s is loopback and should not be flagged", h)
		}
	}
	for _, h := range []string{"10.0.0.5", "203.0.113.9", "evil.example"} {
		if execAllowedHost(h) {
			t.Errorf("%s must not be allowlisted", h)
		}
	}
}
