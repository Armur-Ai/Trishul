// Package redact provides a small, dependency-free secrets-redaction layer so
// that a discovered secret's raw plaintext value never leaves the pipeline.
//
// Mask produces a human-readable preview that is safe to store and transmit,
// and Fingerprint produces a stable, non-reversible identifier that lets two
// findings referring to the same secret be correlated without exposing it.
package redact

import (
	"crypto/sha256"
	"encoding/hex"
)

// minMaskLen is the minimum secret length for which Mask reveals edge
// characters. Below this length a fully-masked fixed token is returned so that
// short secrets cannot be reconstructed from their preview.
const minMaskLen = 12

// redactedToken is the fully-masked placeholder used for short secrets.
const redactedToken = "[REDACTED]"

// Mask returns a redacted preview of secret.
//
// For secrets of length >= 12 it reveals at most the first 4 and last 4
// characters joined by a plain ASCII ellipsis, e.g. "AKIA...MPLE"; the middle
// (and therefore the full secret) is never present in the output. For shorter
// secrets (including the empty string) it returns the fixed token "[REDACTED]".
// Mask is deterministic and uses only the standard library.
func Mask(secret string) string {
	r := []rune(secret)
	if len(r) < minMaskLen {
		return redactedToken
	}
	return string(r[:4]) + "..." + string(r[len(r)-4:])
}

// Fingerprint returns a stable, non-reversible identifier for secret: the first
// 12 hex characters of its SHA-256 digest. It is deterministic across runs and
// processes, and uses only the standard library. The empty string yields a
// fixed, non-empty fingerprint.
func Fingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])[:12]
}
