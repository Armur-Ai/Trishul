// Package bundle defines the signed rules/advisory update bundle that clients
// pull daily (plan D-ARCH.4, the "antivirus model"). Armur serves only a static,
// Ed25519-signed JSON file; the client verifies the signature against an embedded
// public key before applying it. No code or user data is involved — this fits
// local-first: we distribute signed rules, the client does everything else.
package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Armur-Ai/Trishul/internal/advisory"
)

// Bundle is the signed payload: a dated set of advisories plus a hash of the
// rules pack the client should have. Kept small and code-free.
type Bundle struct {
	SchemaVersion int                 `json:"schema_version"`
	Version       string              `json:"version"` // e.g. 2026.11.23
	GeneratedAt   string              `json:"generated_at"`
	RulesSHA256   string              `json:"rules_sha256"` // hash of the rules pack
	Advisories    []advisory.Advisory `json:"advisories"`
}

// Envelope is what gets served: the canonical bundle bytes plus a detached
// signature over exactly those bytes.
type Envelope struct {
	Bundle    json.RawMessage `json:"bundle"`    // canonical JSON of a Bundle
	Signature string          `json:"signature"` // base64 Ed25519 signature over Bundle bytes
}

// ErrBadSignature is returned when verification fails.
var ErrBadSignature = errors.New("bundle signature verification failed")

// Canonical returns the canonical JSON encoding of a bundle that is signed and
// verified (stable field order via the struct, no extra whitespace).
func Canonical(b Bundle) ([]byte, error) {
	return json.Marshal(b)
}

// Sign produces a served envelope: canonical bundle bytes + a base64 Ed25519
// signature over them. Used by the release/build side.
func Sign(b Bundle, priv ed25519.PrivateKey) (Envelope, error) {
	canon, err := Canonical(b)
	if err != nil {
		return Envelope{}, err
	}
	sig := ed25519.Sign(priv, canon)
	return Envelope{Bundle: canon, Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// Marshal renders an envelope as the JSON file Armur serves.
func (e Envelope) Marshal() ([]byte, error) { return json.Marshal(e) }

// Verify parses a served envelope JSON, checks the Ed25519 signature against pub,
// and returns the parsed Bundle. A tampered bundle or wrong key yields
// ErrBadSignature — the client applies nothing on failure (fail closed).
func Verify(envelopeJSON []byte, pub ed25519.PublicKey) (Bundle, error) {
	var env Envelope
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		return Bundle{}, fmt.Errorf("parse envelope: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return Bundle{}, fmt.Errorf("decode signature: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, env.Bundle, sig) {
		return Bundle{}, ErrBadSignature
	}
	var b Bundle
	if err := json.Unmarshal(env.Bundle, &b); err != nil {
		return Bundle{}, fmt.Errorf("parse bundle: %w", err)
	}
	return b, nil
}

// RulesHash computes the SHA-256 (hex) of the concatenated rule-pack bytes, so a
// client can tell whether its rules match the bundle's RulesSHA256.
func RulesHash(packBytes []byte) string {
	sum := sha256.Sum256(packBytes)
	return hex.EncodeToString(sum[:])
}

// ParsePublicKey decodes a base64 or hex Ed25519 public key (the key embedded in
// the client binary).
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	return nil, errors.New("invalid ed25519 public key")
}
