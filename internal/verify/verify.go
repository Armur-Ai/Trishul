// Package verify models "Trishul Verified" (plan D6, rewritten for local-first):
// the user's own CI produces a signed claim about a scan result and attaches it
// as a GitHub artifact attestation. Anyone can verify it with `gh attestation
// verify` against the repo — Armur never re-scans and never hosts anything. This
// package defines the claim shape, its canonical form (for attestation subject
// digests), and the badge-state logic.
package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// PredicateType is the in-toto predicate type for a Trishul verification claim.
const PredicateType = "https://armur.ai/trishul/verification/v1"

// Claim is what the user's CI attests: a scan result bound to a commit. It
// contains NO code — only the repo, commit, rule-set version and the result.
type Claim struct {
	PredicateType string `json:"predicate_type"`
	Repo          string `json:"repo"` // owner/name
	CommitSHA     string `json:"commit_sha"`
	Ref           string `json:"ref,omitempty"` // e.g. refs/heads/main
	RulesVersion  string `json:"rules_version"`
	ToolVersion   string `json:"tool_version"`
	Grade         string `json:"grade"`
	Passed        bool   `json:"passed"`
	NewFindings   int    `json:"new_findings"`
	GeneratedAt   string `json:"generated_at"`
}

// NewClaim fills the predicate type and returns a claim ready to canonicalize.
func NewClaim(c Claim) Claim {
	c.PredicateType = PredicateType
	return c
}

// Canonical returns the stable JSON encoding used as the attestation predicate.
func (c Claim) Canonical() ([]byte, error) {
	c.PredicateType = PredicateType
	return json.Marshal(c)
}

// Digest returns the SHA-256 (hex) of the canonical claim — the subject digest
// the attestation binds to, so a tampered claim won't verify.
func (c Claim) Digest() (string, error) {
	b, err := c.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// BadgeState is the "Trishul Verified" badge text + color, derived purely from a
// claim. It is verified only when the run passed; otherwise "unverified" (D6:
// revocation is automatic on the next failing run).
func (c Claim) BadgeState() (message, color string) {
	if c.Passed {
		return "Trishul Verified ✓", "brightgreen"
	}
	return "unverified", "red"
}

// VerifyCmd returns the `gh attestation verify` command a third party runs to
// check the claim against the repo — no Armur involvement, no re-scan.
func (c Claim) VerifyCmd(artifactPath string) []string {
	return []string{"gh", "attestation", "verify", artifactPath, "--repo", c.Repo}
}
