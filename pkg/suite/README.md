# pkg/suite — Trishul → Armur suite bridge

Adapts Trishul's native `models.ScanResult` into the shared Armur suite contract
(`github.com/Armur-Ai/armur-contracts`) so Akira/Engira can consume Trishul's
code evidence through the common vocabulary.

```go
import "github.com/Armur-Ai/Trishul/pkg/suite"

// From a completed scan:
bundle := suite.EmitCodeAnalysisBundle(scanResult, "v1.2.3")   // contracts.CodeAnalysisBundle
env, _ := suite.EmitEnvelope(scanResult, "v1.2.3")             // versioned, Trishul-attributed envelope
// send env over any armur-contracts transport (inproc / file / http)
```

## Honest mapping

- security findings → `SourceClaim` (`source_weakness`)
- SCA findings → `SourceClaim` (`dependency_advisory`)
- secrets → `SecretCandidate`
- antipattern/complexity → `CodeIssue` (reliability/maintainability) — never
  flattened into vulnerabilities

Claim status is preserved honestly: an unconfirmed native result is `declared`;
only a Trishul-verified (DAST/exploit) finding becomes `runtime_confirmed`.
