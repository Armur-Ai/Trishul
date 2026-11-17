# .trishul.yml Configuration Reference

Place `.trishul.yml` in your project root to configure Trishul's behavior without CLI flags.

> The legacy filename `.armur.yml` is still read as a deprecated fallback when no
> `.trishul.yml` is present; rename it to `.trishul.yml` to silence the deprecation warning.

## Full Schema

```yaml
# Scan settings
scan:
  depth: quick              # quick | deep
  language: go              # override auto-detection; omit for auto
  severity-threshold: medium  # minimum severity to include in output
  fail-on-findings: true    # exit with code 1 if findings at threshold or above

# File/directory exclusions
exclude:
  - vendor/
  - node_modules/
  - testdata/
  - "**/*_test.go"
  - "*.pb.go"
  - "*.generated.*"

# Tool configuration
tools:
  enabled:                  # allowlist (if set, only these run)
    - gosec
    - semgrep
  disabled:                 # blocklist (overrides enabled)
    - gocyclo
  timeout: 300              # per-tool timeout in seconds

# Output settings
output:
  format: text              # text | json | sarif
  save-to: ./reports/       # auto-save reports after each scan

# Secrets scanning
secrets:
  validate: false           # set true to test if found secrets are still active
  scan-history: false       # set true to scan full git history
  custom-patterns:
    - name: "Internal API Key"
      regex: "INTERNAL_[A-Z0-9]{32}"
      severity: critical
  allowlist:
    - path: "testdata/**"
    - regex: "example_key_.*"

# Custom tool plugins
plugins:
  - name: my-custom-linter
    command: "my-linter --json {target}"
    output-format: json
    language: go
```

## Precedence

CLI flags > environment variables > `.trishul.yml` > defaults

## Examples

### Minimal (CI-focused)

```yaml
scan:
  fail-on-findings: true
  severity-threshold: high
exclude:
  - vendor/
  - testdata/
```

### Full development setup

```yaml
scan:
  depth: deep
  severity-threshold: medium
exclude:
  - vendor/
  - node_modules/
  - "**/*_test.go"
tools:
  disabled:
    - gocyclo
    - pydocstyle
output:
  save-to: ./security-reports/
```
