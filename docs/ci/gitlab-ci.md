# GitLab CI Integration

> **Pre-release note.** No published Docker image or binary yet — build Trishul
> from source (see the [Quick Start](../getting-started/quickstart.md)). A scan
> targets a single file or a repository URL.

Add to your `.gitlab-ci.yml`:

```yaml
trishul-scan:
  image: golang:1.25
  stage: test
  script:
    # Build Trishul from source first, then scan.
    - trishul scan <target> --format sarif --output gl-sast-report.json --fail-on-severity high
  artifacts:
    reports:
      sast: gl-sast-report.json
  rules:
    - if: $CI_MERGE_REQUEST_IID
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

This automatically populates the GitLab Security Dashboard.
