# GitLab CI Integration

Add to your `.gitlab-ci.yml`:

```yaml
trishul-scan:
  image: armur/agent:latest
  stage: test
  script:
    - trishul scan . --format sarif --output gl-sast-report.json --fail-on-severity high
  artifacts:
    reports:
      sast: gl-sast-report.json
  rules:
    - if: $CI_MERGE_REQUEST_IID
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

This automatically populates the GitLab Security Dashboard.
