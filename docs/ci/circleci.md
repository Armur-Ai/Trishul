# CircleCI Integration

> **Pre-release note.** No published Docker image or binary yet — build Trishul
> from source (see the [Quick Start](../getting-started/quickstart.md)). A scan
> targets a single file or a repository URL.

Add to your `.circleci/config.yml`:

```yaml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/go:1.25
    steps:
      - checkout
      # Build Trishul from source before this step.
      - run:
          name: Trishul Security Scan
          command: trishul scan <target> --fail-on-severity high --format sarif --output results.sarif
      - store_artifacts:
          path: results.sarif

workflows:
  security:
    jobs:
      - security-scan
```
