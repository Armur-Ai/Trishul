# Jenkins Integration

> **Pre-release note.** No published binary or install script yet — build
> Trishul from source (see the [Quick Start](../getting-started/quickstart.md)).
> A scan targets a single file or a repository URL.

Add to your `Jenkinsfile`:

```groovy
pipeline {
    agent any

    stages {
        stage('Security Scan') {
            steps {
                // Build Trishul from source, then scan a file or repository URL.
                sh 'trishul scan <target> --fail-on-severity high --format sarif --output results.sarif'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'results.sarif', allowEmptyArchive: true
                }
            }
        }
    }
}
```
