# CLI Command Reference

> **Pre-release note.** Trishul is built from source today (no published
> packages). `trishul scan` takes a **single file or a repository URL** —
> scanning a local directory from the CLI is not yet wired. A dedicated
> `trishul agent-security` command is planned; agent supply-chain findings are
> currently emitted as part of every `trishul scan`.

## Global Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--api-key` | `-k` | API key for authenticating with the Trishul server |
| `--verbose` | `-v` | Enable debug output |

## Commands

### `trishul run [target]`

Launch the interactive security agent with a guided wizard and live dashboard.

```bash
trishul run              # scan current directory
trishul run ./src        # scan specific path
trishul run --no-server  # skip auto-starting embedded server
```

### `trishul scan <target>`

Run a one-shot scan of a single file or a repository URL.

```bash
trishul scan server.js                             # scan a single file
trishul scan https://github.com/org/repo -l go     # scan remote repo (language required)
trishul scan <target> --advanced                   # deep scan with all tools
trishul scan <target> --output json                # JSON output
trishul scan <target> --format sarif               # SARIF output
trishul scan <target> --fail-on-severity high      # exit code 1 on HIGH+ findings
trishul scan <target> --min-severity medium        # suppress LOW and INFO
```

### `trishul serve [stop]`

Start or stop the embedded API server.

```bash
trishul serve            # start on port 4500
trishul serve --port 8080  # custom port
trishul serve stop       # stop running server
```

### `trishul init`

Create a `.trishul.yml` configuration file in the current directory.

### `trishul doctor`

Check which tools are installed and diagnose configuration issues.

### `trishul history`

List past scans with timestamps and finding counts.

```bash
trishul history              # list recent scans
trishul history show <id>    # show full results
trishul history clear        # clear all history
```

### `trishul compare <id1> <id2>`

Compare two scan results to find new and fixed findings.

### `trishul report`

Generate reports in various formats.

```bash
trishul report --task <id> --format html   # standalone HTML report
trishul report --task <id> --format csv    # CSV export
trishul report --task <id> --format owasp  # OWASP Top 10 mapping
trishul report --task <id> --format sans   # SANS mapping
```

### `trishul config [key] [value]`

Manage CLI configuration.

```bash
trishul config api_url http://localhost:4500
trishul config api_key my-secret-key
```

### `trishul completion <shell>`

Generate shell completion scripts.

```bash
trishul completion bash
trishul completion zsh
trishul completion fish
trishul completion powershell
```

### `trishul version`

Print version information.
