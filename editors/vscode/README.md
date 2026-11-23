# Trishul for VS Code

Run the [Trishul](https://github.com/Armur-Ai/trishul) security scanner against
your code and see findings inline, right in the editor.

## What it does

- **Scan Workspace** — scans every open workspace folder.
- **Scan Current File** — scans just the active file.
- **Scan on save** (opt-in) — re-scans a file every time you save it, for
  supported languages.

Findings are rendered as native VS Code **diagnostics** (the squiggles in the
editor and rows in the Problems panel), with severity mapped from Trishul's
output:

| Trishul / SARIF level        | VS Code severity |
| ---------------------------- | ---------------- |
| `error` (CRITICAL / HIGH)    | Error            |
| `warning` (MEDIUM)           | Warning          |
| `note` (LOW)                 | Information      |
| anything else (INFO)         | Hint             |

## Local-first — nothing leaves your machine

This extension is **local-first by design**:

- It shells out to the `trishul` binary **already installed on your machine**
  and reads the findings it prints. Your code is never uploaded by this
  extension.
- The extension itself makes **no network calls**. The only outbound action is
  opening the public install-docs page in your browser — and only when *you*
  click the "Install docs" button after the binary could not be found.

The scanner runs entirely locally; where Trishul itself sends data (if at all)
is governed by your own Trishul configuration, not by this extension.

## Requirements

You need the `trishul` CLI installed and on your `PATH` (or point the extension
at it with the `trishul.path` setting).

Install instructions: <https://github.com/Armur-Ai/trishul#installation>

Verify it works from a terminal:

```sh
trishul scan . --format sarif
```

## Commands

Open the Command Palette (`Cmd/Ctrl+Shift+P`) and run:

- `Trishul: Scan Workspace`
- `Trishul: Scan Current File`

## Settings

| Setting             | Type      | Default    | Description                                                                 |
| ------------------- | --------- | ---------- | --------------------------------------------------------------------------- |
| `trishul.path`      | string    | `trishul`  | Path to the `trishul` binary. Use an absolute path if it is not on `PATH`.  |
| `trishul.runOnSave` | boolean   | `false`    | Scan a file automatically when it is saved (supported languages only).      |
| `trishul.format`    | `sarif`\|`json` | `sarif` | Output format requested from `trishul scan`. SARIF is recommended.        |
| `trishul.extraArgs` | string[]  | `[]`       | Extra arguments appended to every `trishul scan` call.                      |

## Supported languages (for scan-on-save)

JavaScript / TypeScript (incl. JSX/TSX), Python, Go, Rust, Java, Ruby, PHP,
C / C++, and Solidity. `Scan Workspace` and `Scan Current File` work regardless
of language.

## How it works

Under the hood the extension runs:

```sh
trishul scan <path> --format sarif
```

captures the output, parses the SARIF (or JSON), and publishes the findings to a
`DiagnosticCollection`. No shell is used to launch the process (arguments are
passed directly), and a missing binary produces a friendly prompt with links to
the install docs and the relevant setting.

## License

MIT
