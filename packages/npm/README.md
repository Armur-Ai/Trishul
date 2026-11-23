# trishul-cli

[![npm version](https://img.shields.io/npm/v/trishul-cli.svg)](https://www.npmjs.com/package/trishul-cli)
[![license: MIT](https://img.shields.io/npm/l/trishul-cli.svg)](https://github.com/Armur-Ai/Trishul/blob/main/LICENSE)

**trishul** — a security scanner for vibe-coded software. SAST, SCA, secrets, and
IaC scanning built for AI-generated code.

## Quick start (10 seconds)

```bash
npx trishul-cli scan .
```

That's it. `npx` downloads the right prebuilt binary for your platform and scans
the current directory. No Go toolchain, no build step.

To install it globally instead:

```bash
npm install -g trishul-cli
trishul scan .
```

## How it works

This package ships no binary itself. Instead it declares one
`optionalDependencies` entry per platform:

| npm package                 | platform        |
| --------------------------- | --------------- |
| `trishul-cli-darwin-arm64`  | macOS (Apple)   |
| `trishul-cli-darwin-x64`    | macOS (Intel)   |
| `trishul-cli-linux-x64`     | Linux x86-64    |
| `trishul-cli-linux-arm64`   | Linux arm64     |
| `trishul-cli-win32-x64`     | Windows x86-64  |

npm installs only the one matching your `os`/`cpu`, and the `trishul` launcher
execs its bundled binary — no postinstall download on the normal path.

If no platform package is present (for example an install run with
`--no-optional`), the launcher falls back to downloading the matching archive
from the [GitHub release](https://github.com/Armur-Ai/Trishul/releases) and
**verifies its SHA-256 against the release `checksums.txt` before running it**.
A download error or checksum mismatch fails closed with a non-zero exit.

## Links

- Homepage: <https://trishul.dev>
- Source & releases: <https://github.com/Armur-Ai/Trishul>
- Issues: <https://github.com/Armur-Ai/Trishul/issues>

## License

MIT © Armur AI
