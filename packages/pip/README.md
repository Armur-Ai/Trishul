# trishul-cli

Security Scanner for Vibe-Coded Software — SAST, SCA, secrets, and IaC
scanning for AI-generated code.

`trishul-cli` ships the native `trishul` binary as a **per-platform binary
wheel**, so there is nothing to compile and nothing to download at first run:
`pip`/`pipx`/`uv` resolve the wheel that matches your OS and CPU and the
`trishul` command runs the bundled binary directly.

## Quick start

Run it without installing anything permanently:

```bash
pipx run trishul-cli scan .
# or, with uv:
uvx trishul-cli scan .
```

## Install

```bash
pipx install trishul-cli      # isolated, recommended
# or
pip install trishul-cli       # into the current environment
# or
uv tool install trishul-cli
```

## Usage

```bash
trishul run .          # scan current directory
trishul scan <path>    # scan a specific path
trishul doctor         # check tool availability
```

## Supported platforms

Binary wheels are published for:

| OS      | Architecture      | Wheel platform tag           |
| ------- | ----------------- | ---------------------------- |
| macOS   | Apple Silicon     | `macosx_11_0_arm64`          |
| macOS   | Intel             | `macosx_10_9_x86_64`         |
| Linux   | x86-64            | `manylinux2014_x86_64`       |
| Linux   | aarch64           | `manylinux2014_aarch64`      |
| Windows | x86-64            | `win_amd64`                  |

## More info

- [GitHub](https://github.com/Armur-Ai/trishul)
- [Documentation](https://trishul.dev)
