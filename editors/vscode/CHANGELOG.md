# Changelog

All notable changes to the Trishul VS Code extension are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - Unreleased

### Added

- Initial local-first release.
- `Trishul: Scan Workspace` and `Trishul: Scan Current File` commands.
- Opt-in scan-on-save (`trishul.runOnSave`) for supported languages.
- Findings rendered as native VS Code diagnostics, with severity mapped from
  SARIF levels (and best-effort JSON).
- Settings: `trishul.path`, `trishul.runOnSave`, `trishul.format`,
  `trishul.extraArgs`.
- Friendly "binary not found" handling with links to the install docs and the
  `trishul.path` setting.
- No network calls made by the extension itself.
