# Records demo/sarif.gif: Trishul emitting SARIF 2.1.0 with stable fingerprints,
# the format GitHub code scanning and most security dashboards ingest directly.
#
# Prerequisites, from the repo root:
#   docker compose up -d --build
#   (cd cli && go build -o ../bin/trishul .)
# Then:
#   vhs demo/sarif.tape

Output demo/sarif.gif

Set Shell bash
Set FontSize 13
Set Width 1500
Set Height 800
Set Padding 22
Set Theme { "name": "Trishul", "background": "#0a0f1c", "foreground": "#e8eef7", "cursor": "#22d3ee", "selection": "#16243c", "black": "#0a0f1c", "red": "#fb6a84", "green": "#2dd4bf", "yellow": "#f5a524", "blue": "#22d3ee", "magenta": "#a78bfa", "cyan": "#22d3ee", "white": "#e8eef7", "brightBlack": "#2a3e5c", "brightRed": "#fb6a84", "brightGreen": "#2dd4bf", "brightYellow": "#f5a524", "brightBlue": "#22d3ee", "brightMagenta": "#a78bfa", "brightCyan": "#8fe8f5", "brightWhite": "#ffffff" }
Set TypingSpeed 35ms

Hide
Type "export PATH=$PWD/bin:$PATH PS1='$ ' && clear"
Enter
Show

Sleep 500ms
Type "# Produce SARIF 2.1.0 for GitHub code scanning / CI"
Enter
Sleep 600ms
Type "trishul scan examples/vibe-coded-app/server.js --format sarif > results.sarif"
Sleep 600ms
Enter
Sleep 14s

Type "# SARIF schema, tool driver, and a stable fingerprint per finding:"
Enter
Sleep 500ms
Type "jq '{version, runs: (.runs | length), tool: .runs[0].tool.driver.name, results: (.runs[0].results | length)}' results.sarif"
Sleep 400ms
Enter
Sleep 2s
Type "jq '.runs[0].results[0].partialFingerprints' results.sarif"
Sleep 400ms
Enter
Sleep 2500ms
