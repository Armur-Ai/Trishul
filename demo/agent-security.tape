# Records demo/agent-security.gif: the AI Agent Supply-Chain Security capability
# firing on an untrusted pull request — component findings plus a correlated
# attack chain.
#
# These analyzers run as part of a repository scan (supported today). A single
# file cannot show a cross-file chain, and the local-directory CLI path
# (`trishul scan .`) is not wired yet — see the Project status table — so this
# demo scans a repository fixture whose PR branch stages the exact pattern the
# engine detects:
#   * README.md with a poisoned instruction  -> untrusted ENTRY POINT
#   * package.json postinstall fetch-and-exec -> enabled ACTION
# Trishul reports each component finding and correlates them into one
# AGENT-CHAIN-001 (CRITICAL, confidence HIGH).
#
# Point the URL below at your own fixtures repo/PR branch before rendering.
#
# Prerequisites, from the repo root:
#   docker compose up -d --build
#   (cd cli && go build -o ../bin/trishul .)
# Then:
#   vhs demo/agent-security.tape

Output demo/agent-security.gif

Set Shell bash
Set FontSize 13
Set Width 1500
Set Height 860
Set Padding 22
Set Theme { "name": "Trishul", "background": "#0a0f1c", "foreground": "#e8eef7", "cursor": "#f5a524", "selection": "#16243c", "black": "#0a0f1c", "red": "#fb6a84", "green": "#2dd4bf", "yellow": "#f5a524", "blue": "#22d3ee", "magenta": "#a78bfa", "cyan": "#22d3ee", "white": "#e8eef7", "brightBlack": "#2a3e5c", "brightRed": "#fb6a84", "brightGreen": "#2dd4bf", "brightYellow": "#f5a524", "brightBlue": "#22d3ee", "brightMagenta": "#a78bfa", "brightCyan": "#8fe8f5", "brightWhite": "#ffffff" }
Set TypingSpeed 35ms

Hide
Type "export PATH=$PWD/bin:$PATH PS1='$ ' && clear"
Enter
Show

Sleep 500ms
Type "# An AI agent is about to review this pull request. What is hiding in it?"
Enter
Sleep 900ms
Type "trishul scan https://github.com/Armur-Ai/trishul-agentsec-fixtures -l js --format json \\"
Enter
Type "  | jq '.agent_security[] | {check_id, severity, confidence, entry_point, enabled_action}'"
Sleep 600ms
Enter
# Expect: an AGENT-INJ/INSTR entry-point finding, an AGENT-EXEC action finding,
# and a correlated AGENT-CHAIN-001 (CRITICAL, confidence HIGH) tying them together.
Sleep 12s
Sleep 1500ms
Type "# Neither signal alone claimed HIGH confidence — the correlated chain does."
Enter
Sleep 2s
