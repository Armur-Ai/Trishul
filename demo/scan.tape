# Records demo/scan.gif: a real scan of the bundled example app.
#
# Prerequisites, from the repo root:
#   docker compose up -d --build
#   (cd cli && go build -o ../bin/trishul .)
# Then:
#   vhs demo/scan.tape

Output demo/scan.gif

Set Shell bash
Set FontSize 13
Set Width 1500
Set Height 820
Set Padding 22
# Trishul identity: deep slate + cyan accent
Set Theme { "name": "Trishul", "background": "#0a0f1c", "foreground": "#e8eef7", "cursor": "#22d3ee", "selection": "#16243c", "black": "#0a0f1c", "red": "#fb6a84", "green": "#2dd4bf", "yellow": "#f5a524", "blue": "#22d3ee", "magenta": "#a78bfa", "cyan": "#22d3ee", "white": "#e8eef7", "brightBlack": "#2a3e5c", "brightRed": "#fb6a84", "brightGreen": "#2dd4bf", "brightYellow": "#f5a524", "brightBlue": "#22d3ee", "brightMagenta": "#a78bfa", "brightCyan": "#8fe8f5", "brightWhite": "#ffffff" }
Set TypingSpeed 35ms

Hide
Type "export PATH=$PWD/bin:$PATH PS1='$ ' && clear"
Enter
Show

Sleep 500ms
Type "# Scan an AI-generated app for security issues"
Enter
Sleep 600ms
Type "trishul scan examples/vibe-coded-app/server.js"
Sleep 600ms
Enter
# The scan runs the parallel analyzers and prints normalized findings.
Sleep 16s
Sleep 1s
