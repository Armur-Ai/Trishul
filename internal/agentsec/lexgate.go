package agentsec

// lexGate wraps a per-file lexical classification (from internal/lexctx) so that
// a detector can require the right LEXICAL CONTEXT before emitting a finding.
//
// Line-based scanners report a 1-based line number; this gate maps a (0-based
// line, 0-based byte column) back to a byte offset in the original content and
// asks lexctx for the Kind there. The mapping mirrors SplitLines (split on '\n'),
// so a token found at strings.Index(line, tok) maps cleanly to its file offset.

import "github.com/Armur-Ai/Trishul/internal/lexctx"

type lexGate struct {
	spans      []lexctx.Span
	lineStarts []int // byte offset of the first byte of each 0-based line
}

// newLexGate classifies content for the language implied by path.
func newLexGate(path string, content []byte) *lexGate {
	g := &lexGate{spans: lexctx.Classify(lexctx.LangFor(path), content)}
	g.lineStarts = append(g.lineStarts, 0)
	for i, b := range content {
		if b == '\n' {
			g.lineStarts = append(g.lineStarts, i+1)
		}
	}
	return g
}

// kindAt returns the lexical Kind at (0-based lineIdx, 0-based byte col). Out of
// range positions classify as Code (fail-open: a finding is kept, not dropped).
func (g *lexGate) kindAt(lineIdx, col int) lexctx.Kind {
	if g == nil || col < 0 || lineIdx < 0 || lineIdx >= len(g.lineStarts) {
		return lexctx.Code
	}
	return lexctx.At(g.spans, g.lineStarts[lineIdx]+col)
}

// obfsInertContext reports whether an encoded blob at (lineIdx, col) sits where
// such strings are shown as examples rather than embedded as live content: a
// comment, echo/printf argument text, or a heredoc usage block. String literals
// are NOT inert (a blob embedded in a real JSON/source string is a live payload).
func (g *lexGate) obfsInertContext(lineIdx, col int) bool {
	switch g.kindAt(lineIdx, col) {
	case lexctx.Comment, lexctx.InertText, lexctx.Heredoc:
		return true
	}
	return false
}

// shellExecContext reports whether the shell command whose first physical line is
// `line` (at 0-based lineIdx) is real executable code — not a comment, a heredoc
// usage block, or the argument text of an echo/printf (which prints, never runs,
// its arguments). The command word (first non-space token) is used as the probe
// point, so a quoted URL inside a genuine command (e.g. curl "https://…" | sh)
// is still gated on the command's own context and keeps firing.
func (g *lexGate) shellExecContext(line string, lineIdx int) bool {
	i := 0
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	switch g.kindAt(lineIdx, i) {
	case lexctx.Comment, lexctx.Heredoc:
		return false
	}
	j := i
	for j < len(line) && line[j] != ' ' && line[j] != '\t' {
		j++
	}
	if w := line[i:j]; w == "echo" || w == "printf" {
		return false
	}
	return true
}
