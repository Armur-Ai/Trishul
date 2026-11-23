// Package lexctx is a lightweight, dependency-free per-language lexical
// classifier. It marks byte ranges of a source file as code, comment, string,
// heredoc, markdown code-fence, markdown prose, or inert text (echo/printf
// arguments and usage/help blocks).
//
// Security rules use the classification to require a lexical context: for
// example, an EXEC rule that looks for "curl ... | sh" should only fire when
// the match lands in real code, not inside a comment, an echo/usage string, or
// a heredoc usage block.
//
// The package operates purely on bytes and never panics, loops forever, or
// allocates beyond the produced spans. Unterminated strings and comments are
// handled gracefully (they extend to end of line or end of input).
package lexctx

import (
	"path/filepath"
	"sort"
	"strings"
)

// Kind is the lexical category of a byte range.
type Kind string

const (
	// Code is ordinary source code (the default).
	Code Kind = "code"
	// Comment is a line or block comment.
	Comment Kind = "comment"
	// StringLit is a string/character literal.
	StringLit Kind = "string"
	// Heredoc is the body of a shell here-document.
	Heredoc Kind = "heredoc"
	// CodeFence is the body of a fenced markdown code block.
	CodeFence Kind = "markdown-code-fence"
	// Prose is ordinary markdown prose (the default for markdown).
	Prose Kind = "markdown-prose"
	// InertText is argument text that is printed, not executed, such as the
	// arguments to echo/printf or usage/help blocks.
	InertText Kind = "inert-text"
)

// Lang identifies a source language.
type Lang string

// Supported languages. Anything else is "unknown".
const (
	LangGo         Lang = "go"
	LangJS         Lang = "js"
	LangTS         Lang = "ts"
	LangPython     Lang = "python"
	LangShell      Lang = "shell"
	LangYAML       Lang = "yaml"
	LangSQL        Lang = "sql"
	LangMarkdown   Lang = "markdown"
	LangTOML       Lang = "toml"
	LangJSON       Lang = "json"
	LangDockerfile Lang = "dockerfile"
	LangUnknown    Lang = "unknown"
)

// Span is a half-open byte range [Start, End) with a lexical Kind.
type Span struct {
	Start, End int
	Kind       Kind
}

// LangFor maps a file path to a Lang using its extension or basename.
func LangFor(path string) Lang {
	base := filepath.Base(path)
	if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") || strings.HasSuffix(base, ".Dockerfile") {
		return LangDockerfile
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go":
		return LangGo
	case ".js", ".jsx", ".mjs", ".cjs":
		return LangJS
	case ".ts", ".tsx":
		return LangTS
	case ".py":
		return LangPython
	case ".sh", ".bash":
		return LangShell
	case ".yaml", ".yml":
		return LangYAML
	case ".sql":
		return LangSQL
	case ".md", ".mdx":
		return LangMarkdown
	case ".toml":
		return LangTOML
	case ".json":
		return LangJSON
	}
	return LangUnknown
}

// Classify returns a contiguous, ordered list of spans covering the whole
// input. The spans have no gaps or overlaps and are sorted by Start. For an
// empty input a single zero-length span is returned. For an unknown language a
// single Code span covering everything is returned.
func Classify(lang Lang, src []byte) []Span {
	switch lang {
	case LangGo, LangJS, LangTS, LangSQL:
		return classifyCLike(lang, src)
	case LangPython, LangYAML, LangTOML, LangDockerfile:
		return classifyHash(lang, src)
	case LangShell:
		return classifyShell(src)
	case LangMarkdown:
		return classifyMarkdown(src)
	case LangJSON:
		return classifyJSON(src)
	default:
		return fillWith(len(src), nil, Code)
	}
}

// At returns the Kind at the given byte offset using binary search. Offsets
// outside the spans (or a negative offset) classify as Code.
func At(spans []Span, offset int) Kind {
	if offset < 0 {
		return Code
	}
	lo, hi := 0, len(spans)
	for lo < hi {
		mid := (lo + hi) / 2
		switch {
		case offset < spans[mid].Start:
			hi = mid
		case offset >= spans[mid].End:
			lo = mid + 1
		default:
			return spans[mid].Kind
		}
	}
	return Code
}

// AtLineCol converts a 1-based line and 1-based (byte) column to a byte offset
// and returns the Kind there. Out-of-range positions classify as Code.
func AtLineCol(src []byte, spans []Span, line, col int) Kind {
	if line < 1 || col < 1 {
		return Code
	}
	i, cur := 0, 1
	for cur < line && i < len(src) {
		if src[i] == '\n' {
			cur++
		}
		i++
	}
	if cur < line {
		return Code
	}
	return At(spans, i+(col-1))
}

// --- helpers -----------------------------------------------------------------

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f' || b == '\v'
}

func isWordByte(b byte) bool {
	return b == '_' || ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z') || ('0' <= b && b <= '9')
}

func hasPrefixAt(src []byte, i int, s string) bool {
	if i < 0 || i+len(s) > len(src) {
		return false
	}
	for k := 0; k < len(s); k++ {
		if src[i+k] != s[k] {
			return false
		}
	}
	return true
}

// fillWith builds a contiguous, ordered span list from (possibly unordered)
// marked regions, filling every gap and the empty input with def.
func fillWith(n int, regions []Span, def Kind) []Span {
	if len(regions) > 1 {
		sort.SliceStable(regions, func(i, j int) bool { return regions[i].Start < regions[j].Start })
	}
	var out []Span
	pos := 0
	for _, r := range regions {
		if r.Start > pos {
			out = append(out, Span{pos, r.Start, def})
		}
		out = append(out, r)
		if r.End > pos {
			pos = r.End
		}
	}
	if pos < n {
		out = append(out, Span{pos, n, def})
	}
	if len(out) == 0 {
		out = append(out, Span{0, n, def})
	}
	return out
}

// scanQuoted scans a quoted literal starting just after the opening quote and
// returns the index just past the closing quote. If !multiline it stops at a
// newline (treating the literal as unterminated and not consuming the newline).
// At end of input it returns len(src).
func scanQuoted(src []byte, i int, q byte, escapes, multiline bool) int {
	n := len(src)
	for i < n {
		c := src[i]
		if escapes && c == '\\' {
			i += 2
			continue
		}
		if c == q {
			return i + 1
		}
		if !multiline && c == '\n' {
			return i
		}
		i++
	}
	return n
}

// scanQuotedBounded is like scanQuoted but bounded to [i, end) and never spans
// past end.
func scanQuotedBounded(src []byte, i, end int, q byte, escapes bool) int {
	for i < end {
		c := src[i]
		if escapes && c == '\\' {
			i += 2
			continue
		}
		if c == q {
			return i + 1
		}
		i++
	}
	return end
}

// scanTriple scans a Python triple-quoted string starting just after the
// opening triple quote and returns the index just past the closing triple.
func scanTriple(src []byte, i int, q byte) int {
	n := len(src)
	for i < n {
		if src[i] == '\\' {
			i += 2
			continue
		}
		if src[i] == q && i+2 < n && src[i+1] == q && src[i+2] == q {
			return i + 3
		}
		i++
	}
	return n
}

// --- C-like languages: go, js, ts, sql --------------------------------------

func classifyCLike(lang Lang, src []byte) []Span {
	n := len(src)
	var regions []Span

	lineCmt := "//"
	if lang == LangSQL {
		lineCmt = "--"
	}
	hasBacktick := lang == LangGo || lang == LangJS || lang == LangTS
	hasSingle := lang == LangJS || lang == LangTS || lang == LangSQL

	i := 0
	for i < n {
		c := src[i]
		switch {
		case hasPrefixAt(src, i, lineCmt):
			j := i + len(lineCmt)
			for j < n && src[j] != '\n' {
				j++
			}
			regions = append(regions, Span{i, j, Comment})
			i = j
		case c == '/' && i+1 < n && src[i+1] == '*':
			j := i + 2
			for j < n && !(src[j] == '*' && j+1 < n && src[j+1] == '/') {
				j++
			}
			if j < n {
				j += 2
			} else {
				j = n
			}
			regions = append(regions, Span{i, j, Comment})
			i = j
		case c == '"':
			j := scanQuoted(src, i+1, '"', true, false)
			regions = append(regions, Span{i, j, StringLit})
			i = j
		case hasSingle && c == '\'':
			j := scanQuoted(src, i+1, '\'', true, false)
			regions = append(regions, Span{i, j, StringLit})
			i = j
		case hasBacktick && c == '`':
			// Go raw strings have no escapes and span lines; JS/TS template
			// literals honor backslash escapes and also span lines.
			escapes := lang != LangGo
			j := scanQuoted(src, i+1, '`', escapes, true)
			regions = append(regions, Span{i, j, StringLit})
			i = j
		default:
			i++
		}
	}
	return fillWith(n, regions, Code)
}

// --- hash-comment languages: python, yaml, toml, dockerfile -----------------

func classifyHash(lang Lang, src []byte) []Span {
	n := len(src)
	var regions []Span

	triple := lang == LangPython
	singleEsc := lang == LangPython

	i := 0
	for i < n {
		c := src[i]
		switch {
		case c == '#' && (i == 0 || isSpace(src[i-1])):
			j := i
			for j < n && src[j] != '\n' {
				j++
			}
			regions = append(regions, Span{i, j, Comment})
			i = j
		case triple && (hasPrefixAt(src, i, `"""`) || hasPrefixAt(src, i, `'''`)):
			j := scanTriple(src, i+3, c)
			regions = append(regions, Span{i, j, StringLit})
			i = j
		case c == '"':
			j := scanQuoted(src, i+1, '"', true, false)
			regions = append(regions, Span{i, j, StringLit})
			i = j
		case c == '\'':
			j := scanQuoted(src, i+1, '\'', singleEsc, false)
			regions = append(regions, Span{i, j, StringLit})
			i = j
		default:
			i++
		}
	}
	return fillWith(n, regions, Code)
}

// --- json -------------------------------------------------------------------

func classifyJSON(src []byte) []Span {
	n := len(src)
	var regions []Span
	i := 0
	for i < n {
		if src[i] == '"' {
			j := scanQuoted(src, i+1, '"', true, false)
			regions = append(regions, Span{i, j, StringLit})
			i = j
			continue
		}
		i++
	}
	return fillWith(n, regions, Code)
}

// --- shell ------------------------------------------------------------------

type lineInfo struct {
	start, end, nlEnd int // content is [start,end); [start,nlEnd) includes the newline
}

func splitLines(src []byte) []lineInfo {
	var out []lineInfo
	n := len(src)
	i := 0
	for i < n {
		j := i
		for j < n && src[j] != '\n' {
			j++
		}
		nlEnd := j
		if j < n {
			nlEnd = j + 1
		}
		out = append(out, lineInfo{i, j, nlEnd})
		i = nlEnd
	}
	return out
}

func firstWordOf(src []byte, start, end int) string {
	i := start
	for i < end && isSpace(src[i]) {
		i++
	}
	j := i
	for j < end && !isSpace(src[j]) {
		j++
	}
	return string(src[i:j])
}

func trimLeadingTabs(b []byte) []byte {
	i := 0
	for i < len(b) && b[i] == '\t' {
		i++
	}
	return b[i:]
}

// detectHeredoc scans a single line (in code context) for a heredoc operator
// (<<, <<-) and returns the unquoted delimiter, whether leading tabs are
// stripped from the terminator, and whether a heredoc was found. Here-strings
// (<<<) and operators inside quotes or comments are ignored.
func detectHeredoc(line []byte) (delim string, strip, ok bool) {
	n := len(line)
	i := 0
	for i < n {
		c := line[i]
		switch {
		case c == '\'':
			i = scanQuotedBounded(line, i+1, n, '\'', false)
			continue
		case c == '"':
			i = scanQuotedBounded(line, i+1, n, '"', true)
			continue
		case c == '#' && (i == 0 || isSpace(line[i-1])):
			return "", false, false // rest of line is a comment
		case c == '<' && i+1 < n && line[i+1] == '<':
			if i+2 < n && line[i+2] == '<' {
				i += 3 // here-string, not a heredoc
				continue
			}
			j := i + 2
			if j < n && line[j] == '-' {
				strip = true
				j++
			}
			for j < n && (line[j] == ' ' || line[j] == '\t') {
				j++
			}
			if j >= n {
				return "", false, false
			}
			var d []byte
			switch line[j] {
			case '\'', '"':
				q := line[j]
				j++
				for j < n && line[j] != q {
					d = append(d, line[j])
					j++
				}
			case '\\':
				j++
				for j < n && isWordByte(line[j]) {
					d = append(d, line[j])
					j++
				}
			default:
				for j < n && isWordByte(line[j]) {
					d = append(d, line[j])
					j++
				}
			}
			if len(d) == 0 {
				return "", false, false
			}
			return string(d), strip, true
		}
		i++
	}
	return "", false, false
}

// findShellComment returns the offset of a trailing comment '#' in [from,end),
// honoring quotes, or -1 if there is none.
func findShellComment(src []byte, from, end int) int {
	i := from
	for i < end {
		c := src[i]
		switch c {
		case '\'':
			i = scanQuotedBounded(src, i+1, end, '\'', false)
			continue
		case '"':
			i = scanQuotedBounded(src, i+1, end, '"', true)
			continue
		case '#':
			if i > from && isSpace(src[i-1]) {
				return i
			}
		}
		i++
	}
	return -1
}

// scanShellLine emits comment and string regions for a single ordinary shell
// line [start,end).
func scanShellLine(src []byte, start, end int, regions *[]Span) {
	i := start
	for i < end {
		c := src[i]
		switch c {
		case '#':
			if i == start || isSpace(src[i-1]) {
				*regions = append(*regions, Span{i, end, Comment})
				return
			}
			i++
		case '\'':
			j := scanQuotedBounded(src, i+1, end, '\'', false)
			*regions = append(*regions, Span{i, j, StringLit})
			i = j
		case '"':
			j := scanQuotedBounded(src, i+1, end, '"', true)
			*regions = append(*regions, Span{i, j, StringLit})
			i = j
		default:
			i++
		}
	}
}

// emitEchoLine marks the argument text of an echo/printf line as InertText,
// splitting off a trailing comment.
func emitEchoLine(src []byte, start, end int, word string, regions *[]Span) {
	i := start
	for i < end && isSpace(src[i]) {
		i++
	}
	i += len(word) // leading whitespace + command word stay Code
	if i > end {
		i = end
	}
	argEnd := end
	if c := findShellComment(src, i, end); c >= 0 {
		argEnd = c
		*regions = append(*regions, Span{c, end, Comment})
	}
	if i < argEnd {
		*regions = append(*regions, Span{i, argEnd, InertText})
	}
}

func classifyShell(src []byte) []Span {
	n := len(src)
	var regions []Span

	hdActive := false
	hdStrip := false
	hdDelim := ""

	for _, ln := range splitLines(src) {
		if hdActive {
			content := src[ln.start:ln.end]
			cmp := content
			if hdStrip {
				cmp = trimLeadingTabs(content)
			}
			if string(cmp) == hdDelim {
				hdActive = false // terminator line is Code
				continue
			}
			regions = append(regions, Span{ln.start, ln.nlEnd, Heredoc})
			continue
		}

		word := firstWordOf(src, ln.start, ln.end)
		if word == "echo" || word == "printf" {
			emitEchoLine(src, ln.start, ln.end, word, &regions)
			continue
		}

		scanShellLine(src, ln.start, ln.end, &regions)
		if d, strip, ok := detectHeredoc(src[ln.start:ln.end]); ok {
			hdActive = true
			hdDelim = d
			hdStrip = strip
		}
	}
	return fillWith(n, regions, Code)
}

// --- markdown ---------------------------------------------------------------

func fenceMarker(content []byte) (ch byte, cnt int, ok bool) {
	i := 0
	for i < len(content) && i < 3 && content[i] == ' ' {
		i++
	}
	if i >= len(content) {
		return 0, 0, false
	}
	ch = content[i]
	if ch != '`' && ch != '~' {
		return 0, 0, false
	}
	for i < len(content) && content[i] == ch {
		cnt++
		i++
	}
	if cnt < 3 {
		return 0, 0, false
	}
	return ch, cnt, true
}

func onlyFenceChars(content []byte, ch byte) bool {
	for _, b := range content {
		if b != ch && b != ' ' && b != '\t' {
			return false
		}
	}
	return true
}

func classifyMarkdown(src []byte) []Span {
	n := len(src)
	var regions []Span

	inFence := false
	var fenceChar byte
	fenceLen := 0
	fenceStart := 0

	for _, ln := range splitLines(src) {
		content := src[ln.start:ln.end]
		ch, cnt, isFence := fenceMarker(content)
		if !inFence {
			if isFence {
				inFence = true
				fenceChar = ch
				fenceLen = cnt
				fenceStart = ln.start
			}
			continue
		}
		if isFence && ch == fenceChar && cnt >= fenceLen && onlyFenceChars(content, ch) {
			regions = append(regions, Span{fenceStart, ln.nlEnd, CodeFence})
			inFence = false
		}
	}
	if inFence {
		regions = append(regions, Span{fenceStart, n, CodeFence})
	}
	return fillWith(n, regions, Prose)
}
