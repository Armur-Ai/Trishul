// Component 6 — Encoded-content & obfuscation analysis.
//
// scanEncoded detects agent-instructions that are concealed from a human
// reviewer but still readable by an AI agent that parses raw repository text:
//
//   - AGENT-OBFS-001  invisible / bidirectional Unicode controls and zero-width
//     characters that hide or reorder visible text;
//   - AGENT-OBFS-002  homoglyph / confusable look-alike characters disguising a
//     security-relevant keyword (conservative);
//   - AGENT-OBFS-003  base64 / hex blobs that DECODE to instruction-like text
//     (decoded conceptually, in-process — nothing is ever executed);
//   - AGENT-OBFS-004  directives hidden inside HTML / Markdown comments that are
//     invisible when rendered but read from the raw source by an agent.
//
// Analysis is strictly passive and read-only: untrusted bytes are classified and
// (for base64/hex) decoded for inspection only, never run. The scanner is
// deliberately conservative — ordinary base64 assets, a leading BOM, emoji
// zero-width joiners and ordinary code comments must NOT be flagged; the
// encoded/hidden categories are elevated only when the recovered text looks like
// an agent instruction.
package agentsec

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

func init() { register(scanEncoded) }

// scanEncoded walks files an agent is likely to read and reports concealed
// instruction content. It never executes decoded or hidden bytes.
func scanEncoded(dir string) ([]AgentFinding, error) {
	var out []AgentFinding
	err := WalkFiles(dir, encRelevantFile, func(path string, content []byte) {
		rel := Rel(dir, path)
		text := string(content)
		lines := SplitLines(content)
		for i, line := range lines {
			ln := i + 1
			out = append(out, encScanUnicode(rel, line, ln, i == 0)...)
			out = append(out, encScanHomoglyph(rel, line, ln)...)
			out = append(out, encScanBlobs(rel, line, ln)...)
		}
		out = append(out, encScanComments(rel, text)...)
	})
	return out, err
}

// encRelevantFile matches the file types an agent reads as instructions or
// context: markdown, agent-config files, structured config, and source (for
// comments / embedded blobs).
func encRelevantFile(name, _ string) bool {
	lower := strings.ToLower(name)
	if encConfigNames[lower] {
		return true
	}
	for _, ext := range encExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

var encExts = []string{
	".md", ".markdown", ".mdx", ".txt", ".rst",
	".json", ".yml", ".yaml", ".toml", ".ini", ".env",
	".go", ".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".java", ".sh", ".html",
}

var encConfigNames = map[string]bool{
	".cursorrules": true, ".windsurfrules": true, ".clinerules": true,
	".aider.conf.yml": true, "agents.md": true, "claude.md": true,
	"gemini.md": true, "copilot-instructions.md": true,
}

// ---------------------------------------------------------------------------
// AGENT-OBFS-001 — invisible / bidirectional Unicode controls & zero-width chars
// ---------------------------------------------------------------------------

func encScanUnicode(rel, line string, ln int, firstLine bool) []AgentFinding {
	runes := []rune(line)
	var flagged []rune
	var cleaned strings.Builder
	for idx, r := range runes {
		if firstLine && idx == 0 && r == '\uFEFF' {
			continue // leading byte-order mark is benign
		}
		switch {
		case encIsBidiControl(r):
			flagged = append(flagged, r) // bidi overrides are a strong signal on their own
		case encIsZeroWidth(r):
			if encWordNeighbor(runes, idx) {
				flagged = append(flagged, r) // zero-width inside a word = concealment
			}
		default:
			cleaned.WriteRune(r)
		}
	}
	if len(flagged) == 0 {
		return nil
	}
	recovered := strings.TrimSpace(cleaned.String())
	sev, conf := "MEDIUM", "MEDIUM"
	if encLooksInstructionLike(recovered) {
		sev, conf = "HIGH", "HIGH"
	}
	return []AgentFinding{encNewFinding(
		"AGENT-OBFS-001",
		"Hidden/bidirectional Unicode concealing text",
		sev, conf, rel, ln,
		"hidden or reordered text can smuggle a directive past human review into the agent's context",
		[]string{
			"invisible/bidi Unicode controls present: " + encDescribeRunes(flagged),
			"de-obfuscated (controls stripped): \"" + encPreview(recovered) + "\"",
		},
		"some invisible characters occur benignly (BOM, emoji ZWJ); flagged only inside words or for bidi overrides, and raised to HIGH only when the de-obfuscated text is instruction-like",
		"Normalize and strip invisible/bidirectional Unicode from instruction and context files; treat any text that only appears after stripping controls as untrusted.",
	)}
}

func encIsBidiControl(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E: // LRE RLE PDF LRO RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI RLI FSI PDI
		return true
	case r == 0x061C: // Arabic Letter Mark
		return true
	}
	return false
}

func encIsZeroWidth(r rune) bool {
	switch r {
	case 0x200B, 0x200C, 0x200D, // ZWSP ZWNJ ZWJ
		0xFEFF, // ZW no-break space (non-leading)
		0x2060: // word joiner
		return true
	}
	return false
}

// encWordNeighbor reports whether the rune at idx is adjacent to a letter/digit,
// i.e. embedded within a word (the concealment pattern) rather than sitting
// between symbols or emoji.
func encWordNeighbor(runes []rune, idx int) bool {
	isWord := func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }
	if idx > 0 && isWord(runes[idx-1]) {
		return true
	}
	if idx+1 < len(runes) && isWord(runes[idx+1]) {
		return true
	}
	return false
}

func encDescribeRunes(rs []rune) string {
	seen := map[rune]int{}
	var order []rune
	for _, r := range rs {
		if seen[r] == 0 {
			order = append(order, r)
		}
		seen[r]++
	}
	parts := make([]string, 0, len(order))
	for _, r := range order {
		parts = append(parts, fmt.Sprintf("U+%04X x%d", r, seen[r]))
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// AGENT-OBFS-002 — homoglyph / confusable keyword disguise (conservative)
// ---------------------------------------------------------------------------

// encConfusable maps common Cyrillic/Greek look-alikes to their Latin twin.
var encConfusable = map[rune]rune{
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
	'і': 'i', 'ѕ': 's', 'к': 'k', 'т': 't', 'н': 'h', 'в': 'b', 'м': 'm',
	'ο': 'o', 'α': 'a', 'ε': 'e', 'ρ': 'p', 'ν': 'v', 'τ': 't', 'κ': 'k', 'ι': 'i',
}

// encKeywords are security-relevant words worth disguising; a token is flagged
// only when it carries a confusable AND normalizes exactly to one of these.
var encKeywords = map[string]bool{
	"ignore": true, "token": true, "curl": true, "system": true,
	"password": true, "secret": true, "sudo": true, "admin": true,
	"export": true, "bash": true, "wget": true, "exec": true, "eval": true,
}

func encScanHomoglyph(rel, line string, ln int) []AgentFinding {
	var out []AgentFinding
	for _, w := range encWords(line) {
		var b strings.Builder
		hasConfusable := false
		for _, r := range w {
			if m, ok := encConfusable[r]; ok {
				b.WriteRune(m)
				hasConfusable = true
			} else {
				b.WriteRune(unicode.ToLower(r))
			}
		}
		if !hasConfusable {
			continue
		}
		mapped := b.String()
		if len(mapped) < 3 || !encKeywords[mapped] {
			continue
		}
		out = append(out, encNewFinding(
			"AGENT-OBFS-002",
			"Homoglyph/confusable disguising a security keyword",
			"MEDIUM", "MEDIUM", rel, ln,
			"look-alike characters disguise a security keyword to evade human review and keyword filters",
			[]string{
				"mixed-script token with confusable characters: \"" + encPreview(w) + "\"",
				"normalizes to security keyword: \"" + mapped + "\"",
			},
			"conservative Cyrillic/Greek confusable map; flagged only when a token normalizes exactly to a known keyword, so sophisticated homoglyph sets may be missed",
			"Normalize identifiers/keywords to a single script (skeleton/confusable check) before trusting them; reject mixed-script security keywords.",
		))
	}
	return out
}

// encWords splits a line into maximal runs of letters.
func encWords(line string) []string {
	var words []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			words = append(words, cur.String())
			cur.Reset()
		}
	}
	for _, r := range line {
		if unicode.IsLetter(r) {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return words
}

// ---------------------------------------------------------------------------
// AGENT-OBFS-003 — base64 / hex blobs decoding to instruction-like text
// ---------------------------------------------------------------------------

func encScanBlobs(rel, line string, ln int) []AgentFinding {
	var out []AgentFinding
	for _, tok := range encB64Tokens(line) {
		if len(tok) < 24 {
			continue
		}
		if b, ok := encTryBase64(tok); ok && encIsPrintableText(b) && encLooksInstructionLike(string(b)) {
			out = append(out, encBlobFinding(rel, ln, "base64", tok, b))
			continue
		}
		if len(tok) >= 32 && len(tok)%2 == 0 && encAllHex(tok) {
			if b, ok := encTryHex(tok); ok && encIsPrintableText(b) && encLooksInstructionLike(string(b)) {
				out = append(out, encBlobFinding(rel, ln, "hex", tok, b))
			}
		}
	}
	return out
}

func encBlobFinding(rel string, ln int, kind, tok string, decoded []byte) AgentFinding {
	return encNewFinding(
		"AGENT-OBFS-003",
		"Encoded blob decodes to instruction-like text",
		"HIGH", "HIGH", rel, ln,
		"an encoded blob decodes to an instruction the agent could be induced to act on",
		[]string{
			fmt.Sprintf("%s blob (%d chars) decodes to printable, instruction-like text", kind, len(tok)),
			"decoded preview (redacted): \"" + encPreview(string(decoded)) + "\"",
		},
		"ordinary base64/hex assets exist (images, keys, hashes); flagged only when the decoded bytes are printable and contain agent-instruction phrases",
		"Do not decode-and-act on embedded blobs; treat decoded content as untrusted data and require explicit human review of any instruction it contains.",
	)
}

// encB64Tokens returns maximal runs of base64/base64url alphabet characters.
func encB64Tokens(line string) []string {
	isB64 := func(r rune) bool {
		return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '+' || r == '/' || r == '=' || r == '-' || r == '_'
	}
	var toks []string
	var cur strings.Builder
	for _, r := range line {
		if isB64(r) {
			cur.WriteRune(r)
		} else if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	if cur.Len() > 0 {
		toks = append(toks, cur.String())
	}
	return toks
}

func encTryBase64(tok string) ([]byte, bool) {
	for _, e := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := e.DecodeString(tok); err == nil && len(b) >= 4 {
			return b, true
		}
	}
	return nil, false
}

func encTryHex(tok string) ([]byte, bool) {
	if b, err := hex.DecodeString(tok); err == nil && len(b) >= 4 {
		return b, true
	}
	return nil, false
}

func encAllHex(tok string) bool {
	for _, r := range tok {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return len(tok) > 0
}

// encIsPrintableText reports whether the decoded bytes are overwhelmingly
// printable ASCII text (so binary assets — images, keys — are excluded).
func encIsPrintableText(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c <= 0x7E) {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) >= 0.85
}

// ---------------------------------------------------------------------------
// AGENT-OBFS-004 — directives hidden in HTML / Markdown comments
// ---------------------------------------------------------------------------

func encScanComments(rel, text string) []AgentFinding {
	var out []AgentFinding

	// HTML comments: <!-- ... --> (may span lines). Invisible when rendered,
	// read from raw source by an agent.
	idx := 0
	for {
		s := strings.Index(text[idx:], "<!--")
		if s < 0 {
			break
		}
		s += idx
		e := strings.Index(text[s+4:], "-->")
		if e < 0 {
			break
		}
		e += s + 4
		inner := text[s+4 : e]
		if encLooksInstructionLike(inner) {
			ln := strings.Count(text[:s], "\n") + 1
			out = append(out, encCommentFinding(rel, ln, "HTML", inner))
		}
		idx = e + 3
	}

	// Markdown "comment" link-label hacks: [//]: # (text) / [x]: <> (text).
	// These render to nothing but are present in the raw text.
	if encIsMarkdownFile(rel) {
		for i, line := range strings.Split(text, "\n") {
			if inner, ok := encMarkdownComment(line); ok && encLooksInstructionLike(inner) {
				out = append(out, encCommentFinding(rel, i+1, "Markdown", inner))
			}
		}
	}
	return out
}

func encCommentFinding(rel string, ln int, kind, inner string) AgentFinding {
	return encNewFinding(
		"AGENT-OBFS-004",
		"Directive hidden in a comment invisible when rendered",
		"HIGH", "HIGH", rel, ln,
		"a directive invisible in rendered output but parsed from raw text can reach the agent",
		[]string{
			kind + " comment is invisible when rendered but readable from the raw source",
			"hidden directive (redacted): \"" + encPreview(inner) + "\"",
		},
		"ordinary comments exist; flagged only when the hidden comment text is instruction-like",
		"Treat rendered and raw content as the same trust surface; strip or review comments in instruction/context files before an agent consumes them.",
	)
}

func encIsMarkdownFile(rel string) bool {
	l := strings.ToLower(rel)
	return strings.HasSuffix(l, ".md") || strings.HasSuffix(l, ".markdown") || strings.HasSuffix(l, ".mdx")
}

// encMarkdownComment recognizes the link-label comment forms and returns the
// hidden text.
func encMarkdownComment(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "[") {
		return "", false
	}
	i := strings.Index(t, "]:")
	if i < 0 {
		return "", false
	}
	rest := strings.TrimSpace(t[i+2:])
	if strings.HasPrefix(rest, "#") || strings.HasPrefix(rest, "<>") {
		return rest, true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

// encInstructionPhrases are lower-cased markers of agent-directed instructions.
// Applied ONLY to recovered/decoded/hidden content, never to raw source lines,
// so ordinary code (e.g. "export const") is not matched.
var encInstructionPhrases = []string{
	"ignore previous", "ignore all previous", "ignore the above", "ignore prior",
	"disregard previous", "disregard all", "disregard the above", "forget previous",
	"new instructions", "you are now", "system prompt", "system:", "assistant:",
	"curl ", "wget ", "sudo ", "rm -rf", "bash -c", "/bin/sh", "base64 -d",
	"api key", "api_key", "access token", "secret key", "password",
	"exfiltrate", "eval(", "exec(", "run:", "run ", " token",
}

func encLooksInstructionLike(s string) bool {
	l := strings.ToLower(s)
	for _, p := range encInstructionPhrases {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

// encPreview returns a short, whitespace-collapsed, length-capped preview so the
// evidence describes WHAT was concealed without reproducing a runnable payload.
func encPreview(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	const max = 80
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func encNewFinding(checkID, title, sev, conf, rel string, line int, enabled string, evidence []string, limitations, remediation string) AgentFinding {
	return AgentFinding{
		CheckID:          checkID,
		Title:            title,
		Severity:         sev,
		Confidence:       conf,
		EntryPoint:       rel,
		TrustBoundary:    "concealed instruction in untrusted content -> agent reads hidden directive",
		AffectedWorkflow: "an AI agent reads repository content/instructions",
		EnabledAction:    enabled,
		File:             rel,
		Line:             line,
		Evidence:         evidence,
		Limitations:      limitations,
		Remediation:      remediation,
		CWE:              "CWE-506, CWE-116",
	}
}
