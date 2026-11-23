package internal

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Armur-Ai/Trishul/internal/logger"
	utils "github.com/Armur-Ai/Trishul/pkg"
)

// RunFirebaseRules statically scans Firebase / Firestore / Cloud Storage
// security-rules files (*.rules, firestore.rules, storage.rules and any rules
// inlined into firebase.json) for insecure, over-permissive access rules — the
// "open data layer" class that commonly ships in AI-generated apps. It is a
// read-only defensive detector: it only FLAGS insecure configuration, it never
// writes, deletes, or exploits the target. It complements the Supabase RLS
// analyzer and emits its findings under the same INFRA_SECURITY category, with
// the same finding shape.
//
// The detector is deliberately conservative: a rule locked with `if false`, a
// rule gated by an ownership/`uid` predicate, or an admin-only
// (`request.auth.token.admin == true`) rule is treated as clean. It flags only
// the unambiguous over-exposure patterns described by FIREBASE-001..004.
func RunFirebaseRules(dir string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "firebase-rules").Str("dir", dir).Msg("running")

	categorized := utils.InitAdvancedCategorizedResults()

	// Context gate: only run the Firebase rule checks when the repo is actually a
	// Firebase project. A bare `*.rules` file name is ambiguous (udev, logrotate,
	// Snort and many other tools ship `.rules` files), so scanning every repo that
	// merely contains one is a precision problem. If none of the Firebase signals
	// are present we emit nothing.
	if !isFirebaseProject(dir) {
		logger.Debug().Str("tool", "firebase-rules").Str("dir", dir).Msg("not a firebase project; skipping")
		return utils.ConvertCategorizedResults(categorized), nil
	}

	findings, err := scanFirebaseDir(dir)
	if err != nil {
		return utils.ConvertCategorizedResults(categorized), nil
	}

	for _, f := range findings {
		categorized[utils.INFRA_SECURITY] = append(categorized[utils.INFRA_SECURITY], f)
	}

	return utils.ConvertCategorizedResults(categorized), nil
}

// errFirebaseSignal short-circuits the context-gate walk the moment any Firebase
// signal is found.
var errFirebaseSignal = errors.New("firebase signal")

// reFirebaseRulesSignal matches the tokens that only appear in a Firebase
// security-rules file: the `rules_version` pragma or a `service cloud.firestore`
// / `service firebase.storage` declaration.
var reFirebaseRulesSignal = regexp.MustCompile(`(?i)rules_version|service\s+cloud\.firestore|service\s+firebase\.storage`)

// reFirebaseDep matches a `firebase` or `@firebase/*` dependency entry in a
// package.json ("firebase": "..." or "@firebase/app": "...").
var reFirebaseDep = regexp.MustCompile(`"(?:firebase|@firebase/[^"]+)"\s*:`)

// isFirebaseProject reports whether directory looks like a Firebase project.
// Any one of the following signals qualifies it:
//   - a `firebase.json` config exists;
//   - a canonically named `firestore.rules` / `storage.rules` (or
//     `database.rules.json`) file exists;
//   - a `*.rules` file carries a Firebase rules signal (`rules_version`,
//     `service cloud.firestore`, `service firebase.storage`);
//   - a `firebase` / `@firebase/*` dependency appears in a package.json.
//
// It is read-only and skips vendored trees (node_modules, .git, vendor) so a
// dependency's own files do not mask the project's real intent. With no signal
// the caller emits nothing.
func isFirebaseProject(directory string) bool {
	// Fast path: the canonical firebase.json at the repo root.
	if _, err := os.Stat(filepath.Join(directory, "firebase.json")); err == nil {
		return true
	}

	walkErr := filepath.WalkDir(directory, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "vendor":
				return filepath.SkipDir
			}
			return nil
		}

		lower := strings.ToLower(d.Name())
		switch {
		case lower == "firebase.json" ||
			lower == "firestore.rules" ||
			lower == "storage.rules" ||
			lower == "database.rules.json":
			return errFirebaseSignal
		case strings.HasSuffix(lower, ".rules"):
			if content, readErr := os.ReadFile(path); readErr == nil && reFirebaseRulesSignal.Match(content) {
				return errFirebaseSignal
			}
		case lower == "package.json":
			if content, readErr := os.ReadFile(path); readErr == nil && reFirebaseDep.Match(content) {
				return errFirebaseSignal
			}
		}
		return nil
	})

	return errors.Is(walkErr, errFirebaseSignal)
}

// fbFrame is one entry on the brace stack. isMatch is true when the block was
// opened by a `match <path> { ... }` construct (as opposed to a service{} or
// function(){} block), in which case path holds the match path pattern.
//
// A match frame accumulates every `allow` statement lexically inside it so the
// block's *effective* (OR-combined) access can be evaluated when the block
// closes — Firestore/Storage grant access if ANY allow matches, so two separate
// `allow read: if true;` / `allow write: if true;` statements combine into a
// world read+write block that a per-statement view would miss.
type fbFrame struct {
	path    string
	isMatch bool
	service string
	allows  []fbAllow
}

// fbAllow is one parsed `allow` statement within a match block.
type fbAllow struct {
	line        int
	coversRead  bool
	coversWrite bool
	always      bool // effectively "if true" or an unconditional allow
	authOnly    bool // condition is exactly `request.auth != null`
	hasCond     bool // a condition was written (distinguishes `if true` from a bare allow)
}

// scanFirebaseDir walks directory (read-only) for Firebase rules files and
// returns deterministic findings. It is exported for testing via a temp dir of
// sample rules.
func scanFirebaseDir(directory string) ([]map[string]interface{}, error) {
	var findings []map[string]interface{}

	walkErr := filepath.WalkDir(directory, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries rather than aborting the whole scan
		}
		if d.IsDir() {
			return nil
		}
		if !isFirebaseRulesFile(d.Name()) {
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}

		// A generic `*.rules` file (not the canonical firestore.rules/storage.rules)
		// is only treated as Firebase rules when its content actually carries a
		// Firebase rules signal. This keeps unrelated `.rules` files (udev, Snort,
		// logrotate, …) that happen to live in a Firebase repo from being parsed as
		// security rules.
		if strings.HasSuffix(strings.ToLower(d.Name()), ".rules") &&
			!isNamedFirebaseRules(d.Name()) &&
			!reFirebaseRulesSignal.Match(content) {
			return nil
		}

		relPath := path
		if rel, relErr := filepath.Rel(directory, path); relErr == nil {
			relPath = rel
		}

		findings = append(findings, scanFirebaseFile(string(content), relPath, defaultServiceFor(d.Name()))...)
		return nil
	})
	if walkErr != nil {
		return findings, walkErr
	}

	// Reuse the package-shared deterministic sort (defined in supabase.go).
	sortFindings(findings)
	return findings, nil
}

// isFirebaseRulesFile reports whether a file name is a Firebase rules file or a
// firebase.json config that may inline rules.
func isFirebaseRulesFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".rules") || lower == "firebase.json"
}

// isNamedFirebaseRules reports whether name is one of the canonical Firebase
// rules file names, which are a strong enough signal to scan unconditionally.
func isNamedFirebaseRules(name string) bool {
	lower := strings.ToLower(name)
	return lower == "firestore.rules" || lower == "storage.rules"
}

// defaultServiceFor picks the service context for a file before any explicit
// `service` declaration is seen. storage.rules (and any *storage*.rules) default
// to the storage service; everything else defaults to firestore.
func defaultServiceFor(name string) string {
	if strings.Contains(strings.ToLower(name), "storage") {
		return "storage"
	}
	return "firestore"
}

// scanFirebaseFile parses one rules file into match/allow structure and returns
// its findings. It tracks the service context (firestore vs storage) and the
// nested match-path stack so each `allow` is evaluated against the block that
// encloses it.
func scanFirebaseFile(content, relPath, defaultService string) []map[string]interface{} {
	s := stripFirebaseNoise(content)
	n := len(s)

	var out []map[string]interface{}
	var stack []fbFrame
	service := defaultService

	i, lineNo := 0, 1
	// advance moves i forward to `to`, counting newlines so lineNo stays accurate
	// across multi-character spans (paths, allow statements, etc.).
	advance := func(to int) {
		for ; i < to && i < n; i++ {
			if s[i] == '\n' {
				lineNo++
			}
		}
	}

	for i < n {
		c := s[i]
		switch {
		case c == '\n':
			lineNo++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '}':
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				// A closing match block: evaluate its effective (OR-combined) access.
				if top.isMatch {
					if f, ok := classifyFirebaseBlock(top, relPath); ok {
						out = append(out, f)
					}
				}
			}
			i++
		case c == '{':
			// A block brace not attached to a match (service{} / function(){}).
			stack = append(stack, fbFrame{isMatch: false})
			i++
		case fbIsIdentStart(c):
			j := i
			for j < n && fbIsIdentChar(s[j]) {
				j++
			}
			word := s[i:j]
			switch word {
			case "service":
				k := fbSkipInlineWS(s, j)
				m := k
				for m < n && s[m] != '{' && !fbIsWS(s[m]) {
					m++
				}
				name := s[k:m]
				if strings.Contains(name, "storage") {
					service = "storage"
				} else if strings.Contains(name, "firestore") {
					service = "firestore"
				}
				advance(m)
			case "match":
				k := fbSkipInlineWS(s, j)
				// The path is the whole non-whitespace run after `match`. It may
				// itself contain balanced `{wildcard}` segments (e.g.
				// `/users/{userId}`, `/{document=**}`); the block-opening `{` is a
				// separate token that follows after whitespace, so we must NOT stop
				// the path at `{`.
				p := k
				for p < n && !fbIsWS(s[p]) {
					p++
				}
				path := s[k:p]
				q := p
				for q < n && fbIsWS(s[q]) {
					q++
				}
				advance(q)
				if q < n && s[q] == '{' {
					stack = append(stack, fbFrame{path: path, isMatch: true, service: service})
					i = q + 1
				} else {
					i = q
				}
			case "allow":
				startLine := lineNo
				k := j
				for k < n && s[k] != ';' && s[k] != '{' && s[k] != '}' {
					k++
				}
				stmt := s[i:k]
				a := parseFirebaseAllow(stmt, startLine)
				// Attach the allow to the innermost enclosing match block; an allow
				// outside any match is invalid and ignored.
				for idx := len(stack) - 1; idx >= 0; idx-- {
					if stack[idx].isMatch {
						stack[idx].allows = append(stack[idx].allows, a)
						break
					}
				}
				advance(k)
			default:
				advance(j)
			}
		default:
			i++
		}
	}

	return out
}

// parseFirebaseAllow parses one `allow ...` statement into its method coverage
// and an effective classification of its condition. It does not know the
// enclosing path/service — that context is applied per block in
// classifyFirebaseBlock.
func parseFirebaseAllow(stmt string, line int) fbAllow {
	rest := strings.TrimSpace(strings.TrimPrefix(stmt, "allow"))

	methodsPart := rest
	condPart := ""
	hasCond := false
	if idx := strings.Index(rest, ":"); idx >= 0 {
		methodsPart = rest[:idx]
		condPart = strings.TrimSpace(rest[idx+1:])
		// Strip a leading `if` keyword (with or without a following space/paren).
		if condPart == "if" {
			condPart = ""
		} else if strings.HasPrefix(condPart, "if ") || strings.HasPrefix(condPart, "if\t") {
			condPart = strings.TrimSpace(condPart[2:])
		} else if strings.HasPrefix(condPart, "if(") {
			condPart = strings.TrimSpace(condPart[2:])
		}
		hasCond = condPart != ""
	}

	methods := fbParseMethods(methodsPart)
	always, authOnly := fbClassifyCond(condPart, hasCond)

	return fbAllow{
		line:        line,
		coversRead:  fbCoversRead(methods),
		coversWrite: fbCoversWrite(methods),
		always:      always,
		authOnly:    authOnly,
		hasCond:     hasCond,
	}
}

// fbClassifyCond reduces an allow condition to the two states the detector acts
// on: `always` (effectively `if true` / unconditional) and `authOnly` (exactly
// `request.auth != null`, i.e. any signed-in user with no ownership check).
// Surrounding parentheses are stripped first so `if (true)` and
// `if (request.auth != null)` are classified the same as their unparenthesized
// forms. Any other (non-trivial) condition is treated as safe.
func fbClassifyCond(condPart string, hasCond bool) (always, authOnly bool) {
	norm := fbStripOuterParens(fbRemoveSpaces(condPart))
	always = !hasCond || norm == "true"
	if norm == "false" {
		always = false
	}
	authOnly = norm == "request.auth!=null" || norm == "null!=request.auth"
	return always, authOnly
}

// fbStripOuterParens removes fully-enclosing parentheses from an already
// space-stripped condition, repeatedly (so `((true))` → `true`). It only strips
// a pair when the opening paren matches the final closing paren, so a condition
// like `(a)&&(b)` is left untouched.
func fbStripOuterParens(s string) string {
	for len(s) >= 2 && s[0] == '(' && s[len(s)-1] == ')' {
		depth := 0
		matched := true
		for i := 0; i < len(s); i++ {
			switch s[i] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 && i != len(s)-1 {
					matched = false
				}
			}
			if !matched {
				break
			}
		}
		if !matched || depth != 0 {
			break
		}
		s = s[1 : len(s)-1]
	}
	return s
}

// classifyFirebaseBlock evaluates the EFFECTIVE (OR-combined) access granted by
// a match block — i.e. the union of every `allow` statement it contains, since
// a request is permitted if any allow matches — and returns the one most-severe
// finding it warrants (or ok=false when the block is safe). Evaluating the whole
// block rather than each statement independently lets two separate
// `allow read: if true;` / `allow write: if true;` lines combine into a single
// world read+write finding, and collapses a catch-all that is split across
// several allows into one finding instead of several.
func classifyFirebaseBlock(f fbFrame, relPath string) (map[string]interface{}, bool) {
	np := fbRemoveSpaces(f.path)
	isDocWild := strings.Contains(np, "{document=**}")
	isAllPaths := strings.Contains(np, "{allPaths=**}")
	hasWildcard := strings.Contains(np, "{")
	isStorage := f.service == "storage"

	pathLabel := strings.TrimSpace(f.path)
	if pathLabel == "" {
		pathLabel = "(root)"
	}

	// Effective state across every allow in the block.
	var readAlways, writeAlways, readAuth, writeAuth bool
	alwaysLine, authLine := 0, 0
	alwaysHasCond := false
	for _, a := range f.allows {
		if a.always {
			if a.coversRead {
				readAlways = true
			}
			if a.coversWrite {
				writeAlways = true
			}
			if (a.coversRead || a.coversWrite) && alwaysLine == 0 {
				alwaysLine = a.line
				alwaysHasCond = a.hasCond
			}
		}
		if a.authOnly {
			if a.coversRead {
				readAuth = true
			}
			if a.coversWrite {
				writeAuth = true
			}
			if (a.coversRead || a.coversWrite) && authLine == 0 {
				authLine = a.line
			}
		}
	}

	switch {
	case isStorage && (writeAlways || (isAllPaths && (readAlways || writeAlways))):
		// FIREBASE-003 — Storage: unconditional write / public-bucket exposure.
		return firebaseFinding(relPath, alwaysLine, "HIGH", "HIGH", "FIREBASE-003", []string{"CWE-668"},
			"Cloud Storage match `"+pathLabel+"` grants an unconditional allow ("+fbAlwaysReason(alwaysHasCond)+"); stored objects are world-writable/readable with no authorization.",
			"Require authentication and ownership before writing, e.g. `allow write: if request.auth != null && request.auth.uid == <ownerSegment>;`, and never leave a `match /{allPaths=**}` block with an unconditional allow.",
		), true

	case !isStorage && readAlways && writeAlways:
		// FIREBASE-001 — world-readable AND world-writable Firestore data. The two
		// grants may come from a single `allow read, write` or from separate
		// always-true read and write allows in the same block.
		return firebaseFinding(relPath, alwaysLine, "CRITICAL", "HIGH", "FIREBASE-001", []string{"CWE-284"},
			"Firestore match `"+pathLabel+"` effectively grants `read, write` with "+fbAlwaysReason(alwaysHasCond)+"; the data is world-readable and world-writable by any client, authenticated or not.",
			"Gate the rule behind an ownership/auth predicate, e.g. `allow read, write: if request.auth != null && request.auth.uid == resource.data.ownerId;`. Never ship `allow read, write: if true;`.",
		), true

	case !isStorage && isDocWild && (readAlways || writeAlways):
		// FIREBASE-004 — broad {document=**} catch-all with a permissive allow.
		return firebaseFinding(relPath, alwaysLine, "MEDIUM", "HIGH", "FIREBASE-004", []string{"CWE-732"},
			"Firestore match `"+pathLabel+"` is a broad `{document=**}` catch-all with a permissive, unconditional allow; it overrides more specific rules and exposes the whole database.",
			"Remove the catch-all allow or scope it behind auth/ownership, and grant access per-collection with explicit ownership predicates instead.",
		), true

	case hasWildcard && (readAuth || writeAuth):
		// FIREBASE-002 — any-authenticated-user access with no ownership check.
		methodLabel := fbMethodLabel(readAuth, writeAuth)
		return firebaseFinding(relPath, authLine, "HIGH", "MEDIUM", "FIREBASE-002", []string{"CWE-285"},
			"Firestore/Storage match `"+pathLabel+"` allows `"+methodLabel+"` for any authenticated user (`request.auth != null`) with no ownership check; any signed-in user can access every document in the collection.",
			"Scope the rule to the resource owner, e.g. `allow "+methodLabel+": if request.auth != null && request.auth.uid == resource.data.ownerId;`.",
		), true
	}

	return nil, false
}

// fbMethodLabel renders a human-readable method list from the read/write flags.
func fbMethodLabel(read, write bool) string {
	switch {
	case read && write:
		return "read, write"
	case write:
		return "write"
	case read:
		return "read"
	default:
		return "read, write"
	}
}

// fbAlwaysReason describes why a rule counts as always-allow, for the message.
func fbAlwaysReason(hasCond bool) string {
	if hasCond {
		return "an always-true condition (`if true`)"
	}
	return "no condition (unconditional allow)"
}

func firebaseFinding(relPath string, line int, severity, confidence, checkID string, cwes []string, message, remediation string) map[string]interface{} {
	return map[string]interface{}{
		"path":        relPath,
		"line":        line,
		"message":     message,
		"severity":    severity,
		"check_id":    checkID,
		"cwe":         cwes,
		"confidence":  confidence,
		"remediation": remediation,
	}
}

// fbParseMethods splits the method list of an allow statement ("read, write")
// into normalized lowercase tokens.
func fbParseMethods(methodsPart string) []string {
	var out []string
	for _, p := range strings.Split(methodsPart, ",") {
		m := strings.ToLower(strings.TrimSpace(p))
		if m != "" {
			out = append(out, m)
		}
	}
	return out
}

func fbCoversRead(methods []string) bool {
	for _, m := range methods {
		switch m {
		case "read", "get", "list":
			return true
		}
	}
	return false
}

func fbCoversWrite(methods []string) bool {
	for _, m := range methods {
		switch m {
		case "write", "create", "update", "delete":
			return true
		}
	}
	return false
}

func fbRemoveSpaces(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func fbIsWS(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func fbSkipInlineWS(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

func fbIsIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}

func fbIsIdentChar(c byte) bool {
	return fbIsIdentStart(c) || (c >= '0' && c <= '9')
}

// stripFirebaseNoise removes // line comments, # line comments, /* block */
// comments, and blanks out string-literal interiors (keeping the quotes),
// preserving newlines so line numbers stay accurate. Blanking string interiors
// prevents a stray `{`, `}`, `match` or `allow` inside a string from confusing
// the block/keyword scanner. Suppressing content this way can only ever hide a
// finding, never invent one, keeping the detector conservative.
func stripFirebaseNoise(content string) string {
	var sb strings.Builder
	n := len(content)
	for i := 0; i < n; {
		c := content[i]
		switch {
		case c == '/' && i+1 < n && content[i+1] == '/':
			for i < n && content[i] != '\n' {
				i++
			}
		case c == '#':
			for i < n && content[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && content[i+1] == '*':
			i += 2
			for i+1 < n && !(content[i] == '*' && content[i+1] == '/') {
				if content[i] == '\n' {
					sb.WriteByte('\n')
				}
				i++
			}
			if i+1 < n {
				i += 2
			} else {
				i = n
			}
		case c == '"' || c == '\'':
			quote := c
			sb.WriteByte(c)
			i++
			for i < n && content[i] != quote {
				if content[i] == '\\' && i+1 < n {
					// Skip the escaped char so an escaped quote doesn't end the string.
					sb.WriteByte(' ')
					i += 2
					continue
				}
				if content[i] == '\n' {
					sb.WriteByte('\n')
				} else {
					sb.WriteByte(' ')
				}
				i++
			}
			if i < n {
				sb.WriteByte(content[i]) // closing quote
				i++
			}
		default:
			sb.WriteByte(c)
			i++
		}
	}
	return sb.String()
}
