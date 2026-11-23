package internal

// Client-exposed-secret analyzer (Vibe Top 10 "V01: secrets shipped to the
// client"). A defensive, read-only detector for secrets that leak into
// client/browser bundles — a failure mode that is common in AI-generated web
// apps where a provider key or a privileged token is dropped into front-end
// code or a public-prefixed environment variable.
//
// The detector only ever FLAGS exposure. It never exfiltrates, mutates or
// writes anything, and — exactly like trufflehog.go — it never emits a raw
// secret value: every finding carries only a redacted preview (redact.Mask)
// and a stable fingerprint (redact.Fingerprint).
//
// Findings are returned under the same category trufflehog uses,
// utils.SECRET_DETECTION, so this analyzer slots into the existing pipeline.

import (
	"encoding/base64"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Armur-Ai/Trishul/internal/fileclass"
	"github.com/Armur-Ai/Trishul/internal/logger"
	"github.com/Armur-Ai/Trishul/internal/redact"
	utils "github.com/Armur-Ai/Trishul/pkg"
)

// Check identifiers emitted by this analyzer.
const (
	// checkPublicPrefix: a secret-shaped value assigned to a client-exposed
	// environment variable (NEXT_PUBLIC_, VITE_, ...). These are inlined into
	// the client bundle at build time and are publicly readable.
	checkPublicPrefix = "CLIENT-SECRET-001"
	// checkCommittedEnv: a committed .env file carrying a secret-shaped
	// assignment.
	checkCommittedEnv = "CLIENT-SECRET-002"
	// checkClientSideStrong: a high-confidence privileged secret (Supabase
	// service_role JWT, private key, or sk-style provider key) appearing in a
	// source file. Severity is CRITICAL when the file ships to the browser and
	// is otherwise adjusted by the file's classification.
	checkClientSideStrong = "CLIENT-SECRET-003"
)

// maxScanFileSize bounds how large a file we are willing to read into memory.
const maxScanFileSize = int64(2 << 20) // 2 MiB

// minSecretLen is the minimum length for a value to be considered "key-shaped".
const minSecretLen = 20

// minSecretEntropy is the Shannon-entropy floor (bits/char) a generic
// (non-provider-format) key-shaped value must exceed to be flagged. Random
// tokens sit well above this; prose and identifiers sit below it, which keeps
// false positives down. Values matching a known provider format bypass this
// gate (see matchesProviderFormat).
const minSecretEntropy = 3.5

var (
	// publicAssignRe matches an assignment to a client-exposed env variable,
	// capturing the variable name (group 1) and the right-hand side (group 2).
	// Longer prefixes are listed first so they win the leftmost-first match.
	publicAssignRe = regexp.MustCompile(
		`(?:^|[^A-Za-z0-9_])((?:NEXT_PUBLIC_|EXPO_PUBLIC_|REACT_APP_|VITE_|PUBLIC_)[A-Za-z0-9_]+)\s*[:=]\s*(.+)$`)

	// envAssignRe matches a generic KEY=value line in a .env file.
	envAssignRe = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$`)

	// jwtRe matches a three-segment JWT whose segments are base64url.
	jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}`)

	// skKeyRe matches sk-style provider keys (OpenAI sk-, sk-proj-, Anthropic
	// sk-ant-, ...). A leading non-word guard avoids matching mid-identifier.
	skKeyRe = regexp.MustCompile(`(?:^|[^A-Za-z0-9])(sk-[A-Za-z0-9_-]{16,})`)

	// privKeyRe matches a PEM private-key header.
	privKeyRe = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`)

	// stripeTestKeyRe matches Stripe test-mode keys (sk_test_, pk_test_,
	// rk_test_), which are safe to expose and carry no production access.
	stripeTestKeyRe = regexp.MustCompile(`(?:sk|pk|rk)_test_[A-Za-z0-9]{8,}`)

	// firebaseWebKeyRe matches a Firebase / Google-style browser API key
	// (AIza...). Firebase intends these to ship in the client web config; they
	// are gated by security rules, not by secrecy.
	firebaseWebKeyRe = regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)

	// providerFormatRes are distinctive provider credential shapes. A value
	// matching any of them is treated as key-shaped regardless of entropy.
	providerFormatRes = []*regexp.Regexp{
		jwtRe,
		privKeyRe,
		skKeyRe,
		regexp.MustCompile(`(?:sk|pk|rk)_(?:test|live)_[A-Za-z0-9]{8,}`), // Stripe
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                           // AWS access key id
		regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),                 // GitHub tokens
		regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),               // Slack tokens
		firebaseWebKeyRe, // Google/Firebase API key
		credURLRe,        // scheme://user:pass@host
	}

	// credURLRe matches a URL carrying userinfo with a password
	// (scheme://user:pass@host), i.e. an embedded credential.
	credURLRe = regexp.MustCompile(`://[^/\s:@]+:[^/\s:@]+@`)
)

// emulatorDefaults are well-known, non-secret values baked into local emulator
// and demo stacks (Supabase/Firebase emulators, demo projects). They look
// key-shaped but grant no production access, so findings carrying them are
// downgraded rather than suppressed.
var emulatorDefaults = map[string]bool{
	// Firebase Auth emulator demo values.
	"demo-project":     true,
	"fake-api-key":     true,
	"demo-api-key":     true,
	"AIzaSyFake-local": true,
}

// clientSideEnvPrefixes documents the prefixes publicAssignRe recognises. It is
// used only to keep .env scanning from double-reporting those lines.
var clientSideEnvPrefixes = []string{"NEXT_PUBLIC_", "EXPO_PUBLIC_", "REACT_APP_", "VITE_", "PUBLIC_"}

// skipDirs are directories we never descend into.
var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, "dist": true, "build": true,
	".next": true, "out": true, "vendor": true, "coverage": true,
	".turbo": true, ".cache": true, ".svelte-kit": true,
}

// scannableExts are the source extensions we inspect (in addition to .env files).
var scannableExts = map[string]bool{
	".js": true, ".jsx": true, ".ts": true, ".tsx": true,
	".mjs": true, ".cjs": true, ".vue": true, ".svelte": true, ".astro": true,
}

// clientDirSegments are path segments that strongly imply a file ships to the
// browser.
var clientDirSegments = map[string]bool{
	"src": true, "app": true, "components": true,
	"pages": true, "screens": true, "views": true,
}

// finding is an internal, redacted representation of a single exposure. It
// deliberately holds no raw secret: preview and fingerprint are derived up
// front and the plaintext is dropped.
type finding struct {
	path        string
	line        int
	message     string
	severity    string
	checkID     string
	cwe         string
	preview     string
	fingerprint string
}

// newFinding builds a finding, redacting raw at the boundary so the plaintext
// never reaches a field, a message, or a sink.
func newFinding(path string, line int, severity, checkID, cwe, message, raw string) finding {
	return finding{
		path:        path,
		line:        line,
		message:     message,
		severity:    severity,
		checkID:     checkID,
		cwe:         cwe,
		preview:     redact.Mask(raw),
		fingerprint: redact.Fingerprint(raw),
	}
}

// toMap renders a finding in the SECRET_DETECTION result shape used across the
// pipeline (mirroring trufflehog.go) plus the check metadata this analyzer adds.
func (f finding) toMap() map[string]interface{} {
	return map[string]interface{}{
		"path":           f.path,
		"line":           f.line,
		"message":        f.message,
		"severity":       f.severity,
		"check_id":       f.checkID,
		"cwe":            f.cwe,
		"secret_preview": f.preview,
		"fingerprint":    f.fingerprint,
	}
}

// RunClientSecretExposure walks dir (read-only) and reports secrets that are
// exposed to the client/browser. It returns results under utils.SECRET_DETECTION
// and never emits a raw secret value.
func RunClientSecretExposure(dir string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "clientsecrets").Str("dir", dir).Msg("running")

	results := utils.InitAdvancedCategorizedResults()
	envIgnored := envInGitignore(dir)
	seen := map[string]bool{}

	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable entry: skip it, keep scanning the rest.
			return nil
		}
		if d.IsDir() {
			if path != dir && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !isScannableFile(d.Name()) {
			return nil
		}
		if info, e := d.Info(); e == nil && info.Size() > maxScanFileSize {
			return nil
		}
		data, e := os.ReadFile(path)
		if e != nil {
			return nil
		}

		rel, e := filepath.Rel(dir, path)
		if e != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		for _, f := range analyzeFile(rel, d.Name(), string(data), envIgnored) {
			key := f.checkID + "|" + f.path + "|" + strconv.Itoa(f.line) + "|" + f.fingerprint
			if seen[key] {
				continue
			}
			seen[key] = true
			results[utils.SECRET_DETECTION] = append(results[utils.SECRET_DETECTION], f.toMap())
		}
		return nil
	})

	if walkErr != nil {
		logger.Warn().Str("tool", "clientsecrets").Err(walkErr).Msg("walk failed, returning partial results")
		return utils.ConvertCategorizedResults(results), walkErr
	}
	return utils.ConvertCategorizedResults(results), nil
}

// analyzeFile produces findings for a single file's content.
func analyzeFile(rel, name, content string, envIgnored bool) []finding {
	var out []finding

	// Rule 002: a committed .env file (not an example/template) carrying
	// secret-shaped assignments.
	if isEnvFile(name) && !isEnvExampleFile(name) {
		out = append(out, scanEnvFile(rel, content, envIgnored)...)
	}

	// i18n / locale string tables are translation text, not credentials. Skip
	// the source-scanning rules for them (an .env still scans above).
	if isI18nPath(rel) {
		return out
	}

	kind := fileclass.ClassifyPath(rel)
	clientSide := looksClientSide(rel, content)

	// Rule 001: secret-shaped values assigned to client-exposed env prefixes.
	for i, line := range strings.Split(content, "\n") {
		if isNonSecretContext(line) {
			continue
		}
		m := publicAssignRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		val := cleanValue(m[2])
		if isIgnorableKey(m[1], val) || !isSecretShaped(val) {
			continue
		}
		var sev, msg string
		if isKnownPublicKey(val) {
			sev = "LOW"
			msg = "Client-exposed environment variable '" + m[1] + "' holds a known-public value " +
				"(test key, browser API key, or emulator default). It is inlined into the client bundle, " +
				"which is expected for this kind of value; confirm it is not a production secret."
		} else {
			sev = resolveSeverity("HIGH", kind, matchesProviderFormat(val), isHighEntropy(val))
			msg = "Client-exposed environment variable '" + m[1] + "' is assigned a secret-shaped value. " +
				"Variables with this prefix are inlined into the client/browser bundle at build time and are publicly readable."
		}
		out = append(out, newFinding(rel, i+1, sev, checkPublicPrefix, "CWE-200", msg, val))
	}

	// Rule 003: high-confidence privileged secrets. A service_role JWT, a PEM
	// private key or an sk-style provider key is dangerous wherever it lands —
	// not only in files that ship to the browser — so this scans every source
	// file (committed .env files are covered by rule 002 above).
	if !isEnvFile(name) {
		out = append(out, scanStrongSecrets(rel, content, kind, clientSide)...)
	}

	return out
}

// isHighEntropy reports whether v clears the generic length+entropy bar used to
// treat a value as a real (rather than placeholder) secret.
func isHighEntropy(v string) bool {
	v = strings.TrimSpace(v)
	return len(v) >= minSecretLen && shannonEntropy(v) >= minSecretEntropy
}

// resolveSeverity adjusts a base severity for the file's classification: in
// test/fixture files a secret is informational (INFO) unless it is a
// high-confidence provider-format, high-entropy credential, in which case the
// base severity stands. Other kinds keep the base severity.
func resolveSeverity(base string, kind fileclass.Kind, providerFormat, highEntropy bool) string {
	switch kind {
	case fileclass.KindTest, fileclass.KindFixture:
		if providerFormat && highEntropy {
			return base
		}
		return "INFO"
	default:
		return base
	}
}

// isNonSecretContext reports whether a line sits in a context where a
// secret-shaped token is almost certainly not a live credential: UI attributes
// that merely display example text (placeholder=, aria-label, title=) and test
// typing calls that feed a string into an input (.type(...), fill(...)).
func isNonSecretContext(line string) bool {
	lower := strings.ToLower(line)
	for _, marker := range []string{"placeholder=", "aria-label", "title=", ".type(", "fill("} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// isI18nPath reports whether a file path lives in an i18n / localization
// string-table tree, whose values are translation text rather than secrets.
func isI18nPath(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		switch strings.ToLower(seg) {
		case "locales", "locale", "i18n", "translations", "lang", "langs", "messages":
			return true
		}
	}
	return false
}

// scanEnvFile reports secret-shaped assignments in a committed .env file. Lines
// using a client-exposed prefix are left to rule 001 to avoid double-reporting.
func scanEnvFile(rel, content string, envIgnored bool) []finding {
	var out []finding
	gitignoreNote := ""
	if !envIgnored {
		gitignoreNote = " The .env file does not appear to be listed in .gitignore, so it may be committed to version control."
	}

	for i, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := envAssignRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if hasClientPrefix(m[1]) {
			continue // handled by rule 001
		}
		val := cleanValue(m[2])
		if isIgnorableKey(m[1], val) || !isSecretShaped(val) {
			continue
		}
		sev := "HIGH"
		msg := "Committed .env file assigns a secret-shaped value to '" + m[1] + "'. " +
			"Secrets stored in env files are exposed to anyone with repository access." + gitignoreNote
		if isKnownPublicKey(val) {
			sev = "LOW"
			msg = "Committed .env file assigns a known-public value (test key, browser API key, " +
				"or emulator default) to '" + m[1] + "'. This grants no production access; " +
				"confirm it is not a real secret." + gitignoreNote
		}
		out = append(out, newFinding(rel, i+1, sev, checkCommittedEnv, "CWE-312", msg, val))
	}
	return out
}

// scanStrongSecrets reports high-confidence privileged secrets (service_role
// JWTs, sk-style provider keys, PEM private keys) found anywhere in a file. The
// finding's severity and wording depend on where the secret lives: a file that
// ships to the browser is CRITICAL ("...and ships to the browser"); anywhere
// else the base severity is adjusted by the file's classification, and the
// wording stays neutral so it reads correctly for server and test paths.
func scanStrongSecrets(rel, content string, kind fileclass.Kind, clientSide bool) []finding {
	var out []finding

	base := "CRITICAL"
	if !clientSide {
		base = "HIGH"
	}
	loc := locationPhrase(rel, clientSide)

	// Supabase service_role JWTs (and any JWT whose payload claims service_role).
	for _, tok := range jwtRe.FindAllString(content, -1) {
		if !jwtHasServiceRole(tok) {
			continue
		}
		ln := lineOf(content, tok)
		if isNonSecretContext(lineText(content, ln)) {
			continue
		}
		if isKnownPublicKey(tok) {
			out = append(out, newFinding(rel, ln, "LOW", checkClientSideStrong, "CWE-798",
				"A known-public demo JWT (Supabase/Firebase emulator) appears in "+loc+". "+
					"It grants no production access; confirm it is not a real service_role token.",
				tok))
			continue
		}
		out = append(out, newFinding(rel, ln, resolveSeverity(base, kind, true, true), checkClientSideStrong, "CWE-798",
			"A Supabase service_role JWT appears in "+loc+". "+
				"This token bypasses row-level security and must never be committed to source or exposed to clients.",
			tok))
	}

	// sk-style provider keys (OpenAI, Anthropic, ...).
	for _, m := range skKeyRe.FindAllStringSubmatch(content, -1) {
		tok := m[1]
		ln := lineOf(content, tok)
		if isNonSecretContext(lineText(content, ln)) {
			continue
		}
		if isKnownPublicKey(tok) {
			out = append(out, newFinding(rel, ln, "LOW", checkClientSideStrong, "CWE-798",
				"A known-public test provider key appears in "+loc+". "+
					"Test-mode keys carry no production access; confirm it is not a live key.",
				tok))
			continue
		}
		out = append(out, newFinding(rel, ln, resolveSeverity(base, kind, true, true), checkClientSideStrong, "CWE-798",
			"A provider API key (sk-style) appears in "+loc+". "+
				"Secret provider keys must never be committed to source or shipped to clients, where they can be extracted and abused.",
			tok))
	}

	// PEM private keys.
	if loc := privKeyRe.FindStringIndex(content); loc != nil {
		marker := content[loc[0]:loc[1]]
		ln := lineOf(content, marker)
		if !isNonSecretContext(lineText(content, ln)) {
			out = append(out, newFinding(rel, ln, resolveSeverity(base, kind, true, true), checkClientSideStrong, "CWE-312",
				"A private key appears in "+locationPhrase(rel, clientSide)+". "+
					"Private keys must never be committed to source or bundled into client-side code.",
				marker))
		}
	}

	return out
}

// locationPhrase describes where a secret was found for use in a finding
// message: a browser-shipped file is called out as such, while any other path
// (server, test, config, ...) is named neutrally.
func locationPhrase(rel string, clientSide bool) string {
	if clientSide {
		return "a client-side file ('" + rel + "'), where it ships to the browser"
	}
	return "'" + rel + "'"
}

// lineText returns the text of the 1-based line number ln in content, or "".
func lineText(content string, ln int) string {
	if ln < 1 {
		return ""
	}
	lines := strings.Split(content, "\n")
	if ln > len(lines) {
		return ""
	}
	return lines[ln-1]
}

// isSecretShaped applies a conservative length/charset/entropy heuristic so we
// flag key-like values while ignoring URLs, booleans, numbers and placeholders.
func isSecretShaped(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) > 4096 {
		return false
	}
	// A value matching a distinctive provider credential format is flagged
	// regardless of its length or entropy.
	if matchesProviderFormat(v) {
		return true
	}
	if len(v) < minSecretLen {
		return false
	}
	lower := strings.ToLower(v)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return false
	}
	if strings.ContainsAny(v, " \t") {
		return false
	}
	for _, bad := range []string{"your-", "your_", "changeme", "change-me", "example", "placeholder",
		"xxxx", "<", "todo", "dummy", "replace", "insert-", "sample"} {
		if strings.Contains(lower, bad) {
			return false
		}
	}
	if !mostlyKeyCharset(v) {
		return false
	}
	// A real key mixes letters and digits; prose/identifiers usually do not.
	hasLetter, hasDigit := false, false
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasLetter = true
		}
	}
	if !hasLetter || !hasDigit {
		return false
	}
	return shannonEntropy(v) >= minSecretEntropy
}

// matchesProviderFormat reports whether v contains a distinctive provider
// credential shape (JWT, PEM key, sk-/Stripe/AWS/GitHub/Slack/Google token).
func matchesProviderFormat(v string) bool {
	for _, re := range providerFormatRes {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

// isIgnorableKey reports whether an env key is a non-credential field whose
// value should not be flagged: *_IMAGE, *_VERSION and *_URL (container image
// refs, version strings, plain endpoints), unless the value embeds a credential
// (e.g. a connection URL with an inline password).
func isIgnorableKey(key, val string) bool {
	u := strings.ToUpper(key)
	for _, suf := range []string{"_IMAGE", "_VERSION", "_URL"} {
		if strings.HasSuffix(u, suf) {
			return !hasEmbeddedCredential(val)
		}
	}
	return false
}

// hasEmbeddedCredential reports whether val contains a URL with inline
// userinfo credentials (scheme://user:pass@host).
func hasEmbeddedCredential(val string) bool {
	return credURLRe.MatchString(val)
}

// mostlyKeyCharset reports whether at least 90% of v is drawn from the
// characters that appear in encoded keys/tokens.
func mostlyKeyCharset(v string) bool {
	if v == "" {
		return false
	}
	ok := 0
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9',
			r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r == '-', r == '_', r == '.', r == '+', r == '/', r == '=', r == ':', r == '~':
			ok++
		}
	}
	return float64(ok)/float64(len([]rune(v))) >= 0.9
}

// shannonEntropy returns the Shannon entropy of s in bits per character.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	var e float64
	for _, c := range freq {
		p := c / n
		e -= p * math.Log2(p)
	}
	return e
}

// cleanValue strips a trailing comment, trailing punctuation and one layer of
// surrounding quotes/backticks from an assignment's right-hand side.
func cleanValue(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, " //"); i >= 0 {
		v = v[:i]
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(v)
	v = strings.TrimRight(v, ";,")
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		first, last := v[0], v[len(v)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') || (first == '`' && last == '`') {
			v = v[1 : len(v)-1]
		}
	}
	return strings.TrimSpace(v)
}

// jwtHasServiceRole decodes a JWT's payload segment and reports whether it
// claims the service_role.
func jwtHasServiceRole(token string) bool {
	segs := strings.Split(token, ".")
	if len(segs) < 2 {
		return false
	}
	payload := segs[1]
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		if raw, err = base64.StdEncoding.DecodeString(payload); err != nil {
			return false
		}
	}
	return strings.Contains(string(raw), "service_role")
}

// jwtIssuer decodes a JWT's payload and returns its "iss" claim, or "".
func jwtIssuer(token string) string {
	segs := strings.Split(token, ".")
	if len(segs) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(segs[1])
	if err != nil {
		if raw, err = base64.StdEncoding.DecodeString(segs[1]); err != nil {
			return ""
		}
	}
	m := issuerRe.FindSubmatch(raw)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// issuerRe extracts the "iss" claim value from a decoded JWT payload.
var issuerRe = regexp.MustCompile(`"iss"\s*:\s*"([^"]*)"`)

// isKnownPublicKey reports whether v is a value that is public by design and so
// warrants a downgraded (LOW) finding rather than a secret-exposure alarm:
// Stripe test keys, Firebase browser API keys, Supabase local demo JWTs
// (issuer "supabase-demo"), and common emulator defaults.
func isKnownPublicKey(v string) bool {
	v = strings.TrimSpace(v)
	if emulatorDefaults[v] {
		return true
	}
	if stripeTestKeyRe.MatchString(v) {
		return true
	}
	if firebaseWebKeyRe.MatchString(v) {
		return true
	}
	if jwtRe.MatchString(v) {
		switch jwtIssuer(v) {
		case "supabase-demo", "firebase-demo":
			return true
		}
	}
	return false
}

// lineOf returns the 1-based line number of the first occurrence of sub in
// content, or 1 if it is not found.
func lineOf(content, sub string) int {
	idx := strings.Index(content, sub)
	if idx < 0 {
		return 1
	}
	return strings.Count(content[:idx], "\n") + 1
}

// looksClientSide reports whether a file is likely to ship to the browser,
// based on its path or a "use client" directive. Server-only files (Next.js
// app/api/** route handlers, route.*/middleware.* modules) are not treated as
// client-side even when they sit under an otherwise client-ish directory,
// unless they explicitly opt in with a "use client" directive.
func looksClientSide(rel, content string) bool {
	if strings.Contains(content, `"use client"`) || strings.Contains(content, `'use client'`) {
		return true
	}
	segs := strings.Split(rel, "/")
	base := ""
	if len(segs) > 0 {
		base = segs[len(segs)-1]
	}
	if strings.HasPrefix(base, "route.") || strings.HasPrefix(base, "middleware.") {
		return false
	}
	for i := 0; i+1 < len(segs); i++ {
		if segs[i] == "app" && segs[i+1] == "api" {
			return false // app/api/** is server-side
		}
	}
	for _, p := range segs {
		if clientDirSegments[p] {
			return true
		}
	}
	return false
}

// hasClientPrefix reports whether an env key uses a client-exposed prefix.
func hasClientPrefix(key string) bool {
	for _, p := range clientSideEnvPrefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// isScannableFile reports whether a file name is one we inspect.
func isScannableFile(name string) bool {
	if isEnvFile(name) {
		return true
	}
	return scannableExts[strings.ToLower(filepath.Ext(name))]
}

// isEnvFile reports whether name is a .env or .env.* file.
func isEnvFile(name string) bool {
	return name == ".env" || strings.HasPrefix(name, ".env.")
}

// isEnvExampleFile reports whether an env file is a template/example that
// conventionally holds placeholder values rather than real secrets.
func isEnvExampleFile(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range []string{".example", ".sample", ".template", ".dist", ".local.example"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return strings.Contains(lower, "example") || strings.Contains(lower, "sample") || strings.Contains(lower, "template")
}

// envInGitignore reports whether the directory's .gitignore appears to ignore
// .env files.
func envInGitignore(dir string) bool {
	data, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if t == ".env" || t == ".env*" || t == "*.env" || strings.HasPrefix(t, ".env") {
			return true
		}
	}
	return false
}
