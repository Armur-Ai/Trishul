package internal

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Armur-Ai/Trishul/internal/fileclass"
	"github.com/Armur-Ai/Trishul/internal/logger"
	"github.com/Armur-Ai/Trishul/internal/redact"
	utils "github.com/Armur-Ai/Trishul/pkg"
)

// RunPlaceholderSecurity statically scans source and configuration files for the
// "placeholder / insecure-default" class of vulnerabilities common in rapidly
// vibe-coded apps: hardcoded placeholder secrets, default credentials, disabled
// TLS/cert verification, wildcard CORS paired with credentials, debug mode left
// on, and security TODO/FIXME markers.
//
// It is a read-only, deterministic detector: it only FLAGS insecure patterns, it
// never writes, deletes, or exploits the target. Findings are emitted under the
// VIBE_SECURITY category.
//
// Secrets are never leaked: any finding that would otherwise quote a secret value
// redacts it through internal/redact and emits only a `secret_preview` and a
// stable `fingerprint`.
func RunPlaceholderSecurity(dir string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "placeholder").Str("dir", dir).Msg("running")

	findings := scanPlaceholderDir(dir)

	list := make([]interface{}, 0, len(findings))
	for _, f := range findings {
		list = append(list, f)
	}

	return map[string]interface{}{
		utils.VIBE_SECURITY: list,
	}, nil
}

const (
	phCheckSecret  = "VIBE-PLACEHOLDER-001"
	phCheckDefault = "VIBE-PLACEHOLDER-002"
	phCheckVerify  = "VIBE-PLACEHOLDER-003"
	phCheckCORS    = "VIBE-PLACEHOLDER-004"
	phCheckDebug   = "VIBE-PLACEHOLDER-005"
	phCheckTODO    = "VIBE-PLACEHOLDER-006"
	phMaxFileBytes = 2 << 20 // 2 MiB: skip anything larger (likely generated/binary)
)

// phExtensions is the set of file extensions the detector inspects.
var phExtensions = map[string]bool{
	".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true,
	".py": true, ".go": true, ".rb": true, ".php": true, ".java": true, ".cs": true,
	".c": true, ".cpp": true, ".cc": true, ".h": true, ".hpp": true,
	".env": true, ".yml": true, ".yaml": true, ".json": true, ".toml": true,
	".ini": true, ".cfg": true, ".conf": true, ".config": true, ".properties": true,
	".sh": true, ".bash": true, ".xml": true,
}

// phSkipDirs are directories never descended into.
var phSkipDirs = map[string]bool{
	"node_modules": true, ".git": true, "vendor": true, "dist": true, "build": true,
	".next": true, "__pycache__": true, "venv": true, ".venv": true, "target": true,
	".idea": true, ".vscode": true, "coverage": true,
}

var (
	// 001 — hardcoded placeholder secrets assigned to obvious names.
	rePhSecret = regexp.MustCompile(`(?i)\b(jwt[_-]?secret|session[_-]?secret|secret[_-]?key|signing[_-]?key|signing[_-]?secret|app[_-]?secret|auth[_-]?secret|token[_-]?secret)\b\s*(?::=|[:=])\s*["'` + "`" + `]([^"'` + "`" + `\n]{0,200})["'` + "`" + `]`)
	// env-access / secret-manager reference: suppresses 001/002 for that line.
	rePhEnvAccess = regexp.MustCompile(`(?i)(process\.env|import\.meta\.env|os\.environ|os\.getenv|\bgetenv\s*\(|System\.getenv|\bENV\[|secretsmanager|secrets?manager|vault|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)`)

	// 002 — default credentials.
	rePhUserField   = regexp.MustCompile(`(?i)\b(user(?:name)?|db[_-]?user|login|uid)\b\s*(?::=|[:=])\s*["']?([A-Za-z0-9_.-]{1,64})["']?`)
	rePhPassField   = regexp.MustCompile(`(?i)\b(pass(?:word|wd)?|pwd|db[_-]?pass(?:word)?)\b\s*(?::=|[:=])\s*["']?([^"'\s]{1,64})["']?`)
	rePhInlineCreds = regexp.MustCompile(`(?i)://(admin|root|user|postgres|sa|administrator):(admin|root|password|pass|changeme|1234|12345|123456|test|toor|secret|letmein)@`)

	// 003 — disabled verification.
	rePhVerifyFalse  = regexp.MustCompile(`(?i)\bverify\s*=\s*False\b`)
	rePhRejectUnauth = regexp.MustCompile(`(?i)\brejectUnauthorized\s*(?::=|[:=])\s*false\b`)
	rePhNodeTLS      = regexp.MustCompile(`(?i)\bNODE_TLS_REJECT_UNAUTHORIZED\s*(?::=|[:=])\s*["']?0["']?`)
	rePhInsecureSkip = regexp.MustCompile(`(?i)\bInsecureSkipVerify\s*(?::=|[:=])\s*true\b`)

	// 004 — wildcard CORS + credentials.
	rePhCorsWildcard = regexp.MustCompile(`(?i)(\borigin\b\s*(?::=|[:=])\s*["']\*["']|access-control-allow-origin["']?\s*[:,]\s*["']?\*)`)
	rePhCorsCreds    = regexp.MustCompile(`(?i)(\bcredentials\b\s*(?::=|[:=])\s*true|access-control-allow-credentials["']?\s*[:,]?\s*["']?true)`)

	// 005 — debug mode on.
	rePhDebugOn   = regexp.MustCompile(`(?i)(\bDEBUG\s*(?::=|[:=])\s*(?:true|1)\b|\bapp\.debug\s*=\s*true\b|\bFLASK_DEBUG\s*(?::=|[:=])\s*(?:true|1)\b)`)
	rePhNodeEnv   = regexp.MustCompile(`(?i)\bNODE_ENV\s*(?::=|[:=])\s*["']?(development|dev|test|debug)["']?`)
	rePhDebugWord = regexp.MustCompile(`(?i)\bdebug\b`)

	// 006 — security TODO markers (only within comments).
	rePhMarker     = regexp.MustCompile(`(?i)\b(TODO|FIXME|HACK|XXX)\b`)
	rePhSecurityWd = regexp.MustCompile(`(?i)\b(auth|authn|authz|authentication|authorization|security|secure|insecure|bypass|vuln|csrf|xss|injection|sanitiz|escap|permission|credential|password|token|login|validate|validation|verify)\b`)
	rePhCommentLed = regexp.MustCompile(`(//|#|/\*|<!--|;|--)`)
)

// phPlaceholderWords are the weak/placeholder substrings that make a secret value
// obviously non-production.
var phPlaceholderWords = []string{
	"secret", "changeme", "change-me", "change_me", "password", "passwd", "test",
	"example", "placeholder", "dummy", "demo", "foobar", "foo", "bar", "admin",
	"default", "letmein", "yoursecret", "your-secret", "mysecret", "supersecret",
	"qwerty", "abc123", "123456", "12345", "todo", "sample", "none", "null",
}

// phDefaultUsers are username values treated as defaults.
var phDefaultUsers = map[string]bool{
	"admin": true, "root": true, "user": true, "sa": true, "postgres": true,
	"administrator": true, "superuser": true, "guest": true,
}

// phWeakPasswords are password values treated as default/weak.
var phWeakPasswords = map[string]bool{
	"admin": true, "root": true, "password": true, "passwd": true, "pass": true,
	"changeme": true, "1234": true, "12345": true, "123456": true, "12345678": true,
	"test": true, "user": true, "default": true, "secret": true, "letmein": true,
	"toor": true, "guest": true, "qwerty": true, "admin123": true, "root123": true,
}

// phFinding is a convenience builder that does not carry any secret value.
func phFinding(path string, line int, severity, checkID, cwe, confidence, message, remediation string) map[string]interface{} {
	return map[string]interface{}{
		"path":        path,
		"line":        line,
		"message":     message,
		"severity":    severity,
		"check_id":    checkID,
		"cwe":         cwe,
		"confidence":  confidence,
		"remediation": remediation,
	}
}

// phSecretFinding is a builder for secret-bearing findings. The raw value is
// redacted at the boundary; only a preview and fingerprint are retained.
func phSecretFinding(path string, line int, severity, checkID, confidence, message, remediation, raw string) map[string]interface{} {
	f := phFinding(path, line, severity, checkID, "CWE-798", confidence, message, remediation)
	f["secret_preview"] = redact.Mask(raw)
	f["fingerprint"] = redact.Fingerprint(raw)
	return f
}

// scanPlaceholderDir walks dir (read-only) and returns deterministic findings.
func scanPlaceholderDir(dir string) []map[string]interface{} {
	var findings []map[string]interface{}

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries, keep scanning
		}
		if d.IsDir() {
			if phSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !phEligibleFile(d.Name()) {
			return nil
		}
		info, statErr := d.Info()
		if statErr == nil && info.Size() > phMaxFileBytes {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			logger.Debug().Str("tool", "placeholder").Str("file", path).Err(readErr).Msg("skip unreadable file")
			return nil
		}

		relPath := path
		if rel, relErr := filepath.Rel(dir, path); relErr == nil {
			relPath = rel
		}

		isTest := phIsTestFile(d.Name())
		findings = append(findings, scanPlaceholderFile(relPath, string(content), isTest)...)
		return nil
	})

	findings = phDedupe(findings)
	phSortFindings(findings)
	return findings
}

// phEligibleFile reports whether name should be inspected.
func phEligibleFile(name string) bool {
	if strings.HasPrefix(name, ".env") {
		return true
	}
	return phExtensions[strings.ToLower(filepath.Ext(name))]
}

// phIsTestFile reports whether name is an obvious test/fixture file, used to lower
// confidence on its findings (test files routinely hold placeholder values).
func phIsTestFile(name string) bool {
	l := strings.ToLower(name)
	return strings.HasSuffix(l, "_test.go") ||
		strings.Contains(l, ".test.") || strings.Contains(l, ".spec.") ||
		strings.HasPrefix(l, "test_") || strings.Contains(l, "test") && strings.Contains(l, "fixture") ||
		strings.Contains(l, "mock") || strings.Contains(l, "example")
}

// scanPlaceholderFile runs all detectors against a single file's content.
func scanPlaceholderFile(relPath, content string, isTest bool) []map[string]interface{} {
	var findings []map[string]interface{}
	lines := strings.Split(content, "\n")

	// Classify the file once (path-only) so detectors can tune precision:
	//   - credential rules (001/002) are suppressed in locale/i18n string tables,
	//     which hold translated UI labels rather than real credentials;
	//   - the disabled-verification rule (003) scales severity by code context.
	kind := fileclass.ClassifyPath(relPath)
	skipCreds := kind == fileclass.KindLocale

	// Collected for file-level correlation (checks 002 and 004).
	hasDefaultUser := false
	var weakPassLines []int
	var corsWildcardLines []int
	corsCredLine := -1

	for i, line := range lines {
		lineNo := i + 1
		trimmed := strings.TrimSpace(line)
		comment := phIsCommentLine(trimmed)

		// 006 — security TODO markers (comment-only, informational).
		if rePhCommentLed.MatchString(line) && rePhMarker.MatchString(line) && rePhSecurityWd.MatchString(line) {
			findings = append(findings, phFinding(
				relPath, lineNo, "LOW", phCheckTODO, "CWE-1111", "LOW",
				"Security-related TODO/FIXME/HACK marker indicates an unfinished or intentionally bypassed security control.",
				"Resolve the outstanding security work before shipping, or track it as a blocking issue; do not leave auth/validation gaps behind a comment.",
			))
		}

		// The remaining checks describe active code; skip commented-out lines.
		if comment {
			continue
		}

		// 001 — hardcoded placeholder secret.
		if !skipCreds && !rePhEnvAccess.MatchString(line) {
			if m := rePhSecret.FindStringSubmatch(line); m != nil {
				name, value := m[1], m[2]
				if weak, high := phIsWeakSecret(value); weak && !phIsDisplayLabel(name, value) {
					conf := "HIGH"
					if !high {
						conf = "MEDIUM"
					}
					if isTest {
						conf = phLower(conf)
					}
					findings = append(findings, phSecretFinding(
						relPath, lineNo, "HIGH", phCheckSecret, conf,
						"Hardcoded signing/session credential assigned to `"+name+"` uses a weak or placeholder value.",
						"Generate a strong random value and inject it via an environment variable or a secrets manager; never commit credentials to source control.",
						value,
					))
				}
			}
		}

		// 002 — default-credential correlation inputs. Locale/i18n tables and
		// display-label assignments (e.g. `password: 'Password'`, enum display
		// names) are UI strings, not credentials, and are skipped.
		if !skipCreds && !rePhEnvAccess.MatchString(line) {
			if m := rePhUserField.FindStringSubmatch(line); m != nil {
				if phDefaultUsers[strings.ToLower(m[2])] && !phIsDisplayLabel(m[1], m[2]) {
					hasDefaultUser = true
				}
			}
			if m := rePhPassField.FindStringSubmatch(line); m != nil {
				if phWeakPasswords[strings.ToLower(m[2])] && !phIsDisplayLabel(m[1], m[2]) {
					weakPassLines = append(weakPassLines, lineNo)
				}
			}
		}
		// 002 — inline connection-string credentials (self-contained, HIGH).
		if rePhInlineCreds.MatchString(line) {
			conf := "HIGH"
			if isTest {
				conf = "MEDIUM"
			}
			findings = append(findings, phFinding(
				relPath, lineNo, "HIGH", phCheckDefault, "CWE-798", conf,
				"Connection string embeds default/well-known credentials (e.g. admin/admin, root/root).",
				"Replace embedded default credentials with unique, rotated secrets supplied at runtime; remove credentials from source.",
			))
		}

		// 003 — disabled verification.
		if rePhVerifyFalse.MatchString(line) {
			findings = append(findings, phVerifyFinding(relPath, lineNo, isTest,
				"TLS/certificate verification is disabled (`verify=False`), exposing traffic to man-in-the-middle attacks."))
		}
		if rePhRejectUnauth.MatchString(line) {
			findings = append(findings, phVerifyFinding(relPath, lineNo, isTest,
				"TLS certificate validation is disabled (`rejectUnauthorized: false`), exposing traffic to man-in-the-middle attacks."))
		}
		if rePhNodeTLS.MatchString(line) {
			findings = append(findings, phVerifyFinding(relPath, lineNo, isTest,
				"`NODE_TLS_REJECT_UNAUTHORIZED=0` disables all TLS certificate validation process-wide."))
		}
		if rePhInsecureSkip.MatchString(line) {
			findings = append(findings, phVerifyFinding(relPath, lineNo, isTest,
				"`InsecureSkipVerify: true` disables TLS certificate validation, exposing traffic to man-in-the-middle attacks."))
		}

		// 004 — CORS correlation inputs.
		if rePhCorsWildcard.MatchString(line) {
			corsWildcardLines = append(corsWildcardLines, lineNo)
		}
		if corsCredLine == -1 && rePhCorsCreds.MatchString(line) {
			corsCredLine = lineNo
		}

		// 005 — debug mode on.
		if rePhDebugOn.MatchString(line) {
			conf := "HIGH"
			if isTest {
				conf = "MEDIUM"
			}
			findings = append(findings, phFinding(
				relPath, lineNo, "MEDIUM", phCheckDebug, "CWE-489", conf,
				"Debug mode is enabled; this leaks stack traces and internals and should never be on in production.",
				"Disable debug mode in production builds and drive it from an environment-specific configuration that defaults to off.",
			))
		} else if rePhNodeEnv.MatchString(line) && rePhDebugWord.MatchString(content) {
			// NODE_ENV set to a non-production value in a file that also references debug.
			findings = append(findings, phFinding(
				relPath, lineNo, "MEDIUM", phCheckDebug, "CWE-489", "LOW",
				"`NODE_ENV` is set to a non-production value alongside debug configuration; verify this is not shipped to production.",
				"Ensure production deployments set `NODE_ENV=production` and keep debug tooling disabled.",
			))
		}
	}

	// 002 — field-based default credentials: a default username AND a weak password
	// present in the same file.
	if hasDefaultUser {
		for _, ln := range weakPassLines {
			conf := "MEDIUM"
			if isTest {
				conf = "LOW"
			}
			findings = append(findings, phFinding(
				relPath, ln, "HIGH", phCheckDefault, "CWE-798", conf,
				"Default/weak credentials: a default username is paired with a common default password in this configuration.",
				"Replace default credentials with unique, rotated secrets supplied at runtime; never ship admin/admin-style defaults.",
			))
		}
	}

	// 004 — wildcard CORS paired with credentials anywhere in the file.
	if len(corsWildcardLines) > 0 && corsCredLine != -1 {
		for _, originLine := range corsWildcardLines {
			conf := "HIGH"
			if phAbs(originLine-corsCredLine) > 12 {
				conf = "MEDIUM"
			}
			if isTest {
				conf = phLower(conf)
			}
			findings = append(findings, phFinding(
				relPath, originLine, "HIGH", phCheckCORS, "CWE-942", conf,
				"Wildcard CORS origin (`*`) is combined with credentials, allowing any site to make authenticated cross-origin requests.",
				"Replace the `*` origin with an explicit allow-list of trusted origins when credentials are enabled.",
			))
		}
	}

	return findings
}

// phVerifyFinding builds a check-003 finding.
func phVerifyFinding(relPath string, lineNo int, isTest bool, message string) map[string]interface{} {
	conf := "HIGH"
	if isTest {
		conf = "MEDIUM"
	}
	return phFinding(
		relPath, lineNo, "HIGH", phCheckVerify, "CWE-295", conf,
		message,
		"Keep certificate/host verification enabled; fix the underlying trust issue (install the correct CA) instead of disabling validation.",
	)
}

// phIsWeakSecret reports whether a secret value is weak/placeholder. The second
// return is true when it matched a known placeholder word (high confidence) and
// false when it only qualified by being short (lower confidence).
func phIsWeakSecret(v string) (weak bool, high bool) {
	if v == "" {
		return false, false
	}
	lower := strings.ToLower(v)
	for _, w := range phPlaceholderWords {
		if strings.Contains(lower, w) {
			return true, true
		}
	}
	// Short values are treated as weak but at lower confidence: a real random
	// secret is rarely this short, yet we avoid over-claiming.
	if len(v) <= 8 {
		return true, false
	}
	return false, false
}

// phIsDisplayLabel reports whether value is a display label / translation of the
// field name rather than a real credential. UI code and i18n tables routinely
// assign a human-readable label to a field named after a credential, e.g.
// `password: 'Password'`, `username: 'Username'`, `secret_key: 'Secret Key'`, or
// enum display names. These are detected by comparing the alphanumeric cores of
// the key and the value: a value that is just the field name re-cased (or spaced)
// is a label, never a secret.
func phIsDisplayLabel(name, value string) bool {
	n := phAlnumLower(name)
	v := phAlnumLower(value)
	return n != "" && n == v
}

// phAlnumLower returns s lower-cased with every non-alphanumeric rune removed, so
// "Secret Key" and "secret_key" both collapse to "secretkey".
func phAlnumLower(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// phIsCommentLine reports whether a trimmed line is a comment.
func phIsCommentLine(trimmed string) bool {
	switch {
	case strings.HasPrefix(trimmed, "//"),
		strings.HasPrefix(trimmed, "#"),
		strings.HasPrefix(trimmed, "/*"),
		strings.HasPrefix(trimmed, "*"),
		strings.HasPrefix(trimmed, "<!--"),
		strings.HasPrefix(trimmed, ";"),
		strings.HasPrefix(trimmed, "--"):
		return true
	}
	return false
}

func phLower(conf string) string {
	switch conf {
	case "HIGH":
		return "MEDIUM"
	case "MEDIUM":
		return "LOW"
	default:
		return "LOW"
	}
}

func phAbs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// phDedupe removes duplicate findings keyed by check_id|path|line.
func phDedupe(findings []map[string]interface{}) []map[string]interface{} {
	seen := map[string]bool{}
	out := findings[:0]
	for _, f := range findings {
		path, _ := f["path"].(string)
		line, _ := f["line"].(int)
		check, _ := f["check_id"].(string)
		key := check + "|" + path + "|" + itoaPad(line)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// itoaPad renders n as a fixed-width, zero-padded string so dedupe keys sort and
// compare without ambiguity.
func itoaPad(n int) string {
	var b [12]byte
	i := len(b)
	if n == 0 {
		return "000000000000"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 && i > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	for i > 0 {
		i--
		b[i] = '0'
	}
	return string(b[:])
}

// phSortFindings orders findings deterministically.
func phSortFindings(findings []map[string]interface{}) {
	sort.SliceStable(findings, func(i, j int) bool {
		pi, _ := findings[i]["path"].(string)
		pj, _ := findings[j]["path"].(string)
		if pi != pj {
			return pi < pj
		}
		li, _ := findings[i]["line"].(int)
		lj, _ := findings[j]["line"].(int)
		if li != lj {
			return li < lj
		}
		ci, _ := findings[i]["check_id"].(string)
		cj, _ := findings[j]["check_id"].(string)
		return ci < cj
	})
}
