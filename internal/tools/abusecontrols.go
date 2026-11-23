package internal

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Armur-Ai/Trishul/internal/logger"
	utils "github.com/Armur-Ai/Trishul/pkg"
)

// RunAbuseControls statically scans a project (read-only) for the "missing abuse
// controls" vulnerability class — Vibe Top 10 V08 — common in AI-generated apps.
//
// It is a conservative, deterministic detector: it only FLAGS code that appears
// to expose an abusable surface without the corresponding control, it never
// writes, deletes, or exploits the target, and it suppresses a finding whenever
// the relevant control (a rate limiter / a validation schema / an upload size
// limit) IS present. Findings are emitted under the vibe_security category.
//
// Detected checks:
//
//	VIBE-ABUSE-001  a SENSITIVE, abusable endpoint with no rate limiting anywhere
//	              in the project. To keep precision high, "sensitive" is limited to
//	              authentication (login/signup/register/password-reset/OTP),
//	              LLM/AI inference call sites, and email-sending endpoints. A
//	              generic GET or any non-sensitive route is deliberately NOT a
//	              finding, and a bare `import openai` (no call site) does not fire.
//	VIBE-ABUSE-002  file upload handler with no size limit configured
//	VIBE-ABUSE-003  mutating route spreading req.body into a DB call, no validation
func RunAbuseControls(dir string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "abuse-controls").Str("dir", dir).Msg("running")

	categorized := utils.InitAdvancedCategorizedResults()
	if _, ok := categorized[utils.VIBE_SECURITY]; !ok {
		categorized[utils.VIBE_SECURITY] = []interface{}{}
	}

	findings, err := scanAbuseControls(dir)
	if err != nil {
		logger.Error().Str("tool", "abuse-controls").Err(err).Msg("failed to scan project")
		return utils.ConvertCategorizedResults(categorized), nil
	}

	for _, f := range findings {
		categorized[utils.VIBE_SECURITY] = append(categorized[utils.VIBE_SECURITY], f)
	}

	return utils.ConvertCategorizedResults(categorized), nil
}

// abuseFile is one scanned source file with its lower-cased content cached.
type abuseFile struct {
	relPath string
	content string
	lower   string
	lines   []string
}

var (
	// --- rate limiter signals (project-level and file-level) ---
	reRateLimiter = regexp.MustCompile(`(?i)express-rate-limit|\bratelimit\b|rate_limit|rate-limit|@upstash/ratelimit|\bslowapi\b|\blimiter\b|\bthrottle\b|flask[-_]limiter|django[-_]ratelimit|@nestjs/throttler|\bthrottler\b`)

	// --- auth endpoint signals ---
	reAuthRoute = regexp.MustCompile(`(?i)/?(?:login|signin|sign-in|signup|sign-up|register|password[-_/]?reset|reset[-_/]?password|forgot[-_/]?password|\botp\b|verify[-_/]?otp|authenticate|\bauth/token\b)`)

	// --- LLM provider CALL-SITE signals ---
	// Only an actual inference/embedding CALL counts as a sensitive endpoint — a
	// bare `import openai` / `require('anthropic')` must NOT fire ABUSE-001, as it
	// is not an exposed surface. This is the main precision fix for 001.
	reLLMCall = regexp.MustCompile(`(?i)chat\.completions|completions\.create|messages\.create|embeddings\.create|responses\.create|\.generateContent\b|anthropic\.messages|openai\.chat`)

	// --- email-sending signals (sensitive: abusable for spam / email-bomb / cost) ---
	reEmailSend = regexp.MustCompile(`(?i)nodemailer|@sendgrid/mail|\bsendgrid\b|\bsgMail\b|transporter\.sendMail|\.sendMail\s*\(|\bsendEmail\s*\(|\bsend_email\s*\(|\bsend_mail\s*\(|\bsmtplib\b|\bmailgun\b|\bpostmark\b|resend\.emails|ses\.sendEmail`)

	// --- file upload signals ---
	reUploadHandler = regexp.MustCompile(`(?i)\bmulter\b|\bformidable\b|\bbusboy\b|UploadFile|multipart/form-data|express-fileupload`)
	reUploadLimit   = regexp.MustCompile(`(?i)limits\s*:|fileSize|maxFileSize|max_file_size|maxFileCount|MAX_CONTENT_LENGTH|maxUploadSize|file_size_limit|client_max_body_size|\blimits\b`)

	// --- body-spread into DB signals ---
	reBodySpread = regexp.MustCompile(`(?i)\.\.\.\s*(?:req|request|ctx)\.(?:body|request\.body)`)
	reDBWrite    = regexp.MustCompile(`(?i)\.(?:create|insert|insertOne|insertMany|update|updateOne|updateMany|save|bulkCreate|findOneAndUpdate|upsert)\s*\(|INSERT\s+INTO|UPDATE\s+\w+\s+SET`)

	// --- validation signals ---
	reValidation = regexp.MustCompile(`(?i)\bzod\b|\bfrom\s+['"]zod['"]|\bjoi\b|\byup\b|pydantic|BaseModel|class-validator|express-validator|\.parse\s*\(|\.validate\s*\(|\.safeParse\s*\(|ajv|cerberus|marshmallow|\bschema\b`)

	// --- health / static route signals (suppress noise) ---
	reHealthRoute = regexp.MustCompile(`(?i)/health|/healthz|/ping|/status|/metrics|/favicon|express\.static|/static|/public`)
)

// abuseScannableExts are the source extensions the detector inspects.
var abuseScannableExts = map[string]bool{
	".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true,
	".py": true,
}

// abuseSkipDirs are directories never worth walking.
var abuseSkipDirs = map[string]bool{
	"node_modules": true, ".git": true, "dist": true, "build": true,
	"vendor": true, "__pycache__": true, ".venv": true, "venv": true,
	".next": true, "coverage": true, "out": true,
}

// scanAbuseControls walks dir (read-only) and returns deterministic findings.
// It is exported for testing via a temp dir of sample sources.
func scanAbuseControls(dir string) ([]map[string]interface{}, error) {
	var files []abuseFile

	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries rather than aborting the whole scan
		}
		if d.IsDir() {
			if abuseSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !abuseScannableExts[strings.ToLower(filepath.Ext(d.Name()))] {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			logger.Debug().Str("tool", "abuse-controls").Str("file", path).Err(readErr).Msg("skip unreadable file")
			return nil
		}
		relPath := path
		if rel, relErr := filepath.Rel(dir, path); relErr == nil {
			relPath = rel
		}
		s := string(content)
		files = append(files, abuseFile{
			relPath: relPath,
			content: s,
			lower:   strings.ToLower(s),
			lines:   strings.Split(s, "\n"),
		})
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	// Project-level signal: a rate limiter present ANYWHERE suppresses 001.
	projectHasRateLimiter := false
	for i := range files {
		if reRateLimiter.MatchString(files[i].content) {
			projectHasRateLimiter = true
			break
		}
	}

	var findings []map[string]interface{}
	for i := range files {
		findings = append(findings, scanAbuseFile(&files[i], projectHasRateLimiter)...)
	}

	sortAbuseFindings(findings)
	return findings, nil
}

// scanAbuseFile inspects a single file for the three abuse-control checks.
func scanAbuseFile(f *abuseFile, projectHasRateLimiter bool) []map[string]interface{} {
	var findings []map[string]interface{}

	fileHasValidation := reValidation.MatchString(f.content)
	fileHasUploadLimit := reUploadLimit.MatchString(f.content)

	// Track which lines already produced an ABUSE-001 finding so a line that is
	// both an auth route and an LLM call is only flagged once.
	flagged001 := map[int]bool{}

	for idx, rawLine := range f.lines {
		line := rawLine
		lineNo := idx + 1

		// Skip comment-only lines to stay conservative.
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		// Health / static routes are considered clean, never flagged.
		if reHealthRoute.MatchString(line) {
			continue
		}

		// --- VIBE-ABUSE-001: a SENSITIVE endpoint with no rate limiting anywhere ---
		// Only auth, LLM call sites, and email-sending surfaces qualify; a generic
		// route never does.
		if !projectHasRateLimiter && !flagged001[lineNo] {
			isAuth := reAuthRoute.MatchString(line)
			isLLM := reLLMCall.MatchString(line)
			isEmail := reEmailSend.MatchString(line)
			if isAuth || isLLM || isEmail {
				cwe := []string{"CWE-770"}
				subject := "endpoint calling an LLM provider"
				if isAuth {
					// CWE-307: improper restriction of excessive authentication attempts.
					cwe = []string{"CWE-307", "CWE-770"}
					subject = "authentication endpoint (login/signup/password-reset/OTP)"
				} else if isEmail {
					subject = "email-sending endpoint"
				}
				flagged001[lineNo] = true
				findings = append(findings, abuseFinding(
					f.relPath, lineNo, "MEDIUM", "VIBE-ABUSE-001", "MEDIUM",
					"An "+subject+" is exposed but no rate limiter is present anywhere in the project; the surface can be brute-forced or abused for cost/DoS.",
					cwe,
					"Add a rate limiter (e.g. express-rate-limit / @upstash/ratelimit for Node, slowapi for FastAPI/Flask) as middleware on this route, keyed by IP and/or account.",
				))
			}
		}

		// --- VIBE-ABUSE-002: unbounded file upload ---
		if reUploadHandler.MatchString(line) && !fileHasUploadLimit {
			findings = append(findings, abuseFinding(
				f.relPath, lineNo, "MEDIUM", "VIBE-ABUSE-002", "MEDIUM",
				"A file-upload handler is configured without any size limit; an attacker can exhaust disk/memory by uploading arbitrarily large files.",
				[]string{"CWE-400"},
				"Configure an explicit upload size limit (e.g. multer `{ limits: { fileSize: N } }`, formidable `maxFileSize`, or FastAPI/Starlette request body size limits).",
			))
		}

		// --- VIBE-ABUSE-003: mutating route spreads req.body into DB, no validation ---
		if reBodySpread.MatchString(line) && reDBWrite.MatchString(line) && !fileHasValidation {
			findings = append(findings, abuseFinding(
				f.relPath, lineNo, "LOW", "VIBE-ABUSE-003", "LOW",
				"A mutating handler spreads `req.body` straight into a database create/update with no schema validation in the file; attackers can set arbitrary/unexpected fields (mass assignment).",
				[]string{"CWE-20"},
				"Validate and whitelist the request body with a schema (zod/joi/yup for Node, pydantic for Python) before persisting, and never spread raw `req.body` into a DB write.",
			))
		}
	}

	return findings
}

func abuseFinding(relPath string, line int, severity, checkID, confidence, message string, cwes []string, remediation string) map[string]interface{} {
	return map[string]interface{}{
		"path":        relPath,
		"line":        line,
		"severity":    severity,
		"check_id":    checkID,
		"message":     message,
		"cwe":         cwes,
		"confidence":  confidence,
		"remediation": remediation,
	}
}

// sortAbuseFindings makes output deterministic regardless of walk ordering.
func sortAbuseFindings(findings []map[string]interface{}) {
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
