package internal

// Webhook & payment-logic analyzer (Vibe Top 10 "V07: unverified webhooks &
// payment logic"). A defensive, read-only static detector for two failure
// modes that are common in AI-generated web apps:
//
//   - VIBE-WEBHOOK-001 — a webhook handler for a known provider that consumes
//     the raw request body but never verifies the provider's signature, so any
//     caller can forge events (CWE-345, insufficient verification of data
//     authenticity).
//   - VIBE-WEBHOOK-002 — a payment/checkout/order or access-control handler
//     that trusts a price/amount/plan/role/isAdmin value taken straight from
//     the client request body instead of looking it up server-side (CWE-602,
//     client-side enforcement of server-side security).
//
// The analyzer only ever FLAGS code. It is read-only: it walks the target
// directory, reads source files, and never writes, mutates, executes, or
// exploits anything. It uses stdlib only and is deterministic — findings are
// sorted by (path, line, check_id) so the same tree always yields the same
// output. Style follows internal/tools/supabase.go.
//
// Findings are returned under utils.VIBE_SECURITY so the analyzer slots into
// the existing vibe-security pipeline alongside the other Vibe Top 10 adapters.

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Armur-Ai/Trishul/internal/logger"
	utils "github.com/Armur-Ai/Trishul/pkg"
)

// Check identifiers emitted by this analyzer.
const (
	// checkUnverifiedWebhook: a provider webhook handler that reads the raw body
	// but performs no signature verification.
	checkUnverifiedWebhook = "VIBE-WEBHOOK-001"
	// checkClientTrustedPayment: a payment/access handler that trusts a
	// price/plan/role value supplied by the client.
	checkClientTrustedPayment = "VIBE-WEBHOOK-002"
)

// maxWebhookScanFileSize bounds how large a file we will read into memory.
const maxWebhookScanFileSize = int64(2 << 20) // 2 MiB

var (
	// Raw-body reads: the WHOLE request body (not an individual field). The
	// trailing [^.\w] / end-of-line guard keeps `req.body.amount` (a field read)
	// from matching here — that is a VIBE-WEBHOOK-002 concern, not a raw read.
	reRawBodyWhole = regexp.MustCompile(`\breq(?:uest)?\.body(?:[^.\w]|$)`)
	reRawBodyAlt   = regexp.MustCompile(`\breq(?:uest)?\.rawBody\b`)
	reRawBodyText  = regexp.MustCompile(`\breq(?:uest)?\.text\s*\(`)
	// Python raw body accessors (Flask / Django / FastAPI).
	reRawBodyPy = regexp.MustCompile(`\brequest\.(?:data\b|get_data\s*\(|stream\b|body\b)`)

	// A webhook context: the token "webhook" anywhere in the file. Conservative
	// on purpose — a file that never mentions webhooks is not flagged for 001.
	reWebhookCtx = regexp.MustCompile(`(?i)webhook`)

	// Known webhook providers, used only to make the finding message specific.
	webhookProviders = []struct {
		token *regexp.Regexp
		name  string
	}{
		{regexp.MustCompile(`(?i)\bstripe\b`), "Stripe"},
		{regexp.MustCompile(`(?i)\bsvix\b`), "Svix"},
		{regexp.MustCompile(`(?i)\bclerk\b`), "Clerk"},
		{regexp.MustCompile(`(?i)\bgithub\b`), "GitHub"},
		{regexp.MustCompile(`(?i)\bshopify\b`), "Shopify"},
		{regexp.MustCompile(`(?i)\bpaypal\b`), "PayPal"},
	}

	// Any of these anywhere in the file is treated as a genuine attempt to
	// verify the webhook, which clears the 001 finding. This deliberately errs
	// toward NOT flagging (fewer false positives): a verify call, an HMAC
	// comparison, or even reading a provider signature header all count.
	reVerifyOrSig = regexp.MustCompile(`(?i)` + strings.Join([]string{
		`constructEvent`,         // stripe.webhooks.constructEvent
		`verifyWebhookSignature`, // paypal / generic
		`verifyWebhook\b`,        // clerk helper
		`\.verify\s*\(`,          // svix: new Webhook(secret).verify(...)
		`createHmac`,             // node crypto HMAC compare
		`timingSafeEqual`,        // node constant-time compare
		`hmac\.new`,              // python hmac
		`compare_digest`,         // python constant-time compare
		`stripe-signature`,       // signature headers
		`svix-signature`,
		`svix-id`,
		`x-hub-signature`,       // github
		`x-shopify-hmac-sha256`, // shopify
		`x-webhook-signature`,
		`x-signature`,
		`clerk-signature`,
		`paypal-transmission`, // x-paypal-transmission-sig
	}, "|"))

	// Client-trusted field read from the request body (JS/TS): req.body.<field>.
	reBodyFieldJS = regexp.MustCompile(`\breq(?:uest)?\.body\.(amount|price|total|plan|role|isAdmin|is_admin)\b`)
	// Destructured out of the request body: `const { amount, ... } = req.body`.
	reBodyDestructure = regexp.MustCompile(`\b(?:const|let|var)\s*\{[^}]*\b(amount|price|total|plan|role|isAdmin|is_admin)\b[^}]*\}\s*=\s*req(?:uest)?\.body\b`)
	// Python: request.json['amount'] / request.form.get('price') / request.json.get("role").
	reBodyFieldPy = regexp.MustCompile(`\brequest\.(?:json|form|data)(?:\s*\.\s*get\s*\(\s*|\s*\[\s*)['"](amount|price|total|plan|role|is_admin|isadmin)['"]`)

	// Context tokens. A payment field (amount/price/total) is only flagged in a
	// payment-looking file; a privilege field (role/isAdmin) only in an
	// access-control-looking file. `plan` qualifies under either.
	paymentCtxTokens = []string{"checkout", "charge", "payment", "order", "price", "billing", "subscription", "invoice", "cart", "paymentintent", "stripe"}
	accessCtxTokens  = []string{"role", "isadmin", "is_admin", "grant", "admin", "permission", "access", "promote", "privilege", "entitlement"}
)

// webhookScanExtensions are the source extensions this analyzer inspects.
var webhookScanExtensions = map[string]bool{
	".js": true, ".jsx": true, ".ts": true, ".tsx": true,
	".mjs": true, ".cjs": true, ".py": true,
}

// RunWebhookVerification statically scans a directory (read-only) for
// unverified provider webhooks and client-trusted payment/access logic. It
// always returns a result map keyed by utils.VIBE_SECURITY; the error return is
// reserved for catastrophic walk failures (callers can treat findings as
// best-effort). It never returns a nil map.
func RunWebhookVerification(dir string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "webhook-verification").Str("dir", dir).Msg("running")

	findings := scanWebhookDir(dir)

	out := make([]interface{}, 0, len(findings))
	for _, f := range findings {
		out = append(out, f)
	}
	return map[string]interface{}{utils.VIBE_SECURITY: out}, nil
}

// scanWebhookDir walks dir and returns deterministic findings. Exported for
// testing via a temp dir of sample files.
func scanWebhookDir(dir string) []map[string]interface{} {
	var findings []map[string]interface{}

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries rather than aborting the scan
		}
		if d.IsDir() {
			if skipWebhookDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !webhookScanExtensions[strings.ToLower(filepath.Ext(d.Name()))] {
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil || info.Size() > maxWebhookScanFileSize {
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			logger.Debug().Str("tool", "webhook-verification").Str("file", path).Err(readErr).Msg("skip unreadable file")
			return nil
		}

		relPath := path
		if rel, relErr := filepath.Rel(dir, path); relErr == nil {
			relPath = rel
		}

		findings = append(findings, scanWebhookFile(relPath, content)...)
		return nil
	})

	sortWebhookFindings(findings)
	return findings
}

// skipWebhookDir reports whether a directory should be pruned from the walk.
func skipWebhookDir(name string) bool {
	switch name {
	case "node_modules", "vendor", ".git", "dist", "build", ".next", "out", "coverage":
		return true
	}
	return false
}

// scanWebhookFile applies both detectors to a single file's content.
func scanWebhookFile(relPath string, content []byte) []map[string]interface{} {
	var findings []map[string]interface{}

	text := string(content)
	lower := strings.ToLower(text)
	lines := splitWebhookLines(text)

	findings = append(findings, detectUnverifiedWebhook(relPath, text, lower, lines)...)
	findings = append(findings, detectClientTrustedPayment(relPath, lower, lines)...)

	return findings
}

// detectUnverifiedWebhook implements VIBE-WEBHOOK-001. A file is flagged when it
// (a) is a webhook handler (mentions "webhook"), (b) reads the raw request
// body, and (c) contains NO signature verification or signature-header check
// anywhere. The finding is anchored on the first raw-body read.
func detectUnverifiedWebhook(relPath, text, lower string, lines []string) []map[string]interface{} {
	if !reWebhookCtx.MatchString(lower) {
		return nil
	}
	if reVerifyOrSig.MatchString(text) {
		return nil // a verify call / signature-header check is present — treat as clean
	}

	line, ok := firstRawBodyLine(lines)
	if !ok {
		return nil // no raw body is consumed, so there is nothing forged to verify
	}

	provider := detectProvider(text)
	subject := "Webhook handler"
	if provider != "" {
		subject = provider + " webhook handler"
	}

	msg := subject + " reads the raw request body but never verifies the provider signature, " +
		"so any caller can forge webhook events (e.g. fake a payment or subscription change)."
	var remediation string
	if provider == "Stripe" {
		remediation = "Verify the event with `stripe.webhooks.constructEvent(rawBody, signatureHeader, endpointSecret)` and reject anything that throws, before using the payload."
	} else if provider == "Svix" || provider == "Clerk" {
		remediation = "Verify the request with `new Webhook(secret).verify(rawBody, headers)` (svix) and reject on failure before using the payload."
	} else {
		remediation = "Compute an HMAC of the raw body with the shared webhook secret and constant-time compare it against the provider's signature header (reject on mismatch) before using the payload."
	}

	return []map[string]interface{}{
		webhookFinding(relPath, line, checkUnverifiedWebhook, "CWE-345", msg, remediation),
	}
}

// detectClientTrustedPayment implements VIBE-WEBHOOK-002. Each line that reads a
// sensitive field (amount/price/total/plan/role/isAdmin) directly from the
// request body is flagged, provided the file reads as a payment handler (for
// money fields) or an access-control handler (for privilege fields).
func detectClientTrustedPayment(relPath, lower string, lines []string) []map[string]interface{} {
	paymentCtx := containsAny(lower, paymentCtxTokens)
	accessCtx := containsAny(lower, accessCtxTokens)
	if !paymentCtx && !accessCtx {
		return nil
	}

	var findings []map[string]interface{}
	seen := map[int]bool{}

	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if isCommentLine(line) {
			continue
		}

		field := matchBodyField(line)
		if field == "" {
			continue
		}
		if !fieldInContext(field, paymentCtx, accessCtx) {
			continue
		}
		lineNo := i + 1
		if seen[lineNo] {
			continue
		}
		seen[lineNo] = true

		msg, remediation := clientTrustedMessage(field)
		findings = append(findings, webhookFinding(relPath, lineNo, checkClientTrustedPayment, "CWE-602", msg, remediation))
	}
	return findings
}

// matchBodyField returns the normalized sensitive field name read from the
// request body on this line, or "" if none.
func matchBodyField(line string) string {
	if m := reBodyFieldJS.FindStringSubmatch(line); m != nil {
		return normalizeField(m[1])
	}
	if m := reBodyDestructure.FindStringSubmatch(line); m != nil {
		return normalizeField(m[1])
	}
	if m := reBodyFieldPy.FindStringSubmatch(line); m != nil {
		return normalizeField(m[1])
	}
	return ""
}

func normalizeField(f string) string {
	f = strings.ToLower(f)
	if f == "is_admin" {
		return "isadmin"
	}
	return f
}

// fieldInContext decides whether a field is relevant given the file's context:
// money fields need a payment context, privilege fields need an access context,
// and `plan` qualifies under either.
func fieldInContext(field string, paymentCtx, accessCtx bool) bool {
	switch field {
	case "amount", "price", "total":
		return paymentCtx
	case "role", "isadmin":
		return accessCtx
	case "plan":
		return paymentCtx || accessCtx
	}
	return false
}

func clientTrustedMessage(field string) (string, string) {
	switch field {
	case "amount", "price", "total":
		return "Handler reads the charge `" + field + "` from the client request body and uses it to create the payment; a client can tamper with it to pay an arbitrary (or zero) amount.",
			"Never trust money values from the client. Look up the price/amount server-side from the product or order record (by its ID) and charge that."
	case "role", "isadmin":
		return "Handler reads `" + field + "` from the client request body to decide access/privilege; a client can set it to escalate their own privileges.",
			"Determine roles and admin status server-side from the authenticated session/user record, never from request input."
	case "plan":
		return "Handler reads `plan` from the client request body to grant entitlement; a client can request a higher plan than they paid for.",
			"Derive the plan/entitlement server-side from the verified subscription or payment record, not from request input."
	}
	return "Handler trusts a security-sensitive value from the client request body.",
		"Enforce this value server-side rather than trusting client input."
}

// firstRawBodyLine returns the 1-based line of the first raw-body read.
func firstRawBodyLine(lines []string) (int, bool) {
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if isCommentLine(line) {
			continue
		}
		if reRawBodyWhole.MatchString(line) || reRawBodyAlt.MatchString(line) ||
			reRawBodyText.MatchString(line) || reRawBodyPy.MatchString(line) {
			return i + 1, true
		}
	}
	return 0, false
}

// detectProvider returns the first known provider named in the file, or "".
func detectProvider(text string) string {
	for _, p := range webhookProviders {
		if p.token.MatchString(text) {
			return p.name
		}
	}
	return ""
}

func containsAny(lower string, tokens []string) bool {
	for _, t := range tokens {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}

// isCommentLine reports whether a trimmed line is an obvious single-line comment
// in JS/TS or Python. Skipping comments keeps the detector from flagging
// examples or disabled code.
func isCommentLine(line string) bool {
	return strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") ||
		strings.HasPrefix(line, "*") || strings.HasPrefix(line, "/*")
}

// splitWebhookLines splits content into lines without a trailing empty element
// surprise; a bufio.Scanner keeps line indexing simple and 1:1 with editors.
func splitWebhookLines(text string) []string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), int(maxWebhookScanFileSize)+1)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

func webhookFinding(relPath string, line int, checkID, cwe, message, remediation string) map[string]interface{} {
	return map[string]interface{}{
		"path":        relPath,
		"line":        line,
		"message":     message,
		"severity":    "HIGH",
		"check_id":    checkID,
		"cwe":         cwe,
		"confidence":  "MEDIUM",
		"remediation": remediation,
	}
}

// sortWebhookFindings makes output deterministic regardless of walk ordering.
func sortWebhookFindings(findings []map[string]interface{}) {
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
