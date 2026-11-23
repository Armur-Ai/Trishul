package internal

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	utils "github.com/Armur-Ai/Trishul/pkg"
)

// Synthetic, obviously-fake planted secrets. The core safety contract is that
// none of these plaintext values may ever appear in the emitted finding map.
const (
	plantedPublicSecret = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6" // 32 chars, high entropy
	plantedEnvSecret    = "R7n2K9qZ4wX1mP6vB3cL8dF5gH0jS2tA9uE4yW7i"
)

// buildServiceRoleJWT constructs a syntactically valid Supabase-style
// service_role JWT whose payload is decodable base64url.
func buildServiceRoleJWT() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"role":"service_role","iss":"supabase","ref":"abcdefgh"}`))
	sig := "s1gNATUREfake1234567890abcdefABCDEFghij"
	return header + "." + payload + "." + sig
}

// findings pulls the SECRET_DETECTION list out of a result map as a slice of
// finding maps.
func findings(t *testing.T, res map[string]interface{}) []map[string]interface{} {
	t.Helper()
	raw, ok := res[utils.SECRET_DETECTION]
	if !ok {
		t.Fatalf("result missing %q category", utils.SECRET_DETECTION)
	}
	list, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("SECRET_DETECTION is %T, want []interface{}", raw)
	}
	out := make([]map[string]interface{}, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			t.Fatalf("finding is %T, want map[string]interface{}", item)
		}
		out = append(out, m)
	}
	return out
}

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func TestRunClientSecretExposure(t *testing.T) {
	dir := t.TempDir()
	jwt := buildServiceRoleJWT()

	// Rule 001: NEXT_PUBLIC_* secret-shaped assignment in a client config file.
	write(t, dir, "src/config.ts",
		"export const PUBLIC_FLAG = true;\n"+
			"const NEXT_PUBLIC_API_KEY = \""+plantedPublicSecret+"\";\n")

	// Rule 003: service_role JWT in a client-side ("use client") file.
	write(t, dir, "src/app/page.tsx",
		"\"use client\";\n"+
			"export const client = createClient(url, \""+jwt+"\");\n")

	// Rule 002: committed .env with a non-public secret-shaped assignment,
	// and no .gitignore so it reads as committed.
	write(t, dir, ".env", "API_SECRET="+plantedEnvSecret+"\nDEBUG=true\n")

	// Benign file: ordinary code, a URL, a boolean, short strings. No secrets.
	write(t, dir, "utils.ts",
		"export function add(a: number, b: number) { return a + b; }\n"+
			"const endpoint = \"https://api.example.com/v1\";\n"+
			"const enabled = true;\n"+
			"const name = \"widget\";\n")

	res, err := RunClientSecretExposure(dir)
	if err != nil {
		t.Fatalf("RunClientSecretExposure: %v", err)
	}
	fs := findings(t, res)

	byCheck := map[string]map[string]interface{}{}
	for _, f := range fs {
		id, _ := f["check_id"].(string)
		byCheck[id] = f
		// No finding may reference the benign file.
		if p, _ := f["path"].(string); strings.Contains(p, "utils.ts") {
			t.Errorf("benign file utils.ts was flagged: %v", f)
		}
	}

	// Rule 001 fired with HIGH severity.
	f001, ok := byCheck[checkPublicPrefix]
	if !ok {
		t.Fatalf("expected a %s finding (NEXT_PUBLIC secret), got checks: %v", checkPublicPrefix, keys(byCheck))
	}
	if sev, _ := f001["severity"].(string); sev != "HIGH" {
		t.Errorf("%s severity = %q, want HIGH", checkPublicPrefix, sev)
	}

	// Rule 003 fired with CRITICAL severity.
	f003, ok := byCheck[checkClientSideStrong]
	if !ok {
		t.Fatalf("expected a %s finding (service_role in client file), got checks: %v", checkClientSideStrong, keys(byCheck))
	}
	if sev, _ := f003["severity"].(string); sev != "CRITICAL" {
		t.Errorf("%s severity = %q, want CRITICAL", checkClientSideStrong, sev)
	}

	// Rule 002 fired for the committed .env.
	if _, ok := byCheck[checkCommittedEnv]; !ok {
		t.Fatalf("expected a %s finding (committed .env secret), got checks: %v", checkCommittedEnv, keys(byCheck))
	}

	// Every finding must carry a redacted preview and a fingerprint.
	for _, f := range fs {
		if p, _ := f["secret_preview"].(string); p == "" {
			t.Errorf("finding missing secret_preview: %v", f)
		}
		if fp, _ := f["fingerprint"].(string); fp == "" {
			t.Errorf("finding missing fingerprint: %v", f)
		}
	}

	// CORE CONTRACT: no raw secret may appear anywhere in the serialized result.
	blob, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	s := string(blob)
	for _, secret := range []string{plantedPublicSecret, plantedEnvSecret, jwt} {
		if strings.Contains(s, secret) {
			t.Fatalf("SECRET LEAK: a planted raw secret appears in the emitted result")
		}
	}
	// Defense in depth: the JWT's base64 payload segment (its interior) must
	// not leak either. (The descriptive word "service_role" legitimately
	// appears in finding messages as a label and is not secret material.)
	if payloadSeg := strings.Split(jwt, ".")[1]; strings.Contains(s, payloadSeg) {
		t.Fatalf("SECRET LEAK: an interior JWT segment appears in the emitted result")
	}
}

func TestRunClientSecretExposureBenignOnly(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "src/math.ts",
		"export const PI = 3.14159;\n"+
			"const greeting = \"hello world\";\n"+
			"const url = \"https://example.com\";\n")

	res, err := RunClientSecretExposure(dir)
	if err != nil {
		t.Fatalf("RunClientSecretExposure: %v", err)
	}
	if fs := findings(t, res); len(fs) != 0 {
		t.Fatalf("benign-only tree produced %d findings, want 0: %v", len(fs), fs)
	}
}

func TestRunClientSecretExposureEmptyDir(t *testing.T) {
	dir := t.TempDir()
	res, err := RunClientSecretExposure(dir)
	if err != nil {
		t.Fatalf("empty dir returned error: %v", err)
	}
	if fs := findings(t, res); len(fs) != 0 {
		t.Fatalf("empty dir produced %d findings, want 0", len(fs))
	}
}

// TestNonSecretContextsNotFlagged verifies that secret-shaped tokens sitting in
// UI attributes (placeholder=, aria-label, title=) and test typing calls
// (.type(...), fill(...)) are not reported, and that i18n string tables are
// skipped entirely.
func TestNonSecretContextsNotFlagged(t *testing.T) {
	dir := t.TempDir()
	jwt := buildServiceRoleJWT()

	// A placeholder attribute showing an example sk-style key in a client file:
	// without the context filter this would trip rule 003.
	write(t, dir, "src/app/form.tsx",
		"\"use client\";\n"+
			"export const Form = () => <input placeholder=\"sk-abcdefghijklmnopqrstuvwxyz0123\" />;\n")

	// An aria-label and a title carrying a high-entropy token.
	write(t, dir, "src/app/widget.tsx",
		"\"use client\";\n"+
			"const a = <div aria-label=\""+plantedPublicSecret+"\" title=\""+plantedPublicSecret+"\" />;\n")

	// A test typing call feeding a service_role JWT into an input.
	write(t, dir, "src/app/login.spec.tsx",
		"\"use client\";\n"+
			"await page.fill('#token', '"+jwt+"');\n"+
			"cy.get('#t').type('"+jwt+"');\n")

	// An i18n string table: translation text that happens to be long.
	write(t, dir, "src/locales/en.ts",
		"export const NEXT_PUBLIC_WELCOME = \""+plantedPublicSecret+"\";\n")

	res, err := RunClientSecretExposure(dir)
	if err != nil {
		t.Fatalf("RunClientSecretExposure: %v", err)
	}
	if fs := findings(t, res); len(fs) != 0 {
		t.Fatalf("non-secret contexts produced %d findings, want 0: %v", len(fs), fs)
	}
}

// buildDemoJWT constructs a Supabase local-demo service_role JWT (issuer
// "supabase-demo"), which is public by design.
func buildDemoJWT() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"role":"service_role","iss":"supabase-demo","ref":"local"}`))
	sig := "s1gNATUREfake1234567890abcdefABCDEFghij"
	return header + "." + payload + "." + sig
}

// sevByCheck collapses findings to a check_id -> severity map, failing if a
// check_id appears with conflicting severities.
func sevByCheck(t *testing.T, fs []map[string]interface{}) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, f := range fs {
		id, _ := f["check_id"].(string)
		sev, _ := f["severity"].(string)
		out[id] = sev
	}
	return out
}

// TestKnownPublicKeysDowngraded verifies that public-by-design values are
// reported at LOW rather than HIGH/CRITICAL.
func TestKnownPublicKeysDowngraded(t *testing.T) {
	// Stripe test key on a client-exposed env var -> rule 001 downgraded.
	t.Run("stripe test key (rule 001)", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "src/pay.ts",
			"const NEXT_PUBLIC_STRIPE_KEY = \"sk_test_"+"4eC39HqLyjWDarjtT1zdp7dc\";\n")
		res, err := RunClientSecretExposure(dir)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		sev := sevByCheck(t, findings(t, res))
		if sev[checkPublicPrefix] != "LOW" {
			t.Fatalf("stripe sk_test_ severity = %q, want LOW (findings: %v)", sev[checkPublicPrefix], sev)
		}
	})

	// Stripe test key committed in a .env -> rule 002 downgraded.
	t.Run("stripe test key (.env rule 002)", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, ".env", "STRIPE_SECRET=sk_test_"+"4eC39HqLyjWDarjtT1zdp7dc\n")
		res, err := RunClientSecretExposure(dir)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		sev := sevByCheck(t, findings(t, res))
		if sev[checkCommittedEnv] != "LOW" {
			t.Fatalf(".env sk_test_ severity = %q, want LOW (findings: %v)", sev[checkCommittedEnv], sev)
		}
	})

	// Supabase local-demo service_role JWT in a client file -> rule 003 LOW,
	// not CRITICAL.
	t.Run("supabase-demo JWT (rule 003)", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "src/app/db.tsx",
			"\"use client\";\nexport const c = createClient(u, \""+buildDemoJWT()+"\");\n")
		res, err := RunClientSecretExposure(dir)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		sev := sevByCheck(t, findings(t, res))
		if sev[checkClientSideStrong] != "LOW" {
			t.Fatalf("supabase-demo JWT severity = %q, want LOW (findings: %v)", sev[checkClientSideStrong], sev)
		}
	})
}

// TestValueShapeGate verifies the provider-format-OR-high-entropy value gate
// and the *_IMAGE/*_VERSION/*_URL key ignores.
func TestValueShapeGate(t *testing.T) {
	// A high-entropy, provider-format key (sk-style) is still flagged.
	t.Run("provider-format key flagged", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "src/app/ai.tsx",
			"\"use client\";\nconst k = \"sk-AbCd1234EfGh5678IjKl9012MnOp3456\";\n")
		res, err := RunClientSecretExposure(dir)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		sev := sevByCheck(t, findings(t, res))
		if sev[checkClientSideStrong] != "CRITICAL" {
			t.Fatalf("provider-format sk- key severity = %q, want CRITICAL (findings: %v)", sev[checkClientSideStrong], sev)
		}
	})

	// NEXT_PUBLIC_FOO assigned a plain, non-key-shaped URL/word is not flagged.
	t.Run("non-key-shaped public value ignored", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "src/config.ts",
			"const NEXT_PUBLIC_FOO = \"someurl\";\n"+
				"const NEXT_PUBLIC_API = \"https://api.example.com/v1/endpoint\";\n")
		res, err := RunClientSecretExposure(dir)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if fs := findings(t, res); len(fs) != 0 {
			t.Fatalf("non-key-shaped NEXT_PUBLIC values produced %d findings, want 0: %v", len(fs), fs)
		}
	})

	// *_IMAGE / *_VERSION / *_URL keys with benign values are ignored, but a
	// URL embedding a credential still fires.
	t.Run("image/version/url keys ignored", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, ".env",
			"APP_IMAGE=registry.example.com/app@sha256:abcdef0123456789abcdef0123456789\n"+
				"APP_VERSION=1.2.3-rc.4+build567890abcdef\n"+
				"API_URL=https://api.example.com/v1/service/endpoint/path\n")
		res, err := RunClientSecretExposure(dir)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if fs := findings(t, res); len(fs) != 0 {
			t.Fatalf("image/version/url keys produced %d findings, want 0: %v", len(fs), fs)
		}
	})

	t.Run("url key with embedded credential flagged", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, ".env",
			"DATABASE_URL=postgres://admin:Sup3rS3cretP4ssw0rd@db.example.com:5432/app\n")
		res, err := RunClientSecretExposure(dir)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		if _, ok := sevByCheck(t, findings(t, res))[checkCommittedEnv]; !ok {
			t.Fatalf("DATABASE_URL with embedded credential was not flagged")
		}
	})
}

// findByCheck returns the first finding with the given check_id, or nil.
func findByCheck(fs []map[string]interface{}, checkID string) map[string]interface{} {
	for _, f := range fs {
		if id, _ := f["check_id"].(string); id == checkID {
			return f
		}
	}
	return nil
}

// TestFileClassificationSeverity verifies that file classification shapes
// severity and that strong-secret wording is correct for server paths.
func TestFileClassificationSeverity(t *testing.T) {
	jwt := buildServiceRoleJWT()

	// A generic (non-provider-format) high-entropy secret in a test file is
	// informational.
	t.Run("generic secret in test file -> INFO", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "src/app/foo.test.tsx",
			"const NEXT_PUBLIC_KEY = \""+plantedPublicSecret+"\";\n")
		res, err := RunClientSecretExposure(dir)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		f := findByCheck(findings(t, res), checkPublicPrefix)
		if f == nil {
			t.Fatalf("expected a %s finding in the test file", checkPublicPrefix)
		}
		if sev, _ := f["severity"].(string); sev != "INFO" {
			t.Fatalf("generic secret in test file severity = %q, want INFO", sev)
		}
	})

	// A provider-format, high-entropy secret in a test file keeps its elevated
	// severity (the carve-out).
	t.Run("provider-format secret in test file stays elevated", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "src/__tests__/db.ts",
			"export const c = createClient(u, \""+jwt+"\");\n")
		res, err := RunClientSecretExposure(dir)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		f := findByCheck(findings(t, res), checkClientSideStrong)
		if f == nil {
			t.Fatalf("expected a %s finding in the test file", checkClientSideStrong)
		}
		if sev, _ := f["severity"].(string); sev == "INFO" {
			t.Fatalf("provider-format JWT in test file was downgraded to INFO, want elevated")
		}
	})

	// A service_role JWT in a server-only app/api route handler is flagged but
	// NOT described as client-side / browser-shipped, and is not CRITICAL.
	t.Run("server api route wording and severity", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "src/app/api/db/route.ts",
			"export async function GET() { return createClient(u, \""+jwt+"\"); }\n")
		res, err := RunClientSecretExposure(dir)
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		f := findByCheck(findings(t, res), checkClientSideStrong)
		if f == nil {
			t.Fatalf("expected a %s finding in the server route", checkClientSideStrong)
		}
		if sev, _ := f["severity"].(string); sev == "CRITICAL" {
			t.Fatalf("server-side route secret severity = CRITICAL, want non-critical")
		}
		msg, _ := f["message"].(string)
		if strings.Contains(msg, "client-side") || strings.Contains(msg, "ships to the browser") {
			t.Fatalf("server-side finding wrongly described as client-side: %q", msg)
		}
	})
}

func keys(m map[string]map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
