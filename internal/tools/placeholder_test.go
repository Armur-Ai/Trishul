package internal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	utils "github.com/Armur-Ai/Trishul/pkg"
)

// phWrite is a small helper that writes a file under dir, creating parents.
func phWrite(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// phFindings extracts the VIBE_SECURITY finding list from a run result.
func phFindings(t *testing.T, result map[string]interface{}) []map[string]interface{} {
	t.Helper()
	raw, ok := result[utils.VIBE_SECURITY]
	if !ok {
		t.Fatalf("result missing %q key", utils.VIBE_SECURITY)
	}
	list, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("%q is not []interface{}, got %T", utils.VIBE_SECURITY, raw)
	}
	out := make([]map[string]interface{}, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			t.Fatalf("finding is not a map, got %T", item)
		}
		out = append(out, m)
	}
	return out
}

// phByCheck returns the findings whose check_id equals id.
func phByCheck(findings []map[string]interface{}, id string) []map[string]interface{} {
	var out []map[string]interface{}
	for _, f := range findings {
		if f["check_id"] == id {
			out = append(out, f)
		}
	}
	return out
}

func TestPlaceholder_HardcodedSecret_FlaggedHigh_NoRawLeak(t *testing.T) {
	dir := t.TempDir()
	// Distinctive placeholder literal so the leak assertion is unambiguous: the
	// string "changeme" must appear nowhere in the emitted result.
	phWrite(t, dir, "config.js", `const JWT_SECRET = "changeme";`+"\n")

	result, err := RunPlaceholderSecurity(dir)
	if err != nil {
		t.Fatalf("RunPlaceholderSecurity: %v", err)
	}
	findings := phFindings(t, result)

	secretFindings := phByCheck(findings, "VIBE-PLACEHOLDER-001")
	if len(secretFindings) != 1 {
		t.Fatalf("expected 1 VIBE-PLACEHOLDER-001 finding, got %d: %+v", len(secretFindings), findings)
	}
	f := secretFindings[0]
	if f["severity"] != "HIGH" {
		t.Errorf("expected HIGH severity, got %v", f["severity"])
	}
	if f["cwe"] != "CWE-798" {
		t.Errorf("expected CWE-798, got %v", f["cwe"])
	}
	if f["line"].(int) != 1 {
		t.Errorf("expected line 1, got %v", f["line"])
	}
	if _, ok := f["secret_preview"]; !ok {
		t.Errorf("expected secret_preview to be present")
	}
	if _, ok := f["fingerprint"]; !ok {
		t.Errorf("expected fingerprint to be present")
	}
	if _, ok := f["remediation"]; !ok {
		t.Errorf("expected remediation to be present")
	}

	// The critical guarantee: the marshaled result must NOT contain the raw value.
	blob, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), "changeme") {
		t.Fatalf("raw secret value leaked into emitted result: %s", blob)
	}
}

func TestPlaceholder_DisabledVerification_Flagged(t *testing.T) {
	dir := t.TempDir()
	phWrite(t, dir, "client.py", "resp = requests.get(url, verify=False)\n")

	findings := phFindings(t, mustRun(t, dir))
	vf := phByCheck(findings, "VIBE-PLACEHOLDER-003")
	if len(vf) != 1 {
		t.Fatalf("expected 1 VIBE-PLACEHOLDER-003 finding, got %d: %+v", len(vf), findings)
	}
	if vf[0]["severity"] != "HIGH" {
		t.Errorf("expected HIGH, got %v", vf[0]["severity"])
	}
	if vf[0]["cwe"] != "CWE-295" {
		t.Errorf("expected CWE-295, got %v", vf[0]["cwe"])
	}
}

func TestPlaceholder_WildcardCORSWithCredentials_Flagged(t *testing.T) {
	dir := t.TempDir()
	phWrite(t, dir, "server.js", `app.use(cors({ origin: "*", credentials: true }));`+"\n")

	findings := phFindings(t, mustRun(t, dir))
	cf := phByCheck(findings, "VIBE-PLACEHOLDER-004")
	if len(cf) != 1 {
		t.Fatalf("expected 1 VIBE-PLACEHOLDER-004 finding, got %d: %+v", len(cf), findings)
	}
	if cf[0]["severity"] != "HIGH" {
		t.Errorf("expected HIGH, got %v", cf[0]["severity"])
	}
	if cf[0]["cwe"] != "CWE-942" {
		t.Errorf("expected CWE-942, got %v", cf[0]["cwe"])
	}
}

func TestPlaceholder_SecurityTODO_FlaggedLow(t *testing.T) {
	dir := t.TempDir()
	phWrite(t, dir, "handler.go", "func handler() {\n\t// TODO: add auth check here\n}\n")

	findings := phFindings(t, mustRun(t, dir))
	tf := phByCheck(findings, "VIBE-PLACEHOLDER-006")
	if len(tf) != 1 {
		t.Fatalf("expected 1 VIBE-PLACEHOLDER-006 finding, got %d: %+v", len(tf), findings)
	}
	if tf[0]["severity"] != "LOW" {
		t.Errorf("expected LOW, got %v", tf[0]["severity"])
	}
	if tf[0]["cwe"] != "CWE-1111" {
		t.Errorf("expected CWE-1111, got %v", tf[0]["cwe"])
	}
}

func TestPlaceholder_DefaultCredentials_Flagged(t *testing.T) {
	dir := t.TempDir()
	phWrite(t, dir, "db.yaml", "username: admin\npassword: admin\n")

	findings := phFindings(t, mustRun(t, dir))
	df := phByCheck(findings, "VIBE-PLACEHOLDER-002")
	if len(df) == 0 {
		t.Fatalf("expected a VIBE-PLACEHOLDER-002 finding, got none: %+v", findings)
	}
	if df[0]["severity"] != "HIGH" {
		t.Errorf("expected HIGH, got %v", df[0]["severity"])
	}
}

func TestPlaceholder_DisplayLabels_NotFlagged(t *testing.T) {
	dir := t.TempDir()
	// A UI label / form-field table: the values are display strings (the field
	// name re-cased), not credentials, and must not trip the default-credential
	// rule even though "user"/"password" are otherwise default values.
	phWrite(t, dir, "labels.js", "const labels = {\n"+
		"  user: 'User',\n"+
		"  username: 'Username',\n"+
		"  password: 'Password',\n"+
		"};\n")

	findings := phFindings(t, mustRun(t, dir))
	if got := phByCheck(findings, "VIBE-PLACEHOLDER-002"); len(got) != 0 {
		t.Fatalf("display-label strings should not be flagged as default creds, got %+v", got)
	}
}

func TestPlaceholder_LocaleStringsTable_NotFlagged(t *testing.T) {
	dir := t.TempDir()
	// An i18n / locale string table. Even values that look like default
	// credentials are translation strings here, so the credential rules are
	// suppressed for locale-classified files.
	phWrite(t, dir, "locales/en.json", "{\n  \"username\": \"admin\",\n  \"password\": \"admin\"\n}\n")

	findings := phFindings(t, mustRun(t, dir))
	if got := phByCheck(findings, "VIBE-PLACEHOLDER-002"); len(got) != 0 {
		t.Fatalf("locale string table should not be flagged as default creds, got %+v", got)
	}
	if got := phByCheck(findings, "VIBE-PLACEHOLDER-001"); len(got) != 0 {
		t.Fatalf("locale string table should not be flagged for hardcoded secrets, got %+v", got)
	}
}

func TestPlaceholder_URLNormTestCase_NotFlagged(t *testing.T) {
	dir := t.TempDir()
	// A URL-normalization test fixture: `user:pass@` userinfo is test data for a
	// URL parser, not an embedded credential, so it must not be flagged inside a
	// test file.
	phWrite(t, dir, "url_test.go", "package x\n"+
		"func TestNorm(t *testing.T) { u := \"http://user:pass@example.com/p\"; _ = u }\n")

	findings := phFindings(t, mustRun(t, dir))
	if got := phByCheck(findings, "VIBE-PLACEHOLDER-002"); len(got) != 0 {
		t.Fatalf("user:pass@ in a test file should not be flagged, got %+v", got)
	}
}

func TestPlaceholder_InlineCreds_NonTestStillFlagged(t *testing.T) {
	dir := t.TempDir()
	// The same userinfo in production code is still a real embedded credential.
	phWrite(t, dir, "db.go", "const dsn = \"postgres://user:pass@db:5432/app\"\n")

	findings := phFindings(t, mustRun(t, dir))
	if got := phByCheck(findings, "VIBE-PLACEHOLDER-002"); len(got) != 1 {
		t.Fatalf("inline creds in prod code should still be flagged, got %+v", got)
	}
}

func TestPlaceholder_PrivilegedInlineCreds_FlaggedEvenInTest(t *testing.T) {
	dir := t.TempDir()
	// A privileged default pair (admin:admin@) is a genuine default-credential
	// demonstration and stays flagged even inside a test file.
	phWrite(t, dir, "conn_test.go", "package x\n"+
		"var dsn = \"mongodb://admin:admin@localhost:27017\"\n")

	findings := phFindings(t, mustRun(t, dir))
	if got := phByCheck(findings, "VIBE-PLACEHOLDER-002"); len(got) != 1 {
		t.Fatalf("admin:admin@ should stay flagged even in a test file, got %+v", got)
	}
}

func TestPlaceholder_DebugMode_FlaggedMedium(t *testing.T) {
	dir := t.TempDir()
	phWrite(t, dir, "settings.py", "DEBUG = True\n")

	findings := phFindings(t, mustRun(t, dir))
	gf := phByCheck(findings, "VIBE-PLACEHOLDER-005")
	if len(gf) != 1 {
		t.Fatalf("expected 1 VIBE-PLACEHOLDER-005 finding, got %d: %+v", len(gf), findings)
	}
	if gf[0]["severity"] != "MEDIUM" {
		t.Errorf("expected MEDIUM, got %v", gf[0]["severity"])
	}
	if gf[0]["cwe"] != "CWE-489" {
		t.Errorf("expected CWE-489, got %v", gf[0]["cwe"])
	}
}

func TestPlaceholder_EnvConfig_IsClean(t *testing.T) {
	dir := t.TempDir()
	// A secret read from the environment is correct and must NOT be flagged.
	phWrite(t, dir, "config.js", `const JWT_SECRET = process.env.JWT_SECRET || "";`+"\n"+
		`const SESSION_SECRET = process.env.SESSION_SECRET;`+"\n")

	findings := phFindings(t, mustRun(t, dir))
	if len(findings) != 0 {
		t.Fatalf("expected no findings for env-based config, got %d: %+v", len(findings), findings)
	}
}

func TestPlaceholder_CommentedOutLine_NotFlagged(t *testing.T) {
	dir := t.TempDir()
	// A commented-out insecure line must not produce an active-code finding.
	phWrite(t, dir, "client.py", "# verify=False  (left here as a note)\n")

	findings := phFindings(t, mustRun(t, dir))
	if got := phByCheck(findings, "VIBE-PLACEHOLDER-003"); len(got) != 0 {
		t.Fatalf("commented verify=False should not be flagged, got %+v", got)
	}
}

func TestPlaceholder_StrongEnvSecret_NotFlagged(t *testing.T) {
	dir := t.TempDir()
	// A long, random-looking hardcoded value is not an obvious placeholder; be
	// conservative and do not flag it as a placeholder secret.
	phWrite(t, dir, "config.go", "var apiKey = \"a8F3kD9jQ2mXp7Lz1Nb4Rt6Wc0Yv5Ue\"\n")

	findings := phFindings(t, mustRun(t, dir))
	if got := phByCheck(findings, "VIBE-PLACEHOLDER-001"); len(got) != 0 {
		t.Fatalf("strong random value should not be flagged as placeholder, got %+v", got)
	}
}

func TestPlaceholder_EmptyDir_NoFindings(t *testing.T) {
	dir := t.TempDir()
	result := mustRun(t, dir)
	findings := phFindings(t, result)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for empty dir, got %d", len(findings))
	}
}

func TestPlaceholder_Deterministic(t *testing.T) {
	dir := t.TempDir()
	phWrite(t, dir, "a.py", "verify=False\n")
	phWrite(t, dir, "b.js", `cors({ origin: "*", credentials: true });`+"\n")
	phWrite(t, dir, "settings.py", "DEBUG = True\n")

	first, err := json.Marshal(mustRun(t, dir))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	second, err := json.Marshal(mustRun(t, dir))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("output not deterministic:\n%s\n%s", first, second)
	}
}

func mustRun(t *testing.T, dir string) map[string]interface{} {
	t.Helper()
	result, err := RunPlaceholderSecurity(dir)
	if err != nil {
		t.Fatalf("RunPlaceholderSecurity: %v", err)
	}
	return result
}
