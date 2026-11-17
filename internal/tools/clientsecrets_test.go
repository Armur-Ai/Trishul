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

func keys(m map[string]map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
