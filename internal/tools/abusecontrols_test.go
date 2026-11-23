package internal

import (
	"os"
	"path/filepath"
	"testing"

	utils "github.com/Armur-Ai/Trishul/pkg"
)

// writeSrc writes a source file at rel under dir, creating parent dirs.
func writeSrc(t *testing.T, dir, rel, body string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// abuseByCheck groups findings by their check_id.
func abuseByCheck(findings []map[string]interface{}) map[string][]map[string]interface{} {
	out := map[string][]map[string]interface{}{}
	for _, f := range findings {
		id, _ := f["check_id"].(string)
		out[id] = append(out[id], f)
	}
	return out
}

func TestScanAbuse_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	findings, err := scanAbuseControls(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty dir, got %d: %v", len(findings), findings)
	}
}

func TestScanAbuse_AuthAndLLMNoLimiter_Flags001(t *testing.T) {
	dir := t.TempDir()
	writeSrc(t, dir, "routes/auth.js", `
const express = require('express');
const router = express.Router();

router.post('/login', async (req, res) => {
	const user = await db.users.findOne({ email: req.body.email });
	res.json({ ok: true });
});
`)
	writeSrc(t, dir, "routes/chat.js", `
const OpenAI = require('openai');
const client = new OpenAI();

app.post('/chat', async (req, res) => {
	const completion = await client.chat.completions.create({ model: 'gpt-4', messages: [] });
	res.json(completion);
});
`)

	findings, err := scanAbuseControls(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	by := abuseByCheck(findings)
	if len(by["VIBE-ABUSE-001"]) < 2 {
		t.Fatalf("expected at least 2 VIBE-ABUSE-001 findings (auth + LLM), got %d: %v", len(by["VIBE-ABUSE-001"]), findings)
	}

	// Validate finding shape and CWE differentiation.
	var sawAuthCWE, sawLLMCWE bool
	for _, f := range by["VIBE-ABUSE-001"] {
		if f["severity"] != "MEDIUM" {
			t.Errorf("expected MEDIUM severity, got %v", f["severity"])
		}
		if _, ok := f["remediation"].(string); !ok {
			t.Errorf("finding missing remediation: %v", f)
		}
		if _, ok := f["line"].(int); !ok {
			t.Errorf("finding line not an int: %T", f["line"])
		}
		cwes, _ := f["cwe"].([]string)
		for _, c := range cwes {
			if c == "CWE-307" {
				sawAuthCWE = true
			}
		}
		if len(cwes) == 1 && cwes[0] == "CWE-770" {
			sawLLMCWE = true
		}
	}
	if !sawAuthCWE {
		t.Errorf("expected an auth finding carrying CWE-307: %v", by["VIBE-ABUSE-001"])
	}
	if !sawLLMCWE {
		t.Errorf("expected an LLM finding carrying CWE-770: %v", by["VIBE-ABUSE-001"])
	}
}

func TestScanAbuse_PublicGetAndLLMImport_NoFinding001(t *testing.T) {
	dir := t.TempDir()
	// A generic public GET route is NOT a sensitive endpoint -> must not fire 001.
	writeSrc(t, dir, "routes/products.js", `
app.get('/products', async (req, res) => {
	const items = await db.products.findMany();
	res.json(items);
});

app.get('/api/health-ish/data', (req, res) => res.json({ ok: true }));
`)
	// A bare LLM import with NO call site is not an exposed surface -> no 001.
	writeSrc(t, dir, "lib/ai.js", `
const OpenAI = require('openai');
import anthropic from '@anthropic-ai/sdk';
const client = new OpenAI();
module.exports = { client };
`)

	findings, err := scanAbuseControls(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	by := abuseByCheck(findings)
	if len(by["VIBE-ABUSE-001"]) != 0 {
		t.Errorf("expected no VIBE-ABUSE-001 for a public GET / bare LLM import, got %d: %v", len(by["VIBE-ABUSE-001"]), by["VIBE-ABUSE-001"])
	}
}

func TestScanAbuse_EmailEndpointNoLimiter_Flags001(t *testing.T) {
	dir := t.TempDir()
	writeSrc(t, dir, "routes/contact.js", `
const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({ host: 'smtp.example.com' });

app.post('/contact', async (req, res) => {
	await transporter.sendMail({ to: req.body.to, subject: 'hi', text: req.body.msg });
	res.json({ sent: true });
});
`)

	findings, err := scanAbuseControls(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	by := abuseByCheck(findings)
	if len(by["VIBE-ABUSE-001"]) == 0 {
		t.Fatalf("expected VIBE-ABUSE-001 for an unrate-limited email-sending endpoint, got none: %v", findings)
	}
	// Email findings carry the generic rate-limit CWE (not the auth-specific 307).
	for _, f := range by["VIBE-ABUSE-001"] {
		cwes, _ := f["cwe"].([]string)
		if len(cwes) != 1 || cwes[0] != "CWE-770" {
			t.Errorf("email finding expected [CWE-770], got %v", cwes)
		}
	}
}

func TestScanAbuse_RateLimiterPresent_Clean(t *testing.T) {
	dir := t.TempDir()
	// Limiter declared in one file...
	writeSrc(t, dir, "middleware/limit.js", `
const rateLimit = require('express-rate-limit');
module.exports = rateLimit({ windowMs: 60000, max: 10 });
`)
	// ...suppresses 001 for the auth/LLM routes in other files.
	writeSrc(t, dir, "routes/auth.js", `
app.post('/login', async (req, res) => {
	const user = await db.users.findOne({ email: req.body.email });
	res.json({ ok: true });
});
`)
	writeSrc(t, dir, "routes/chat.js", `
app.post('/chat', async (req, res) => {
	const c = await openai.chat.completions.create({ messages: [] });
	res.json(c);
});
`)

	findings, err := scanAbuseControls(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	by := abuseByCheck(findings)
	if len(by["VIBE-ABUSE-001"]) != 0 {
		t.Errorf("expected 0 VIBE-ABUSE-001 when a rate limiter is present, got %d: %v", len(by["VIBE-ABUSE-001"]), by["VIBE-ABUSE-001"])
	}
}

func TestScanAbuse_UnboundedMulter_Flags002(t *testing.T) {
	dir := t.TempDir()
	writeSrc(t, dir, "upload.js", `
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

app.post('/upload', upload.single('file'), (req, res) => {
	res.json({ name: req.file.originalname });
});
`)

	findings, err := scanAbuseControls(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	by := abuseByCheck(findings)
	if len(by["VIBE-ABUSE-002"]) == 0 {
		t.Fatalf("expected VIBE-ABUSE-002 for unbounded multer upload, got none: %v", findings)
	}
	f := by["VIBE-ABUSE-002"][0]
	if f["severity"] != "MEDIUM" {
		t.Errorf("expected MEDIUM severity, got %v", f["severity"])
	}
	cwes, _ := f["cwe"].([]string)
	if len(cwes) == 0 || cwes[0] != "CWE-400" {
		t.Errorf("expected CWE-400, got %v", cwes)
	}
}

func TestScanAbuse_MulterWithLimit_CleanOf002(t *testing.T) {
	dir := t.TempDir()
	writeSrc(t, dir, "upload.js", `
const multer = require('multer');
const upload = multer({ dest: 'uploads/', limits: { fileSize: 1048576 } });
app.post('/upload', upload.single('file'), (req, res) => res.json({ ok: true }));
`)
	findings, err := scanAbuseControls(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	by := abuseByCheck(findings)
	if len(by["VIBE-ABUSE-002"]) != 0 {
		t.Errorf("expected no VIBE-ABUSE-002 when a size limit is configured, got %v", by["VIBE-ABUSE-002"])
	}
}

func TestScanAbuse_BodySpreadNoValidation_Flags003(t *testing.T) {
	dir := t.TempDir()
	writeSrc(t, dir, "users.js", `
app.put('/users/:id', async (req, res) => {
	const u = await prisma.user.update({ where: { id: req.params.id }, data: { ...req.body } });
	res.json(u);
});
`)
	findings, err := scanAbuseControls(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	by := abuseByCheck(findings)
	if len(by["VIBE-ABUSE-003"]) == 0 {
		t.Fatalf("expected VIBE-ABUSE-003 for body-spread into DB without validation, got none: %v", findings)
	}
	f := by["VIBE-ABUSE-003"][0]
	if f["severity"] != "LOW" {
		t.Errorf("expected LOW severity, got %v", f["severity"])
	}
	cwes, _ := f["cwe"].([]string)
	if len(cwes) == 0 || cwes[0] != "CWE-20" {
		t.Errorf("expected CWE-20, got %v", cwes)
	}
}

func TestScanAbuse_BodySpreadWithZod_CleanOf003(t *testing.T) {
	dir := t.TempDir()
	writeSrc(t, dir, "users.js", `
import { z } from 'zod';
const schema = z.object({ name: z.string() });
app.put('/users/:id', async (req, res) => {
	const data = schema.parse(req.body);
	const u = await prisma.user.update({ where: { id: req.params.id }, data: { ...req.body } });
	res.json(u);
});
`)
	findings, err := scanAbuseControls(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	by := abuseByCheck(findings)
	if len(by["VIBE-ABUSE-003"]) != 0 {
		t.Errorf("expected no VIBE-ABUSE-003 when zod validation is present, got %v", by["VIBE-ABUSE-003"])
	}
}

func TestScanAbuse_HealthRoute_Clean(t *testing.T) {
	dir := t.TempDir()
	writeSrc(t, dir, "health.js", `
app.get('/health', (req, res) => res.json({ status: 'ok' }));
app.get('/status', (req, res) => res.send('ok'));
`)
	findings, err := scanAbuseControls(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected health/status routes to be clean, got %v", findings)
	}
}

func TestRunAbuseControls_CategoryShapeAndCheckIDs(t *testing.T) {
	dir := t.TempDir()
	writeSrc(t, dir, "auth.py", `
from fastapi import FastAPI
app = FastAPI()

@app.post("/login")
async def login(request):
    return {"ok": True}
`)
	writeSrc(t, dir, "chat.py", `
import anthropic
client = anthropic.Anthropic()

@app.post("/chat")
async def chat(request):
    msg = client.messages.create(model="claude-3", messages=[])
    return msg
`)

	res, err := RunAbuseControls(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	raw, ok := res[utils.VIBE_SECURITY]
	if !ok {
		t.Fatalf("expected results under %q category key", utils.VIBE_SECURITY)
	}
	slice, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("expected %q to be a slice, got %T", utils.VIBE_SECURITY, raw)
	}
	if len(slice) == 0 {
		t.Fatalf("expected at least one finding under %q", utils.VIBE_SECURITY)
	}

	ids := map[string]bool{}
	for _, item := range slice {
		f, ok := item.(map[string]interface{})
		if !ok {
			t.Fatalf("finding is not a map: %T", item)
		}
		id, _ := f["check_id"].(string)
		ids[id] = true
		// Every finding must carry the required keys.
		for _, k := range []string{"path", "line", "message", "severity", "check_id", "cwe", "confidence", "remediation"} {
			if _, present := f[k]; !present {
				t.Errorf("finding missing key %q: %v", k, f)
			}
		}
	}
	if !ids["VIBE-ABUSE-001"] {
		t.Errorf("expected VIBE-ABUSE-001 among check_ids, got %v", ids)
	}
}
