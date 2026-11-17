package internal

import (
	"os"
	"path/filepath"
	"testing"

	utils "github.com/Armur-Ai/Trishul/pkg"
)

// writeWebhookFile writes a single source file into dir, creating parents.
func writeWebhookFile(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// vibeFindings extracts the vibe_security finding list from a result map.
func vibeFindings(t *testing.T, res map[string]interface{}) []map[string]interface{} {
	t.Helper()
	raw, ok := res[utils.VIBE_SECURITY]
	if !ok {
		t.Fatalf("result missing %q key; got keys %v", utils.VIBE_SECURITY, webhookKeysOf(res))
	}
	list, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("%q is %T, want []interface{}", utils.VIBE_SECURITY, raw)
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

func webhookKeysOf(m map[string]interface{}) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// checkIDs returns the set of check_id values present in the findings.
func checkIDs(findings []map[string]interface{}) map[string]int {
	counts := map[string]int{}
	for _, f := range findings {
		id, _ := f["check_id"].(string)
		counts[id]++
	}
	return counts
}

func TestRunWebhookVerification_StripeWebhookNoVerify(t *testing.T) {
	dir := t.TempDir()
	writeWebhookFile(t, dir, "stripe_webhook.js", `
const express = require('express');
const app = express();

// Stripe sends subscription events here.
app.post('/webhook/stripe', (req, res) => {
  const event = req.body;
  switch (event.type) {
    case 'checkout.session.completed':
      grantAccess(event.data.object.customer);
      break;
  }
  res.sendStatus(200);
});
`)

	res, err := RunWebhookVerification(dir)
	if err != nil {
		t.Fatalf("RunWebhookVerification: %v", err)
	}
	findings := vibeFindings(t, res)
	ids := checkIDs(findings)
	if ids[checkUnverifiedWebhook] == 0 {
		t.Fatalf("expected %s, got findings %v", checkUnverifiedWebhook, findings)
	}

	// Validate the finding's shape and required keys.
	var got map[string]interface{}
	for _, f := range findings {
		if f["check_id"] == checkUnverifiedWebhook {
			got = f
			break
		}
	}
	for _, key := range []string{"path", "line", "message", "severity", "check_id", "cwe", "confidence", "remediation"} {
		if _, ok := got[key]; !ok {
			t.Errorf("finding missing key %q: %v", key, got)
		}
	}
	if _, ok := got["line"].(int); !ok {
		t.Errorf("line is %T, want int", got["line"])
	}
	if got["severity"] != "HIGH" {
		t.Errorf("severity = %v, want HIGH", got["severity"])
	}
	if got["confidence"] != "MEDIUM" {
		t.Errorf("confidence = %v, want MEDIUM", got["confidence"])
	}
	if got["cwe"] != "CWE-345" {
		t.Errorf("cwe = %v, want CWE-345", got["cwe"])
	}
}

func TestRunWebhookVerification_CheckoutTrustsClientAmount(t *testing.T) {
	dir := t.TempDir()
	writeWebhookFile(t, dir, "checkout.js", `
app.post('/checkout', async (req, res) => {
  const amount = req.body.amount;
  const charge = await stripe.charges.create({
    amount,
    currency: 'usd',
    source: req.body.token,
  });
  res.json({ ok: true, id: charge.id });
});
`)

	res, err := RunWebhookVerification(dir)
	if err != nil {
		t.Fatalf("RunWebhookVerification: %v", err)
	}
	findings := vibeFindings(t, res)
	ids := checkIDs(findings)
	if ids[checkClientTrustedPayment] == 0 {
		t.Fatalf("expected %s, got findings %v", checkClientTrustedPayment, findings)
	}
	// This is not a webhook handler — must NOT be flagged for 001.
	if ids[checkUnverifiedWebhook] != 0 {
		t.Errorf("unexpected %s on a checkout route: %v", checkUnverifiedWebhook, findings)
	}
}

func TestRunWebhookVerification_StripeWebhookVerifiedIsClean(t *testing.T) {
	dir := t.TempDir()
	writeWebhookFile(t, dir, "verified_webhook.js", `
app.post('/webhook/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send('bad signature');
  }
  handleEvent(event);
  res.sendStatus(200);
});
`)

	res, err := RunWebhookVerification(dir)
	if err != nil {
		t.Fatalf("RunWebhookVerification: %v", err)
	}
	findings := vibeFindings(t, res)
	if len(findings) != 0 {
		t.Fatalf("verified webhook should be clean, got %v", findings)
	}
}

func TestRunWebhookVerification_RolePythonHandler(t *testing.T) {
	dir := t.TempDir()
	writeWebhookFile(t, dir, "admin.py", `
@app.route('/users/promote', methods=['POST'])
def promote():
    # trust the client to tell us their role... bad idea
    role = request.json.get('role')
    grant_admin(current_user, role)
    return jsonify(ok=True)
`)

	res, err := RunWebhookVerification(dir)
	if err != nil {
		t.Fatalf("RunWebhookVerification: %v", err)
	}
	findings := vibeFindings(t, res)
	if checkIDs(findings)[checkClientTrustedPayment] == 0 {
		t.Fatalf("expected %s for client-trusted role, got %v", checkClientTrustedPayment, findings)
	}
}

func TestRunWebhookVerification_NonWebhookRouteIsClean(t *testing.T) {
	dir := t.TempDir()
	// A normal route that reads the body but is neither a webhook nor a payment
	// handler — must produce nothing.
	writeWebhookFile(t, dir, "notes.js", `
app.post('/notes', (req, res) => {
  const note = req.body;
  db.notes.insert(note);
  res.sendStatus(201);
});
`)

	res, err := RunWebhookVerification(dir)
	if err != nil {
		t.Fatalf("RunWebhookVerification: %v", err)
	}
	if findings := vibeFindings(t, res); len(findings) != 0 {
		t.Fatalf("non-webhook route should be clean, got %v", findings)
	}
}

func TestRunWebhookVerification_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	res, err := RunWebhookVerification(dir)
	if err != nil {
		t.Fatalf("RunWebhookVerification: %v", err)
	}
	findings := vibeFindings(t, res)
	if len(findings) != 0 {
		t.Fatalf("empty dir should yield no findings, got %v", findings)
	}
}
