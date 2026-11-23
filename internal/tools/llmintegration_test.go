package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	utils "github.com/Armur-Ai/Trishul/pkg"
)

// writeLLMFile writes content to a file under dir, creating parent dirs.
func writeLLMFile(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// llmFindings extracts the vibe_security findings slice from a run result.
func llmFindings(t *testing.T, res map[string]interface{}) []map[string]interface{} {
	t.Helper()
	raw, ok := res[utils.VIBE_SECURITY]
	if !ok {
		t.Fatalf("result missing key %q; keys=%v", utils.VIBE_SECURITY, keysOf(res))
	}
	list, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("vibe_security is %T, want []interface{}", raw)
	}
	var out []map[string]interface{}
	for _, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			t.Fatalf("finding is %T, want map[string]interface{}", item)
		}
		out = append(out, m)
	}
	return out
}

func keysOf(m map[string]interface{}) []string {
	var k []string
	for key := range m {
		k = append(k, key)
	}
	return k
}

func findByCheckID(findings []map[string]interface{}, id string) map[string]interface{} {
	for _, f := range findings {
		if f["check_id"] == id {
			return f
		}
	}
	return nil
}

func TestRunUnsafeLLMIntegration_PromptInjection(t *testing.T) {
	dir := t.TempDir()
	writeLLMFile(t, dir, "handler.js", `
const express = require("express");
const OpenAI = require("openai");
const openai = new OpenAI();

app.post("/chat", async (req, res) => {
  const systemPrompt = "You are a helpful assistant. " + req.body.userMessage;
  const completion = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "system", content: systemPrompt }],
  });
  res.json(completion);
});
`)

	res, err := RunUnsafeLLMIntegration(dir)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	findings := llmFindings(t, res)

	f := findByCheckID(findings, "VIBE-LLM-001")
	if f == nil {
		t.Fatalf("expected VIBE-LLM-001; got %v", findings)
	}
	if f["severity"] != "HIGH" {
		t.Errorf("severity = %v, want HIGH", f["severity"])
	}
	if f["confidence"] != "MEDIUM" {
		t.Errorf("confidence = %v, want MEDIUM", f["confidence"])
	}
	if cwes, _ := f["cwe"].([]string); len(cwes) == 0 || cwes[0] != "CWE-94" {
		t.Errorf("cwe = %v, want CWE-94", f["cwe"])
	}
	if _, ok := f["remediation"].(string); !ok || f["remediation"] == "" {
		t.Errorf("remediation missing")
	}
}

func TestRunUnsafeLLMIntegration_DangerousSink(t *testing.T) {
	dir := t.TempDir()
	writeLLMFile(t, dir, "run.js", `
const openai = new OpenAI();
const completion = await openai.chat.completions.create({ model: "gpt-4", messages: [{ role: "user", content: "write code" }] });
const code = completion.choices[0].message.content;
eval(code);
`)

	res, err := RunUnsafeLLMIntegration(dir)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	findings := llmFindings(t, res)

	f := findByCheckID(findings, "VIBE-LLM-002")
	if f == nil {
		t.Fatalf("expected VIBE-LLM-002; got %v", findings)
	}
	if f["severity"] != "HIGH" {
		t.Errorf("severity = %v, want HIGH", f["severity"])
	}
}

func TestRunUnsafeLLMIntegration_ClientApiKey(t *testing.T) {
	dir := t.TempDir()
	const fakeKey = "sk-FAKE1234567890SECRETVALUE"
	writeLLMFile(t, dir, "Chat.jsx", `
"use client";
import OpenAI from "openai";

const apiKey = "`+fakeKey+`";
const client = new OpenAI({ apiKey, dangerouslyAllowBrowser: true });
`)

	res, err := RunUnsafeLLMIntegration(dir)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	findings := llmFindings(t, res)

	f := findByCheckID(findings, "VIBE-LLM-003")
	if f == nil {
		t.Fatalf("expected VIBE-LLM-003; got %v", findings)
	}
	if f["severity"] != "CRITICAL" {
		t.Errorf("severity = %v, want CRITICAL", f["severity"])
	}
	if cwes, _ := f["cwe"].([]string); len(cwes) == 0 || cwes[0] != "CWE-200" {
		t.Errorf("cwe = %v, want CWE-200", f["cwe"])
	}
	// The raw key value must never appear in any finding field.
	for _, fnd := range findings {
		for k, v := range fnd {
			if s, ok := v.(string); ok && strings.Contains(s, fakeKey) {
				t.Fatalf("finding field %q leaked raw key: %q", k, s)
			}
		}
	}
}

// runLLM is a small helper that scans a single-file fixture and returns its
// findings.
func runLLM(t *testing.T, name, content string) []map[string]interface{} {
	t.Helper()
	dir := t.TempDir()
	writeLLMFile(t, dir, name, content)
	res, err := RunUnsafeLLMIntegration(dir)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return llmFindings(t, res)
}

// VIBE-LLM-002 must not treat `.exec()` method calls on non-child_process
// objects (RegExp.prototype.exec, a db handle's .exec) as a shell sink.
func TestRunUnsafeLLMIntegration_ExecSink_MethodCallsDoNotFire(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"regexp.exec", `
const openai = new OpenAI();
const completion = await openai.chat.completions.create({ messages: [] });
const text = completion.choices[0].message.content;
const re = /danger/;
const m = re.exec(text);
`},
		{"db.exec", `
const openai = new OpenAI();
const completion = await openai.chat.completions.create({ messages: [] });
const sql = completion.choices[0].message.content;
db.exec(sql);
`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings := runLLM(t, "f.js", c.src)
			if f := findByCheckID(findings, "VIBE-LLM-002"); f != nil {
				t.Fatalf("VIBE-LLM-002 should not fire on %s; got %v", c.name, f)
			}
		})
	}
}

// A real child_process exec/spawn call reached by model output must fire.
func TestRunUnsafeLLMIntegration_ExecSink_ChildProcessFires(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"require destructure", `
const { exec } = require("child_process");
const openai = new OpenAI();
const completion = await openai.chat.completions.create({ messages: [] });
const cmd = completion.choices[0].message.content;
exec(cmd);
`},
		{"require namespace", `
const cp = require("node:child_process");
const openai = new OpenAI();
const completion = await openai.chat.completions.create({ messages: [] });
const cmd = completion.choices[0].message.content;
cp.execSync(cmd);
`},
		{"esm named import", `
import { spawn } from "child_process";
import OpenAI from "openai";
const openai = new OpenAI();
const completion = await openai.chat.completions.create({ messages: [] });
const cmd = completion.choices[0].message.content;
spawn(cmd);
`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			findings := runLLM(t, "f.js", c.src)
			f := findByCheckID(findings, "VIBE-LLM-002")
			if f == nil {
				t.Fatalf("expected VIBE-LLM-002 on %s; got %v", c.name, findings)
			}
			if f["severity"] != "HIGH" {
				t.Errorf("severity = %v, want HIGH", f["severity"])
			}
			if _, ok := f["experimental"]; ok {
				t.Errorf("command sink should not be experimental; got %v", f["experimental"])
			}
		})
	}
}

// A bare child_process exec binding not tainted by model output must not fire.
func TestRunUnsafeLLMIntegration_ExecSink_UntaintedDoesNotFire(t *testing.T) {
	findings := runLLM(t, "f.js", `
const { exec } = require("child_process");
exec("ls -la /tmp");
`)
	if f := findByCheckID(findings, "VIBE-LLM-002"); f != nil {
		t.Fatalf("VIBE-LLM-002 should not fire without LLM taint; got %v", f)
	}
}

// Python: exec()/subprocess(shell=True) reached by model output fire; a
// subprocess call without a shell does not.
func TestRunUnsafeLLMIntegration_ExecSink_Python(t *testing.T) {
	t.Run("bare exec fires", func(t *testing.T) {
		findings := runLLM(t, "h.py", `
from openai import OpenAI
client = OpenAI()

def handle(user):
    completion = client.chat.completions.create(model="gpt-4", messages=[])
    code = completion.choices[0].message.content
    exec(code)
`)
		if findByCheckID(findings, "VIBE-LLM-002") == nil {
			t.Fatalf("expected VIBE-LLM-002 for Python exec(); got %v", findings)
		}
	})
	t.Run("subprocess shell=True fires", func(t *testing.T) {
		findings := runLLM(t, "h.py", `
import subprocess
from openai import OpenAI
client = OpenAI()

def handle():
    completion = client.chat.completions.create(model="gpt-4", messages=[])
    cmd = completion.choices[0].message.content
    subprocess.run(cmd, shell=True)
`)
		if findByCheckID(findings, "VIBE-LLM-002") == nil {
			t.Fatalf("expected VIBE-LLM-002 for subprocess shell=True; got %v", findings)
		}
	})
	t.Run("subprocess without shell does not fire", func(t *testing.T) {
		findings := runLLM(t, "h.py", `
import subprocess
from openai import OpenAI
client = OpenAI()

def handle():
    completion = client.chat.completions.create(model="gpt-4", messages=[])
    arg = completion.choices[0].message.content
    subprocess.run(["echo", arg])
`)
		if f := findByCheckID(findings, "VIBE-LLM-002"); f != nil {
			t.Fatalf("VIBE-LLM-002 should not fire for argv subprocess; got %v", f)
		}
	})
}

// Go: exec.Command reached by model output fires.
func TestRunUnsafeLLMIntegration_ExecSink_Go(t *testing.T) {
	findings := runLLM(t, "main.go", `
package main

import (
	"os/exec"
	anthropic "github.com/anthropics/anthropic-sdk-go"
)

func handle(client *anthropic.Client, ctx interface{}, params interface{}) {
	resp, _ := client.Messages.New(ctx, params)
	cmd := resp.Content[0].Text
	exec.Command("sh", "-c", cmd).Run()
}
`)
	f := findByCheckID(findings, "VIBE-LLM-002")
	if f == nil {
		t.Fatalf("expected VIBE-LLM-002 for Go exec.Command; got %v", findings)
	}
	if f["severity"] != "HIGH" {
		t.Errorf("severity = %v, want HIGH", f["severity"])
	}
}

// VIBE-LLM-002 fires on concrete SQL/HTML output sinks (marked experimental),
// but not on a query with no model-output taint or output that is merely logged.
func TestRunUnsafeLLMIntegration_ConcreteSinks(t *testing.T) {
	t.Run("sql sink fires experimental", func(t *testing.T) {
		findings := runLLM(t, "q.js", `
const openai = new OpenAI();
const completion = await openai.chat.completions.create({ messages: [] });
const name = completion.choices[0].message.content;
db.query("SELECT * FROM t WHERE n = '" + name + "'");
`)
		f := findByCheckID(findings, "VIBE-LLM-002")
		if f == nil {
			t.Fatalf("expected VIBE-LLM-002 for SQL sink; got %v", findings)
		}
		if f["experimental"] != true {
			t.Errorf("SQL sink should be marked experimental; got %v", f["experimental"])
		}
	})
	t.Run("html sink fires experimental", func(t *testing.T) {
		findings := runLLM(t, "view.jsx", `
export function View({ openai }) {
  const completion = openai.chat.completions.create({ messages: [] });
  const html = completion.choices[0].message.content;
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
`)
		f := findByCheckID(findings, "VIBE-LLM-002")
		if f == nil {
			t.Fatalf("expected VIBE-LLM-002 for HTML sink; got %v", findings)
		}
		if f["experimental"] != true {
			t.Errorf("HTML sink should be marked experimental; got %v", f["experimental"])
		}
	})
	t.Run("query without taint does not fire", func(t *testing.T) {
		findings := runLLM(t, "q.js", `
const rows = await db.query("SELECT 1");
console.log(rows);
`)
		if f := findByCheckID(findings, "VIBE-LLM-002"); f != nil {
			t.Fatalf("VIBE-LLM-002 should not fire for an untainted query; got %v", f)
		}
	})
	t.Run("model output only logged does not fire", func(t *testing.T) {
		findings := runLLM(t, "q.js", `
const openai = new OpenAI();
const completion = await openai.chat.completions.create({ messages: [] });
const text = completion.choices[0].message.content;
console.log(text);
res.send(text);
`)
		if f := findByCheckID(findings, "VIBE-LLM-002"); f != nil {
			t.Fatalf("VIBE-LLM-002 should not fire when output is only displayed; got %v", f)
		}
	})
}

// VIBE-LLM-001: request-derived input built into a prompt fires; a prompt built
// only from trusted/constant values does not.
func TestRunUnsafeLLMIntegration_PromptInjection_FPTP(t *testing.T) {
	t.Run("request query into prompt fires HIGH", func(t *testing.T) {
		findings := runLLM(t, "r.js", `
app.get("/ask", (req, res) => {
  const prompt = "Answer this question: " + req.query.q;
});
`)
		f := findByCheckID(findings, "VIBE-LLM-001")
		if f == nil {
			t.Fatalf("expected VIBE-LLM-001; got %v", findings)
		}
		if f["severity"] != "HIGH" {
			t.Errorf("severity = %v, want HIGH", f["severity"])
		}
	})
	t.Run("constant prompt does not fire", func(t *testing.T) {
		findings := runLLM(t, "r.js", `
const prompt = "Summarize the following: " + DOCUMENT_HEADER;
const messages = [{ role: "system", content: "You are helpful." }];
`)
		if f := findByCheckID(findings, "VIBE-LLM-001"); f != nil {
			t.Fatalf("VIBE-LLM-001 should not fire for a trusted/constant prompt; got %v", f)
		}
	})
}

func TestRunUnsafeLLMIntegration_Clean(t *testing.T) {
	dir := t.TempDir()
	writeLLMFile(t, dir, "safe.js", `
const openai = new OpenAI();

async function ask() {
  const systemPrompt = "You are a helpful assistant.";
  const completion = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "system", content: systemPrompt }],
  });
  const text = completion.choices[0].message.content;
  res.send(text);
  console.log(text);
}
`)

	res, err := RunUnsafeLLMIntegration(dir)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	findings := llmFindings(t, res)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %v", findings)
	}
}

func TestRunUnsafeLLMIntegration_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	res, err := RunUnsafeLLMIntegration(dir)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	findings := llmFindings(t, res)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for empty dir, got %v", findings)
	}
}
