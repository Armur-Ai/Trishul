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
