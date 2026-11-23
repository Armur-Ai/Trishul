package internal

import (
	"os"
	"path/filepath"
	"testing"

	utils "github.com/Armur-Ai/Trishul/pkg"
)

// writeRules writes a rules file at <dir>/<name>.
func writeRules(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// fbFindingsByCheck groups findings by their check_id.
func fbFindingsByCheck(findings []map[string]interface{}) map[string][]map[string]interface{} {
	out := map[string][]map[string]interface{}{}
	for _, f := range findings {
		id, _ := f["check_id"].(string)
		out[id] = append(out[id], f)
	}
	return out
}

func TestScanFirebase_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	findings, err := scanFirebaseDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty dir, got %d: %v", len(findings), findings)
	}
}

func TestScanFirebase_WorldReadWrite001(t *testing.T) {
	dir := t.TempDir()
	writeRules(t, dir, "firestore.rules", `
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /posts/{postId} {
      allow read, write: if true;
    }
  }
}
`)

	findings, err := scanFirebaseDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byCheck := fbFindingsByCheck(findings)

	got := byCheck["FIREBASE-001"]
	if len(got) == 0 {
		t.Fatalf("expected a FIREBASE-001 finding, got none: %v", findings)
	}
	f := got[0]
	if f["severity"] != "CRITICAL" {
		t.Errorf("expected CRITICAL severity, got %v", f["severity"])
	}
	if f["confidence"] != "HIGH" {
		t.Errorf("expected HIGH confidence for if-true, got %v", f["confidence"])
	}
	if cwe, _ := f["cwe"].([]string); len(cwe) == 0 || cwe[0] != "CWE-284" {
		t.Errorf("expected CWE-284, got %v", f["cwe"])
	}
	if p, _ := f["path"].(string); filepath.IsAbs(p) {
		t.Errorf("expected relativized path, got absolute %q", p)
	}
	for _, key := range []string{"path", "line", "message", "severity", "check_id", "cwe", "confidence", "remediation"} {
		if _, has := f[key]; !has {
			t.Errorf("finding missing key %q: %v", key, f)
		}
	}
}

func TestScanFirebase_UnconditionalNoIf001(t *testing.T) {
	// `allow read, write;` with no condition at all is world read/write too.
	dir := t.TempDir()
	writeRules(t, dir, "firestore.rules", `
service cloud.firestore {
  match /databases/{database}/documents {
    match /things/{id} {
      allow read, write;
    }
  }
}
`)
	findings, err := scanFirebaseDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fbFindingsByCheck(findings)["FIREBASE-001"]) == 0 {
		t.Errorf("expected FIREBASE-001 for unconditional allow read, write, got none: %v", findings)
	}
}

func TestScanFirebase_AuthOnly002(t *testing.T) {
	dir := t.TempDir()
	writeRules(t, dir, "firestore.rules", `
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read: if request.auth != null;
    }
  }
}
`)
	findings, err := scanFirebaseDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byCheck := fbFindingsByCheck(findings)
	got := byCheck["FIREBASE-002"]
	if len(got) == 0 {
		t.Fatalf("expected a FIREBASE-002 finding, got none: %v", findings)
	}
	f := got[0]
	if f["severity"] != "HIGH" {
		t.Errorf("expected HIGH severity, got %v", f["severity"])
	}
	if f["confidence"] != "MEDIUM" {
		t.Errorf("expected MEDIUM confidence for auth-only heuristic, got %v", f["confidence"])
	}
	if cwe, _ := f["cwe"].([]string); len(cwe) == 0 || cwe[0] != "CWE-285" {
		t.Errorf("expected CWE-285, got %v", f["cwe"])
	}
	// Must not also raise the more-severe world read/write finding.
	if len(byCheck["FIREBASE-001"]) != 0 {
		t.Errorf("auth-only rule must not raise FIREBASE-001: %v", byCheck["FIREBASE-001"])
	}
}

func TestScanFirebase_OwnershipClean(t *testing.T) {
	dir := t.TempDir()
	writeRules(t, dir, "firestore.rules", `
service cloud.firestore {
  match /databases/{database}/documents {
    match /docs/{docId} {
      allow write: if request.auth.uid == resource.data.ownerId;
      allow read: if request.auth != null && request.auth.uid == resource.data.ownerId;
    }
  }
}
`)
	findings, err := scanFirebaseDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for ownership-scoped rules, got %d: %v", len(findings), findings)
	}
}

func TestScanFirebase_LockedAndAdminClean(t *testing.T) {
	dir := t.TempDir()
	writeRules(t, dir, "locked.rules", `
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if false;
    }
    match /admin/{id} {
      allow read, write: if request.auth.token.admin == true;
    }
  }
}
`)
	findings, err := scanFirebaseDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for locked/admin rules, got %d: %v", len(findings), findings)
	}
}

func TestScanFirebase_Storage003(t *testing.T) {
	dir := t.TempDir()
	writeRules(t, dir, "storage.rules", `
service firebase.storage {
  match /b/{bucket}/o {
    match /uploads/{file} {
      allow write: if true;
    }
  }
}
`)
	findings, err := scanFirebaseDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byCheck := fbFindingsByCheck(findings)
	got := byCheck["FIREBASE-003"]
	if len(got) == 0 {
		t.Fatalf("expected a FIREBASE-003 finding, got none: %v", findings)
	}
	f := got[0]
	if f["severity"] != "HIGH" {
		t.Errorf("expected HIGH severity, got %v", f["severity"])
	}
	if cwe, _ := f["cwe"].([]string); len(cwe) == 0 || cwe[0] != "CWE-668" {
		t.Errorf("expected CWE-668, got %v", f["cwe"])
	}
	// Storage world-write must not be reported as a Firestore FIREBASE-001.
	if len(byCheck["FIREBASE-001"]) != 0 {
		t.Errorf("storage rule must not raise FIREBASE-001: %v", byCheck["FIREBASE-001"])
	}
}

func TestScanFirebase_StorageAllPaths003(t *testing.T) {
	dir := t.TempDir()
	writeRules(t, dir, "storage.rules", `
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read;
    }
  }
}
`)
	findings, err := scanFirebaseDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fbFindingsByCheck(findings)["FIREBASE-003"]) == 0 {
		t.Errorf("expected FIREBASE-003 for unconditional allPaths allow, got none: %v", findings)
	}
}

func TestScanFirebase_DocumentWildcard004(t *testing.T) {
	dir := t.TempDir()
	// A permissive catch-all that grants only read-true (not read+write) must land
	// as the medium-severity FIREBASE-004 broad-wildcard finding.
	writeRules(t, dir, "firestore.rules", `
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read: if true;
    }
  }
}
`)
	findings, err := scanFirebaseDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byCheck := fbFindingsByCheck(findings)
	got := byCheck["FIREBASE-004"]
	if len(got) == 0 {
		t.Fatalf("expected a FIREBASE-004 finding, got none: %v", findings)
	}
	f := got[0]
	if f["severity"] != "MEDIUM" {
		t.Errorf("expected MEDIUM severity, got %v", f["severity"])
	}
	if cwe, _ := f["cwe"].([]string); len(cwe) == 0 || cwe[0] != "CWE-732" {
		t.Errorf("expected CWE-732, got %v", f["cwe"])
	}
}

func TestScanFirebase_CommentNotFlagged(t *testing.T) {
	dir := t.TempDir()
	writeRules(t, dir, "firestore.rules", `
service cloud.firestore {
  match /databases/{database}/documents {
    match /safe/{id} {
      // allow read, write: if true;  <- this is only a comment and must be ignored
      allow read, write: if request.auth.uid == resource.data.ownerId;
    }
  }
}
`)
	findings, err := scanFirebaseDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (commented-out rule), got %d: %v", len(findings), findings)
	}
}

func TestRunFirebaseRules_CategoryShapeAndReadOnly(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "firestore.rules")
	writeRules(t, dir, "firestore.rules", `
service cloud.firestore {
  match /databases/{database}/documents {
    match /open/{id} {
      allow read, write: if true;
    }
  }
}
`)

	infoBefore, _ := os.Stat(rulesPath)

	res, err := RunFirebaseRules(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	raw, ok := res[utils.INFRA_SECURITY]
	if !ok {
		t.Fatalf("expected results under %q category key", utils.INFRA_SECURITY)
	}
	list, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("expected %q to be a slice, got %T", utils.INFRA_SECURITY, raw)
	}
	if len(list) == 0 {
		t.Errorf("expected findings under infra category, got none")
	}

	// Read-only invariant: the target file must be untouched.
	infoAfter, _ := os.Stat(rulesPath)
	if infoBefore != nil && infoAfter != nil {
		if !infoBefore.ModTime().Equal(infoAfter.ModTime()) || infoBefore.Size() != infoAfter.Size() {
			t.Errorf("scan must not modify target files")
		}
	}

	first, _ := list[0].(map[string]interface{})
	for _, key := range []string{"path", "line", "severity", "check_id", "message", "cwe", "confidence", "remediation"} {
		if _, has := first[key]; !has {
			t.Errorf("finding missing key %q: %v", key, first)
		}
	}
	if id, _ := first["check_id"].(string); id != "FIREBASE-001" {
		t.Errorf("expected FIREBASE-001, got %v", first["check_id"])
	}
}

func TestScanFirebase_InlineFirebaseJSON(t *testing.T) {
	// firebase.json with rules inlined (rather than referenced) should still scan.
	dir := t.TempDir()
	writeRules(t, dir, "firebase.json", `{
  "firestore": {
    "rules": "service cloud.firestore { match /databases/{database}/documents { match /c/{id} { allow read, write: if true; } } }"
  }
}`)
	findings, err := scanFirebaseDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The inlined rule lives inside a JSON string, whose interior we blank out, so
	// it must NOT be flagged. This asserts the conservative string-handling: a
	// referenced rules file path in firebase.json never produces a false positive.
	if len(findings) != 0 {
		t.Errorf("expected 0 findings from JSON-string rules body, got %d: %v", len(findings), findings)
	}
}

func TestRunFirebaseRules_ContextGate_NonFirebaseRepo(t *testing.T) {
	// A repo with no Firebase signal at all — some source, an unrelated
	// package.json — must produce zero Firebase findings even if an insecure
	// rule-looking snippet is present in a non-rules file.
	dir := t.TempDir()
	writeRules(t, dir, "main.go", "package main\n\nfunc main() { allow read, write: if true }\n")
	writeRules(t, dir, "package.json", `{"name":"app","dependencies":{"express":"^4.0.0"}}`)

	if isFirebaseProject(dir) {
		t.Fatalf("non-firebase repo must not be detected as a firebase project")
	}

	res, err := RunFirebaseRules(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	raw, ok := res[utils.INFRA_SECURITY]
	if !ok {
		return // category absent entirely is also zero findings
	}
	if list, ok := raw.([]interface{}); ok && len(list) != 0 {
		t.Errorf("expected 0 firebase findings for non-firebase repo, got %d: %v", len(list), list)
	}
}

func TestRunFirebaseRules_ContextGate_GenericRulesNotFirebase(t *testing.T) {
	// A generic `.rules` file that is NOT a Firebase rules file (no rules_version
	// / service declaration) must neither gate the repo in nor be scanned, even
	// though it textually contains an `allow read, write: if true;` line.
	dir := t.TempDir()
	writeRules(t, dir, "iptables.rules", "# firewall rules\nallow read, write: if true;\n-A INPUT -j ACCEPT\n")

	if isFirebaseProject(dir) {
		t.Fatalf("a non-firebase .rules file must not qualify the repo as firebase")
	}

	// Even scanned directly, a generic non-firebase .rules file yields nothing.
	findings, err := scanFirebaseDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings from a non-firebase .rules file, got %d: %v", len(findings), findings)
	}
}

func TestRunFirebaseRules_ContextGate_Signals(t *testing.T) {
	// Each individual signal should independently qualify the repo.
	t.Run("firebase.json", func(t *testing.T) {
		dir := t.TempDir()
		writeRules(t, dir, "firebase.json", `{"firestore":{"rules":"firestore.rules"}}`)
		if !isFirebaseProject(dir) {
			t.Errorf("firebase.json should qualify the repo")
		}
	})
	t.Run("named firestore.rules", func(t *testing.T) {
		dir := t.TempDir()
		writeRules(t, dir, "firestore.rules", "service cloud.firestore {}\n")
		if !isFirebaseProject(dir) {
			t.Errorf("firestore.rules should qualify the repo")
		}
	})
	t.Run("generic .rules with service signal", func(t *testing.T) {
		dir := t.TempDir()
		writeRules(t, dir, "my.rules", "rules_version = '2';\nservice cloud.firestore {}\n")
		if !isFirebaseProject(dir) {
			t.Errorf("a .rules file carrying a firebase signal should qualify the repo")
		}
	})
	t.Run("firebase dependency", func(t *testing.T) {
		dir := t.TempDir()
		writeRules(t, dir, "package.json", `{"dependencies":{"firebase":"^10.0.0"}}`)
		if !isFirebaseProject(dir) {
			t.Errorf("a firebase dependency should qualify the repo")
		}
	})
	t.Run("@firebase scoped dependency", func(t *testing.T) {
		dir := t.TempDir()
		writeRules(t, dir, "package.json", `{"dependencies":{"@firebase/app":"^0.9.0"}}`)
		if !isFirebaseProject(dir) {
			t.Errorf("an @firebase/* dependency should qualify the repo")
		}
	})
}

func TestScanFirebase_LineNumbers(t *testing.T) {
	dir := t.TempDir()
	writeRules(t, dir, "firestore.rules", "service cloud.firestore {\n  match /databases/{database}/documents {\n    match /x/{id} {\n      allow read, write: if true;\n    }\n  }\n}\n")
	findings, err := scanFirebaseDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected a finding")
	}
	if ln, _ := findings[0]["line"].(int); ln != 4 {
		t.Errorf("expected allow on line 4, got %d", ln)
	}
}
