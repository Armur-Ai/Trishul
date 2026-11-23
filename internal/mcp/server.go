package mcp

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Armur-Ai/Trishul/engine"
	"github.com/Armur-Ai/Trishul/internal/ai"
	"github.com/Armur-Ai/Trishul/internal/autofix"
	"github.com/Armur-Ai/Trishul/internal/findings"
	"github.com/Armur-Ai/Trishul/internal/mcpaudit"
	"github.com/Armur-Ai/Trishul/internal/models"
	"github.com/Armur-Ai/Trishul/internal/prgate"
	"github.com/Armur-Ai/Trishul/internal/redact"
	"github.com/Armur-Ai/Trishul/internal/tasks"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	_ "modernc.org/sqlite"
)

// StartMCPServer starts the trishul MCP server over stdio.
func StartMCPServer() error {
	s := server.NewMCPServer(
		"trishul",
		"1.0.0",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, false),
	)

	registerScanPathTool(s)
	registerScanCodeTool(s)
	registerCheckDependencyTool(s)
	registerExplainFindingTool(s)
	registerGetHistoryTool(s)
	registerAuditMCPConfigTool(s)
	registerSuggestFixTool(s)
	registerScanDiffTool(s)
	registerResources(s)

	return server.ServeStdio(s)
}

func getArg(request mcp.CallToolRequest, key string) string {
	args := request.GetArguments()
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

// maxFindings caps how many findings any tool echoes back, so a huge scan can't
// flood the MCP transport. Callers report the true total alongside the subset.
const maxFindings = 50

// reLongToken matches a long contiguous run of non-space characters, the shape
// of a leaked secret/token pasted into a snippet or message.
var reLongToken = regexp.MustCompile(`\S{24,}`)

// maskLongTokens redacts any long token in s via redact.Mask, so secrets echoed
// back in a snippet or message never leave in plaintext.
func maskLongTokens(s string) string {
	return reLongToken.ReplaceAllStringFunc(s, redact.Mask)
}

// workspacePath confines a user-supplied path to the current working directory.
// It resolves input (relative to cwd when not absolute) and rejects anything
// that escapes the workspace via an absolute path elsewhere or ".." traversal.
func workspacePath(input string) (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to determine working directory: %s", err)
	}
	abs := input
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(cwd, abs)
	}
	abs = filepath.Clean(abs)
	rel, err := filepath.Rel(cwd, abs)
	if err != nil {
		return "", fmt.Errorf("invalid path %q", input)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the workspace", input)
	}
	return abs, nil
}

// languageExtension maps language names to file extensions for temp file creation.
var languageExtension = map[string]string{
	"go":         ".go",
	"golang":     ".go",
	"python":     ".py",
	"py":         ".py",
	"javascript": ".js",
	"js":         ".js",
	"typescript": ".ts",
	"ts":         ".ts",
	"rust":       ".rs",
	"rs":         ".rs",
	"java":       ".java",
	"kotlin":     ".kt",
	"kt":         ".kt",
	"ruby":       ".rb",
	"rb":         ".rb",
	"php":        ".php",
	"c":          ".c",
	"cpp":        ".cpp",
	"c++":        ".cpp",
	"solidity":   ".sol",
	"sol":        ".sol",
}

// normalizeLanguage maps user-facing language names to the internal scan language keys.
var normalizeLanguage = map[string]string{
	"go":         "go",
	"golang":     "go",
	"python":     "py",
	"py":         "py",
	"javascript": "js",
	"js":         "js",
	"typescript": "js",
	"ts":         "js",
	"rust":       "rust",
	"rs":         "rust",
	"java":       "java",
	"kotlin":     "java",
	"kt":         "java",
	"ruby":       "ruby",
	"rb":         "ruby",
	"php":        "php",
	"c":          "c",
	"cpp":        "c",
	"c++":        "c",
	"solidity":   "sol",
	"sol":        "sol",
}

func registerScanPathTool(s *server.MCPServer) {
	tool := mcp.NewTool("trishul_scan_path",
		mcp.WithDescription("Scan a local file or directory for security vulnerabilities"),
		mcp.WithString("path", mcp.Required(), mcp.Description("Path to scan")),
		mcp.WithString("depth", mcp.Description("Scan depth: quick or deep (default: quick)")),
	)

	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		path := getArg(request, "path")
		if path == "" {
			return mcp.NewToolResultError("path is required"), nil
		}

		// Validate path exists
		info, err := os.Stat(path)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("path not found: %s", err)), nil
		}

		// If it's a file, use its parent directory
		scanPath := path
		if !info.IsDir() {
			scanPath = filepath.Dir(path)
		}

		// Run the scan in-process via the engine (no server/Redis; read-only;
		// auto-detects language).
		res, err := engine.ScanLocal(scanPath, "")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("scan failed: %s", err)), nil
		}

		// Convert to typed findings for cleaner output
		findings := models.ConvertFromLegacy(res.Findings)

		output := struct {
			Path         string           `json:"path"`
			FindingCount int              `json:"finding_count"`
			Findings     []models.Finding `json:"findings"`
		}{
			Path:         path,
			FindingCount: len(findings),
			Findings:     findings,
		}

		jsonBytes, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to marshal results: %s", err)), nil
		}

		return mcp.NewToolResultText(string(jsonBytes)), nil
	})
}

func registerScanCodeTool(s *server.MCPServer) {
	tool := mcp.NewTool("trishul_scan_code",
		mcp.WithDescription("Scan a code snippet for security vulnerabilities"),
		mcp.WithString("code", mcp.Required(), mcp.Description("The code to scan")),
		mcp.WithString("language", mcp.Required(), mcp.Description("Programming language")),
	)

	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		code := getArg(request, "code")
		language := getArg(request, "language")
		if code == "" || language == "" {
			return mcp.NewToolResultError("code and language are required"), nil
		}

		langLower := strings.ToLower(strings.TrimSpace(language))

		// Determine file extension
		ext, ok := languageExtension[langLower]
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("unsupported language: %s (supported: go, python, javascript, typescript, rust, java, ruby, php, c, cpp, solidity)", language)), nil
		}

		// Determine internal scan language key
		scanLang, ok := normalizeLanguage[langLower]
		if !ok {
			scanLang = langLower
		}

		// Create temp directory and write the code snippet
		tmpDir, err := os.MkdirTemp("", "trishul-snippet-*")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to create temp directory: %s", err)), nil
		}
		defer os.RemoveAll(tmpDir)

		tmpFile := filepath.Join(tmpDir, "snippet"+ext)
		if err := os.WriteFile(tmpFile, []byte(code), 0644); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to write temp file: %s", err)), nil
		}

		// Run scan on the temp directory (use Local variant so it doesn't delete our working dir)
		results, scanErrors, err := tasks.RunSimpleScanLocal(tmpDir, scanLang)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("scan failed: %s", err)), nil
		}

		// Convert to typed findings
		findings := models.ConvertFromLegacy(results)

		// Build output
		output := struct {
			Language     string            `json:"language"`
			FindingCount int               `json:"finding_count"`
			Findings     []models.Finding  `json:"findings"`
			ScanErrors   []tasks.ScanError `json:"scan_errors,omitempty"`
		}{
			Language:     scanLang,
			FindingCount: len(findings),
			Findings:     findings,
		}
		if len(scanErrors) > 0 {
			output.ScanErrors = scanErrors
		}

		jsonBytes, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to marshal results: %s", err)), nil
		}

		return mcp.NewToolResultText(string(jsonBytes)), nil
	})
}

// osvQuery is the request body for the OSV API.
type osvQuery struct {
	Package *osvPackage `json:"package"`
	Version string      `json:"version,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// osvResponse is the response from the OSV API.
type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

func registerCheckDependencyTool(s *server.MCPServer) {
	tool := mcp.NewTool("trishul_check_dependency",
		mcp.WithDescription("Check if a specific package version has known vulnerabilities"),
		mcp.WithString("package", mcp.Required(), mcp.Description("Package name")),
		mcp.WithString("version", mcp.Required(), mcp.Description("Package version")),
		mcp.WithString("ecosystem", mcp.Required(), mcp.Description("Package ecosystem (e.g., npm, PyPI, Go, Maven, crates.io, RubyGems, Packagist)")),
	)

	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		pkg := getArg(request, "package")
		version := getArg(request, "version")
		ecosystem := getArg(request, "ecosystem")

		if pkg == "" || version == "" || ecosystem == "" {
			return mcp.NewToolResultError("package, version, and ecosystem are all required"), nil
		}

		// Build OSV API request
		query := osvQuery{
			Package: &osvPackage{
				Name:      pkg,
				Ecosystem: ecosystem,
			},
			Version: version,
		}

		body, err := json.Marshal(query)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to build query: %s", err)), nil
		}

		// Make HTTP request to OSV
		httpClient := &http.Client{Timeout: 30 * time.Second}
		resp, err := httpClient.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewReader(body))
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to query OSV API: %s", err)), nil
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to read OSV response: %s", err)), nil
		}

		if resp.StatusCode != http.StatusOK {
			return mcp.NewToolResultError(fmt.Sprintf("OSV API returned status %d: %s", resp.StatusCode, string(respBody))), nil
		}

		var osvResp osvResponse
		if err := json.Unmarshal(respBody, &osvResp); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to parse OSV response: %s", err)), nil
		}

		// Format output
		if len(osvResp.Vulns) == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("No known vulnerabilities found for %s@%s (%s).", pkg, version, ecosystem)), nil
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Found %d known vulnerabilities for %s@%s (%s):\n\n", len(osvResp.Vulns), pkg, version, ecosystem))

		for i, vuln := range osvResp.Vulns {
			sb.WriteString(fmt.Sprintf("--- Vulnerability %d ---\n", i+1))
			sb.WriteString(fmt.Sprintf("ID: %s\n", vuln.ID))

			if len(vuln.Aliases) > 0 {
				sb.WriteString(fmt.Sprintf("Aliases: %s\n", strings.Join(vuln.Aliases, ", ")))
			}

			if vuln.Summary != "" {
				sb.WriteString(fmt.Sprintf("Summary: %s\n", vuln.Summary))
			}

			// Show severity if available
			for _, sev := range vuln.Severity {
				sb.WriteString(fmt.Sprintf("Severity (%s): %s\n", sev.Type, sev.Score))
			}

			// Show fix versions
			for _, aff := range vuln.Affected {
				for _, r := range aff.Ranges {
					for _, ev := range r.Events {
						if ev.Fixed != "" {
							sb.WriteString(fmt.Sprintf("Fixed in: %s\n", ev.Fixed))
						}
					}
				}
			}

			// Show references (limit to first 3)
			refCount := 0
			for _, ref := range vuln.References {
				if refCount >= 3 {
					break
				}
				sb.WriteString(fmt.Sprintf("Reference: %s\n", ref.URL))
				refCount++
			}

			sb.WriteString("\n")
		}

		return mcp.NewToolResultText(sb.String()), nil
	})
}

// commonCWEDescriptions provides static fallback explanations when no AI provider is available.
var commonCWEDescriptions = map[string]string{
	"CWE-79":  "Cross-Site Scripting (XSS): User input is rendered in HTML without proper escaping, allowing attackers to inject malicious scripts that execute in other users' browsers. Fix: sanitize and escape all user-supplied data before rendering.",
	"CWE-89":  "SQL Injection: User input is incorporated into SQL queries without proper sanitization, allowing attackers to manipulate queries to access or modify data. Fix: use parameterized queries or prepared statements.",
	"CWE-78":  "OS Command Injection: User input is passed to system shell commands without sanitization, allowing attackers to execute arbitrary commands. Fix: avoid shell commands with user input; use safe APIs instead.",
	"CWE-22":  "Path Traversal: User input is used in file paths without validation, allowing attackers to access files outside the intended directory. Fix: validate and canonicalize paths; use allowlists.",
	"CWE-287": "Improper Authentication: The application does not properly verify user identity, allowing unauthorized access. Fix: implement proper authentication mechanisms and session management.",
	"CWE-306": "Missing Authentication for Critical Function: A critical function lacks authentication checks. Fix: add authentication and authorization checks to all sensitive endpoints.",
	"CWE-352": "Cross-Site Request Forgery (CSRF): The application does not verify that requests originate from its own pages, allowing attackers to trick users into performing unintended actions. Fix: use CSRF tokens.",
	"CWE-502": "Deserialization of Untrusted Data: The application deserializes data from untrusted sources, which can lead to remote code execution. Fix: validate serialized data; use safe deserialization methods.",
	"CWE-798": "Use of Hard-coded Credentials: Credentials are embedded directly in source code, making them accessible to anyone with access to the code. Fix: use environment variables or a secrets manager.",
	"CWE-200": "Exposure of Sensitive Information: The application exposes sensitive data to unauthorized users through error messages, logs, or responses. Fix: sanitize error output and restrict information disclosure.",
	"CWE-20":  "Improper Input Validation: The application fails to validate user input, leading to various injection and logic vulnerabilities. Fix: validate all inputs against expected formats.",
	"CWE-119": "Buffer Overflow: The application writes data beyond allocated buffer boundaries, potentially allowing code execution. Fix: use bounds checking and safe memory handling functions.",
	"CWE-434": "Unrestricted Upload of File with Dangerous Type: The application allows uploading files without proper type validation. Fix: validate file types, use allowlists, and store uploads outside the webroot.",
	"CWE-611": "XML External Entity (XXE) Injection: The application processes XML with external entity references, allowing attackers to read files or perform SSRF. Fix: disable external entity processing in XML parsers.",
	"CWE-918": "Server-Side Request Forgery (SSRF): The application makes HTTP requests to user-controlled URLs, allowing attackers to access internal services. Fix: validate and restrict outbound URLs.",
	"CWE-259": "Use of Hard-coded Password: A password is hard-coded in the application source. Fix: externalize credentials using environment variables or a secrets manager.",
	"CWE-327": "Use of a Broken or Risky Cryptographic Algorithm: The application uses weak or obsolete cryptography. Fix: use modern, well-vetted cryptographic algorithms (AES-256, SHA-256+).",
	"CWE-732": "Incorrect Permission Assignment for Critical Resource: File or resource permissions are too permissive. Fix: apply the principle of least privilege to file and resource permissions.",
}

func registerExplainFindingTool(s *server.MCPServer) {
	tool := mcp.NewTool("trishul_explain_finding",
		mcp.WithDescription("Explain a security finding in plain English"),
		mcp.WithString("cwe", mcp.Description("CWE ID (e.g., CWE-79)")),
		mcp.WithString("message", mcp.Description("Finding message")),
		mcp.WithString("file", mcp.Description("File path")),
		mcp.WithString("code_context", mcp.Description("Code around the finding")),
	)

	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		message := getArg(request, "message")
		cwe := getArg(request, "cwe")
		file := getArg(request, "file")
		codeContext := getArg(request, "code_context")

		if message == "" && cwe == "" {
			return mcp.NewToolResultError("at least one of 'message' or 'cwe' is required"), nil
		}

		// Build finding map for the AI provider
		finding := map[string]string{
			"cwe":     cwe,
			"message": message,
			"file":    file,
			"snippet": codeContext,
		}

		// Try to use AI provider
		provider, err := ai.GetProvider(ai.DefaultProviderConfig())
		if err == nil {
			explanation, aiErr := ai.ExplainFinding(ctx, provider, finding)
			if aiErr == nil {
				return mcp.NewToolResultText(explanation), nil
			}
			// AI call failed; fall through to static explanation
		}

		// Static fallback: provide explanation based on CWE
		var sb strings.Builder
		sb.WriteString("## Security Finding Explanation\n\n")

		if cwe != "" {
			// Normalize CWE format
			normalizedCWE := strings.ToUpper(strings.TrimSpace(cwe))
			if !strings.HasPrefix(normalizedCWE, "CWE-") {
				normalizedCWE = "CWE-" + normalizedCWE
			}

			if desc, ok := commonCWEDescriptions[normalizedCWE]; ok {
				sb.WriteString(fmt.Sprintf("**%s**: %s\n\n", normalizedCWE, desc))
			} else {
				sb.WriteString(fmt.Sprintf("**%s**: This is a known weakness category. See https://cwe.mitre.org/data/definitions/%s.html for details.\n\n",
					normalizedCWE, strings.TrimPrefix(normalizedCWE, "CWE-")))
			}
		}

		if message != "" {
			sb.WriteString(fmt.Sprintf("**Finding**: %s\n\n", message))
		}

		if file != "" {
			sb.WriteString(fmt.Sprintf("**Location**: %s\n\n", file))
		}

		if codeContext != "" {
			sb.WriteString(fmt.Sprintf("**Code context**:\n```\n%s\n```\n\n", codeContext))
		}

		sb.WriteString("**Recommendation**: Review the flagged code for the vulnerability described above. Apply input validation, proper escaping, or use safe API alternatives as appropriate.\n")
		sb.WriteString("\n_Note: AI-powered explanation unavailable. Set ANTHROPIC_API_KEY or start Ollama for detailed analysis._")

		return mcp.NewToolResultText(sb.String()), nil
	})
}

func registerGetHistoryTool(s *server.MCPServer) {
	tool := mcp.NewTool("trishul_get_history",
		mcp.WithDescription("Get recent scan history"),
		mcp.WithString("limit", mcp.Description("Number of recent scans to return (default: 20)")),
		mcp.WithString("path", mcp.Description("Filter by scan target path (optional)")),
	)

	s.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		limitStr := getArg(request, "limit")
		pathFilter := getArg(request, "path")

		limit := 20
		if limitStr != "" {
			if _, err := fmt.Sscanf(limitStr, "%d", &limit); err != nil || limit <= 0 {
				limit = 20
			}
		}

		// Open the history database directly
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to determine home directory: %s", err)), nil
		}

		dbPath := filepath.Join(homeDir, ".trishul", "history.db")

		// Check if DB exists
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			return mcp.NewToolResultText("No scan history found. Run a scan first with `trishul scan`."), nil
		}

		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to open history database: %s", err)), nil
		}
		defer db.Close()

		// Build query
		var query string
		var args []interface{}

		if pathFilter != "" {
			query = `SELECT id, task_id, target, language, scan_type, status, critical, high, medium, low, info, created_at
				FROM scans WHERE target LIKE ? ORDER BY created_at DESC LIMIT ?`
			args = []interface{}{"%" + pathFilter + "%", limit}
		} else {
			query = `SELECT id, task_id, target, language, scan_type, status, critical, high, medium, low, info, created_at
				FROM scans ORDER BY created_at DESC LIMIT ?`
			args = []interface{}{limit}
		}

		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to query history: %s", err)), nil
		}
		defer rows.Close()

		type scanEntry struct {
			ID        int64  `json:"id"`
			TaskID    string `json:"task_id"`
			Target    string `json:"target"`
			Language  string `json:"language"`
			ScanType  string `json:"scan_type"`
			Status    string `json:"status"`
			Critical  int    `json:"critical"`
			High      int    `json:"high"`
			Medium    int    `json:"medium"`
			Low       int    `json:"low"`
			Info      int    `json:"info"`
			CreatedAt string `json:"created_at"`
		}

		var entries []scanEntry
		for rows.Next() {
			var e scanEntry
			var createdAt time.Time
			if err := rows.Scan(&e.ID, &e.TaskID, &e.Target, &e.Language, &e.ScanType,
				&e.Status, &e.Critical, &e.High, &e.Medium, &e.Low, &e.Info, &createdAt); err != nil {
				continue
			}
			e.CreatedAt = createdAt.Format(time.RFC3339)
			entries = append(entries, e)
		}

		if len(entries) == 0 {
			msg := "No scan history found."
			if pathFilter != "" {
				msg = fmt.Sprintf("No scan history found for path matching '%s'.", pathFilter)
			}
			return mcp.NewToolResultText(msg), nil
		}

		// Format as readable text with JSON data
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Recent scan history (%d results):\n\n", len(entries)))

		for _, e := range entries {
			totalFindings := e.Critical + e.High + e.Medium + e.Low + e.Info
			sb.WriteString(fmt.Sprintf("Scan #%d | %s\n", e.ID, e.CreatedAt))
			sb.WriteString(fmt.Sprintf("  Target:   %s\n", e.Target))
			sb.WriteString(fmt.Sprintf("  Language: %s | Type: %s | Status: %s\n", e.Language, e.ScanType, e.Status))
			sb.WriteString(fmt.Sprintf("  Findings: %d total (Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d)\n",
				totalFindings, e.Critical, e.High, e.Medium, e.Low, e.Info))
			sb.WriteString("\n")
		}

		return mcp.NewToolResultText(sb.String()), nil
	})
}

func registerAuditMCPConfigTool(s *server.MCPServer) {
	tool := mcp.NewTool("trishul_audit_mcp_config",
		mcp.WithDescription("Audit MCP/agent client configuration for security issues (unpinned servers, plaintext tokens, overbroad permissions, insecure remote servers). Read-only."),
		mcp.WithString("path", mcp.Description("Optional config file or directory within the workspace to audit; when empty, discovers configs under the home directory")),
	)
	s.AddTool(tool, handleAuditMCPConfig)
}

func handleAuditMCPConfig(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path := getArg(request, "path")

	var fs []mcpaudit.Finding
	if path != "" {
		abs, err := workspacePath(path)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if _, err := os.Stat(abs); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("path not found: %s", err)), nil
		}
		fs, _ = mcpaudit.AuditHome("", abs)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to determine home directory: %s", err)), nil
		}
		fs, _ = mcpaudit.AuditHome(home, "")
	}

	grade := mcpaudit.Grade(fs)
	total := len(fs)
	truncated := false
	if len(fs) > maxFindings {
		fs = fs[:maxFindings]
		truncated = true
	}

	output := struct {
		Grade        string             `json:"grade"`
		FindingCount int                `json:"finding_count"`
		Returned     int                `json:"returned"`
		Truncated    bool               `json:"truncated,omitempty"`
		Findings     []mcpaudit.Finding `json:"findings"`
	}{
		Grade:        grade,
		FindingCount: total,
		Returned:     len(fs),
		Truncated:    truncated,
		Findings:     fs,
	}

	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal results: %s", err)), nil
	}
	return mcp.NewToolResultText(string(jsonBytes)), nil
}

func registerSuggestFixTool(s *server.MCPServer) {
	tool := mcp.NewTool("trishul_suggest_fix",
		mcp.WithDescription("Suggest a deterministic, local fix for a finding, when one is available. Read-only (returns a patch; does not write files)."),
		mcp.WithString("rule_id", mcp.Required(), mcp.Description("Rule ID of the finding (e.g., SUPABASE-RLS-001)")),
		mcp.WithString("path", mcp.Required(), mcp.Description("File path (within the workspace) the finding is in")),
		mcp.WithNumber("line", mcp.Description("1-based line of the finding")),
		mcp.WithString("message", mcp.Description("Finding message (some fixers read details from it)")),
		mcp.WithString("snippet", mcp.Description("Optional code snippet; used as source when the file cannot be read")),
	)
	s.AddTool(tool, handleSuggestFix)
}

func handleSuggestFix(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ruleID := getArg(request, "rule_id")
	path := getArg(request, "path")
	message := getArg(request, "message")
	snippet := getArg(request, "snippet")
	line := request.GetInt("line", 0)

	if ruleID == "" || path == "" {
		return mcp.NewToolResultError("rule_id and path are required"), nil
	}

	abs, err := workspacePath(path)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// Prefer the on-disk file (confined to the workspace); fall back to the
	// provided snippet when the file cannot be read.
	var src string
	if data, readErr := os.ReadFile(abs); readErr == nil {
		src = string(data)
	} else if snippet != "" {
		src = snippet
	} else {
		return mcp.NewToolResultError(fmt.Sprintf("could not read file and no snippet provided: %s", readErr)), nil
	}

	f := findings.New(findings.Finding{
		RuleID:   ruleID,
		Message:  message,
		Snippet:  snippet,
		Location: findings.Location{Path: path, StartLine: line},
	})

	patch, ok := autofix.FixFor(f, src)
	if !ok {
		return mcp.NewToolResultText("no deterministic fix available"), nil
	}

	output := struct {
		RuleID      string `json:"rule_id"`
		Path        string `json:"path"`
		StartLine   int    `json:"start_line"`
		EndLine     int    `json:"end_line"`
		Replacement string `json:"replacement"`
	}{
		RuleID:      ruleID,
		Path:        patch.Path,
		StartLine:   patch.StartLine,
		EndLine:     patch.EndLine,
		Replacement: maskLongTokens(patch.Replacement),
	}

	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal results: %s", err)), nil
	}
	return mcp.NewToolResultText(string(jsonBytes)), nil
}

func registerScanDiffTool(s *server.MCPServer) {
	tool := mcp.NewTool("trishul_scan_diff",
		mcp.WithDescription("Scan a git checkout and report only the findings introduced relative to a base ref (the PR-gate diff). Read-only."),
		mcp.WithString("dir", mcp.Required(), mcp.Description("Git repository directory within the workspace")),
		mcp.WithString("base_ref", mcp.Required(), mcp.Description("Base git ref to diff against (e.g., origin/main, a commit SHA)")),
	)
	s.AddTool(tool, handleScanDiff)
}

func handleScanDiff(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	dir := getArg(request, "dir")
	baseRef := getArg(request, "base_ref")

	if dir == "" || baseRef == "" {
		return mcp.NewToolResultError("dir and base_ref are required"), nil
	}

	abs, err := workspacePath(dir)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if info, statErr := os.Stat(abs); statErr != nil || !info.IsDir() {
		return mcp.NewToolResultError(fmt.Sprintf("directory not found: %s", dir)), nil
	}

	headScan, err := prgate.ScanDir(abs)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("head scan failed: %s", err)), nil
	}
	baseScan, err := prgate.ScanGitRef(abs, baseRef)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("base scan failed: %s", err)), nil
	}

	introduced, _ := prgate.Diff(headScan.Findings, baseScan.Findings)
	total := len(introduced)
	truncated := false
	if len(introduced) > maxFindings {
		introduced = introduced[:maxFindings]
		truncated = true
	}
	// Redact any secret-shaped token echoed back in a finding message.
	for i := range introduced {
		introduced[i].Message = maskLongTokens(introduced[i].Message)
	}

	output := struct {
		BaseRef         string           `json:"base_ref"`
		IntroducedCount int              `json:"introduced_count"`
		Returned        int              `json:"returned"`
		Truncated       bool             `json:"truncated,omitempty"`
		Introduced      []prgate.Finding `json:"introduced"`
	}{
		BaseRef:         baseRef,
		IntroducedCount: total,
		Returned:        len(introduced),
		Truncated:       truncated,
		Introduced:      introduced,
	}

	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to marshal results: %s", err)), nil
	}
	return mcp.NewToolResultText(string(jsonBytes)), nil
}

func registerResources(s *server.MCPServer) {
	s.AddResource(mcp.NewResource(
		"trishul://findings/latest",
		"Latest scan findings",
		mcp.WithResourceDescription("Findings from the most recent scan"),
		mcp.WithMIMEType("application/json"),
	), func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		// Try to load the latest scan from history
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return []mcp.ResourceContents{
				mcp.TextResourceContents{
					URI:      request.Params.URI,
					MIMEType: "application/json",
					Text:     `{"findings": [], "note": "Failed to determine home directory"}`,
				},
			}, nil
		}

		dbPath := filepath.Join(homeDir, ".trishul", "history.db")
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			return []mcp.ResourceContents{
				mcp.TextResourceContents{
					URI:      request.Params.URI,
					MIMEType: "application/json",
					Text:     `{"findings": [], "note": "No scan history. Run trishul scan first."}`,
				},
			}, nil
		}

		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			return []mcp.ResourceContents{
				mcp.TextResourceContents{
					URI:      request.Params.URI,
					MIMEType: "application/json",
					Text:     fmt.Sprintf(`{"findings": [], "error": "%s"}`, err.Error()),
				},
			}, nil
		}
		defer db.Close()

		var results string
		err = db.QueryRowContext(ctx,
			`SELECT results FROM scans ORDER BY created_at DESC LIMIT 1`,
		).Scan(&results)
		if err != nil {
			return []mcp.ResourceContents{
				mcp.TextResourceContents{
					URI:      request.Params.URI,
					MIMEType: "application/json",
					Text:     `{"findings": [], "note": "No scans found in history"}`,
				},
			}, nil
		}

		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      request.Params.URI,
				MIMEType: "application/json",
				Text:     results,
			},
		}, nil
	})
}
