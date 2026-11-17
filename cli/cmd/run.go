package cmd

import (
	"fmt"
	"github.com/Armur-Ai/Trishul/cli/internal/api"
	"github.com/Armur-Ai/Trishul/cli/internal/config"
	"github.com/Armur-Ai/Trishul/cli/internal/tui"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run [target]",
	Short: "Launch the interactive security agent",
	Long: `Start an interactive security scan with a guided wizard and live dashboard.
If no target is specified, scans the current directory.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig()
		if err != nil {
			color.Red("Error loading configuration: %v", err)
			os.Exit(1)
		}

		if flagKey, _ := cmd.Root().PersistentFlags().GetString("api-key"); flagKey != "" {
			cfg.APIKey = flagKey
		}

		noServer, _ := cmd.Flags().GetBool("no-server")
		cfg.API.URL = ensureServer(cfg.API.URL, noServer)

		// Determine target
		target := "."
		if len(args) > 0 {
			target = args[0]
		}

		// If it's a relative path, make it absolute
		if !strings.HasPrefix(target, "http") {
			abs, err := filepath.Abs(target)
			if err == nil {
				target = abs
			}
		}

		// --- Wizard ---
		var scanDepth string
		var language string
		var outputFormat string

		// Try to auto-detect language
		detectedLang := detectLanguage(target)

		form := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title("Scan depth").
					Description("Quick runs core tools (~30s). Deep runs the full suite (~2-3min).").
					Options(
						huh.NewOption("Quick", "quick"),
						huh.NewOption("Deep", "deep"),
					).
					Value(&scanDepth),

				huh.NewSelect[string]().
					Title(fmt.Sprintf("Language%s", langHint(detectedLang))).
					Options(
						huh.NewOption("Auto-detect", ""),
						huh.NewOption("Go", "go"),
						huh.NewOption("Python", "py"),
						huh.NewOption("JavaScript/TypeScript", "js"),
						huh.NewOption("Rust", "rust"),
						huh.NewOption("Java/Kotlin", "java"),
						huh.NewOption("Ruby", "ruby"),
						huh.NewOption("PHP", "php"),
						huh.NewOption("C/C++", "c"),
						huh.NewOption("Infrastructure as Code", "iac"),
						huh.NewOption("Solidity", "sol"),
					).
					Value(&language),

				huh.NewSelect[string]().
					Title("Output format").
					Options(
						huh.NewOption("Text (terminal)", "text"),
						huh.NewOption("JSON", "json"),
						huh.NewOption("SARIF", "sarif"),
					).
					Value(&outputFormat),
			),
		)

		if err := form.Run(); err != nil {
			fmt.Println("Cancelled.")
			return
		}

		if language == "" {
			language = detectedLang
		}

		isAdvanced := scanDepth == "deep"

		// --- Confirmation ---
		fmt.Println()
		confirmStyle := lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63")).
			Padding(0, 2).
			Width(50)

		langDisplay := language
		if langDisplay == "" {
			langDisplay = "auto-detect"
		}

		confirmation := fmt.Sprintf(
			"%s\n%s\n%s\n%s",
			lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Render("Scan Configuration"),
			fmt.Sprintf("Target:   %s", target),
			fmt.Sprintf("Language: %s", langDisplay),
			fmt.Sprintf("Depth:    %s", scanDepth),
		)
		fmt.Println(confirmStyle.Render(confirmation))
		fmt.Println()

		// --- Start Scan ---
		apiClient := api.NewClient(cfg.API.URL).WithAPIKey(cfg.APIKey)

		var taskID string
		var scanErr error

		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			taskID, scanErr = apiClient.ScanRepository(target, language, isAdvanced)
		} else {
			taskID, scanErr = apiClient.ScanFile(target, isAdvanced)
		}

		if scanErr != nil {
			color.Red("Error starting scan: %v", scanErr)
			os.Exit(1)
		}

		color.Green("Scan started. Task ID: %s", taskID)

		// --- Live Dashboard ---
		tools := getToolsForLanguage(language, isAdvanced)
		dashboard := tui.NewDashboard(target, language, scanDepth, tools)

		// Run dashboard in a goroutine, poll for results
		go pollAndUpdateDashboard(apiClient, taskID)

		p := tea.NewProgram(dashboard, tea.WithAltScreen())
		finalModel, err := p.Run()
		if err != nil {
			color.Red("TUI error: %v", err)
		}

		_ = finalModel

		// --- Fetch final results ---
		_, scanResult, err := apiClient.GetTaskStatus(taskID)
		if err != nil {
			color.Red("Error fetching results: %v", err)
			os.Exit(1)
		}

		// Save to history
		counts := countSeverities(scanResult)
		saveToHistory(taskID, target, language, isAdvanced, scanResult, counts)

		// --- Results Browser ---
		items := buildResultItems(scanResult)
		if len(items) > 0 {
			resultsBrowser := tui.NewResults(items)
			resultsBrowser.Skipped = buildSkippedTools(scanResult)
			p2 := tea.NewProgram(resultsBrowser, tea.WithAltScreen())
			_, _ = p2.Run()
		}

		// --- Summary Card ---
		printSummaryCard(counts)

		// Print task ID for future reference
		fmt.Printf("\nTask ID: %s\n", taskID)
		fmt.Printf("View again: trishul history show %s\n", taskID)
	},
}

// detectLanguage tries to determine the primary language of a local path.
func detectLanguage(target string) string {
	if strings.HasPrefix(target, "http") {
		return ""
	}

	extensions := map[string]string{
		"go.mod":        "go",
		"Cargo.toml":    "rust",
		"package.json":  "js",
		"pom.xml":       "java",
		"build.gradle":  "java",
		"Gemfile":       "ruby",
		"composer.json": "php",
		"Makefile":      "",
	}

	for file, lang := range extensions {
		if _, err := os.Stat(filepath.Join(target, file)); err == nil {
			return lang
		}
	}

	// Count file extensions
	counts := map[string]int{}
	_ = filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		counts[ext]++
		return nil
	})

	best := ""
	bestCount := 0
	extMap := map[string]string{
		".go":   "go",
		".py":   "py",
		".js":   "js",
		".ts":   "js",
		".rs":   "rust",
		".java": "java",
		".rb":   "ruby",
		".php":  "php",
		".c":    "c",
		".cpp":  "c",
		".sol":  "sol",
	}
	for ext, lang := range extMap {
		if counts[ext] > bestCount {
			best = lang
			bestCount = counts[ext]
		}
	}
	return best
}

func langHint(detected string) string {
	if detected != "" {
		return fmt.Sprintf(" (detected: %s)", detected)
	}
	return ""
}

func getToolsForLanguage(language string, advanced bool) []string {
	tools := []string{"semgrep"}
	switch language {
	case "go":
		tools = append(tools, "gosec", "golint", "govet", "staticcheck", "gocyclo")
	case "py":
		tools = append(tools, "bandit", "pydocstyle", "radon", "pylint")
	case "js":
		tools = append(tools, "eslint")
	case "rust":
		tools = append(tools, "cargo-audit", "cargo-geiger", "clippy")
	case "java":
		tools = append(tools, "spotbugs", "pmd", "dependency-check")
	case "ruby":
		tools = append(tools, "brakeman", "bundler-audit")
	case "php":
		tools = append(tools, "phpcs", "psalm")
	case "c":
		tools = append(tools, "cppcheck", "flawfinder")
	case "iac":
		tools = append(tools, "hadolint", "tfsec", "kics", "kube-linter", "kube-score")
	case "sol":
		tools = append(tools, "slither", "mythril")
	}
	if advanced {
		tools = append(tools, "jscpd", "checkov", "trufflehog", "trivy", "osv-scanner")
	}
	return tools
}

func pollAndUpdateDashboard(apiClient *api.APIClient, taskID string) {
	// This is a placeholder — in a full implementation, this would
	// send ToolUpdateMsg and ScanDoneMsg to the Bubbletea program.
	// For now, the dashboard exits when the user presses q.
}

func buildResultItems(results map[string]interface{}) []tui.ResultItem {
	var items []tui.ResultItem
	for category, data := range results {
		if category == "scan_errors" {
			continue
		}
		issues, ok := data.([]interface{})
		if !ok {
			continue
		}
		for _, issue := range issues {
			m, ok := issue.(map[string]interface{})
			if !ok {
				continue
			}
			// Direct findings (flat categories: agent_security, secret_detection,
			// sca, infra_security, and any tool that reports at the top level).
			if _, hasMsg := m["message"]; hasMsg {
				items = append(items, newResultItem(category, m, "-", ""))
			}
			// Nested files -> issues (security_issues, antipatterns_bugs, ...).
			if files, ok := m["files"].([]interface{}); ok {
				cwe := getStringValue(m, "cwe", "")
				for _, file := range files {
					if fm, ok := file.(map[string]interface{}); ok {
						fpath := getStringValue(fm, "path", "-")
						if nested, ok := fm["issues"].([]interface{}); ok {
							for _, ni := range nested {
								if nd, ok := ni.(map[string]interface{}); ok {
									items = append(items, newResultItem(category, nd, fpath, cwe))
								}
							}
						}
					}
				}
			}
		}
	}
	return items
}

// newResultItem maps a raw finding map to a tui.ResultItem, filling the
// category-specific fields. Secrets are redacted here, at the boundary, so a
// raw secret value never reaches the TUI model.
func newResultItem(category string, m map[string]interface{}, fallbackPath, fallbackCWE string) tui.ResultItem {
	path := getStringValue(m, "path", fallbackPath)
	cwe := getStringValue(m, "cwe", fallbackCWE)

	item := tui.ResultItem{
		Severity: getStringValue(m, "severity", "INFO"),
		File:     path,
		Line:     getIntValue(m, "line"),
		RuleID:   getStringValue(m, "rule_id", ""),
		Message:  getStringValue(m, "message", ""),
		Category: category,
		CWE:      cwe,
		Tool:     getStringValue(m, "tool", ""),
	}

	switch category {
	case "agent_security":
		item.CheckID = getStringValue(m, "check_id", "")
		item.Confidence = getStringValue(m, "confidence", "")
		item.TrustBoundary = getStringValue(m, "trust_boundary", "")
		item.Remediation = getStringValue(m, "remediation", "")
		item.IsChain = strings.HasPrefix(strings.ToUpper(item.CheckID), "AGENT-CHAIN")
	case "secret_detection":
		// Look for any field that might carry the raw secret and redact it.
		raw := firstNonEmpty(m, "secret", "match", "value", "raw", "token")
		item.Redacted = tui.Redact(raw)
	case "sca":
		item.Package = getStringValue(m, "package", "")
		item.Version = getStringValue(m, "version", "")
	}

	return item
}

// firstNonEmpty returns the first non-empty string value among the given keys.
func firstNonEmpty(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v := getStringValue(m, k, ""); v != "" {
			return v
		}
	}
	return ""
}

// buildSkippedTools extracts analyzers that did not run from scan_errors so the
// results browser can honestly flag that their findings are absent.
func buildSkippedTools(results map[string]interface{}) []tui.SkippedTool {
	raw, ok := results["scan_errors"].([]interface{})
	if !ok {
		return nil
	}
	var out []tui.SkippedTool
	for _, e := range raw {
		if em, ok := e.(map[string]interface{}); ok {
			out = append(out, tui.SkippedTool{
				Tool:   getStringValue(em, "tool", "unknown"),
				Reason: getStringValue(em, "message", ""),
			})
		}
	}
	return out
}

func getIntValue(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case float64:
			return int(val)
		case int:
			return val
		}
	}
	return 0
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().Bool("no-server", false, "Skip auto-starting the embedded server")
}
