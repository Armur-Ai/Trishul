package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/Armur-Ai/Trishul/internal/mcpaudit"
	"github.com/Armur-Ai/Trishul/internal/sharecard"
)

var (
	auditMCPPath   string
	auditMCPFormat string
	auditMCPShare  string
	auditMCPFailOn string
)

var auditMCPCmd = &cobra.Command{
	Use:   "audit-mcp",
	Short: "Audit your AI setup — MCP servers, tokens, permissions (local, offline)",
	Long: `Audits the MCP servers, tokens and permissions configured across your AI
clients (Claude, Cursor, Windsurf, VS Code, Zed, Codex, Gemini). It finds
unpinned servers, plaintext tokens, overbroad permissions, insecure remote
servers, shadowed tool names and the "lethal trifecta".

Everything runs locally and offline — config files are only read, never
executed, and nothing leaves your machine. Use --path to audit a specific
config/dir (for CI or a repo's committed .mcp.json).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		home, _ := os.UserHomeDir()
		code, err := runAuditMCP(home, auditMCPPath, auditMCPFormat, auditMCPShare, auditMCPFailOn, os.Stdout)
		if err != nil {
			return err
		}
		os.Exit(code)
		return nil
	},
}

// runAuditMCP is the testable core: audit, render, optionally write a share card,
// and return the process exit code.
func runAuditMCP(home, path, format, shareFile, failOn string, w io.Writer) (int, error) {
	findings, _ := mcpaudit.AuditHome(home, path)
	grade := mcpaudit.Grade(findings)

	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{"grade": grade, "findings": findings}); err != nil {
			return 1, err
		}
	case "markdown":
		fmt.Fprintf(w, "# AI setup audit — grade %s\n\n", grade)
		for _, f := range findings {
			fmt.Fprintf(w, "- **%s** (%s) `%s` — %s\n  - fix: %s\n", f.Title, f.Severity, f.Server, f.Detail, f.Fix)
		}
	default: // table
		fmt.Fprintf(w, "Trishul AI-setup audit — grade %s (%d finding(s))\n", grade, len(findings))
		for _, f := range findings {
			fmt.Fprintf(w, "  [%s] %-22s %s\n        %s\n        fix: %s\n", f.Severity, f.CheckID, f.Server, f.Detail, f.Fix)
		}
		if len(findings) == 0 {
			fmt.Fprintln(w, "  no issues found ✓")
		}
	}

	if shareFile != "" {
		card := sharecard.Card{Title: "My AI setup", Grade: grade, Counts: severityCounts(findings)}
		if err := os.WriteFile(shareFile, []byte(card.SVG()), 0o644); err != nil {
			return 1, err
		}
		fmt.Fprintf(w, "\nshare card written to %s\n", shareFile)
	}

	return auditExitCode(findings, failOn), nil
}

func severityCounts(fs []mcpaudit.Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.Severity]++
	}
	return m
}

// auditExitCode returns non-zero when any finding is at/above failOn (default
// off → always 0 unless failOn set). Severities: CRITICAL>HIGH>MEDIUM>LOW.
func auditExitCode(fs []mcpaudit.Finding, failOn string) int {
	if failOn == "" {
		return 0
	}
	rank := map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	threshold := rank[normalizeSeverity(failOn)]
	if threshold == 0 {
		return 0
	}
	for _, f := range fs {
		if rank[normalizeSeverity(f.Severity)] >= threshold {
			return 2
		}
	}
	return 0
}

func normalizeSeverity(s string) string {
	up := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		up = append(up, c)
	}
	return string(up)
}

func init() {
	auditMCPCmd.Flags().StringVar(&auditMCPPath, "path", "", "audit a specific config file or directory instead of the default client locations")
	auditMCPCmd.Flags().StringVar(&auditMCPFormat, "format", "table", "output format: table|json|markdown")
	auditMCPCmd.Flags().StringVar(&auditMCPShare, "share", "", "write a shareable SVG grade card to this path (no paths/secrets)")
	auditMCPCmd.Flags().StringVar(&auditMCPFailOn, "fail-on", "", "exit non-zero if any finding is at/above this severity (low|medium|high|critical)")
	rootCmd.AddCommand(auditMCPCmd)
}
