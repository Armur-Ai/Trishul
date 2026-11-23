package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/Armur-Ai/Trishul/internal/mcp"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start Trishul as an MCP server for AI coding assistants",
	Long: `Start Trishul as a Model Context Protocol (MCP) server over stdio, so AI
coding assistants (Claude Code, Cursor, Windsurf, …) can call Trishul's scan,
audit and explain tools. Everything runs locally; no code leaves your machine.

One-line setup:  trishul mcp setup claude`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return mcp.StartMCPServer()
	},
}

var (
	mcpSetupProject   bool
	mcpSetupUninstall bool
)

var mcpSetupCmd = &cobra.Command{
	Use:   "setup [client]",
	Short: "Configure Trishul as an MCP server for an AI client (idempotent, with backup)",
	Long: `Adds (or with --uninstall removes) a "trishul" MCP server entry in the client's
config, preserving your other servers and writing a .bak backup first.

Clients: claude, cursor, windsurf, vscode. --project writes the repo-local config
instead of the user-level one.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		home, _ := os.UserHomeDir()
		path, err := mcpClientConfigPath(args[0], mcpSetupProject, home)
		if err != nil {
			return err
		}
		var action string
		if mcpSetupUninstall {
			action, err = removeMCPServer(path, "trishul")
		} else {
			action, err = upsertMCPServer(path, "trishul", map[string]any{"command": "trishul", "args": []string{"mcp"}})
		}
		if err != nil {
			return err
		}
		fmt.Println(color.GreenString("%s %s", action, path))
		return nil
	},
}

// mcpClientConfigPath returns the config file to edit for a client.
func mcpClientConfigPath(client string, project bool, home string) (string, error) {
	switch client {
	case "claude":
		if project {
			return ".mcp.json", nil
		}
		return filepath.Join(home, ".claude.json"), nil
	case "cursor":
		if project {
			return filepath.Join(".cursor", "mcp.json"), nil
		}
		return filepath.Join(home, ".cursor", "mcp.json"), nil
	case "windsurf":
		return filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), nil
	case "vscode":
		return filepath.Join(".vscode", "mcp.json"), nil
	default:
		return "", fmt.Errorf("unknown client %q (supported: claude, cursor, windsurf, vscode)", client)
	}
}

// upsertMCPServer adds/updates the named server entry under mcpServers in a JSON
// config, preserving everything else. Returns "added"/"updated"/"unchanged". A
// .bak backup is written before any change.
func upsertMCPServer(path, name string, entry map[string]any) (string, error) {
	root, err := readJSONObject(path)
	if err != nil {
		return "", err
	}
	servers, _ := root["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	existing, had := servers[name]
	if had && jsonEqual(existing, entry) {
		return "unchanged", nil
	}
	servers[name] = entry
	root["mcpServers"] = servers
	if err := writeJSONObject(path, root); err != nil {
		return "", err
	}
	if had {
		return "updated", nil
	}
	return "added", nil
}

// removeMCPServer deletes the named server entry if present.
func removeMCPServer(path, name string) (string, error) {
	root, err := readJSONObject(path)
	if err != nil {
		return "", err
	}
	servers, _ := root["mcpServers"].(map[string]any)
	if servers == nil {
		return "not present", nil
	}
	if _, ok := servers[name]; !ok {
		return "not present", nil
	}
	delete(servers, name)
	root["mcpServers"] = servers
	if err := writeJSONObject(path, root); err != nil {
		return "", err
	}
	return "removed", nil
}

func readJSONObject(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: not valid JSON: %w", path, err)
	}
	return m, nil
}

func writeJSONObject(path string, m map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	// backup an existing file first
	if b, err := os.ReadFile(path); err == nil {
		_ = os.WriteFile(path+".bak", b, 0o644)
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}

func jsonEqual(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

func init() {
	mcpSetupCmd.Flags().BoolVar(&mcpSetupProject, "project", false, "write the repo-local config instead of the user-level one")
	mcpSetupCmd.Flags().BoolVar(&mcpSetupUninstall, "uninstall", false, "remove the trishul MCP server entry")
	rootCmd.AddCommand(mcpCmd)
	mcpCmd.AddCommand(mcpSetupCmd)
}
