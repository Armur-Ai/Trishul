package pluginmeta

import "testing"

// requireKeys fails the test if any named top-level key is missing from m.
func requireKeys(t *testing.T, name string, m map[string]any, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			t.Errorf("%s: missing required key %q", name, k)
		}
	}
}

func TestPluginManifest(t *testing.T) {
	m, err := LoadJSON(PluginManifestPath)
	if err != nil {
		t.Fatalf("plugin.json: %v", err)
	}
	requireKeys(t, "plugin.json", m, "name", "description", "version", "author")

	if got := m["name"]; got != "trishul" {
		t.Errorf("plugin.json: name = %v, want \"trishul\"", got)
	}
	author, ok := m["author"].(map[string]any)
	if !ok {
		t.Fatalf("plugin.json: author is %T, want object", m["author"])
	}
	if got := author["name"]; got != "Armur-Ai" {
		t.Errorf("plugin.json: author.name = %v, want \"Armur-Ai\"", got)
	}
}

func TestPluginHooks(t *testing.T) {
	m, err := LoadJSON(PluginHooksPath)
	if err != nil {
		t.Fatalf("hooks.json: %v", err)
	}
	hooks, ok := m["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("hooks.json: hooks is %T, want object", m["hooks"])
	}
	for _, ev := range []string{"PostToolUse", "PreToolUse", "Stop", "SessionEnd"} {
		if _, ok := hooks[ev]; !ok {
			t.Errorf("hooks.json: missing event %q", ev)
		}
	}
}

func TestPluginMCP(t *testing.T) {
	m, err := LoadJSON(PluginMCPPath)
	if err != nil {
		t.Fatalf(".mcp.json: %v", err)
	}
	servers, ok := m["mcpServers"].(map[string]any)
	if !ok {
		t.Fatalf(".mcp.json: mcpServers is %T, want object", m["mcpServers"])
	}
	tr, ok := servers["trishul"].(map[string]any)
	if !ok {
		t.Fatalf(".mcp.json: mcpServers.trishul is %T, want object", servers["trishul"])
	}
	if got := tr["command"]; got != "trishul" {
		t.Errorf(".mcp.json: trishul.command = %v, want \"trishul\"", got)
	}
}

func TestMarketplaceManifest(t *testing.T) {
	m, err := LoadJSON(MarketplacePath)
	if err != nil {
		t.Fatalf("marketplace.json: %v", err)
	}
	requireKeys(t, "marketplace.json", m, "name", "owner", "plugins")

	plugins, ok := m["plugins"].([]any)
	if !ok || len(plugins) == 0 {
		t.Fatalf("marketplace.json: plugins is %T (len check failed), want non-empty array", m["plugins"])
	}
	first, ok := plugins[0].(map[string]any)
	if !ok {
		t.Fatalf("marketplace.json: plugins[0] is %T, want object", plugins[0])
	}
	requireKeys(t, "marketplace.json plugins[0]", first, "name", "source")
	if got := first["name"]; got != "trishul" {
		t.Errorf("marketplace.json: plugins[0].name = %v, want \"trishul\"", got)
	}
}
