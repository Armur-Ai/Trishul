package agenthook

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the agent-hook configuration, read from `.trishul.yml` at the
// workspace root under the `agent_hook:` key:
//
//	agent_hook:
//	  block_on: high          # info|low|medium|high|critical (default: high)
//	  rules_exclude: [RULE-A] # rule IDs never reported by the hook
//	  bash_guard: warn        # warn|block|off (default: warn)
//
// The file is read tolerantly: a missing file, malformed YAML, or an unknown
// value never fails the hook — Defaults() is returned (or the valid subset is
// kept). A hook that aborts an agent's turn over its own config error would be
// worse than no hook at all.
type Config struct {
	// BlockOn is the minimum severity a NEW finding must reach for a PostToolUse
	// edit to be blocked (exit code 2). Lower-severity new findings are ignored.
	BlockOn string
	// RulesExclude lists rule IDs the hook never reports. A trailing "*" matches
	// by prefix (e.g. "AGENT-EXEC-*").
	RulesExclude []string
	// BashGuard controls the PreToolUse Bash guard: "warn" (report, allow),
	// "block" (report, exit 2), or "off" (disabled).
	BashGuard string
}

// Defaults returns the configuration used when `.trishul.yml` is absent or
// unreadable.
func Defaults() Config {
	return Config{BlockOn: "high", BashGuard: "warn"}
}

// rawConfig mirrors the on-disk YAML. It is intentionally permissive: fields
// absent from the file keep their zero value and are then defaulted.
type rawConfig struct {
	AgentHook struct {
		BlockOn      string   `yaml:"block_on"`
		RulesExclude []string `yaml:"rules_exclude"`
		BashGuard    string   `yaml:"bash_guard"`
	} `yaml:"agent_hook"`
}

var validSeverities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}

var validBashModes = map[string]bool{"warn": true, "block": true, "off": true}

// LoadConfig reads `.trishul.yml` from dir. Any failure yields Defaults(); valid
// fields present in the file override the defaults. It never returns an error —
// the hook must stay robust in the face of a broken config.
func LoadConfig(dir string) Config {
	cfg := Defaults()
	if dir == "" {
		return cfg
	}
	data, err := os.ReadFile(filepath.Join(dir, ".trishul.yml"))
	if err != nil {
		return cfg
	}
	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return cfg // tolerate malformed YAML
	}
	if s := strings.ToLower(strings.TrimSpace(raw.AgentHook.BlockOn)); validSeverities[s] {
		cfg.BlockOn = s
	}
	if m := strings.ToLower(strings.TrimSpace(raw.AgentHook.BashGuard)); validBashModes[m] {
		cfg.BashGuard = m
	}
	for _, r := range raw.AgentHook.RulesExclude {
		if r = strings.TrimSpace(r); r != "" {
			cfg.RulesExclude = append(cfg.RulesExclude, r)
		}
	}
	return cfg
}

// excludes reports whether ruleID is excluded by the configured rules_exclude
// list. A trailing "*" in a pattern matches by prefix.
func (c Config) excludes(ruleID string) bool {
	for _, p := range c.RulesExclude {
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(ruleID, strings.TrimSuffix(p, "*")) {
				return true
			}
			continue
		}
		if strings.EqualFold(p, ruleID) {
			return true
		}
	}
	return false
}
