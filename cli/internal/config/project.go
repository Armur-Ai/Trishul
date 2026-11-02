package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ProjectConfig represents the .trishul.yml project configuration.
type ProjectConfig struct {
	Scan struct {
		Depth             string `yaml:"depth"`
		Language          string `yaml:"language"`
		SeverityThreshold string `yaml:"severity-threshold"`
		FailOnFindings    bool   `yaml:"fail-on-findings"`
	} `yaml:"scan"`
	Exclude []string `yaml:"exclude"`
	Tools   struct {
		Enabled  []string `yaml:"enabled"`
		Disabled []string `yaml:"disabled"`
		Timeout  int      `yaml:"timeout"`
	} `yaml:"tools"`
	Output struct {
		Format string `yaml:"format"`
		SaveTo string `yaml:"save-to"`
	} `yaml:"output"`
}

// LoadProjectConfig loads the project config from the given directory (or cwd
// if empty). It prefers the canonical .trishul.yml and falls back to the
// deprecated legacy .vibescan.yml for backward compatibility (see
// docs/rename-vibescan-to-trishul.md). The canonical name always wins.
func LoadProjectConfig(dir string) (*ProjectConfig, error) {
	prefix := ""
	if dir != "" && dir != "." {
		prefix = dir + "/"
	}
	path := prefix + ".trishul.yml"
	legacyPath := prefix + ".vibescan.yml"

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		legacyData, legacyErr := os.ReadFile(legacyPath)
		if legacyErr != nil {
			return nil, err // report the canonical not-found error
		}
		fmt.Fprintf(os.Stderr, "warning: %s is deprecated; rename it to %s\n", legacyPath, path)
		data = legacyData
	} else if err != nil {
		return nil, err
	}

	var cfg ProjectConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
