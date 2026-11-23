// Package mcpmeta loads and validates the MCP-registry listing artifact
// (server.json) that ships at the repo root. It exists so the listing's
// version and required fields can be checked offline as part of the normal
// test run, keeping the public listing from drifting behind releases.
//
// Nothing here contacts a registry or network: it only parses local files.
package mcpmeta

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ExpectedName is the MCP Registry name Trishul lists under.
const ExpectedName = "io.github.armur-ai/trishul"

// semverRe matches a bare semantic version (no leading "v"), optionally with a
// pre-release / build suffix (e.g. 0.2.0, 1.0.0-rc.1).
var semverRe = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

// actionVersionRe extracts the actionVersion constant from
// cli/cmd/init_github.go, e.g. const actionVersion = "v0.2.0".
var actionVersionRe = regexp.MustCompile(`actionVersion\s*=\s*"v?([^"]+)"`)

// Server is the subset of the MCP Registry server.json we validate.
type Server struct {
	Schema      string `json:"$schema"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Version     string `json:"version"`
	Repository  struct {
		URL    string `json:"url"`
		Source string `json:"source"`
	} `json:"repository"`
	Packages []Package              `json:"packages"`
	Meta     map[string]interface{} `json:"_meta"`
}

// Package is one installable distribution entry.
type Package struct {
	RegistryType string `json:"registryType"`
	Identifier   string `json:"identifier"`
	Version      string `json:"version"`
	Transport    struct {
		Type string `json:"type"`
	} `json:"transport"`
}

// FindRepoRoot walks up from start until it finds server.json (the repo root).
func FindRepoRoot(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "server.json")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("server.json not found walking up from %q", start)
		}
		dir = parent
	}
}

// Load reads and parses server.json from the given repo root.
func Load(repoRoot string) (*Server, error) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "server.json"))
	if err != nil {
		return nil, err
	}
	var s Server
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("server.json is not valid JSON: %w", err)
	}
	return &s, nil
}

// Tools returns the advertised tool list from _meta, if present.
func (s *Server) Tools() []string {
	ns, ok := s.Meta[ExpectedName].(map[string]interface{})
	if !ok {
		return nil
	}
	raw, ok := ns["tools"].([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		if str, ok := t.(string); ok {
			out = append(out, str)
		}
	}
	return out
}

// Validate checks that the required MCP Registry fields are present and
// well-formed. It does not perform any network access.
func (s *Server) Validate() error {
	if strings.TrimSpace(s.Schema) == "" {
		return fmt.Errorf("$schema is required")
	}
	if s.Name != ExpectedName {
		return fmt.Errorf("name = %q, want %q", s.Name, ExpectedName)
	}
	if strings.TrimSpace(s.Description) == "" {
		return fmt.Errorf("description is required")
	}
	if !semverRe.MatchString(s.Version) {
		return fmt.Errorf("version %q is not a bare semver (e.g. 0.2.0)", s.Version)
	}
	if s.Repository.URL == "" || s.Repository.Source == "" {
		return fmt.Errorf("repository.url and repository.source are required")
	}
	if len(s.Packages) == 0 {
		return fmt.Errorf("at least one package is required")
	}
	for i, p := range s.Packages {
		if p.RegistryType == "" || p.Identifier == "" {
			return fmt.Errorf("packages[%d]: registryType and identifier are required", i)
		}
		if !semverRe.MatchString(p.Version) {
			return fmt.Errorf("packages[%d]: version %q is not a bare semver", i, p.Version)
		}
		if p.Transport.Type != "stdio" {
			return fmt.Errorf("packages[%d]: transport.type = %q, want \"stdio\" (Trishul is local-first)", i, p.Transport.Type)
		}
		if p.Version != s.Version {
			return fmt.Errorf("packages[%d]: version %q != server version %q", i, p.Version, s.Version)
		}
	}
	return nil
}

// ReleaseVersion reads the actionVersion constant from cli/cmd/init_github.go
// and returns it without the leading "v". This is the single source of truth
// the server.json version must match.
func ReleaseVersion(repoRoot string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "cli", "cmd", "init_github.go"))
	if err != nil {
		return "", err
	}
	m := actionVersionRe.FindSubmatch(raw)
	if m == nil {
		return "", fmt.Errorf("actionVersion constant not found in cli/cmd/init_github.go")
	}
	return string(m[1]), nil
}
