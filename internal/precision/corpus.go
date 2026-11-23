package precision

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Corpus scaffolding (P0.1): a list of public repositories pinned to commit SHAs
// that the precision harness scans. Pinning to a SHA makes the measured
// precision reproducible — the corpus cannot drift under us.

// Repo is one pinned corpus entry.
type Repo struct {
	Repo string `yaml:"repo"` // clone URL or owner/name
	SHA  string `yaml:"sha"`  // full or abbreviated commit SHA
	Note string `yaml:"note,omitempty"`
}

// Corpus is the loaded corpus.yaml.
type Corpus struct {
	Repos []Repo `yaml:"repos"`
}

var shaRe = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)

// LoadCorpus reads and validates corpus.yaml. Every entry must have a repo and a
// SHA-looking pin; duplicate repos are rejected so the corpus stays a set.
func LoadCorpus(path string) (*Corpus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Corpus
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	seen := map[string]bool{}
	for i, r := range c.Repos {
		if strings.TrimSpace(r.Repo) == "" {
			return nil, fmt.Errorf("corpus entry %d: empty repo", i)
		}
		if !shaRe.MatchString(r.SHA) {
			return nil, fmt.Errorf("corpus entry %q: sha %q is not a commit SHA", r.Repo, r.SHA)
		}
		key := strings.ToLower(r.Repo)
		if seen[key] {
			return nil, fmt.Errorf("corpus: duplicate repo %q", r.Repo)
		}
		seen[key] = true
	}
	return &c, nil
}

// CacheDir returns the local cache directory name for a repo (owner__name), so a
// corpus of GitHub repos maps to stable, collision-free directories.
func (r Repo) CacheDir() string {
	s := r.Repo
	s = strings.TrimSuffix(s, ".git")
	s = strings.TrimPrefix(s, "https://github.com/")
	s = strings.TrimPrefix(s, "git@github.com:")
	s = strings.ReplaceAll(s, "/", "__")
	s = strings.ReplaceAll(s, ":", "__")
	return s
}

// Len reports how many repos are in the corpus.
func (c *Corpus) Len() int { return len(c.Repos) }
