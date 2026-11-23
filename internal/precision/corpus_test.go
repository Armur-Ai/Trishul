package precision

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCorpus(t *testing.T) {
	c, err := LoadCorpus("testdata/corpus.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 2 {
		t.Fatalf("len=%d want 2", c.Len())
	}
	if c.Repos[0].CacheDir() != "example__alpha" {
		t.Errorf("cachedir=%q", c.Repos[0].CacheDir())
	}
	if c.Repos[1].CacheDir() != "example__beta" {
		t.Errorf("cachedir=%q", c.Repos[1].CacheDir())
	}
}

func TestLoadCorpus_RejectsBadSHA(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	os.WriteFile(p, []byte("repos:\n  - repo: a/b\n    sha: not-a-sha-zzz\n"), 0o644)
	if _, err := LoadCorpus(p); err == nil {
		t.Error("non-SHA pin should be rejected")
	}
}

func TestLoadCorpus_RejectsDuplicate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	os.WriteFile(p, []byte("repos:\n  - repo: a/b\n    sha: abc1234\n  - repo: A/B\n    sha: def5678\n"), 0o644)
	if _, err := LoadCorpus(p); err == nil {
		t.Error("duplicate repo (case-insensitive) should be rejected")
	}
}

func TestCacheDir_StripsGitAndScheme(t *testing.T) {
	if r := (Repo{Repo: "https://github.com/o/n.git"}); r.CacheDir() != "o__n" {
		t.Errorf("cachedir=%q", r.CacheDir())
	}
	if r := (Repo{Repo: "git@github.com:o/n"}); r.CacheDir() != "o__n" {
		t.Errorf("ssh cachedir=%q", r.CacheDir())
	}
}
