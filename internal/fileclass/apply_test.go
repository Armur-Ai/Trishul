package fileclass

import "testing"

func TestClassifyPath_NameBased(t *testing.T) {
	cases := map[string]Kind{
		"src/main_test.go":      KindTest,
		"testdata/x.json":       KindFixture,
		"vendor/foo/bar.go":     KindVendored,
		".claude/settings.json": KindAgentSurface,
		"src/main.go":           KindSource,
	}
	for p, want := range cases {
		if got := ClassifyPath(p); got != want {
			t.Errorf("ClassifyPath(%q)=%q want %q", p, got, want)
		}
	}
}

func TestAppliesTo(t *testing.T) {
	// no declared kinds -> applies everywhere
	if !AppliesTo(KindTest, nil) {
		t.Error("empty declaration should apply to all")
	}
	// restricted to agent-surface
	if !AppliesTo(KindAgentSurface, []string{"agent-surface"}) {
		t.Error("should apply to its declared kind")
	}
	if AppliesTo(KindDocs, []string{"agent-surface", "source"}) {
		t.Error("docs should be skipped when not declared")
	}
	// case-insensitive
	if !AppliesTo(KindSource, []string{"SOURCE"}) {
		t.Error("match should be case-insensitive")
	}
}

func TestSkipForRule(t *testing.T) {
	if !SkipForRule(KindDocs, []string{"source"}) {
		t.Error("docs should be skipped for a source-only rule")
	}
	if SkipForRule(KindSource, []string{"source"}) {
		t.Error("source should not be skipped for a source rule")
	}
}
