package fileclass

import "strings"

// File-kind rule gating (P2.1). Each rule declares the file_kinds it applies to
// (in the rule catalog); the engine classifies a file once and skips rules whose
// declared kinds don't include it, before the analyzer runs. This is the single
// noise filter that replaces scattered per-analyzer path heuristics.

// ClassifyPath classifies by path alone, without file content. Content-based
// signals (generated headers, minified line-length) are not available, so a file
// that would be detected as generated/minified only by its content classifies by
// its name and extension instead. Use Classify when content is available.
func ClassifyPath(path string) Kind {
	return Classify(path, nil)
}

// AppliesTo reports whether a rule that declares ruleFileKinds should run on a
// file of the given kind. An empty declaration means "all kinds" (the rule is
// not file-kind restricted). Matching is case-insensitive on the kind string.
func AppliesTo(kind Kind, ruleFileKinds []string) bool {
	if len(ruleFileKinds) == 0 {
		return true
	}
	k := strings.ToLower(string(kind))
	for _, want := range ruleFileKinds {
		if strings.ToLower(strings.TrimSpace(want)) == k {
			return true
		}
	}
	return false
}

// SkipForRule is the inverse of AppliesTo: true when the engine should skip a
// rule on this file before running the analyzer.
func SkipForRule(kind Kind, ruleFileKinds []string) bool {
	return !AppliesTo(kind, ruleFileKinds)
}
