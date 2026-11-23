// Package diffmap parses a unified diff into a lookup of which lines each file
// gained or changed (plan P5.2), so the gate annotates only lines the PR
// actually touched — GitHub rejects annotations off the diff, and a comment on
// an unchanged line is noise.
package diffmap

import (
	"strconv"
	"strings"
)

// Map answers "did this PR add/change this line of this file?".
type Map struct {
	changed map[string]map[int]bool // path -> set of new-file line numbers
}

// Changed reports whether path gained or changed the given 1-based new-file line.
func (m *Map) Changed(path string, line int) bool {
	if m == nil || m.changed[path] == nil {
		return false
	}
	return m.changed[path][line]
}

// Files returns the paths the diff touched.
func (m *Map) Files() []string {
	out := make([]string, 0, len(m.changed))
	for p := range m.changed {
		out = append(out, p)
	}
	return out
}

// Parse reads a unified diff (git or plain) and records the added lines per new
// file. Hunk headers (@@ -a,b +c,d @@) set the new-file cursor; '+' lines are
// recorded as changed, ' ' context lines advance the cursor, '-' lines don't.
func Parse(diff string) *Map {
	m := &Map{changed: map[string]map[int]bool{}}
	var curPath string
	var newLine int
	inHunk := false

	for _, line := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(line, "+++ "):
			curPath = cleanPath(strings.TrimPrefix(line, "+++ "))
			inHunk = false
			if curPath != "" && m.changed[curPath] == nil {
				m.changed[curPath] = map[int]bool{}
			}
		case strings.HasPrefix(line, "--- "):
			// old-file header; ignore (path taken from +++).
		case strings.HasPrefix(line, "@@"):
			newLine = parseHunkNewStart(line)
			inHunk = newLine > 0
		case inHunk && curPath != "":
			switch {
			case strings.HasPrefix(line, "+"):
				m.changed[curPath][newLine] = true
				newLine++
			case strings.HasPrefix(line, "-"):
				// deletion: no new-file line consumed.
			case strings.HasPrefix(line, "\\"):
				// "\ No newline at end of file": ignore.
			default:
				// context line.
				newLine++
			}
		}
	}
	// Drop files that ended up with no changed lines (e.g. pure deletions).
	for p, set := range m.changed {
		if len(set) == 0 {
			delete(m.changed, p)
		}
	}
	return m
}

// cleanPath strips the b/ (or a/) prefix and any trailing tab-metadata.
func cleanPath(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\t'); i >= 0 {
		s = s[:i]
	}
	if s == "/dev/null" {
		return ""
	}
	s = strings.TrimPrefix(s, "b/")
	s = strings.TrimPrefix(s, "a/")
	return s
}

// parseHunkNewStart extracts the new-file start line from "@@ -a,b +c,d @@".
func parseHunkNewStart(h string) int {
	plus := strings.IndexByte(h, '+')
	if plus < 0 {
		return 0
	}
	rest := h[plus+1:]
	end := strings.IndexAny(rest, ", ")
	if end >= 0 {
		rest = rest[:end]
	}
	n, err := strconv.Atoi(rest)
	if err != nil {
		return 0
	}
	return n
}
