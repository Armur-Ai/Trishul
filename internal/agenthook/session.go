package agenthook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// session is the per-session state cached between hook invocations. Claude Code
// runs the hook as a fresh process on every tool call, so cross-call memory
// (pre-edit fingerprints for diffing, loop-breaker counters, summary tallies)
// has to live on disk.
//
// It is stored at <tmpRoot>/<session>.json. All reads and writes are
// best-effort: a corrupt or missing file yields an empty session, and a failed
// write is swallowed — the hook never fails over its own cache.
type session struct {
	Edits   int                 `json:"edits"`   // edits inspected this session
	Blocked int                 `json:"blocked"` // issues blocked this session
	Files   map[string][]string `json:"files"`   // relPath -> last-seen fingerprints
	Reports map[string]int      `json:"reports"` // fingerprint -> times blocked on
}

func newSession() *session {
	return &session{Files: map[string][]string{}, Reports: map[string]int{}}
}

// sanitizeSessionID keeps the cache filename safe regardless of what the host
// sends as the session id.
func sanitizeSessionID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "default"
	}
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" {
		return "default"
	}
	return s
}

func sessionPath(tmpRoot, id string) string {
	return filepath.Join(tmpRoot, sanitizeSessionID(id)+".json")
}

func loadSession(path string) *session {
	s := newSession()
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	if err := json.Unmarshal(data, s); err != nil {
		return newSession() // corrupt cache: start clean
	}
	if s.Files == nil {
		s.Files = map[string][]string{}
	}
	if s.Reports == nil {
		s.Reports = map[string]int{}
	}
	return s
}

func (s *session) save(path string) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}

// baseline returns the known fingerprints for relPath (empty when the file has
// not been seen this session).
func (s *session) baseline(relPath string) map[string]bool {
	out := map[string]bool{}
	for _, fp := range s.Files[relPath] {
		out[fp] = true
	}
	return out
}

func (s *session) setFile(relPath string, fs []Finding) {
	fps := make([]string, 0, len(fs))
	for _, f := range fs {
		fps = append(fps, f.fingerprint())
	}
	s.Files[relPath] = fps
}
