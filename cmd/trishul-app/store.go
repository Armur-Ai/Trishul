package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Store is a small JSON-file store: installations, per-repo state for badges,
// and an append-only event log for adoption/retention metrics. It is
// deliberately simple; at the scale where this hurts, move to Postgres.
type Store struct {
	mu   sync.Mutex
	path string
	data storeData
	evf  *os.File
}

type storeData struct {
	Installations map[string]*Installation `json:"installations"` // key: installation id
	Repos         map[string]*RepoState    `json:"repos"`         // key: owner/repo (lowercase)
}

// Installation is a GitHub App installation.
type Installation struct {
	ID          int64     `json:"id"`
	Account     string    `json:"account"`
	AccountType string    `json:"account_type"`
	CreatedAt   time.Time `json:"created_at"`
	DeletedAt   time.Time `json:"deleted_at,omitempty"`
	Suspended   bool      `json:"suspended,omitempty"`
}

// RepoState is the latest default-branch scan of a repo (drives the badge).
type RepoState struct {
	FullName       string         `json:"full_name"`
	InstallationID int64          `json:"installation_id"`
	Private        bool           `json:"private"`
	DefaultBranch  string         `json:"default_branch"`
	SHA            string         `json:"sha,omitempty"`
	Grade          string         `json:"grade,omitempty"`
	Counts         map[string]int `json:"counts,omitempty"`
	ScannedAt      time.Time      `json:"scanned_at,omitempty"`
	LastPRScanAt   time.Time      `json:"last_pr_scan_at,omitempty"`
	PRScans        int            `json:"pr_scans"`
	Removed        bool           `json:"removed,omitempty"`
}

// Event is one line of the metrics log.
type Event struct {
	Time   time.Time `json:"t"`
	Kind   string    `json:"kind"` // install, uninstall, pr_scan, push_scan, comment, scan_error
	Repo   string    `json:"repo,omitempty"`
	Inst   int64     `json:"inst,omitempty"`
	New    int       `json:"new,omitempty"`
	Fixed  int       `json:"fixed,omitempty"`
	Millis int64     `json:"ms,omitempty"`
}

// OpenStore loads (or creates) the store under dir.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "state.json")}
	s.data.Installations = map[string]*Installation{}
	s.data.Repos = map[string]*RepoState{}
	if b, err := os.ReadFile(s.path); err == nil {
		if err := json.Unmarshal(b, &s.data); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	s.evf = f
	return s, nil
}

func (s *Store) saveLocked() {
	b, err := json.MarshalIndent(&s.data, "", " ")
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, s.path)
	}
}

// Update mutates the store under lock and persists it.
func (s *Store) Update(fn func(d *storeData)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.data)
	s.saveLocked()
}

// Repo returns a copy of a repo's state.
func (s *Store) Repo(fullName string) (RepoState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.data.Repos[key(fullName)]
	if !ok {
		return RepoState{}, false
	}
	return *r, true
}

// Log appends a metrics event.
func (s *Store) Log(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b, _ := json.Marshal(e)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.evf.Write(append(b, '\n'))
}

// Events reads the event log.
func (s *Store) Events() []Event {
	s.mu.Lock()
	path := s.evf.Name()
	s.mu.Unlock()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []Event
	dec := json.NewDecoder(bytesReader(b))
	for dec.More() {
		var e Event
		if dec.Decode(&e) != nil {
			break
		}
		out = append(out, e)
	}
	return out
}

// Stats summarizes adoption and retention.
func (s *Store) Stats(now time.Time) map[string]interface{} {
	evs := s.Events()
	s.mu.Lock()
	activeInst, removedInst := 0, 0
	var accounts []string
	for _, in := range s.data.Installations {
		if in.DeletedAt.IsZero() {
			activeInst++
			accounts = append(accounts, in.Account)
		} else {
			removedInst++
		}
	}
	repos := 0
	retained, eligible := 0, 0
	for _, r := range s.data.Repos {
		if r.Removed {
			continue
		}
		repos++
	}
	s.mu.Unlock()
	sort.Strings(accounts)

	window := func(d time.Duration) (scans, repoSet, comments int) {
		seen := map[string]bool{}
		for _, e := range evs {
			if now.Sub(e.Time) > d {
				continue
			}
			switch e.Kind {
			case "pr_scan":
				scans++
				seen[e.Repo] = true
			case "comment":
				comments++
			}
		}
		return scans, len(seen), comments
	}
	s7, r7, c7 := window(7 * 24 * time.Hour)
	s30, r30, c30 := window(30 * 24 * time.Hour)

	// 30-day retention: repos whose first PR scan was >30d ago that still had
	// a PR scan in the last 7 days.
	first := map[string]time.Time{}
	last := map[string]time.Time{}
	for _, e := range evs {
		if e.Kind != "pr_scan" {
			continue
		}
		if t, ok := first[e.Repo]; !ok || e.Time.Before(t) {
			first[e.Repo] = e.Time
		}
		if e.Time.After(last[e.Repo]) {
			last[e.Repo] = e.Time
		}
	}
	for repo, t := range first {
		if now.Sub(t) > 30*24*time.Hour {
			eligible++
			if now.Sub(last[repo]) < 7*24*time.Hour {
				retained++
			}
		}
	}
	ret := 0.0
	if eligible > 0 {
		ret = float64(retained) / float64(eligible)
	}
	return map[string]interface{}{
		"installations_active":  activeInst,
		"installations_removed": removedInst,
		"accounts":              accounts,
		"repos":                 repos,
		"pr_scans_7d":           s7, "active_repos_7d": r7, "comments_7d": c7,
		"pr_scans_30d": s30, "active_repos_30d": r30, "comments_30d": c30,
		"retention_30d": map[string]interface{}{"eligible_repos": eligible, "retained": retained, "rate": ret},
	}
}

func key(fullName string) string { return lower(fullName) }
