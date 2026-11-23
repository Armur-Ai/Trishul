package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Armur-Ai/Trishul/internal/ghapp"
	"github.com/Armur-Ai/Trishul/internal/prgate"
)

func tarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		_ = tw.WriteHeader(&tar.Header{Name: "o-r-sha/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

// fakeGitHub records the calls trishul-app makes.
type fakeGitHub struct {
	mu        sync.Mutex
	trees     map[string][]byte // sha -> tarball
	checkRuns []map[string]interface{}
	comments  []issueComment
	posted    int
	patched   int
}

func (f *fakeGitHub) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		p := r.URL.Path
		switch {
		case r.Method == "POST" && p == "/app/installations/1/access_tokens":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"token": "inst-token", "expires_at": time.Now().Add(time.Hour)})
		case r.Header.Get("Authorization") != "token inst-token":
			http.Error(w, "bad auth", http.StatusUnauthorized)
		case r.Method == "POST" && p == "/repos/o/r/check-runs":
			_ = json.NewEncoder(w).Encode(map[string]int{"id": 7})
		case r.Method == "PATCH" && p == "/repos/o/r/check-runs/7":
			var m map[string]interface{}
			_ = json.Unmarshal(body, &m)
			// Mirror GitHub's validation: annotations, when present, must be an array.
			if out, ok := m["output"].(map[string]interface{}); ok {
				if a, present := out["annotations"]; present {
					if _, isArr := a.([]interface{}); !isArr {
						http.Error(w, "For 'properties/annotations', nil is not an array.", http.StatusUnprocessableEntity)
						return
					}
				}
			}
			f.checkRuns = append(f.checkRuns, m)
			_, _ = w.Write([]byte("{}"))
		case r.Method == "GET" && strings.HasPrefix(p, "/repos/o/r/compare/"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"merge_base_commit": map[string]string{"sha": "base"}})
		case r.Method == "GET" && strings.HasPrefix(p, "/repos/o/r/tarball/"):
			tb, ok := f.trees[strings.TrimPrefix(p, "/repos/o/r/tarball/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(tb)
		case r.Method == "GET" && p == "/repos/o/r/issues/5/comments":
			_ = json.NewEncoder(w).Encode(f.comments)
		case r.Method == "POST" && p == "/repos/o/r/issues/5/comments":
			var m map[string]string
			_ = json.Unmarshal(body, &m)
			c := issueComment{ID: 99, Body: m["body"]}
			c.User.Login = "trishul-test[bot]"
			f.comments = append(f.comments, c)
			f.posted++
			_, _ = w.Write([]byte("{}"))
		case r.Method == "PATCH" && p == "/repos/o/r/issues/comments/99":
			var m map[string]string
			_ = json.Unmarshal(body, &m)
			f.comments[0].Body = m["body"]
			f.patched++
			_, _ = w.Write([]byte("{}"))
		default:
			t.Errorf("unexpected call %s %s", r.Method, p)
			http.NotFound(w, r)
		}
	})
}

func newTestServer(t *testing.T, gh *fakeGitHub) *Server {
	t.Helper()
	srv := httptest.NewServer(gh.handler(t))
	t.Cleanup(srv.Close)
	old := ghapp.APIBase
	ghapp.APIBase = srv.URL
	t.Cleanup(func() { ghapp.APIBase = old })
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &Server{app: ghapp.New(1, key), secret: []byte("whsec"), slug: "trishul-test", store: store, queue: NewQueue(10), publicURL: "https://x/trishul-app"}
}

func TestPRFlowEndToEnd(t *testing.T) {
	fixture, err := os.ReadFile("../../examples/vibe-coded-app/supabase/migrations/0001_init.sql")
	if err != nil {
		t.Skip("fixture missing")
	}
	gh := &fakeGitHub{trees: map[string][]byte{
		"base":  tarGz(t, map[string]string{"README.md": "# app\n"}),
		"head1": tarGz(t, map[string]string{"README.md": "# app\n", "supabase/migrations/0001_init.sql": string(fixture)}),
		"head2": tarGz(t, map[string]string{"README.md": "# app, fixed\n"}),
	}}
	s := newTestServer(t, gh)
	s.store.Update(func(d *storeData) { d.Repos["o/r"] = &RepoState{FullName: "o/r", InstallationID: 1} })

	// 1. PR introduces vulnerable SQL -> neutral check, annotations, one comment.
	if err := s.processPR(context.Background(), Job{Kind: KindPR, Inst: 1, Repo: "o/r", PR: 5, HeadSHA: "head1", BaseSHA: "base"}); err != nil {
		t.Fatal(err)
	}
	if len(gh.checkRuns) == 0 || gh.checkRuns[0]["conclusion"] != "neutral" {
		t.Fatalf("want neutral check run, got %+v", gh.checkRuns)
	}
	out := gh.checkRuns[0]["output"].(map[string]interface{})
	if anns, _ := out["annotations"].([]interface{}); len(anns) == 0 {
		t.Error("expected inline annotations")
	}
	if gh.posted != 1 || !strings.HasPrefix(gh.comments[0].Body, prgate.CommentMarker) {
		t.Fatalf("expected one Trishul comment, posted=%d", gh.posted)
	}

	// 2. Next push fixes it -> success, same comment edited (not a new one).
	gh.checkRuns = nil
	if err := s.processPR(context.Background(), Job{Kind: KindPR, Inst: 1, Repo: "o/r", PR: 5, HeadSHA: "head2", BaseSHA: "base"}); err != nil {
		t.Fatal(err)
	}
	if gh.checkRuns[0]["conclusion"] != "success" {
		t.Fatalf("want success, got %v", gh.checkRuns[0]["conclusion"])
	}
	if gh.posted != 1 || gh.patched != 1 || !strings.Contains(gh.comments[0].Body, "No new issues") {
		t.Fatalf("comment should be updated in place: posted=%d patched=%d body=%q", gh.posted, gh.patched, gh.comments[0].Body)
	}

	// 3. Default-branch scan sets the badge grade.
	if err := s.processFull(context.Background(), Job{Kind: KindFull, Inst: 1, Repo: "o/r", HeadSHA: "head1"}); err != nil {
		t.Fatal(err)
	}
	st, _ := s.store.Repo("o/r")
	if st.Grade != "F" {
		t.Errorf("vulnerable tree should grade F, got %q (%v)", st.Grade, st.Counts)
	}
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest("GET", "/badge/o/r.svg", nil))
	if !strings.Contains(rec.Body.String(), "critical") {
		t.Errorf("badge should show critical: %s", rec.Body.String())
	}

	stats := s.store.Stats(time.Now())
	if stats["pr_scans_7d"] != 2 || stats["comments_7d"] != 2 {
		t.Errorf("stats = %+v", stats)
	}
}

func TestCleanPRDoesNotComment(t *testing.T) {
	gh := &fakeGitHub{trees: map[string][]byte{
		"base": tarGz(t, map[string]string{"a.txt": "1"}),
		"head": tarGz(t, map[string]string{"a.txt": "2"}),
	}}
	s := newTestServer(t, gh)
	if err := s.processPR(context.Background(), Job{Kind: KindPR, Inst: 1, Repo: "o/r", PR: 5, HeadSHA: "head", BaseSHA: "base"}); err != nil {
		t.Fatal(err)
	}
	if gh.posted != 0 {
		t.Error("clean PR must not get a comment")
	}
	if gh.checkRuns[0]["conclusion"] != "success" {
		t.Errorf("want success, got %v", gh.checkRuns[0]["conclusion"])
	}
}

func sign(secret, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func TestWebhookAuthAndDispatch(t *testing.T) {
	s := newTestServer(t, &fakeGitHub{})
	h := s.routes()
	payload := []byte(`{"action":"opened","installation":{"id":1},"repository":{"full_name":"o/r","default_branch":"main"},
		"pull_request":{"number":5,"head":{"sha":"h"},"base":{"sha":"b"}}}`)

	req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(payload))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", sign([]byte("wrong"), payload))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 || s.queue.Len() != 0 {
		t.Fatalf("bad signature must be rejected: %d", rec.Code)
	}

	req = httptest.NewRequest("POST", "/webhook", bytes.NewReader(payload))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", sign([]byte("whsec"), payload))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 202 || s.queue.Len() != 1 {
		t.Fatalf("valid PR webhook should queue 1 job: code=%d len=%d", rec.Code, s.queue.Len())
	}

	// Stats are protected.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/stats", nil))
	if rec.Code != 401 {
		t.Errorf("stats without token: %d", rec.Code)
	}
}

func TestQueueSkipsSuperseded(t *testing.T) {
	q := NewQueue(10)
	q.Push(Job{Kind: KindPR, Repo: "o/r", PR: 1, HeadSHA: "a"})
	q.Push(Job{Kind: KindPR, Repo: "o/r", PR: 1, HeadSHA: "b"})
	var ran []string
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		q.Run(ctx, func(_ context.Context, j Job) {
			ran = append(ran, j.HeadSHA)
			if j.HeadSHA == "b" {
				cancel()
			}
		})
		close(done)
	}()
	<-done
	if len(ran) != 1 || ran[0] != "b" {
		t.Fatalf("want only newest commit scanned, got %v", ran)
	}
}
