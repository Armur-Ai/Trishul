// Command trishul-app is the Trishul GitHub App server.
//
// DEPRECATED (2026-11-23, LOCAL-FIRST decision / D-ARCH.1): the hosted GitHub
// App is frozen. Trishul never handles user code on our servers — scanning runs
// on the user's machine, in their CI (the GitHub Action), their editor, or their
// agent. This server-side scanning path receives no new features and is not
// shipped in the default release archives. It is kept compiling and tested only
// until the owner decides between a thin results-only App (D-ARCH.6) and removal.
// Use the GitHub Action instead; see docs/github-app.md and docs/ci/.
//
// Install the app on an org once and every pull request in every repository
// gets a "Trishul" check run with inline annotations, plus a single PR comment
// that is edited in place, reporting only the security issues that PR
// introduces. No workflow YAML is needed. Default-branch pushes are scanned
// to keep the README badge current.
//
// Configuration (environment):
//
//	TRISHUL_APP_ID                 GitHub App id
//	TRISHUL_APP_KEY_FILE           path to the app private key (PEM)
//	TRISHUL_WEBHOOK_SECRET_FILE    path to the webhook secret
//	TRISHUL_PUBLIC_URL             public base URL, e.g. https://armur.ai/trishul-app
//	TRISHUL_DATA_DIR               state directory (default ./data)
//	TRISHUL_LISTEN                 listen address (default 127.0.0.1:4610)
//	TRISHUL_STATS_TOKEN_FILE       bearer token protecting /stats (optional; /stats disabled if unset)
//	TRISHUL_WORKERS                concurrent scans (default 1)
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Armur-Ai/Trishul/internal/ghapp"
	"github.com/rs/zerolog"
)

var version = "dev"

// Server holds app state.
type Server struct {
	app        *ghapp.App
	secret     []byte
	statsToken string
	publicURL  string
	slug       string
	store      *Store
	queue      *Queue
}

func main() {
	zerolog.SetGlobalLevel(zerolog.WarnLevel) // analyzer progress logs are noise here
	id, err := strconv.ParseInt(os.Getenv("TRISHUL_APP_ID"), 10, 64)
	if err != nil {
		log.Fatal("TRISHUL_APP_ID is required")
	}
	keyPEM := mustRead("TRISHUL_APP_KEY_FILE")
	key, err := ghapp.ParsePrivateKey(keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	secret := bytes.TrimSpace(mustRead("TRISHUL_WEBHOOK_SECRET_FILE"))
	statsToken := ""
	if p := os.Getenv("TRISHUL_STATS_TOKEN_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			log.Fatal(err)
		}
		statsToken = strings.TrimSpace(string(b))
	}
	dataDir := envOr("TRISHUL_DATA_DIR", "./data")
	store, err := OpenStore(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	workers, _ := strconv.Atoi(envOr("TRISHUL_WORKERS", "1"))
	if workers < 1 {
		workers = 1
	}

	s := &Server{
		app:        ghapp.New(id, key),
		secret:     secret,
		statsToken: statsToken,
		publicURL:  strings.TrimRight(envOr("TRISHUL_PUBLIC_URL", "http://localhost:4610"), "/"),
		store:      store,
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var appInfo struct {
		Slug string `json:"slug"`
	}
	if err := s.app.AppRequest(ctx, "GET", "/app", nil, &appInfo); err != nil {
		log.Fatalf("authenticate as app %d: %v", id, err)
	}
	s.slug = appInfo.Slug
	log.Printf("trishul-app %s authenticated as %s (app %d)", version, s.slug, id)

	s.queue = NewQueue(200)
	for i := 0; i < workers; i++ {
		go s.queue.Run(ctx, s.process)
	}

	srv := &http.Server{
		Addr:              envOr("TRISHUL_LISTEN", "127.0.0.1:4610"),
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = srv.Shutdown(shutCtx)
	}()
	log.Printf("listening on %s (public %s)", srv.Addr, s.publicURL)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", s.handleWebhook)
	mux.HandleFunc("/badge/", s.handleBadge)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "ok %s queue=%d\n", version, s.queue.Len())
	})
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/setup", s.handleSetup)
	mux.HandleFunc("/", s.handleHome)
	return mux
}

func (s *Server) installURL() string {
	return "https://github.com/apps/" + s.slug + "/installations/new"
}

// --- webhooks ---

type repoPayload struct {
	FullName      string `json:"full_name"`
	Private       bool   `json:"private"`
	DefaultBranch string `json:"default_branch"`
}

type prRef struct {
	SHA  string `json:"sha"`
	Ref  string `json:"ref"`
	Repo struct {
		FullName string `json:"full_name"`
	} `json:"repo"`
}

type prPayload struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	Draft  bool   `json:"draft"`
	Head   prRef  `json:"head"`
	Base   prRef  `json:"base"`
}

type webhookPayload struct {
	Action       string `json:"action"`
	Installation struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
			Type  string `json:"type"`
		} `json:"account"`
	} `json:"installation"`
	Repository   *repoPayload  `json:"repository"`
	Repositories []repoPayload `json:"repositories"`
	ReposAdded   []repoPayload `json:"repositories_added"`
	ReposRemoved []repoPayload `json:"repositories_removed"`
	PullRequest  *prPayload    `json:"pull_request"`
	Ref          string        `json:"ref"`
	After        string        `json:"after"`
	Deleted      bool          `json:"deleted"`
	CheckRun     *struct {
		Name         string      `json:"name"`
		PullRequests []prPayload `json:"pull_requests"`
		App          struct {
			ID int64 `json:"id"`
		} `json:"app"`
	} `json:"check_run"`
	CheckSuite *struct {
		HeadSHA      string      `json:"head_sha"`
		PullRequests []prPayload `json:"pull_requests"`
	} `json:"check_suite"`
}

func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 25<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if !ghapp.VerifySignature(s.secret, body, r.Header.Get("X-Hub-Signature-256")) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	event := r.Header.Get("X-GitHub-Event")
	var p webhookPayload
	if err := json.Unmarshal(body, &p); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	queued := s.dispatch(event, &p)
	w.WriteHeader(http.StatusAccepted)
	_, _ = fmt.Fprintf(w, "ok %s queued=%d\n", event, queued)
}

// dispatch records state and enqueues scans; returns the number queued.
func (s *Server) dispatch(event string, p *webhookPayload) int {
	inst := p.Installation.ID
	n := 0
	enqueue := func(j Job) {
		if s.queue.Push(j) {
			n++
		}
	}
	switch event {
	case "installation":
		switch p.Action {
		case "created", "unsuspend", "new_permissions_accepted":
			s.store.Update(func(d *storeData) {
				in := d.Installations[fmt.Sprint(inst)]
				if in == nil {
					in = &Installation{ID: inst, CreatedAt: time.Now().UTC()}
					d.Installations[fmt.Sprint(inst)] = in
				}
				in.Account, in.AccountType = p.Installation.Account.Login, p.Installation.Account.Type
				in.DeletedAt, in.Suspended = time.Time{}, false
			})
			if p.Action == "created" {
				s.store.Log(Event{Kind: "install", Inst: inst, Repo: p.Installation.Account.Login})
				for _, r := range p.Repositories {
					enqueue(s.trackRepo(inst, r, true))
				}
			}
		case "deleted", "suspend":
			s.store.Update(func(d *storeData) {
				if in := d.Installations[fmt.Sprint(inst)]; in != nil {
					if p.Action == "deleted" {
						in.DeletedAt = time.Now().UTC()
					} else {
						in.Suspended = true
					}
				}
				for _, r := range d.Repos {
					if r.InstallationID == inst && p.Action == "deleted" {
						r.Removed = true
					}
				}
			})
			if p.Action == "deleted" {
				s.store.Log(Event{Kind: "uninstall", Inst: inst, Repo: p.Installation.Account.Login})
			}
		}
	case "installation_repositories":
		for _, r := range p.ReposAdded {
			enqueue(s.trackRepo(inst, r, true))
		}
		s.store.Update(func(d *storeData) {
			for _, r := range p.ReposRemoved {
				if st := d.Repos[key(r.FullName)]; st != nil {
					st.Removed = true
				}
			}
		})
	case "pull_request":
		pr := p.PullRequest
		if pr == nil || p.Repository == nil {
			return 0
		}
		switch p.Action {
		case "opened", "synchronize", "reopened", "ready_for_review":
			s.trackRepo(inst, *p.Repository, false)
			enqueue(Job{Kind: KindPR, Inst: inst, Repo: p.Repository.FullName, PR: pr.Number, HeadSHA: pr.Head.SHA, BaseSHA: pr.Base.SHA})
		}
	case "push":
		if p.Repository == nil || p.Deleted || p.After == "" || strings.Trim(p.After, "0") == "" {
			return 0
		}
		if p.Ref == "refs/heads/"+p.Repository.DefaultBranch {
			s.trackRepo(inst, *p.Repository, false)
			enqueue(Job{Kind: KindFull, Inst: inst, Repo: p.Repository.FullName, HeadSHA: p.After})
		}
	case "check_run":
		if p.Action == "rerequested" && p.CheckRun != nil && p.Repository != nil {
			for _, pr := range p.CheckRun.PullRequests {
				enqueue(Job{Kind: KindPR, Inst: inst, Repo: p.Repository.FullName, PR: pr.Number, HeadSHA: pr.Head.SHA, BaseSHA: pr.Base.SHA, Force: true})
			}
		}
	case "check_suite":
		if p.Action == "rerequested" && p.CheckSuite != nil && p.Repository != nil {
			for _, pr := range p.CheckSuite.PullRequests {
				enqueue(Job{Kind: KindPR, Inst: inst, Repo: p.Repository.FullName, PR: pr.Number, HeadSHA: pr.Head.SHA, BaseSHA: pr.Base.SHA, Force: true})
			}
		}
	}
	return n
}

// trackRepo upserts repo state; when scanDefault, returns a job scanning the
// default branch (to populate the badge right after install).
func (s *Server) trackRepo(inst int64, r repoPayload, scanDefault bool) Job {
	s.store.Update(func(d *storeData) {
		st := d.Repos[key(r.FullName)]
		if st == nil {
			st = &RepoState{FullName: r.FullName}
			d.Repos[key(r.FullName)] = st
		}
		st.InstallationID, st.Private, st.Removed = inst, r.Private, false
		if r.DefaultBranch != "" {
			st.DefaultBranch = r.DefaultBranch
		}
	})
	if !scanDefault {
		return Job{}
	}
	return Job{Kind: KindFull, Inst: inst, Repo: r.FullName, HeadSHA: "HEAD"}
}

// --- helpers ---

func mustRead(env string) []byte {
	p := os.Getenv(env)
	if p == "" {
		log.Fatalf("%s is required", env)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		log.Fatalf("%s: %v", env, err)
	}
	return b
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
func lower(s string) string          { return strings.ToLower(s) }
