package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Armur-Ai/Trishul/internal/config"
	"github.com/Armur-Ai/Trishul/internal/ghapp"
	"github.com/Armur-Ai/Trishul/internal/prgate"
)

const (
	checkName      = "Trishul"
	jobTimeout     = 6 * time.Minute
	minSeverity    = "medium"
	maxAnnotations = 150 // GitHub accepts 50 per request; we send up to 3 batches
	maxSummary     = 60000
)

func (s *Server) process(ctx context.Context, j Job) {
	ctx, cancel := context.WithTimeout(ctx, jobTimeout)
	defer cancel()
	start := time.Now()
	var err error
	switch j.Kind {
	case KindPR:
		err = s.processPR(ctx, j)
	case KindFull:
		err = s.processFull(ctx, j)
	}
	if err != nil {
		log.Printf("%s %s@%.7s failed after %s: %v", j.Kind, j.Repo, j.HeadSHA, time.Since(start).Round(time.Millisecond), err)
		s.store.Log(Event{Kind: "scan_error", Repo: j.Repo, Inst: j.Inst})
		return
	}
	log.Printf("%s %s@%.7s done in %s", j.Kind, j.Repo, j.HeadSHA, time.Since(start).Round(time.Millisecond))
}

// fetch downloads repo@ref into a fresh directory under parent.
func (s *Server) fetch(ctx context.Context, j Job, ref, parent, name string) (string, error) {
	dir := filepath.Join(parent, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if err := s.app.DownloadTree(ctx, j.Inst, j.Repo, ref, dir, ghapp.DefaultLimits); err != nil {
		return "", fmt.Errorf("download %s@%.12s: %w", j.Repo, ref, err)
	}
	return dir, nil
}

type checkRun struct {
	ID int64 `json:"id"`
}

type annotation struct {
	Path            string `json:"path"`
	StartLine       int    `json:"start_line"`
	EndLine         int    `json:"end_line"`
	AnnotationLevel string `json:"annotation_level"`
	Message         string `json:"message"`
	Title           string `json:"title"`
}

func (s *Server) processPR(ctx context.Context, j Job) error {
	start := time.Now()
	var cr checkRun
	if err := s.app.Request(ctx, j.Inst, "POST", "/repos/"+j.Repo+"/check-runs", map[string]interface{}{
		"name": checkName, "head_sha": j.HeadSHA, "status": "in_progress",
		"started_at": time.Now().UTC().Format(time.RFC3339),
		"output":     map[string]string{"title": "Scanning…", "summary": "Trishul is checking this PR for new security issues."},
	}, &cr); err != nil {
		return fmt.Errorf("create check run: %w", err)
	}
	fail := func(title, msg string) error {
		_ = s.app.Request(context.Background(), j.Inst, "PATCH", fmt.Sprintf("/repos/%s/check-runs/%d", j.Repo, cr.ID), map[string]interface{}{
			"status": "completed", "conclusion": "neutral",
			"output": map[string]string{"title": title, "summary": msg},
		}, nil)
		return errors.New(title + ": " + msg)
	}

	// Diff against the merge base, not the base tip, so changes that landed on
	// the base branch after this PR forked aren't attributed to it.
	baseRef := j.BaseSHA
	var cmp struct {
		MergeBase struct {
			SHA string `json:"sha"`
		} `json:"merge_base_commit"`
	}
	if err := s.app.Request(ctx, j.Inst, "GET", fmt.Sprintf("/repos/%s/compare/%s...%s", j.Repo, j.BaseSHA, j.HeadSHA), nil, &cmp); err == nil && cmp.MergeBase.SHA != "" {
		baseRef = cmp.MergeBase.SHA
	}

	tmp, err := os.MkdirTemp("", "trishul-pr-*")
	if err != nil {
		return fail("Internal error", err.Error())
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	headDir, err := s.fetch(ctx, j, j.HeadSHA, tmp, "head")
	if err != nil {
		if errors.Is(err, ghapp.ErrTooLarge) {
			return fail("Repository too large", "This repository exceeds the hosted scanner's size limit. Use the Trishul GitHub Action instead.")
		}
		return fail("Could not download the PR", err.Error())
	}
	baseDir, err := s.fetch(ctx, j, baseRef, tmp, "base")
	if err != nil {
		return fail("Could not download the base commit", err.Error())
	}

	headScan, err := prgate.ScanDir(headDir)
	if err != nil {
		return fail("Scan failed", err.Error())
	}
	baseScan, err := prgate.ScanDir(baseDir)
	if err != nil {
		return fail("Scan failed", err.Error())
	}

	fopts := prgate.FilterOptions{}
	headF := prgate.Filter(headScan.Findings, headDir, fopts)
	baseF := prgate.Filter(baseScan.Findings, headDir, fopts)
	bl, _ := prgate.LoadBaseline(filepath.Join(headDir, prgate.DefaultBaselineFile))
	current := bl.Apply(headF)
	intro, fixed := prgate.Diff(current, bl.Apply(baseF))

	rep := &prgate.Report{
		Mode:     "pr",
		New:      prgate.AtOrAbove(intro, minSeverity),
		Fixed:    prgate.AtOrAbove(fixed, minSeverity),
		Total:    len(headF),
		FailOn:   failPolicy(baseDir),
		LinkBase: fmt.Sprintf("https://github.com/%s/blob/%s/", j.Repo, j.HeadSHA),
	}
	rep.Existing = len(prgate.AtOrAbove(current, minSeverity)) - len(rep.New)
	if rep.Existing < 0 {
		rep.Existing = 0
	}
	rep.Duration = time.Since(start)
	rep.Evaluate()

	conclusion := "success"
	switch {
	case rep.Failed:
		conclusion = "failure"
	case len(rep.New) > 0:
		conclusion = "neutral"
	}
	md := rep.Markdown()
	summary := md
	if len(summary) > maxSummary {
		summary = summary[:maxSummary] + "\n…(truncated)"
	}

	anns := annotations(rep.New)
	first := anns
	if len(first) > 50 {
		first = first[:50]
	}
	if err := s.app.Request(ctx, j.Inst, "PATCH", fmt.Sprintf("/repos/%s/check-runs/%d", j.Repo, cr.ID), map[string]interface{}{
		"status": "completed", "conclusion": conclusion,
		"completed_at": time.Now().UTC().Format(time.RFC3339),
		"output":       map[string]interface{}{"title": rep.Title(), "summary": summary, "annotations": first},
	}, nil); err != nil {
		return fmt.Errorf("complete check run: %w", err)
	}
	for i := 50; i < len(anns); i += 50 {
		end := i + 50
		if end > len(anns) {
			end = len(anns)
		}
		_ = s.app.Request(ctx, j.Inst, "PATCH", fmt.Sprintf("/repos/%s/check-runs/%d", j.Repo, cr.ID), map[string]interface{}{
			"output": map[string]interface{}{"title": rep.Title(), "summary": summary, "annotations": anns[i:end]},
		}, nil)
	}

	commented, err := s.upsertComment(ctx, j, md, len(rep.New))
	if err != nil {
		log.Printf("comment %s#%d: %v", j.Repo, j.PR, err)
	}
	if commented {
		s.store.Log(Event{Kind: "comment", Repo: j.Repo, Inst: j.Inst})
	}
	s.store.Log(Event{Kind: "pr_scan", Repo: j.Repo, Inst: j.Inst, New: len(rep.New), Fixed: len(rep.Fixed), Millis: time.Since(start).Milliseconds()})
	s.store.Update(func(d *storeData) {
		if st := d.Repos[key(j.Repo)]; st != nil {
			st.PRScans++
			st.LastPRScanAt = time.Now().UTC()
		}
	})
	return nil
}

// failPolicy reads the blocking threshold from the BASE branch's .trishul.yml
// (so a PR can't switch off its own gate). Default: never block.
func failPolicy(baseDir string) string {
	cfg, err := config.LoadProjectConfig(baseDir)
	if err != nil || cfg == nil || !cfg.FailOnFindings {
		return ""
	}
	if prgate.ValidSeverity(cfg.SeverityThreshold) {
		return strings.ToLower(cfg.SeverityThreshold)
	}
	return "high"
}

func annotations(fs []prgate.Finding) []annotation {
	var out []annotation
	for _, f := range fs {
		if f.Path == "" || f.Line <= 0 {
			continue
		}
		level := "notice"
		switch f.Severity {
		case "critical", "high":
			level = "failure"
		case "medium":
			level = "warning"
		}
		msg := f.Message
		if len(msg) > 4000 {
			msg = msg[:4000]
		}
		out = append(out, annotation{
			Path: f.Path, StartLine: f.Line, EndLine: f.Line, AnnotationLevel: level,
			Title: fmt.Sprintf("[%s] %s", strings.ToUpper(f.Severity), f.RuleID), Message: msg,
		})
		if len(out) == maxAnnotations {
			break
		}
	}
	return out
}

type issueComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
	User struct {
		Login string `json:"login"`
	} `json:"user"`
}

// upsertComment keeps one Trishul comment per PR. It only creates a comment
// when there are new findings; once one exists it is always updated so a
// fixed PR flips to "all clear". Returns whether a comment was written.
func (s *Server) upsertComment(ctx context.Context, j Job, body string, newCount int) (bool, error) {
	bot := s.slug + "[bot]"
	var existing int64
	for page := 1; page <= 10 && existing == 0; page++ {
		var cs []issueComment
		if err := s.app.Request(ctx, j.Inst, "GET", fmt.Sprintf("/repos/%s/issues/%d/comments?per_page=100&page=%d", j.Repo, j.PR, page), nil, &cs); err != nil {
			return false, err
		}
		for _, c := range cs {
			if c.User.Login == bot && strings.HasPrefix(c.Body, prgate.CommentMarker) {
				existing = c.ID
				break
			}
		}
		if len(cs) < 100 {
			break
		}
	}
	switch {
	case existing != 0:
		return true, s.app.Request(ctx, j.Inst, "PATCH", fmt.Sprintf("/repos/%s/issues/comments/%d", j.Repo, existing), map[string]string{"body": body}, nil)
	case newCount > 0:
		return true, s.app.Request(ctx, j.Inst, "POST", fmt.Sprintf("/repos/%s/issues/%d/comments", j.Repo, j.PR), map[string]string{"body": body}, nil)
	}
	return false, nil
}

// processFull scans a default-branch commit and records the badge grade.
func (s *Server) processFull(ctx context.Context, j Job) error {
	start := time.Now()
	ref := j.HeadSHA
	if st, ok := s.store.Repo(j.Repo); ok && ref == "HEAD" && st.DefaultBranch != "" {
		ref = st.DefaultBranch
	}
	tmp, err := os.MkdirTemp("", "trishul-full-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	dir, err := s.fetch(ctx, j, ref, tmp, "tree")
	if err != nil {
		return err
	}
	scan, err := prgate.ScanDir(dir)
	if err != nil {
		return err
	}
	bl, _ := prgate.LoadBaseline(filepath.Join(dir, prgate.DefaultBaselineFile))
	fs := prgate.AtOrAbove(bl.Apply(prgate.Filter(scan.Findings, dir, prgate.FilterOptions{})), minSeverity)
	s.store.Update(func(d *storeData) {
		st := d.Repos[key(j.Repo)]
		if st == nil {
			st = &RepoState{FullName: j.Repo, InstallationID: j.Inst}
			d.Repos[key(j.Repo)] = st
		}
		st.SHA, st.Grade, st.Counts, st.ScannedAt = j.HeadSHA, prgate.Grade(fs), prgate.Counts(fs), time.Now().UTC()
	})
	s.store.Log(Event{Kind: "push_scan", Repo: j.Repo, Inst: j.Inst, New: len(fs), Millis: time.Since(start).Milliseconds()})
	return nil
}
