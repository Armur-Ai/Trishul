package main

import (
	"context"
	"fmt"
	"log"
	"sync"
)

// Job kinds.
const (
	KindPR   = "pr"   // diff a PR head against its merge base
	KindFull = "full" // scan a default-branch commit (badge)
)

// Job is one unit of scan work.
type Job struct {
	Kind    string
	Inst    int64
	Repo    string
	PR      int
	HeadSHA string
	BaseSHA string
	Force   bool // re-run requested by a user
}

func (j Job) key() string {
	if j.Kind == KindPR {
		return fmt.Sprintf("pr:%s#%d", lower(j.Repo), j.PR)
	}
	return "full:" + lower(j.Repo)
}

// Queue is a bounded FIFO that coalesces work: when a newer commit for the
// same PR (or default branch) arrives, the older queued job is skipped.
type Queue struct {
	ch     chan Job
	mu     sync.Mutex
	latest map[string]string // job key -> newest head sha
}

// NewQueue returns a queue with the given capacity.
func NewQueue(capacity int) *Queue {
	return &Queue{ch: make(chan Job, capacity), latest: map[string]string{}}
}

// Push enqueues a job; it returns false if the job is empty or the queue is full.
func (q *Queue) Push(j Job) bool {
	if j.Kind == "" || j.Repo == "" || j.HeadSHA == "" {
		return false
	}
	q.mu.Lock()
	q.latest[j.key()] = j.HeadSHA
	q.mu.Unlock()
	select {
	case q.ch <- j:
		return true
	default:
		log.Printf("queue full; dropping %s@%s", j.key(), j.HeadSHA)
		return false
	}
}

// Len is the number of queued jobs.
func (q *Queue) Len() int { return len(q.ch) }

// Run processes jobs until ctx is cancelled, skipping superseded ones.
func (q *Queue) Run(ctx context.Context, fn func(context.Context, Job)) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-q.ch:
			q.mu.Lock()
			superseded := q.latest[j.key()] != j.HeadSHA
			q.mu.Unlock()
			if superseded {
				continue
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("panic processing %s: %v", j.key(), r)
					}
				}()
				fn(ctx, j)
			}()
		}
	}
}
