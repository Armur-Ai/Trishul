package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// handleBadge serves /badge/{owner}/{repo}.svg for public repos that have
// the app installed.
func (s *Server) handleBadge(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/badge/"), ".svg")
	parts := strings.Split(name, "/")
	label, msg, color := "trishul", "not installed", "#9f9f9f"
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		if st, ok := s.store.Repo(name); ok && !st.Removed {
			switch {
			case st.Private:
				msg = "private"
			case st.Grade == "":
				msg = "scan pending"
			default:
				msg, color = badgeText(st.Grade, st.Counts)
			}
		}
	}
	w.Header().Set("Content-Type", "image/svg+xml;charset=utf-8")
	w.Header().Set("Cache-Control", "max-age=300, s-maxage=300")
	_, _ = w.Write([]byte(badgeSVG(label, msg, color)))
}

func badgeText(grade string, c map[string]int) (string, string) {
	color := map[string]string{"A": "#2ea44f", "B": "#97ca00", "C": "#dfb317", "D": "#fe7d37", "F": "#e05d44"}[grade]
	switch {
	case c["critical"] > 0:
		return fmt.Sprintf("%s · %d critical", grade, c["critical"]), color
	case c["high"] > 0:
		return fmt.Sprintf("%s · %d high", grade, c["high"]), color
	default:
		return grade + " · no high-risk issues", color
	}
}

// badgeSVG renders a shields.io-style flat badge.
func badgeSVG(label, msg, color string) string {
	cw := func(s string) int { return 7*utf8.RuneCountInString(s) + 12 }
	lw, mw := cw(label)+14, cw(msg)
	total := lw + mw
	l, m := html.EscapeString(label), html.EscapeString(msg)
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">`+
		`<title>%s: %s</title><linearGradient id="s" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>`+
		`<clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#r)">`+
		`<rect width="%d" height="20" fill="#555"/><rect x="%d" width="%d" height="20" fill="%s"/><rect width="%d" height="20" fill="url(#s)"/></g>`+
		`<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">`+
		`<text x="%d" y="14" fill="#010101" fill-opacity=".3">🔱 %s</text><text x="%d" y="13">🔱 %s</text>`+
		`<text x="%d" y="14" fill="#010101" fill-opacity=".3">%s</text><text x="%d" y="13">%s</text></g></svg>`,
		total, l, m, l, m, total, lw, lw, mw, color, total,
		lw/2, l, lw/2, l, lw+mw/2, m, lw+mw/2, m)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if s.statsToken == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(s.statsToken)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.store.Stats(time.Now().UTC()))
}

const pageCSS = `body{font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;max-width:720px;margin:48px auto;padding:0 20px;color:#1f2328}
h1{font-size:28px;margin-bottom:4px}code,pre{background:#f6f8fa;border-radius:6px;font-size:13px}pre{padding:12px;overflow:auto}
a.btn{display:inline-block;background:#6f42c1;color:#fff;padding:10px 18px;border-radius:6px;text-decoration:none;font-weight:600}
.muted{color:#59636e}li{margin:4px 0}`

func (s *Server) page(w http.ResponseWriter, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' https:")
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title><style>%s</style></head><body>%s</body></html>`,
		html.EscapeString(title), pageCSS, body)
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.page(w, "Trishul for GitHub", fmt.Sprintf(`<h1>🔱 Trishul for GitHub</h1>
<p class="muted">Security review for AI-written code, on every pull request.</p>
<p><a class="btn" href="%s">Install on GitHub</a></p>
<ul>
<li><b>Only what the PR adds.</b> Trishul diffs each PR against its merge base, so existing debt never shows up as noise.</li>
<li><b>Catches what generic SAST misses:</b> prompt injection in <code>CLAUDE.md</code>/<code>.cursorrules</code>, risky MCP servers, Supabase tables without RLS, leaked service keys, hallucinated packages.</li>
<li><b>Never blocks by default.</b> Turn on blocking per repo with <code>fail-on-findings: true</code> in <code>.trishul.yml</code>.</li>
<li><b>Read-only.</b> Code is downloaded to a temporary directory, scanned in-process without being executed, and deleted.</li>
</ul>
<p class="muted">Prefer to run it in your own CI? Use the <a href="https://github.com/Armur-Ai/Trishul#github-action">GitHub Action</a>. Open source: <a href="https://github.com/Armur-Ai/Trishul">Armur-Ai/Trishul</a>.</p>`,
		html.EscapeString(s.installURL())))
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	badge := s.publicURL + "/badge/OWNER/REPO.svg"
	s.page(w, "Trishul installed", fmt.Sprintf(`<h1>✅ Trishul is installed</h1>
<p>Open or push to a pull request in any repository you selected. Trishul adds a <b>Trishul</b> check with inline annotations, and comments only if the PR introduces a security issue.</p>
<h3>Add the badge to your README</h3>
<pre>[![Trishul](%s)](https://github.com/Armur-Ai/Trishul)</pre>
<h3>Optional: block merges on new high-severity issues</h3>
<pre># .trishul.yml
fail-on-findings: true
severity-threshold: high</pre>
<p class="muted">Then mark the <b>Trishul</b> check as required in your branch protection rules.</p>`,
		html.EscapeString(badge)))
}
