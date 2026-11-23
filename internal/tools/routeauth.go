package internal

// routeauth.go implements a NEW self-contained deterministic analyzer for the
// "Vibe Top 10 V02 — missing / client-only authorization" vulnerability class
// commonly found in AI-generated ("vibe-coded") web backends: API routes and
// handlers that read or write data but never check who is calling.
//
// It is a read-only, static, heuristic detector. It only FLAGS suspicious
// handlers; it never writes, mutates, or exploits the target. Findings are
// emitted under the vibe_security category (utils.VIBE_SECURITY).
//
// Two checks are produced:
//
//	VIBE-AUTHZ-001  Unauthenticated data route (CWE-862, missing authorization):
//	                an API route / handler that touches a data layer but has no
//	                visible session / auth / token guard.
//	VIBE-AUTHZ-002  IDOR heuristic (CWE-639): a handler that reads an id from the
//	                request and queries by it with no owner/user predicate.
//
// Design goal: be CONSERVATIVE. We prefer MISSES over FALSE POSITIVES. False
// positives are suppressed aggressively via (a) whole-file auth detection,
// (b) per-handler auth detection, (c) Express middleware-arity detection,
// (d) public / health / auth-endpoint path allow-listing, and (e) skipping
// vendored / build directories. Confidence is reported honestly as MEDIUM
// because this is a static heuristic, not a dataflow analysis.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Armur-Ai/Trishul/internal/logger"
	utils "github.com/Armur-Ai/Trishul/pkg"
)

// RunRouteAuth statically scans a directory tree (read-only) for API
// route/handler definitions that lack an authorization check, and for the IDOR
// pattern. It never fails hard: scan errors degrade to an empty result.
func RunRouteAuth(dir string) (map[string]interface{}, error) {
	logger.Info().Str("tool", "route-authz").Str("dir", dir).Msg("running")

	findings, err := scanRouteAuth(dir)
	if err != nil {
		logger.Error().Str("tool", "route-authz").Err(err).Msg("scan failed")
		findings = nil
	}

	arr := make([]interface{}, 0, len(findings))
	for _, f := range findings {
		arr = append(arr, f)
	}
	return map[string]interface{}{utils.VIBE_SECURITY: arr}, nil
}

const (
	raCheckUnauth = "VIBE-AUTHZ-001"
	raCheckIDOR   = "VIBE-AUTHZ-002"
	raCWEMissing  = "CWE-862"
	raCWEIDOR     = "CWE-639"

	raRemediationUnauth = "Add an authentication/authorization check at the start of this handler " +
		"(e.g. getServerSession()/auth()/getToken()/currentUser() in Next.js, an auth middleware in Express, " +
		"or Depends(get_current_user)/@login_required in FastAPI/Flask) and reject unauthenticated requests " +
		"before reading or writing any data."
	raRemediationIDOR = "Scope the query to the authenticated principal: include an ownership predicate such as " +
		"`where: { id, userId: session.user.id }` (or the equivalent tenant/owner filter) so a caller cannot " +
		"read or modify records they do not own by changing the id in the request."

	raMaxFileBytes = 2 << 20 // 2 MiB: skip unusually large files.
	raBraceMaxGap  = 300     // max bytes between a handler signature and its body `{`.
)

// Directories that never contain first-party route code; skipping them avoids
// flagging third-party library code (a major false-positive source) and speeds
// the walk.
var raSkipDirs = map[string]bool{
	"node_modules": true, ".git": true, "vendor": true, "dist": true,
	"build": true, ".next": true, "out": true, "coverage": true,
	"__pycache__": true, ".venv": true, "venv": true, ".tox": true,
	"site-packages": true, ".mypy_cache": true, "target": true,
}

// Path segments that mark a route as intentionally public or as the auth
// endpoint itself; such routes must NOT be flagged for VIBE-AUTHZ-001.
var raPublicSegments = map[string]bool{
	"health": true, "healthz": true, "healthcheck": true, "livez": true,
	"readyz": true, "liveness": true, "readiness": true, "ping": true,
	"status": true, "metrics": true, "public": true, "static": true,
	"assets": true, "asset": true, "favicon": true, "robots": true,
	"webhook": true, "webhooks": true, "login": true, "signin": true,
	"signup": true, "register": true, "logout": true, "auth": true,
	"oauth": true, "callback": true, "csrf": true, "providers": true,
	"docs": true, "openapi": true, "swagger": true, "version": true,
	"sitemap": true, "manifest": true, "home": true,
}

// Auth / session / token tokens (lowercase substrings) that, when present,
// indicate an authorization check and therefore SUPPRESS an unauth finding.
var raJSAuthTokens = []string{
	"getserversession", "gettoken", "currentuser", "requireauth", "withauth",
	"authmiddleware", "isauthenticated", "ensureauth", "getsession", "verifytoken",
	"verifyjwt", "jwt.verify", "clerk", "getauth(", "requireuser", "authenticate",
	"passport", "authorize", "checkauth", "validatesession", "req.user",
	"request.user", "session.user", "ensureloggedin", "protect(", "auth(",
	"ironsession", "nextauth", "supabase.auth", "getuser(", "permissionguard",
	"requirerole", "hasrole", "checkrole", "requirepermission", "haspermission",
	"assertauth", "ensureauthenticated", "getcurrentuser", "getsessionuser",
	"verifysession", "getuserfromrequest", "clerkmiddleware", "auth.protect",
	"authguard", "rbac", "authz",
}

var raPyAuthTokens = []string{
	"get_current_user", "current_user", "login_required", "jwt_required",
	"requires_auth", "security(", "isauthenticated", "verify_token",
	"oauth2_scheme", "require_auth", "authenticate", "permission_classes",
	"httpbearer", "token_required", "auth_required", "get_current_active_user",
	"require_login", "depends(get_user", "depends(authenticate",
	"require_role", "has_permission", "has_perm", "has_role", "check_permissions",
	"require_scope", "requires_scopes", "is_staff", "is_superuser",
	"user.is_authenticated", "request.user", "get_current_user_id",
}

// Data-layer tokens (lowercase substrings) indicating the handler reads/writes
// persisted data — a precondition for VIBE-AUTHZ-001.
var raJSDataTokens = []string{
	"prisma.", "findmany", "findunique", "findfirst", "findbyid", ".create(",
	".update(", ".updatemany", ".delete(", ".deletemany", ".upsert", ".insert(",
	".save(", ".aggregate", "db.", ".query(", "supabase", "mongoose", "knex",
	".collection(", "drizzle", ".findone", ".updateone", ".deleteone",
	".insertone", ".insertmany", "repository.", ".execute(",
}

var raPyDataTokens = []string{
	".query(", "session.", "db.", ".execute(", ".filter(", ".filter_by(",
	".all()", ".first()", "objects.", "cursor", ".commit(", ".add(",
	"select(", "insert(", ".scalar", ".get(", "sqlalchemy",
}

var (
	raReAppFunc    = regexp.MustCompile(`export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b`)
	raReAppConst   = regexp.MustCompile(`export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*=`)
	raRePagesFunc  = regexp.MustCompile(`export\s+default\s+(?:async\s+)?function\b`)
	raRePagesArrow = regexp.MustCompile(`export\s+default\s+(?:async\s+)?\(`)
	raReServerFn   = regexp.MustCompile(`export\s+(?:async\s+)?function\s+([A-Za-z_]\w*)\b`)
	raReUseServer  = regexp.MustCompile(`['"]use server['"]`)
	raReExpress    = regexp.MustCompile(`([A-Za-z_]\w*)\.(get|post|put|patch|delete|all)\s*\(`)
	raReUse        = regexp.MustCompile(`([A-Za-z_]\w*)\.use\s*\(`)
	raRePyRoute    = regexp.MustCompile(`(?m)^[ \t]*@[ \t]*([A-Za-z_]\w*)\.(get|post|put|patch|delete|route)[ \t]*\(`)
	raRePyDef      = regexp.MustCompile(`^\s*(?:async\s+)?def\s+\w+\s*\(`)
	raReFirstStr   = regexp.MustCompile(`['"]([^'"]*)['"]`)

	// IDOR building blocks.
	raReIDPath = regexp.MustCompile(`(?i)(\[\.*\w*id\]|\{\.*\w*id\}|:\w*id\b)`)
	raReIDBody = regexp.MustCompile(`(?i)(\b(?:params|query|body)\s*\.\s*\w*id\b|\b(?:params|query|body)\s*\[\s*['"]\w*id['"]\s*\]|req\.params|searchparams\.get\(\s*['"]\w*id['"]|(?:args|query_params)\.get\(\s*['"]\w*id['"])`)
	raReByID   = regexp.MustCompile(`(?i)(findunique\s*\(|findbyid\s*\(|find_by_id|where\s*:\s*\{[^}{]{0,120}\bid\b|\.get\(\s*\w*id\b|filter_by\(\s*\w*id\s*=|\.filter\([^()]{0,120}\.id\s*==|query\.get\(|where\s+\w*id\s*=)`)
	// Owner/tenant SCOPING predicates. Note: an authenticated principal such as
	// `current_user` or `req.user` on its own is NOT an ownership predicate — the
	// query must be scoped by the owner — so those are deliberately excluded here
	// (an authenticated handler that fetches by id without owner scoping is IDOR).
	raReOwner = regexp.MustCompile(`(?i)(user_?id|owner_?id|org_?id|team_?id|tenant_?id|account_?id|\buserid\b|created_?by|author_?id|user\s*\.\s*id|owner\s*\.\s*id|filter_by\([^)]*\buser|where[^}]*\buser|\.eq\(\s*['"][a-z_]*id['"])`)
)

// raHandler is one route/handler candidate extracted from a file.
type raHandler struct {
	line      int    // 1-based line of the handler signature / route registration
	body      string // handler text (signature + body) used for token checks
	routePath string // declared route path, if available (else the file path)
	guarded   bool   // Express: middleware present (treated as an auth guard)
}

// raScanOpts carries directory-level context resolved once per scan: extra
// auth-helper names and public path segments from an optional .trishul.yml, and
// a predicate that reports whether an app-wide Next.js auth middleware covers a
// given App Router route. Threading it keeps per-file scanning pure.
type raScanOpts struct {
	extraJSAuth    []string        // additional JS/TS auth-helper substrings (lowercased)
	extraPyAuth    []string        // additional Python auth-helper substrings (lowercased)
	extraPublicSeg map[string]bool // additional public path segments (lowercased)
	nextMwCovers   func(rel string) bool
}

func (o raScanOpts) covers(rel string) bool {
	return o.nextMwCovers != nil && o.nextMwCovers(rel)
}

// scanRouteAuth walks directory (read-only) and returns deterministic findings.
// Exported-for-test entry point used by the unit tests.
func scanRouteAuth(directory string) ([]map[string]interface{}, error) {
	var findings []map[string]interface{}

	opts := raBuildOpts(directory)

	walkErr := filepath.WalkDir(directory, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries rather than aborting the scan
		}
		if d.IsDir() {
			if raSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))
		isJS := ext == ".js" || ext == ".jsx" || ext == ".ts" || ext == ".tsx" || ext == ".mjs" || ext == ".cjs" || ext == ".mts" || ext == ".cts"
		isPy := ext == ".py"
		if !isJS && !isPy {
			return nil
		}

		info, statErr := d.Info()
		if statErr == nil && info.Size() > raMaxFileBytes {
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			logger.Debug().Str("tool", "route-authz").Str("file", path).Err(readErr).Msg("skip unreadable file")
			return nil
		}

		rel := path
		if r, relErr := filepath.Rel(directory, path); relErr == nil {
			rel = r
		}
		rel = filepath.ToSlash(rel)

		if isJS {
			findings = append(findings, raScanJS(rel, string(content), opts)...)
		} else {
			findings = append(findings, raScanPy(rel, string(content), opts)...)
		}
		return nil
	})
	if walkErr != nil {
		return findings, walkErr
	}

	findings = raDedup(findings)
	raSortFindings(findings)
	return findings, nil
}

// raScanJS gathers handler candidates from a JavaScript/TypeScript file and
// evaluates the two checks against each.
func raScanJS(rel, content string, opts raScanOpts) []map[string]interface{} {
	lower := strings.ToLower(content)
	authTokens := append(append([]string{}, raJSAuthTokens...), opts.extraJSAuth...)
	// A route is considered auth-covered if the file references an auth helper
	// anywhere, if the file installs an app-wide auth guard (Express `.use`,
	// NestJS `@UseGuards`), or if an app-wide Next.js auth middleware matches it.
	fileHasAuth := raContainsAny(lower, authTokens) || raJSAppWideAuth(content) || opts.covers(rel)

	base := strings.ToLower(filepath.Base(rel))
	isRouteFile := strings.HasPrefix(base, "route.")
	isPagesAPI := strings.Contains(rel, "pages/api/")

	var handlers []raHandler
	switch {
	case isRouteFile:
		handlers = append(handlers, raAppRouterHandlers(content, rel)...)
	case isPagesAPI:
		handlers = append(handlers, raPagesHandlers(content, rel)...)
	}
	// Express routes may appear in any JS file (including ones that also define
	// App Router handlers in unusual setups).
	handlers = append(handlers, raExpressHandlers(content)...)
	// Server actions: only in files that declare "use server" and are not route
	// handler / pages-api files (whose exports are not actions).
	if !isRouteFile && !isPagesAPI && raReUseServer.MatchString(content) {
		handlers = append(handlers, raServerActionHandlers(content, rel)...)
	}

	return raEvaluate(handlers, rel, fileHasAuth, authTokens, raJSDataTokens, opts)
}

// raScanPy gathers decorator-based route handlers from a Python file.
func raScanPy(rel, content string, opts raScanOpts) []map[string]interface{} {
	lower := strings.ToLower(content)
	authTokens := append(append([]string{}, raPyAuthTokens...), opts.extraPyAuth...)
	// File-wide auth: an auth helper anywhere, or an app-wide guard (Flask
	// before_request, Django LoginRequiredMixin, FastAPI router dependencies).
	fileHasAuth := raContainsAny(lower, authTokens) || raPyAppWideAuth(content)

	lines := strings.Split(content, "\n")
	var handlers []raHandler

	for _, m := range raRePyRoute.FindAllStringSubmatchIndex(content, -1) {
		decoLine := raLineAt(content, m[0]) // 1-based
		di := decoLine - 1                  // 0-based index into lines

		// Route path = first string literal on the decorator line.
		routePath := ""
		if di >= 0 && di < len(lines) {
			if sm := raReFirstStr.FindStringSubmatch(lines[di]); sm != nil {
				routePath = sm[1]
			}
		}

		// Find the def line, skipping stacked decorators and blank lines.
		j := di + 1
		for j < len(lines) && (strings.TrimSpace(lines[j]) == "" || strings.HasPrefix(strings.TrimSpace(lines[j]), "@")) {
			j++
		}
		if j >= len(lines) || !raRePyDef.MatchString(lines[j]) {
			continue // decorator not attached to a function; skip conservatively
		}
		defIndent := raIndent(lines[j])

		// Body extends until a line dedents to/below the def's indentation.
		k := j + 1
		for k < len(lines) {
			if strings.TrimSpace(lines[k]) == "" {
				k++
				continue
			}
			if raIndent(lines[k]) <= defIndent {
				break
			}
			k++
		}
		body := strings.Join(lines[di:k], "\n") // include decorators + signature + body
		handlers = append(handlers, raHandler{line: decoLine, body: body, routePath: routePath})
	}

	return raEvaluate(handlers, rel, fileHasAuth, authTokens, raPyDataTokens, opts)
}

// raEvaluate runs both checks over the collected handlers for one file.
func raEvaluate(handlers []raHandler, rel string, fileHasAuth bool, authTokens, dataTokens []string, opts raScanOpts) []map[string]interface{} {
	var out []map[string]interface{}
	for _, h := range handlers {
		bodyLower := strings.ToLower(h.body)
		handlerHasAuth := raContainsAny(bodyLower, authTokens)

		// VIBE-AUTHZ-001: unauthenticated data route.
		if !fileHasAuth && !handlerHasAuth && !h.guarded &&
			raContainsAny(bodyLower, dataTokens) &&
			!raPublicPath(rel, h.routePath) {
			out = append(out, raFinding(rel, h.line, raCheckUnauth, raCWEMissing,
				"API route handler reads/writes data with no visible authentication or authorization check; "+
					"any unauthenticated client can invoke it.",
				raRemediationUnauth))
		}

		// VIBE-AUTHZ-002: IDOR heuristic. Independent of auth — an authenticated
		// handler that fetches by a request-supplied id without an owner predicate
		// is the classic IDOR.
		idRead := raReIDBody.MatchString(h.body) || raReIDPath.MatchString(rel) || raReIDPath.MatchString(h.routePath)
		if idRead && raReByID.MatchString(h.body) && !raReOwner.MatchString(h.body) {
			out = append(out, raFinding(rel, h.line, raCheckIDOR, raCWEIDOR,
				"Handler looks up a record by a request-supplied id with no owner/user predicate; "+
					"a caller may be able to access another user's record by changing the id (IDOR).",
				raRemediationIDOR))
		}
	}
	return out
}

// raAppRouterHandlers extracts Next.js App Router method handlers.
func raAppRouterHandlers(content, rel string) []raHandler {
	var hs []raHandler
	for _, re := range []*regexp.Regexp{raReAppFunc, raReAppConst} {
		for _, m := range re.FindAllStringSubmatchIndex(content, -1) {
			if body, ok := raExtractBlock(content, m[1]); ok {
				hs = append(hs, raHandler{line: raLineAt(content, m[0]), body: body, routePath: rel})
			}
		}
	}
	return hs
}

// raPagesHandlers extracts the Next.js Pages API default-export handler. When no
// explicit default function/arrow is found (e.g. `export default handler`), the
// whole file is treated as a single handler body so the checks still apply.
func raPagesHandlers(content, rel string) []raHandler {
	var hs []raHandler
	for _, re := range []*regexp.Regexp{raRePagesFunc, raRePagesArrow} {
		for _, m := range re.FindAllStringSubmatchIndex(content, -1) {
			if body, ok := raExtractBlock(content, m[1]); ok {
				hs = append(hs, raHandler{line: raLineAt(content, m[0]), body: body, routePath: rel})
			}
		}
	}
	if len(hs) == 0 {
		hs = append(hs, raHandler{line: 1, body: content, routePath: rel})
	}
	return hs
}

// raServerActionHandlers extracts exported async functions from a "use server"
// module (Next.js server actions).
func raServerActionHandlers(content, rel string) []raHandler {
	var hs []raHandler
	for _, m := range raReServerFn.FindAllStringSubmatchIndex(content, -1) {
		if body, ok := raExtractBlock(content, m[1]); ok {
			hs = append(hs, raHandler{line: raLineAt(content, m[0]), body: body, routePath: rel})
		}
	}
	return hs
}

// raExpressHandlers extracts Express route registrations. The handler "body"
// used for token checks is the full argument list (which contains the handler
// function). Routes with 3+ arguments (path, middleware…, handler) are treated
// as guarded, since the middleware is assumed to perform auth.
func raExpressHandlers(content string) []raHandler {
	var hs []raHandler
	for _, m := range raReExpress.FindAllStringSubmatchIndex(content, -1) {
		recv := strings.ToLower(content[m[2]:m[3]])
		if !raExpressReceiver(recv) {
			continue
		}
		openIdx := m[1] - 1 // index of the '(' (last char of the match)
		closeIdx, ok := raMatchDelim(content, openIdx)
		if !ok {
			continue
		}
		inner := content[openIdx+1 : closeIdx]
		args := raSplitTopArgs(inner)
		routePath := ""
		if len(args) > 0 {
			routePath = raStripQuotes(strings.TrimSpace(args[0]))
		}
		hs = append(hs, raHandler{
			line:      raLineAt(content, m[0]),
			body:      inner,
			routePath: routePath,
			guarded:   len(args) >= 3,
		})
	}
	return hs
}

func raExpressReceiver(recv string) bool {
	switch recv {
	case "app", "router", "route", "routes":
		return true
	}
	return strings.HasSuffix(recv, "router")
}

// ---- app-wide / middleware auth resolution ---------------------------------

// raJSMiddlewareAuthHints are substrings that, when present in the argument of
// an `app.use(...)` / `router.use(...)` call, mark that middleware as an auth
// guard. Kept narrow so generic middleware (json, cors, helmet, compression)
// is not mistaken for authentication.
var raJSMiddlewareAuthHints = []string{
	"auth", "guard", "protect", "passport", "clerk", "verifytoken", "verifyjwt",
	"jwt.verify", "ensureloggedin", "requirelogin", "requireuser", "session.user",
	"withauth", "isauthenticated", "checkauth", "ensureauth",
}

// raJSAppWideAuth reports whether a JS/TS file installs an app-wide auth guard:
// an Express/Connect `.use(<auth middleware>)` mounted on app/router, or a
// NestJS `@UseGuards(...)` applied at the controller (or method) level.
func raJSAppWideAuth(content string) bool {
	if strings.Contains(strings.ToLower(content), "@useguards(") {
		return true
	}
	for _, m := range raReUse.FindAllStringSubmatchIndex(content, -1) {
		recv := strings.ToLower(content[m[2]:m[3]])
		if !raExpressReceiver(recv) {
			continue
		}
		openIdx := m[1] - 1 // index of the '(' (last char of the match)
		closeIdx, ok := raMatchDelim(content, openIdx)
		if !ok {
			continue
		}
		args := strings.ToLower(content[openIdx+1 : closeIdx])
		if raContainsAny(args, raJSMiddlewareAuthHints) {
			return true
		}
	}
	return false
}

// raPyAppWideHints are substrings marking an app-wide/class-wide Python auth
// guard (Flask before_request hooks, Django auth mixins/decorators).
var raPyAppWideHints = []string{
	"before_request", "loginrequiredmixin", "permissionrequiredmixin",
	"permission_required", "staff_member_required", "user_passes_test",
	"accessmixin", "userpassestestmixin",
}

// raPyAppWideAuth reports whether a Python file installs an app-wide auth guard:
// a Flask before_request hook, a Django auth mixin/decorator, or a FastAPI
// router/app wired with auth dependencies or middleware.
func raPyAppWideAuth(content string) bool {
	lower := strings.ToLower(content)
	if raContainsAny(lower, raPyAppWideHints) {
		return true
	}
	// FastAPI router- or app-level dependencies: APIRouter(dependencies=[...]) /
	// include_router(..., dependencies=[...]) / app.add_middleware(AuthMiddleware).
	if (strings.Contains(lower, "dependencies=") || strings.Contains(lower, "dependencies =")) &&
		(strings.Contains(lower, "depends(") || strings.Contains(lower, "security(")) &&
		raContainsAny(lower, []string{"auth", "login", "require", "token", "current_user", "permission", "verify", "session"}) {
		return true
	}
	if strings.Contains(lower, "add_middleware(") &&
		raContainsAny(lower, []string{"auth", "login", "jwt", "session", "token"}) {
		return true
	}
	return false
}

// raBuildOpts resolves directory-level scan context once per scan: an optional
// .trishul.yml (extra auth helpers / public segments) and the Next.js
// middleware coverage predicate.
func raBuildOpts(directory string) raScanOpts {
	opts := raScanOpts{nextMwCovers: raBuildNextMiddleware(directory)}
	opts.extraJSAuth, opts.extraPyAuth, opts.extraPublicSeg = raLoadConfig(directory)
	return opts
}

// raBuildNextMiddleware looks for a Next.js middleware file that performs auth
// and returns a predicate reporting whether it covers a given App Router / Pages
// route. A middleware without an explicit `matcher` config applies to every
// route; otherwise only matching routes are covered. Returns nil when there is
// no authenticating middleware.
func raBuildNextMiddleware(directory string) func(string) bool {
	cands := []string{
		"middleware.ts", "middleware.js", "middleware.mjs", "middleware.mts",
		"src/middleware.ts", "src/middleware.js", "src/middleware.mjs", "src/middleware.mts",
	}
	var content string
	for _, c := range cands {
		if b, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(c))); err == nil {
			content = string(b)
			break
		}
	}
	if content == "" {
		return nil
	}
	if !raContainsAny(strings.ToLower(content), raJSAuthTokens) && !raJSAppWideAuth(content) {
		return nil // a middleware that never authenticates does not protect routes
	}
	matchers := raNextMatchers(content)
	return func(rel string) bool {
		base := strings.ToLower(filepath.Base(rel))
		isRoute := strings.HasPrefix(base, "route.") || strings.HasPrefix(base, "page.") ||
			strings.Contains(rel, "pages/api/")
		if !isRoute {
			return false // Next middleware governs Next routes, not e.g. Express files
		}
		if len(matchers) == 0 {
			return true // no matcher config => applies to all routes
		}
		url := raAppRouteURL(rel)
		for _, pat := range matchers {
			if raMatchNextMatcher(pat, url) {
				return true
			}
		}
		return false
	}
}

// raNextMatchers extracts the string patterns from a Next.js middleware
// `matcher` config (array or single-string form).
func raNextMatchers(content string) []string {
	idx := strings.Index(strings.ToLower(content), "matcher")
	if idx < 0 {
		return nil
	}
	if br := raFindDelim(content, idx, '[', 80); br >= 0 {
		if end, ok := raMatchDelim(content, br); ok {
			var out []string
			for _, m := range raReFirstStr.FindAllStringSubmatch(content[br:end+1], -1) {
				out = append(out, m[1])
			}
			return out
		}
	}
	line := content[idx:]
	if nl := strings.IndexByte(line, '\n'); nl >= 0 {
		line = line[:nl]
	}
	if m := raReFirstStr.FindStringSubmatch(line); m != nil {
		return []string{m[1]}
	}
	return nil
}

// raAppRouteURL derives the URL path of a Next.js App Router / Pages route from
// its relative file path (dropping the extension, the route/page basename, a
// leading src/ or app/ and any (route-group) segments).
func raAppRouteURL(rel string) string {
	u := rel
	if i := strings.LastIndex(u, "."); i >= 0 {
		u = u[:i]
	}
	u = strings.TrimSuffix(u, "/route")
	u = strings.TrimSuffix(u, "/page")
	u = strings.TrimSuffix(u, "/index")
	u = strings.TrimPrefix(u, "src/")
	u = strings.TrimPrefix(u, "app/")
	u = strings.TrimPrefix(u, "pages/")
	var segs []string
	for _, s := range strings.Split(u, "/") {
		if s == "" || (strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")")) {
			continue
		}
		segs = append(segs, s)
	}
	return "/" + strings.Join(segs, "/")
}

// raMatchNextMatcher reports whether a Next.js matcher pattern covers url. It
// matches on the literal prefix up to the first dynamic token (:param, *, regex)
// so `/api/:path*` covers `/api/notes`.
func raMatchNextMatcher(pattern, url string) bool {
	prefix := pattern
	if i := strings.IndexAny(pattern, ":*(?[{"); i >= 0 {
		prefix = pattern[:i]
	}
	prefix = strings.TrimRight(prefix, "/")
	if prefix == "" {
		return true
	}
	return url == prefix || strings.HasPrefix(url, prefix+"/")
}

// raLoadConfig reads an optional .trishul.yml / .trishul.yaml at the scan root
// and returns extra auth-helper substrings (JS and Py) and extra public path
// segments. Unknown keys are ignored (this is a tolerant, additive read that
// never fails the scan); projcfg owns the authoritative schema.
func raLoadConfig(directory string) (extraJS, extraPy []string, extraSeg map[string]bool) {
	for _, name := range []string{".trishul.yml", ".trishul.yaml"} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			continue
		}
		var cfg struct {
			RouteAuth struct {
				AuthHelpers    []string `yaml:"auth_helpers"`
				JSAuthHelpers  []string `yaml:"js_auth_helpers"`
				PyAuthHelpers  []string `yaml:"py_auth_helpers"`
				PublicSegments []string `yaml:"public_segments"`
			} `yaml:"routeauth"`
		}
		if yaml.Unmarshal(data, &cfg) != nil {
			return nil, nil, nil
		}
		ra := cfg.RouteAuth
		lower := func(in []string) []string {
			var out []string
			for _, s := range in {
				if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
					out = append(out, s)
				}
			}
			return out
		}
		shared := lower(ra.AuthHelpers)
		extraJS = append(append([]string{}, shared...), lower(ra.JSAuthHelpers)...)
		extraPy = append(append([]string{}, shared...), lower(ra.PyAuthHelpers)...)
		if segs := lower(ra.PublicSegments); len(segs) > 0 {
			extraSeg = map[string]bool{}
			for _, s := range segs {
				extraSeg[s] = true
			}
		}
		return extraJS, extraPy, extraSeg
	}
	return nil, nil, nil
}

// ---- finding construction & helpers ----------------------------------------

func raFinding(path string, line int, checkID, cwe, message, remediation string) map[string]interface{} {
	return map[string]interface{}{
		"path":        path,
		"line":        line,
		"message":     message,
		"severity":    "HIGH",
		"check_id":    checkID,
		"cwe":         cwe,
		"confidence":  "MEDIUM",
		"remediation": remediation,
	}
}

// raPublicPath reports whether any path segment of rel or routePath marks the
// route as intentionally public (health, login, webhook, static, …).
func raPublicPath(rel, routePath string) bool {
	for _, tok := range raSegments(rel + "/" + routePath) {
		if raPublicSegments[tok] {
			return true
		}
	}
	return false
}

func raSegments(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
}

func raContainsAny(lowerText string, tokens []string) bool {
	for _, t := range tokens {
		if strings.Contains(lowerText, t) {
			return true
		}
	}
	return false
}

func raLineAt(content string, off int) int {
	if off < 0 {
		off = 0
	}
	if off > len(content) {
		off = len(content)
	}
	return 1 + strings.Count(content[:off], "\n")
}

func raIndent(line string) int {
	n := 0
	for _, r := range line {
		if r == ' ' || r == '\t' {
			n++
		} else {
			break
		}
	}
	return n
}

func raStripQuotes(s string) string {
	return strings.Trim(s, "'\"`")
}

// raExtractBlock returns the balanced `{…}` body of a function/arrow whose
// signature begins at/after `from`. It first skips the parameter list `(…)` (so
// a destructured parameter such as `{ params }` is not mistaken for the body),
// then returns the first balanced brace block after it. ok is false if no nearby
// body is found or it is unbalanced.
func raExtractBlock(content string, from int) (string, bool) {
	parenIdx := raFindDelim(content, from, '(', raBraceMaxGap)
	braceIdx := raFindDelim(content, from, '{', raBraceMaxGap)

	bodyStart := braceIdx
	// If a parameter list opens before the first brace, skip past its matching
	// `)` and look for the body brace after it.
	if parenIdx >= 0 && (braceIdx < 0 || parenIdx < braceIdx) {
		closeParen, ok := raMatchDelim(content, parenIdx)
		if !ok {
			return "", false
		}
		bodyStart = raFindDelim(content, closeParen+1, '{', raBraceMaxGap)
	}
	if bodyStart < 0 {
		return "", false
	}
	closeBrace, ok := raMatchDelim(content, bodyStart)
	if !ok {
		return "", false
	}
	return content[bodyStart : closeBrace+1], true
}

// raFindDelim returns the index of the first top-level occurrence of ch at/after
// `from`, skipping string and comment content, or -1 if none within maxGap bytes.
func raFindDelim(content string, from int, ch byte, maxGap int) int {
	n := len(content)
	i := from
	gap := 0
	for i < n {
		if j := raSkipStringComment(content, i); j != i {
			i = j
			continue
		}
		if content[i] == ch {
			return i
		}
		i++
		gap++
		if maxGap > 0 && gap > maxGap {
			return -1
		}
	}
	return -1
}

// raMatchDelim returns the index of the delimiter matching the opener at `open`
// (one of ( [ {), skipping strings and comments. ok is false if unbalanced.
func raMatchDelim(content string, open int) (int, bool) {
	n := len(content)
	oc := content[open]
	var cc byte
	switch oc {
	case '{':
		cc = '}'
	case '(':
		cc = ')'
	case '[':
		cc = ']'
	default:
		return -1, false
	}
	depth := 0
	i := open
	for i < n {
		if j := raSkipStringComment(content, i); j != i {
			i = j
			continue
		}
		switch content[i] {
		case oc:
			depth++
		case cc:
			depth--
			if depth == 0 {
				return i, true
			}
		}
		i++
	}
	return -1, false
}

// raSkipStringComment, if content[i] starts a string literal ('…', "…", `…`),
// a line comment (//…) or a block comment (/*…*/), returns the index just past
// it; otherwise it returns i unchanged.
func raSkipStringComment(content string, i int) int {
	n := len(content)
	c := content[i]
	if c == '/' && i+1 < n && content[i+1] == '/' {
		j := i + 2
		for j < n && content[j] != '\n' {
			j++
		}
		return j
	}
	if c == '/' && i+1 < n && content[i+1] == '*' {
		j := i + 2
		for j+1 < n && !(content[j] == '*' && content[j+1] == '/') {
			j++
		}
		if j+1 < n {
			return j + 2
		}
		return n
	}
	if c == '"' || c == '\'' || c == '`' {
		j := i + 1
		for j < n {
			if content[j] == '\\' {
				j += 2
				continue
			}
			if content[j] == c {
				return j + 1
			}
			j++
		}
		return n
	}
	return i
}

// raSplitTopArgs splits a comma-separated argument list on top-level commas,
// respecting nested () [] {} and string literals.
func raSplitTopArgs(s string) []string {
	var args []string
	depth := 0
	start := 0
	i := 0
	n := len(s)
	for i < n {
		if j := raSkipStringComment(s, i); j != i {
			i = j
			continue
		}
		switch s[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
		i++
	}
	if strings.TrimSpace(s[start:]) != "" {
		args = append(args, strings.TrimSpace(s[start:]))
	}
	return args
}

// raDedup removes identical (path,line,check_id) findings.
func raDedup(findings []map[string]interface{}) []map[string]interface{} {
	seen := map[string]bool{}
	out := findings[:0]
	for _, f := range findings {
		path, _ := f["path"].(string)
		line, _ := f["line"].(int)
		id, _ := f["check_id"].(string)
		key := path + "\x00" + id + "\x00" + routeItoa(line)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func routeItoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// raSortFindings makes output deterministic regardless of walk/map ordering.
func raSortFindings(findings []map[string]interface{}) {
	sort.SliceStable(findings, func(i, j int) bool {
		pi, _ := findings[i]["path"].(string)
		pj, _ := findings[j]["path"].(string)
		if pi != pj {
			return pi < pj
		}
		li, _ := findings[i]["line"].(int)
		lj, _ := findings[j]["line"].(int)
		if li != lj {
			return li < lj
		}
		ci, _ := findings[i]["check_id"].(string)
		cj, _ := findings[j]["check_id"].(string)
		return ci < cj
	})
}
