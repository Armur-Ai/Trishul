package internal

import (
	"os"
	"path/filepath"
	"testing"

	utils "github.com/Armur-Ai/Trishul/pkg"
)

// raWrite writes body to <dir>/<relpath>, creating parent dirs.
func raWrite(t *testing.T, dir, relpath, body string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(relpath))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", relpath, err)
	}
}

// raCheckIDs returns the set of check_ids present in the findings.
func raCheckIDs(findings []map[string]interface{}) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		id, _ := f["check_id"].(string)
		out[id]++
	}
	return out
}

func raScan(t *testing.T, dir string) []map[string]interface{} {
	t.Helper()
	findings, err := scanRouteAuth(dir)
	if err != nil {
		t.Fatalf("scanRouteAuth: %v", err)
	}
	return findings
}

func TestRouteAuth_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	findings := raScan(t, dir)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for empty dir, got %d: %v", len(findings), findings)
	}

	// Entry point must still emit the vibe_security category key (empty list).
	res, err := RunRouteAuth(dir)
	if err != nil {
		t.Fatalf("RunRouteAuth: %v", err)
	}
	arr, ok := res[utils.VIBE_SECURITY].([]interface{})
	if !ok {
		t.Fatalf("expected %q to be []interface{}, got %T", utils.VIBE_SECURITY, res[utils.VIBE_SECURITY])
	}
	if len(arr) != 0 {
		t.Fatalf("expected empty findings list, got %d", len(arr))
	}
}

func TestRouteAuth_NextUnauthenticatedWrite(t *testing.T) {
	dir := t.TempDir()
	raWrite(t, dir, "app/api/notes/route.ts", `
import { prisma } from '@/lib/prisma';

export async function POST(req: Request) {
  const body = await req.json();
  const note = await prisma.note.create({
    data: { title: body.title, content: body.content },
  });
  return Response.json(note);
}
`)

	ids := raCheckIDs(raScan(t, dir))
	if ids[raCheckUnauth] == 0 {
		t.Fatalf("expected %s on an unauthenticated writing route, got %v", raCheckUnauth, ids)
	}

	// Confirm finding shape via the public entry point.
	res, _ := RunRouteAuth(dir)
	arr := res[utils.VIBE_SECURITY].([]interface{})
	if len(arr) == 0 {
		t.Fatalf("expected findings under %q", utils.VIBE_SECURITY)
	}
	f := arr[0].(map[string]interface{})
	for _, key := range []string{"path", "line", "message", "severity", "check_id", "cwe", "confidence", "remediation"} {
		if _, ok := f[key]; !ok {
			t.Errorf("finding missing key %q: %v", key, f)
		}
	}
	if f["severity"] != "HIGH" {
		t.Errorf("expected severity HIGH, got %v", f["severity"])
	}
	if f["confidence"] != "MEDIUM" {
		t.Errorf("expected confidence MEDIUM, got %v", f["confidence"])
	}
	if f["cwe"] != raCWEMissing {
		t.Errorf("expected cwe %s, got %v", raCWEMissing, f["cwe"])
	}
	if _, ok := f["line"].(int); !ok {
		t.Errorf("expected line to be int, got %T", f["line"])
	}
}

func TestRouteAuth_ExpressWithAuthClean(t *testing.T) {
	dir := t.TempDir()
	raWrite(t, dir, "src/routes/users.js", `
const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');

router.get('/users', requireAuth, async (req, res) => {
  const users = await db.query('SELECT id, name FROM users');
  res.json(users);
});

module.exports = router;
`)

	findings := raScan(t, dir)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for an authed Express route, got %d: %v", len(findings), findings)
	}
}

func TestRouteAuth_FastAPIDependsClean(t *testing.T) {
	dir := t.TempDir()
	raWrite(t, dir, "api/items.py", `
from fastapi import APIRouter, Depends
from .db import get_db
from .auth import get_current_user

router = APIRouter()

@router.get("/items")
def list_items(user=Depends(get_current_user), db=Depends(get_db)):
    return db.query(Item).all()
`)

	findings := raScan(t, dir)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for a FastAPI route guarded by Depends(get_current_user), got %d: %v", len(findings), findings)
	}
}

func TestRouteAuth_IDORFlagged(t *testing.T) {
	dir := t.TempDir()
	// Authenticated, but fetches by a request id with no owner predicate => IDOR.
	raWrite(t, dir, "app/api/orders/[id]/route.ts", `
import { getServerSession } from 'next-auth';
import { prisma } from '@/lib/prisma';

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  if (!session) {
    return new Response('Unauthorized', { status: 401 });
  }
  const order = await prisma.order.findUnique({ where: { id: params.id } });
  return Response.json(order);
}
`)

	ids := raCheckIDs(raScan(t, dir))
	if ids[raCheckIDOR] == 0 {
		t.Fatalf("expected %s on an owner-less by-id lookup, got %v", raCheckIDOR, ids)
	}
	// Authentication IS present, so the unauth check must NOT fire here.
	if ids[raCheckUnauth] != 0 {
		t.Errorf("did not expect %s on an authenticated route, got %v", raCheckUnauth, ids)
	}
}

// A FastAPI route that reads a path id and queries by it without an owner
// predicate is flagged as IDOR even though the project is Python.
func TestRouteAuth_FastAPIIDOR(t *testing.T) {
	dir := t.TempDir()
	raWrite(t, dir, "api/orders.py", `
from fastapi import APIRouter, Depends
from .auth import get_current_user

router = APIRouter()

@router.get("/orders/{order_id}")
def get_order(order_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    return db.query(Order).get(order_id)
`)

	ids := raCheckIDs(raScan(t, dir))
	if ids[raCheckIDOR] == 0 {
		t.Fatalf("expected %s on FastAPI by-id lookup with no owner predicate, got %v", raCheckIDOR, ids)
	}
}

// A health endpoint and an owner-scoped route must stay clean (false-positive guards).
func TestRouteAuth_PublicAndOwnerScopedClean(t *testing.T) {
	dir := t.TempDir()
	// Public health route (no auth, touches data, but path is allow-listed).
	raWrite(t, dir, "app/api/health/route.ts", `
import { db } from '@/lib/db';
export async function GET() {
  await db.query('SELECT 1');
  return Response.json({ ok: true });
}
`)
	// Owner-scoped by-id lookup => not IDOR.
	raWrite(t, dir, "app/api/me/orders/[id]/route.ts", `
import { getServerSession } from 'next-auth';
import { prisma } from '@/lib/prisma';
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  if (!session) return new Response('no', { status: 401 });
  const order = await prisma.order.findUnique({
    where: { id: params.id, userId: session.user.id },
  });
  return Response.json(order);
}
`)

	findings := raScan(t, dir)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for public + owner-scoped routes, got %d: %v", len(findings), findings)
	}
}

// --- fix #1: app-wide / middleware auth resolution --------------------------

// An Express route with no per-route guard but an app-wide `app.use(authMiddleware)`
// must NOT be flagged: the middleware protects every route beneath it.
func TestRouteAuth_ExpressAppUseGuardClean(t *testing.T) {
	dir := t.TempDir()
	raWrite(t, dir, "src/server.js", `
const express = require('express');
const app = express();
const authGuard = require('./middleware/authGuard');

app.use(express.json());
app.use(authGuard);

app.post('/api/notes', async (req, res) => {
  const note = await db.query('INSERT INTO notes ...');
  res.json(note);
});
`)
	findings := raScan(t, dir)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings behind an app-wide auth guard, got %d: %v", len(findings), findings)
	}
}

// A generic (non-auth) app.use middleware must NOT suppress an otherwise
// unauthenticated data route.
func TestRouteAuth_ExpressAppUseGenericStillFlagged(t *testing.T) {
	dir := t.TempDir()
	raWrite(t, dir, "src/server.js", `
const express = require('express');
const cors = require('cors');
const app = express();
app.use(express.json());
app.use(cors({ origin: '*' }));

app.post('/api/notes', async (req, res) => {
  const note = await db.query('INSERT INTO notes ...');
  res.json(note);
});
`)
	ids := raCheckIDs(raScan(t, dir))
	if ids[raCheckUnauth] == 0 {
		t.Fatalf("expected %s: generic (json/cors) middleware must not count as auth, got %v", raCheckUnauth, ids)
	}
}

// A NestJS controller guarded with @UseGuards must NOT be flagged.
func TestRouteAuth_NestUseGuardsClean(t *testing.T) {
	dir := t.TempDir()
	raWrite(t, dir, "src/notes.controller.ts", `
import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from './jwt.guard';

@Controller('notes')
@UseGuards(JwtAuthGuard)
export class NotesController {
  @Post()
  async create(@Body() dto: any) {
    return this.repository.save(dto);
  }
}
`)
	findings := raScan(t, dir)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings behind @UseGuards, got %d: %v", len(findings), findings)
	}
}

// A Next.js App Router route with no in-handler auth is NOT flagged when a
// middleware.ts authenticates and its matcher covers the route; a route the
// matcher does NOT cover is still flagged.
func TestRouteAuth_NextMiddlewareCoverage(t *testing.T) {
	dir := t.TempDir()
	raWrite(t, dir, "middleware.ts", `
import { withAuth } from 'next-auth/middleware';
export default withAuth(function middleware(req) {});
export const config = { matcher: ['/api/:path*'] };
`)
	// Covered by matcher => clean.
	raWrite(t, dir, "app/api/notes/route.ts", `
import { prisma } from '@/lib/prisma';
export async function POST(req: Request) {
  const body = await req.json();
  return Response.json(await prisma.note.create({ data: body }));
}
`)
	// Outside the matcher => still flagged.
	raWrite(t, dir, "app/dashboard/stats/route.ts", `
import { prisma } from '@/lib/prisma';
export async function POST(req: Request) {
  const body = await req.json();
  return Response.json(await prisma.stat.create({ data: body }));
}
`)
	findings := raScan(t, dir)
	for _, f := range findings {
		if p, _ := f["path"].(string); p == "app/api/notes/route.ts" {
			t.Fatalf("route covered by middleware matcher must not be flagged: %v", f)
		}
	}
	ids := raCheckIDs(findings)
	if ids[raCheckUnauth] == 0 {
		t.Fatalf("expected %s on the route outside the middleware matcher, got %v", raCheckUnauth, ids)
	}
}

// A Flask blueprint with a before_request auth hook protects its routes.
func TestRouteAuth_FlaskBeforeRequestClean(t *testing.T) {
	dir := t.TempDir()
	raWrite(t, dir, "api/notes.py", `
from flask import Blueprint, request

bp = Blueprint("notes", __name__)

@bp.before_request
def require_login():
    if not session.get("user"):
        abort(401)

@bp.route("/notes", methods=["POST"])
def create_note():
    db.session.add(Note(**request.json))
    db.session.commit()
    return "ok"
`)
	findings := raScan(t, dir)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings behind a Flask before_request guard, got %d: %v", len(findings), findings)
	}
}

// --- fix #2: whole-body auth scanning + configurable helpers ----------------

// An auth helper that appears deep in the handler body (not in the first lines)
// must still suppress the finding: the whole body is scanned.
func TestRouteAuth_AuthHelperDeepInBody(t *testing.T) {
	dir := t.TempDir()
	raWrite(t, dir, "app/api/reports/route.ts", `
import { prisma } from '@/lib/prisma';
import { getServerSession } from 'next-auth';

export async function POST(req: Request) {
  // lots of setup work before the auth check
  const body = await req.json();
  const normalized = { ...body, createdAt: new Date() };
  const parsed = JSON.parse(JSON.stringify(normalized));
  const meta = computeMeta(parsed);
  const tags = parsed.tags || [];
  const draft = await buildDraft(parsed, meta, tags);
  // auth check happens only here, well into the body:
  const session = await getServerSession();
  if (!session) return new Response('no', { status: 401 });
  return Response.json(await prisma.report.create({ data: draft }));
}
`)
	ids := raCheckIDs(raScan(t, dir))
	if ids[raCheckUnauth] != 0 {
		t.Fatalf("auth helper deep in the body must suppress %s, got %v", raCheckUnauth, ids)
	}
}

// requireRole() (a built-in role helper) must be recognized as auth.
func TestRouteAuth_RequireRoleRecognized(t *testing.T) {
	dir := t.TempDir()
	raWrite(t, dir, "app/api/admin/route.ts", `
import { prisma } from '@/lib/prisma';
import { requireRole } from '@/lib/rbac';
export async function POST(req: Request) {
  await requireRole(req, 'admin');
  const body = await req.json();
  return Response.json(await prisma.widget.create({ data: body }));
}
`)
	ids := raCheckIDs(raScan(t, dir))
	if ids[raCheckUnauth] != 0 {
		t.Fatalf("requireRole must be recognized as auth, got %v", ids)
	}
}

// A project-specific auth helper named in .trishul.yml must suppress findings;
// without that config the same helper is unknown and the route is flagged.
func TestRouteAuth_ConfigurableAuthHelper(t *testing.T) {
	route := `
import { prisma } from '@/lib/prisma';
import { mustBeMember } from '@/lib/gate';
export async function POST(req: Request) {
  await mustBeMember(req);
  const body = await req.json();
  return Response.json(await prisma.thing.create({ data: body }));
}
`
	// Without config: the custom helper is unknown => route is flagged.
	noCfg := t.TempDir()
	raWrite(t, noCfg, "app/api/things/route.ts", route)
	if raCheckIDs(raScan(t, noCfg))[raCheckUnauth] == 0 {
		t.Fatalf("control: an unknown custom helper should leave the route flagged")
	}

	// With config: declaring the helper suppresses the finding.
	withCfg := t.TempDir()
	raWrite(t, withCfg, ".trishul.yml", "routeauth:\n  auth_helpers:\n    - mustBeMember\n")
	raWrite(t, withCfg, "app/api/things/route.ts", route)
	if ids := raCheckIDs(raScan(t, withCfg)); ids[raCheckUnauth] != 0 {
		t.Fatalf("a .trishul.yml auth_helper must suppress %s, got %v", raCheckUnauth, ids)
	}
}

// --- fix #3: public-by-design routes ----------------------------------------

// A webhook receiver that verifies the provider signature authenticates its
// caller and must NOT be flagged, even when its path is not named "webhook".
func TestRouteAuth_SignedWebhookClean(t *testing.T) {
	dir := t.TempDir()
	raWrite(t, dir, "app/api/stripe/events/route.ts", `
import Stripe from 'stripe';
import { prisma } from '@/lib/prisma';
const stripe = new Stripe(process.env.STRIPE_KEY!);
export async function POST(req: Request) {
  const sig = req.headers.get('stripe-signature')!;
  const event = stripe.webhooks.constructEvent(await req.text(), sig, process.env.WH_SECRET!);
  await prisma.event.create({ data: { type: event.type } });
  return Response.json({ received: true });
}
`)
	findings := raScan(t, dir)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for a signature-verified webhook, got %d: %v", len(findings), findings)
	}
}

// A webhook-style receiver that does NOT verify any signature and has no auth
// still gets flagged when its path is not an allow-listed public segment.
func TestRouteAuth_UnsignedReceiverStillFlagged(t *testing.T) {
	dir := t.TempDir()
	raWrite(t, dir, "app/api/ingest/events/route.ts", `
import { prisma } from '@/lib/prisma';
export async function POST(req: Request) {
  const body = await req.json();
  await prisma.event.create({ data: { type: body.type } });
  return Response.json({ received: true });
}
`)
	if raCheckIDs(raScan(t, dir))[raCheckUnauth] == 0 {
		t.Fatalf("an unsigned, unauthenticated receiver must still be flagged %s", raCheckUnauth)
	}
}

// A standard health endpoint that touches the data layer stays clean.
func TestRouteAuth_HealthEndpointClean(t *testing.T) {
	dir := t.TempDir()
	raWrite(t, dir, "app/api/healthz/route.ts", `
import { db } from '@/lib/db';
export async function GET() {
  await db.query('SELECT 1');
  return Response.json({ ok: true });
}
`)
	if findings := raScan(t, dir); len(findings) != 0 {
		t.Fatalf("expected 0 findings for a health endpoint, got %d: %v", len(findings), findings)
	}
}

// Extra public segments declared in .trishul.yml are honored.
func TestRouteAuth_ConfigPublicSegment(t *testing.T) {
	route := `
import { prisma } from '@/lib/prisma';
export async function POST(req: Request) {
  const body = await req.json();
  return Response.json(await prisma.ping.create({ data: body }));
}
`
	// Control: not public => flagged.
	ctrl := t.TempDir()
	raWrite(t, ctrl, "app/api/telemetry/route.ts", route)
	if raCheckIDs(raScan(t, ctrl))[raCheckUnauth] == 0 {
		t.Fatalf("control: a non-public route should be flagged")
	}
	// Declared public => clean.
	cfg := t.TempDir()
	raWrite(t, cfg, ".trishul.yml", "routeauth:\n  public_segments:\n    - telemetry\n")
	raWrite(t, cfg, "app/api/telemetry/route.ts", route)
	if findings := raScan(t, cfg); len(findings) != 0 {
		t.Fatalf("a configured public_segment must suppress findings, got %d: %v", len(findings), findings)
	}
}

// Findings must be sorted deterministically by (path, line, check_id).
func TestRouteAuth_Deterministic(t *testing.T) {
	dir := t.TempDir()
	raWrite(t, dir, "app/api/a/route.ts", `
import { prisma } from '@/lib/prisma';
export async function POST(req: Request) {
  const b = await req.json();
  return Response.json(await prisma.a.create({ data: b }));
}
`)
	raWrite(t, dir, "app/api/b/route.ts", `
import { prisma } from '@/lib/prisma';
export async function POST(req: Request) {
  const b = await req.json();
  return Response.json(await prisma.b.create({ data: b }));
}
`)

	first := raScan(t, dir)
	second := raScan(t, dir)
	if len(first) != 2 {
		t.Fatalf("expected 2 findings, got %d: %v", len(first), first)
	}
	for i := range first {
		if first[i]["path"] != second[i]["path"] || first[i]["check_id"] != second[i]["check_id"] {
			t.Fatalf("non-deterministic ordering at %d: %v vs %v", i, first[i], second[i])
		}
	}
	if first[0]["path"] != "app/api/a/route.ts" {
		t.Errorf("expected sorted paths, first=%v", first[0]["path"])
	}
}
