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
