# VIBE-AUTHZ-001: Unauthenticated data route (missing authorization)

An API route touches a data layer with no visible auth check.

## Metadata

| Field | Value |
| --- | --- |
| Severity | HIGH |
| Confidence | 0.50 |
| Maturity | stable |
| Mode | comment |
| Languages | javascript, typescript, python |
| File kinds | source |
| CWE | CWE-862 |
| OWASP | A01 |

## Description

An API route/handler reads or writes persisted data but has no visible session/auth/token
guard (whole-file, per-handler, or Express middleware), so any unauthenticated client can
invoke it. Public/health/auth-endpoint paths are allow-listed and not flagged.

## Fix

Add an authentication/authorization check at the start of the handler (getServerSession/auth/getToken in Next.js, auth middleware in Express, Depends(get_current_user) in FastAPI) and reject unauthenticated requests before touching data.

## Examples

Bad:

```bad
export async function GET() { return Response.json(await prisma.user.findMany()) }
```

Good:

```good
export async function GET() { const s = await auth(); if (!s) return new Response(null, { status: 401 }); return Response.json(await prisma.user.findMany()) }
```

