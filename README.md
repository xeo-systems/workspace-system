# Multi-tenant RBAC backend (reference)

This repository is a concise reference implementation of a multi‑tenant API with RBAC, audit logging, and background jobs. It is intended for learning and internal evaluation, not production deployment.

**Core capabilities**
- Auth with access JWTs and hashed refresh tokens
- Multi‑tenant organizations and workspaces
- RBAC with permissions attached to memberships
- Append‑only audit logs (async)
- Idempotent background jobs (async)

```
                ┌───────────────┐
                │   Web UI      │
                └──────┬────────┘
                       │ HTTP
                ┌──────▼────────┐      ┌──────────────┐
                │  API (Express)│───►  │ Postgres     │
                └──────┬────────┘      └──────────────┘
                       │
                       ├──────────────► Redis (BullMQ)
                       │
                ┌──────▼────────┐
                │   Worker      │
                └───────────────┘
```

## Local setup

### Port conflicts

By default, this stack binds Postgres to `5432` and Redis to `6379`.

Quick check:

```bash
lsof -i :5432 || true
lsof -i :6379 || true
docker ps
```

Option A (recommended): stop this repo’s containers and re-check ports

```bash
docker compose down
lsof -i :5432 || true
lsof -i :6379 || true
docker ps
```

If other containers are binding these ports, stop those specific containers.

Option B (advanced): use alternate ports

This repo’s `docker-compose.yml` hardcodes `5432:5432` and `6379:6379`. If you need alternate ports, manually edit the compose file and update env values accordingly. Example:

```
POSTGRES_PORT=5433
REDIS_PORT=6380
DATABASE_URL=postgresql://user:password@localhost:5433/database
REDIS_URL=redis://localhost:6380
```

Note: the API binds to port `4000` by default and will fail with `EADDRINUSE` if that port is already in use. Check before starting:

```bash
lsof -i :4000 || true
```

```bash
docker compose up -d
pnpm install
cp .env.example .env
pnpm prisma:migrate -- --name init
pnpm prisma:seed
lsof -i :4000 || true
# Start the API (use exactly one line below).
# If 4000 is in use, use the PORT=4001 line instead of the default.
JWT_SECRET=replace_with_strong_secret pnpm dev
PORT=4001 JWT_SECRET=replace_with_strong_secret pnpm dev
JWT_SECRET=replace_with_strong_secret pnpm worker
```

`.env.example` uses local dev defaults that match `docker-compose.yml`; change values for production.

## Minimal curl smoke test

Set variables:

```bash
export TOKEN="..."
export ORG_ID="..."
export WORKSPACE_ID="..."
export INVITE_TOKEN="..."
export MEMBERSHIP_ID="..."
```

Capture variables (jq optional):

```bash
# if you have jq
TOKEN=$(curl -s -X POST http://localhost:4000/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"owner@example.com","password":"password123","name":"Owner"}' | jq -r '.data.accessToken')

ORG_ID=$(curl -s -X POST http://localhost:4000/orgs \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Acme","slug":"acme"}' | jq -r '.data.org.id')

WORKSPACE_ID=$(curl -s -X POST http://localhost:4000/workspaces \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"orgId":"'$ORG_ID'","name":"Core","slug":"core"}' | jq -r '.data.workspace.id')

INVITE_TOKEN=$(curl -s -X POST http://localhost:4000/orgs/$ORG_ID/invites \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"email":"invitee@example.com","roleName":"member"}' | jq -r '.data.token')

# select the appropriate membership from the list
MEMBERSHIP_ID=$(curl -s -X GET http://localhost:4000/orgs/$ORG_ID/members \
  -H "Authorization: Bearer $TOKEN" | jq -r '.data.memberships[0].id')
```

If you don’t have `jq`, run the commands below and manually copy values into the exported variables.

```bash
curl -s -X POST http://localhost:4000/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"owner@example.com","password":"password123","name":"Owner"}'
```

```bash
curl -s -X POST http://localhost:4000/orgs \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Acme","slug":"acme"}'
```

```bash
curl -s -X POST http://localhost:4000/workspaces \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"orgId":"$ORG_ID","name":"Core","slug":"core"}'
```

```bash
curl -s -X POST http://localhost:4000/jobs/enqueue \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"orgId":"$ORG_ID","type":"echo","payload":{"msg":"hi"},"idempotencyKey":"abc"}'
```

Idempotency should be stable (second request returns existing job, not 500):

```bash
curl -s -X POST http://localhost:4000/jobs/enqueue \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"orgId":"$ORG_ID","type":"echo","payload":{"msg":"hi"},"idempotencyKey":"abc"}'
```

Invite double-accept should fail deterministically:

```bash
curl -s -X POST http://localhost:4000/invites/accept \
  -H 'Content-Type: application/json' \
  -d '{"token":"$INVITE_TOKEN"}'
curl -s -X POST http://localhost:4000/invites/accept \
  -H 'Content-Type: application/json' \
  -d '{"token":"$INVITE_TOKEN"}'
```

Membership role changes require `members.manage` (403 otherwise):

```bash
curl -s -X PATCH http://localhost:4000/memberships/$MEMBERSHIP_ID/roles \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"roleIds":["$ROLE_ID"]}'
```

## Web UI (apps/web)

Set the API base URL and run:

```bash
cd apps/web
cp .env.example .env.local
pnpm install
pnpm dev
```

**UI description**
A minimal Next.js UI is provided for login/signup and basic org, workspace, audit, invites, and jobs flows.

## Disclaimer

This project is for educational/reference use. It is **not production‑hardened** and omits security hardening, monitoring, backups, and operational controls required for real deployments.
