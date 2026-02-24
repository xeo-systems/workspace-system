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

Note: the API binds to port `4000` by default. This guide uses `4001` to avoid conflicts. If you prefer the default, start the API with `PORT=4000` instead.

```bash
lsof -i :4001 || true
```

```bash
docker compose up -d
pnpm install
cp .env.example .env
pnpm prisma:migrate -- --name init
pnpm prisma:seed
# Pick a free port starting at 4001
PORT=${PORT:-4001}
while lsof -i :$PORT >/dev/null 2>&1; do PORT=$((PORT+1)); done
export PORT
export API_BASE_URL="http://localhost:$PORT"
JWT_SECRET=replace_with_strong_secret node --import tsx src/index.ts
JWT_SECRET=replace_with_strong_secret node --import tsx src/worker.ts
```

If you see `EPERM` when binding a port, run the above commands from a normal terminal session (some sandboxed environments disallow network binds).

`.env.example` uses local dev defaults that match `docker-compose.yml`; change values for production.

## Minimal curl smoke test

Set variables:

```bash
export API_BASE_URL="${API_BASE_URL:-http://localhost:4001}"
export TOKEN="..."
export ORG_ID="..."
export WORKSPACE_ID="..."
export INVITE_TOKEN="..."
export MEMBERSHIP_ID="..."
export OWNER_EMAIL="..."
export INVITEE_EMAIL="..."
```

Capture variables (jq optional):

```bash
# if you have jq
command -v jq >/dev/null || { echo "jq is required for this block. Install jq or use the manual mode below."; exit 1; }
API_BASE_URL="${API_BASE_URL:-http://localhost:4001}"
TS=$(date +%s)
OWNER_EMAIL="owner-$TS@example.com"
INVITEE_EMAIL="invitee-$TS@example.com"

TOKEN=$(curl -sfS -X POST $API_BASE_URL/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"'$OWNER_EMAIL'","password":"password123","name":"Owner"}' | jq -r '.data.accessToken')
[ -n "$TOKEN" ] || { echo "Failed to capture TOKEN. Signup may have failed or parsing failed."; exit 1; }

ORG_ID=$(curl -sfS -X POST $API_BASE_URL/orgs \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Acme","slug":"acme"}' | jq -r '.data.org.id')

WORKSPACE_ID=$(curl -sfS -X POST $API_BASE_URL/workspaces \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"orgId":"'$ORG_ID'","name":"Core","slug":"core"}' | jq -r '.data.workspace.id')

INVITE_TOKEN=$(curl -sfS -X POST $API_BASE_URL/orgs/$ORG_ID/invites \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"email":"'$INVITEE_EMAIL'","roleName":"member"}' | jq -r '.data.token')

# select the appropriate membership from the list
MEMBERSHIP_ID=$(curl -sfS -X GET $API_BASE_URL/orgs/$ORG_ID/members \
  -H "Authorization: Bearer $TOKEN" | jq -r '.data.memberships[0].id')
```

If you don’t have `jq`, run the commands below and manually copy values into the exported variables.

```bash
API_BASE_URL="${API_BASE_URL:-http://localhost:4001}"
TS=$(date +%s)
OWNER_EMAIL="owner-$TS@example.com"
INVITEE_EMAIL="invitee-$TS@example.com"

curl -s -X POST $API_BASE_URL/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"'$OWNER_EMAIL'","password":"password123","name":"Owner"}'
```

```bash
curl -s -X POST $API_BASE_URL/orgs \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"Acme","slug":"acme"}'
```

```bash
curl -s -X POST $API_BASE_URL/workspaces \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"orgId":"$ORG_ID","name":"Core","slug":"core"}'
```

```bash
curl -s -X POST $API_BASE_URL/jobs/enqueue \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"orgId":"$ORG_ID","type":"echo","payload":{"msg":"hi"},"idempotencyKey":"abc"}'
```

Idempotency should be stable (second request returns existing job, not 500):

```bash
curl -s -X POST $API_BASE_URL/jobs/enqueue \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"orgId":"$ORG_ID","type":"echo","payload":{"msg":"hi"},"idempotencyKey":"abc"}'
```

Invite double-accept should fail deterministically:

```bash
curl -s -X POST $API_BASE_URL/invites/accept \
  -H 'Content-Type: application/json' \
  -d '{"token":"$INVITE_TOKEN"}'
curl -s -X POST $API_BASE_URL/invites/accept \
  -H 'Content-Type: application/json' \
  -d '{"token":"$INVITE_TOKEN"}'
```

Membership role changes require `members.manage` (403 otherwise):

```bash
curl -s -X PATCH $API_BASE_URL/memberships/$MEMBERSHIP_ID/roles \
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
