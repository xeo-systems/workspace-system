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

```bash
docker compose up -d
pnpm install
cp .env.example .env
pnpm prisma:migrate -- --name init
pnpm prisma:seed
JWT_SECRET=replace_with_strong_secret pnpm dev
JWT_SECRET=replace_with_strong_secret pnpm worker
```

## Minimal curl smoke test

```bash
curl -s -X POST http://localhost:4000/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"password123","name":"User"}'
```

```bash
curl -s -X POST http://localhost:4000/orgs \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -d '{"name":"Acme","slug":"acme"}'
```

```bash
curl -s -X POST http://localhost:4000/workspaces \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -d '{"orgId":"<ORG_ID>","name":"Core","slug":"core"}'
```

```bash
curl -s -X POST http://localhost:4000/jobs/enqueue \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -d '{"orgId":"<ORG_ID>","type":"echo","payload":{"msg":"hi"},"idempotencyKey":"abc"}'
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
