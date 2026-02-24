# Architecture

This repository is a reference implementation of a multi-tenant backend with RBAC, audit logging, and background jobs.

## Tenant model

- **Organization** is the primary tenant boundary.
- **Workspace** belongs to an organization and is a secondary scope for access and data.
- All org/workspace operations verify membership in the database; IDs are never trusted alone.

## RBAC model

- Roles attach to **Membership**, not directly to User.
- Role → Permission mappings are stored in `RolePermission`.
- Permission checks are enforced via middleware and keyed permissions (e.g., `members.manage`).

## Audit design

- Audit logs are **append-only** and written asynchronously.
- The API enqueues audit events; a BullMQ worker persists them to Postgres.
- Read endpoints are permission‑gated (`audit.view`).

## Jobs system

- Jobs are persisted in Postgres with an idempotency key per `(orgId, type, idempotencyKey)`.
- The API enqueues jobs; workers handle execution and transition status.
- Job status changes are written by the worker only (RUNNING → SUCCEEDED/FAILED).

## DB invariants

- **Workspace memberships must belong to the same organization**: a composite foreign key enforces `Membership(workspaceId, organizationId)` → `Workspace(id, organizationId)` so tenant boundaries cannot be crossed by mismatched IDs.

## Key decisions

- **Async audit** to avoid request‑path latency and to keep audit append‑only.
- **Membership‑scoped roles** to support different roles per org/workspace.
- **DB‑backed idempotency** to prevent duplicate jobs in concurrent requests.
