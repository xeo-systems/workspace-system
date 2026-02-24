import { auditQueue } from "../queues/index.js";

export type AuditEvent = {
  orgId: string | null;
  workspaceId?: string | null;
  actorUserId?: string | null;
  actorType: "user" | "system";
  action: string;
  entityType?: string | null;
  entityId?: string | null;
  metadata?: Record<string, unknown> | null;
  ip?: string | null;
  userAgent?: string | null;
};

export async function enqueueAudit(event: AuditEvent) {
  if (!event.orgId) {
    return;
  }
  try {
    await auditQueue.add("audit", {
      ...event,
      workspaceId: event.workspaceId ?? null,
      actorUserId: event.actorUserId ?? null,
      entityType: event.entityType ?? null,
      entityId: event.entityId ?? null,
      metadata: event.metadata ?? null,
      ip: event.ip ?? null,
      userAgent: event.userAgent ?? null
    });
  } catch (err) {
    console.warn("[audit] enqueue failed", err);
  }
}
