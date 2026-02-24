import express from "express";
import { z } from "zod";
import { Prisma } from "@prisma/client";
import { prisma } from "../db/prisma.js";
import { requireAuth, type AuthedRequest } from "../middleware/auth.js";
import { requireJobPermission, requirePermission } from "../middleware/permissions.js";
import { jobQueue } from "../queues/index.js";
import { enqueueAudit } from "../lib/audit.js";

export const jobsRouter = express.Router();

const enqueueJobSchema = z.object({
  orgId: z.string().min(1),
  workspaceId: z.string().min(1).optional(),
  type: z.string().min(1),
  payload: z.unknown().optional(),
  idempotencyKey: z.string().min(1),
  maxAttempts: z.number().int().min(1).max(10).optional()
});

jobsRouter.post(
  "/jobs/enqueue",
  requireAuth,
  requirePermission("jobs.run", {
    scope: "ORG",
    idSource: { source: "body", key: "orgId" }
  }),
  async (req: AuthedRequest, res) => {
    const parsed = enqueueJobSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.flatten() });
    }

    const { orgId, workspaceId, type, payload, idempotencyKey, maxAttempts } =
      parsed.data;

    if (workspaceId) {
      const workspace = await prisma.workspace.findUnique({
        where: { id: workspaceId }
      });
      if (!workspace) {
        return res.status(400).json({ error: "Workspace not found" });
      }
      if (workspace.organizationId !== orgId) {
        return res.status(400).json({ error: "Workspace does not belong to org" });
      }
    }

    let job;
    try {
      job = await prisma.job.create({
        data: {
          orgId,
          workspaceId: workspaceId ?? null,
          type,
          payload: (payload ?? undefined) as any,
          idempotencyKey,
          status: "QUEUED",
          attempts: 0,
          maxAttempts: maxAttempts ?? 1
        }
      });
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
        const existing = await prisma.job.findUnique({
          where: { orgId_type_idempotencyKey: { orgId, type, idempotencyKey } }
        });
        if (existing) {
          return res.json({ data: { job: existing } });
        }
      }
      throw err;
    }

    await jobQueue.add(type, { payload }, { jobId: job.id, attempts: job.maxAttempts });

    void enqueueAudit({
      action: "job.enqueued",
      actorType: "user",
      actorUserId: req.user!.id,
      orgId: job.orgId,
      workspaceId: job.workspaceId ?? null,
      entityType: "job",
      entityId: job.id,
      metadata: { type: job.type, status: job.status },
      ip: req.context?.ip ?? null,
      userAgent: req.context?.userAgent ?? null
    });

    return res.status(201).json({ data: { job } });
  }
);

jobsRouter.get(
  "/jobs",
  requireAuth,
  requirePermission("jobs.run", {
    scope: "ORG",
    idSource: { source: "query", key: "orgId" }
  }),
  async (req: AuthedRequest, res) => {
    const orgId = typeof req.query.orgId === "string" ? req.query.orgId : null;
    if (!orgId) {
      return res.status(400).json({ error: "orgId is required" });
    }

    const limit = Math.min(Number(req.query.limit ?? 20), 100);
    const cursor = typeof req.query.cursor === "string" ? req.query.cursor : null;

    const rows = await prisma.job.findMany({
      where: { orgId },
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: limit + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {})
    });

    const nextCursor = rows.length > limit ? rows[limit].id : null;
    const items = rows.slice(0, limit);

    return res.json({ data: { items, nextCursor } });
  }
);

jobsRouter.get(
  "/jobs/:jobId",
  requireAuth,
  requireJobPermission("jobs.run"),
  async (req: AuthedRequest, res) => {
    const job = await prisma.job.findUnique({
      where: { id: req.params.jobId }
    });

    if (!job) {
      return res.status(404).json({ error: "Job not found" });
    }

    return res.json({ data: { job } });
  }
);
