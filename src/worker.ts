import "dotenv/config";
import { Worker } from "bullmq";
import { Prisma } from "@prisma/client";
import { prisma } from "./db/prisma.js";
import { redisConfig } from "./config/redis.js";
import { auditQueue } from "./queues/index.js";
import { getEnv } from "./config/auth.js";

getEnv();

const worker = new Worker(
  "jobs",
  async (job) => {
    const jobId = String(job.id);

    const dbJob = await prisma.job.findUnique({
      where: { id: jobId }
    });

    if (!dbJob) {
      return { ok: false };
    }

    await prisma.job.update({
      where: { id: jobId },
      data: {
        status: "RUNNING",
        startedAt: new Date(),
        attempts: { increment: 1 }
      }
    });

    const handlers: Record<string, (payload: unknown) => Promise<unknown>> = {
      noop: async () => ({ ok: true }),
      echo: async (payload) => ({ payload })
    };

    const handler = handlers[job.name];
    if (!handler) {
      throw new Error(`Unknown job type: ${job.name}`);
    }

    const result = await handler(job.data?.payload);

    await prisma.job.update({
      where: { id: jobId },
      data: {
        status: "SUCCEEDED",
        result: result as Prisma.InputJsonValue,
        finishedAt: new Date()
      }
    });

    void auditQueue
      .add("audit", {
      action: "job.completed",
      actorType: "system",
      actorUserId: null,
      orgId: dbJob.orgId,
      workspaceId: dbJob.workspaceId,
      entityType: "job",
      entityId: dbJob.id,
      metadata: { type: dbJob.type, status: "SUCCEEDED" },
      ip: null,
      userAgent: null
      })
      .catch(() => {});

    return { ok: true };
  },
  { connection: { url: redisConfig.url } }
);

const auditWorker = new Worker(
  "audit",
  async (job) => {
    const data = job.data as {
      orgId: string;
      workspaceId: string | null;
      actorUserId: string | null;
      actorType: "user" | "system";
      action: string;
      entityType: string | null;
      entityId: string | null;
      metadata: Record<string, unknown> | null;
      ip: string | null;
      userAgent: string | null;
    };

    await prisma.auditLog.create({
      data: {
        orgId: data.orgId,
        workspaceId: data.workspaceId ?? null,
        actorUserId: data.actorUserId ?? null,
        actorType: data.actorType,
        action: data.action,
        entityType: data.entityType ?? null,
        entityId: data.entityId ?? null,
        metadata: (data.metadata ?? undefined) as Prisma.InputJsonValue | undefined,
        ip: data.ip ?? null,
        userAgent: data.userAgent ?? null
      } as any
    });

    return { ok: true };
  },
  { connection: { url: redisConfig.url } }
);

worker.on("completed", (job) => {
  console.log(`Job completed: ${job.id}`);
});

worker.on("failed", async (job, err) => {
  console.error(`Job failed: ${job?.id}`, err);
  if (!job?.id) return;
  const jobId = String(job.id);
  const dbJob = await prisma.job.findUnique({ where: { id: jobId } });
  if (!dbJob) return;

  await prisma.job.update({
    where: { id: jobId },
    data: {
      status: "FAILED",
      error: err?.message ?? "Job failed",
      finishedAt: new Date()
    }
  });

  void auditQueue
    .add("audit", {
    action: "job.failed",
    actorType: "system",
    actorUserId: null,
    orgId: dbJob.orgId,
    workspaceId: dbJob.workspaceId,
    entityType: "job",
    entityId: dbJob.id,
    metadata: { type: dbJob.type, status: "FAILED" },
    ip: null,
    userAgent: null
    })
    .catch(() => {});
});

auditWorker.on("completed", (job) => {
  console.log(`Audit completed: ${job.id}`);
});

auditWorker.on("failed", (job, err) => {
  console.error(`Audit failed: ${job?.id}`, err);
});

let shuttingDown = false;
async function shutdown(signal: string) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`Received ${signal}, shutting down...`);
  try {
    await Promise.all([worker.close(), auditWorker.close(), auditQueue.close()]);
  } finally {
    await prisma.$disconnect();
    process.exit(0);
  }
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
