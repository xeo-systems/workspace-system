import "dotenv/config";
import { Worker } from "bullmq";
import { Prisma } from "@prisma/client";
import { prisma } from "./db/prisma.js";
import { redisConfig } from "./config/redis.js";
import { auditQueue } from "./queues/index.js";
import { getEnv } from "./config/auth.js";
import { logger } from "./lib/logger.js";

getEnv();

const worker = new Worker(
  "jobs",
  async (job) => {
    const jobId = String(job.id);

    const dbJob = await prisma.job.findUnique({
      where: { id: jobId }
    });

    if (!dbJob) {
      logger.warn(
        {
          queue: "jobs",
          jobId,
          jobType: job.name
        },
        "job missing"
      );
      return { ok: false };
    }

    logger.info(
      {
        queue: "jobs",
        jobId,
        jobType: dbJob.type,
        orgId: dbJob.orgId,
        workspaceId: dbJob.workspaceId,
        status: "RUNNING"
      },
      "job started"
    );

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

    logger.info(
      {
        queue: "jobs",
        jobId,
        jobType: dbJob.type,
        orgId: dbJob.orgId,
        workspaceId: dbJob.workspaceId,
        status: "SUCCEEDED"
      },
      "job completed"
    );

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
      }
    });

    logger.info(
      {
        queue: "audit",
        jobId: String(job.id),
        orgId: data.orgId,
        workspaceId: data.workspaceId,
        status: "SUCCEEDED"
      },
      "audit persisted"
    );

    return { ok: true };
  },
  { connection: { url: redisConfig.url } }
);

worker.on("completed", (job) => {
  logger.info(
    {
      queue: "jobs",
      jobId: String(job.id),
      status: "SUCCEEDED"
    },
    "job completed event"
  );
});

worker.on("failed", async (job, err) => {
  logger.error(
    {
      queue: "jobs",
      jobId: String(job?.id),
      status: "FAILED",
      stack: err?.stack
    },
    "job failed"
  );
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
  logger.info(
    {
      queue: "audit",
      jobId: String(job.id),
      status: "SUCCEEDED"
    },
    "audit completed event"
  );
});

auditWorker.on("failed", (job, err) => {
  logger.error(
    {
      queue: "audit",
      jobId: String(job?.id),
      status: "FAILED",
      stack: err?.stack
    },
    "audit failed"
  );
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
