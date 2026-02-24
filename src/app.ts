import express from "express";
import { prisma } from "./db/prisma.js";
import { jobQueue } from "./queues/index.js";
import { authRouter } from "./routes/auth.js";
import { orgsRouter } from "./routes/orgs.js";
import { workspacesRouter } from "./routes/workspaces.js";
import { membersRouter } from "./routes/members.js";
import { invitesRouter } from "./routes/invites.js";
import { auditRouter } from "./routes/audit.js";
import { jobsRouter } from "./routes/jobs.js";
import type { AuthedRequest } from "./middleware/auth.js";
import { getRequestId, logger } from "./lib/logger.js";

export const app = express();

app.use(express.json());
app.use((req, res, next) => {
  const requestId = getRequestId(req);
  (req as { requestId?: string }).requestId = requestId;
  res.setHeader("x-request-id", requestId);
  next();
});
app.use((req, res, next) => {
  const start = process.hrtime.bigint();
  res.on("finish", () => {
    const status = res.statusCode;
    const durationMs = Number(process.hrtime.bigint() - start) / 1_000_000;
    const authedReq = req as AuthedRequest & { requestId?: string };
    const requestId = authedReq.requestId ?? "unknown";
    const userId = authedReq.user?.id;
    const orgId =
      authedReq.job?.orgId ??
      (typeof req.params.orgId === "string"
        ? req.params.orgId
        : typeof (req.body as Record<string, unknown> | undefined)?.orgId === "string"
        ? ((req.body as Record<string, unknown>).orgId as string)
        : typeof req.query.orgId === "string"
        ? (req.query.orgId as string)
        : undefined);
    const workspaceId =
      authedReq.job?.workspaceId ??
      (typeof req.params.workspaceId === "string"
        ? req.params.workspaceId
        : typeof (req.body as Record<string, unknown> | undefined)?.workspaceId === "string"
        ? ((req.body as Record<string, unknown>).workspaceId as string)
        : typeof req.query.workspaceId === "string"
        ? (req.query.workspaceId as string)
        : undefined);

    logger.info(
      {
        requestId,
        method: req.method,
        path: req.originalUrl,
        status,
        latencyMs: Number(durationMs.toFixed(2)),
        userId,
        orgId,
        workspaceId
      },
      "request"
    );
  });
  next();
});
app.use((req, _res, next) => {
  (req as { context?: { ip?: string | null; userAgent?: string | null } }).context = {
    ip: req.ip ?? null,
    userAgent: req.header("user-agent") ?? null
  };
  next();
});

app.get("/health", async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    await jobQueue.getJobCounts();
    res.json({ status: "ok" });
  } catch (err) {
    res.status(500).json({ status: "error" });
  }
});

app.use(authRouter);
app.use(orgsRouter);
app.use(workspacesRouter);
app.use(membersRouter);
app.use(invitesRouter);
app.use(auditRouter);
app.use(jobsRouter);

app.use(
  (
    err: Error,
    req: express.Request & { requestId?: string },
    res: express.Response,
    next: express.NextFunction
  ) => {
    logger.error(
      {
        requestId: req.requestId ?? "unknown",
        path: req.originalUrl,
        status: res.statusCode || 500,
        stack: err?.stack
      },
      "request error"
    );
    next(err);
  }
);
