import express from "express";
import { prisma } from "../db/prisma.js";
import { requireAuth, type AuthedRequest } from "../middleware/auth.js";
import { requirePermission } from "../middleware/permissions.js";

export const auditRouter = express.Router();

auditRouter.get(
  "/audit/org/:orgId",
  requireAuth,
  requirePermission("audit.view", {
    scope: "ORG",
    idSource: { source: "params", key: "orgId" }
  }),
  async (req: AuthedRequest, res) => {
    const limit = Math.min(Number(req.query.limit ?? 20), 100);
    const cursor = typeof req.query.cursor === "string" ? req.query.cursor : null;

    const rows = await prisma.auditLog.findMany({
      where: { orgId: req.params.orgId },
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: limit + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {})
    });

    const nextCursor = rows.length > limit ? rows[limit].id : null;
    const items = rows.slice(0, limit);

    return res.json({ data: { items, nextCursor } });
  }
);

auditRouter.get(
  "/audit/workspace/:workspaceId",
  requireAuth,
  requirePermission("audit.view", {
    scope: "WORKSPACE",
    idSource: { source: "params", key: "workspaceId" }
  }),
  async (req: AuthedRequest, res) => {
    const limit = Math.min(Number(req.query.limit ?? 20), 100);
    const cursor = typeof req.query.cursor === "string" ? req.query.cursor : null;

    const rows = await prisma.auditLog.findMany({
      where: { workspaceId: req.params.workspaceId },
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: limit + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {})
    });

    const nextCursor = rows.length > limit ? rows[limit].id : null;
    const items = rows.slice(0, limit);

    return res.json({ data: { items, nextCursor } });
  }
);
