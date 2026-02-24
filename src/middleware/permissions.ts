import type express from "express";
import { prisma } from "../db/prisma.js";
import type { AuthedRequest } from "./auth.js";

type PermissionScope = "ORG" | "WORKSPACE";
type IdSource =
  | { source: "body"; key: string }
  | { source: "params"; key: string }
  | { source: "query"; key: string };

function getIdFromRequest(req: express.Request, idSource: IdSource): string | null {
  if (idSource.source === "body") {
    const value = (req.body as Record<string, unknown> | undefined)?.[idSource.key];
    return typeof value === "string" ? value : null;
  }
  if (idSource.source === "params") {
    const value = req.params[idSource.key];
    return typeof value === "string" ? value : null;
  }
  const value = req.query[idSource.key];
  return typeof value === "string" ? value : null;
}

export function requirePermission(
  permissionKey: string,
  options: { scope: PermissionScope; idSource: IdSource }
) {
  return async (req: AuthedRequest, res: express.Response, next: express.NextFunction) => {
    const targetId = getIdFromRequest(req, options.idSource);
    if (!targetId) {
      return res.status(400).json({ error: `${options.idSource.key} is required` });
    }

    const membershipWhere =
      options.scope === "ORG"
        ? { organizationId: targetId, scope: "ORG" as const }
        : { workspaceId: targetId, scope: "WORKSPACE" as const };

    const membershipRole = await prisma.membershipRole.findFirst({
      where: {
        membership: {
          userId: req.user!.id,
          status: "ACTIVE",
          ...membershipWhere
        },
        role: {
          scope: options.scope,
          permissions: {
            some: {
              permission: { key: permissionKey }
            }
          }
        }
      }
    });

    if (!membershipRole) {
      return res.status(403).json({ error: "Forbidden" });
    }

    return next();
  };
}

export function requireJobPermission(permissionKey: string) {
  return async (req: AuthedRequest, res: express.Response, next: express.NextFunction) => {
    const jobId = req.params.jobId;
    if (!jobId) {
      return res.status(400).json({ error: "jobId is required" });
    }

    const job = await prisma.job.findUnique({
      where: { id: jobId }
    });

    if (!job) {
      return res.status(404).json({ error: "Job not found" });
    }

    const membershipRole = await prisma.membershipRole.findFirst({
      where: {
        membership: {
          userId: req.user!.id,
          status: "ACTIVE",
          organizationId: job.orgId,
          scope: "ORG"
        },
        role: {
          scope: "ORG",
          permissions: {
            some: {
              permission: { key: permissionKey }
            }
          }
        }
      }
    });

    if (!membershipRole) {
      return res.status(403).json({ error: "Forbidden" });
    }

    req.job = {
      id: job.id,
      orgId: job.orgId,
      workspaceId: job.workspaceId,
      type: job.type,
      status: job.status
    };

    return next();
  };
}
