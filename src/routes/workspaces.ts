import express from "express";
import { z } from "zod";
import { prisma } from "../db/prisma.js";
import { requireAuth, type AuthedRequest } from "../middleware/auth.js";
import { requirePermission } from "../middleware/permissions.js";
import { enqueueAudit } from "../lib/audit.js";

export const workspacesRouter = express.Router();

const createWorkspaceSchema = z.object({
  orgId: z.string().min(1),
  name: z.string().min(1),
  slug: z.string().min(2).regex(/^[a-z0-9-]+$/)
});

const updateWorkspaceSchema = z
  .object({
    name: z.string().min(1).optional(),
    slug: z.string().min(2).regex(/^[a-z0-9-]+$/).optional()
  })
  .refine((data) => data.name || data.slug, {
    message: "At least one field is required"
  });

workspacesRouter.post("/workspaces", requireAuth, async (req: AuthedRequest, res) => {
  const parsed = createWorkspaceSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const { orgId, name, slug } = parsed.data;

  const orgMembership = await prisma.membership.findFirst({
    where: {
      userId: req.user!.id,
      organizationId: orgId,
      scope: "ORG",
      status: "ACTIVE"
    }
  });

  if (!orgMembership) {
    return res.status(403).json({ error: "Not a member of this organization" });
  }

  const existing = await prisma.workspace.findFirst({
    where: { organizationId: orgId, slug }
  });
  if (existing) {
    return res.status(409).json({ error: "Workspace slug already in use" });
  }

  const result = await prisma.$transaction(async (tx) => {
    const adminRole = await tx.role.findFirst({
      where: { orgId: null, scope: "WORKSPACE", name: "admin" }
    });

    if (!adminRole) {
      throw new Error("WORKSPACE_ADMIN_ROLE_MISSING");
    }

    const workspace = await tx.workspace.create({
      data: { organizationId: orgId, name, slug }
    });

    const membership = await tx.membership.create({
      data: {
        userId: req.user!.id,
        organizationId: orgId,
        workspaceId: workspace.id,
        scope: "WORKSPACE",
        status: "ACTIVE"
      }
    });

    await tx.membershipRole.create({
      data: { membershipId: membership.id, roleId: adminRole.id }
    });

    return { workspace };
  }).catch((err) => {
    if (err instanceof Error && err.message === "WORKSPACE_ADMIN_ROLE_MISSING") {
      return null;
    }
    throw err;
  });

  if (!result) {
    return res.status(500).json({ error: "Workspace admin role not configured" });
  }

  void enqueueAudit({
    action: "workspace.created",
    actorType: "user",
    actorUserId: req.user!.id,
    orgId: orgId,
    workspaceId: result.workspace.id,
    entityType: "workspace",
    entityId: result.workspace.id,
    metadata: { name: result.workspace.name, slug: result.workspace.slug },
    ip: req.context?.ip ?? null,
    userAgent: req.context?.userAgent ?? null
  });

  return res.status(201).json({ data: { workspace: result.workspace } });
});

workspacesRouter.get("/workspaces", requireAuth, async (req: AuthedRequest, res) => {
  const orgId = typeof req.query.orgId === "string" ? req.query.orgId : null;
  if (!orgId) {
    return res.status(400).json({ error: "orgId is required" });
  }

  const orgMembership = await prisma.membership.findFirst({
    where: {
      userId: req.user!.id,
      organizationId: orgId,
      scope: "ORG",
      status: "ACTIVE"
    }
  });

  if (orgMembership) {
    const workspaces = await prisma.workspace.findMany({
      where: { organizationId: orgId },
      orderBy: { createdAt: "desc" }
    });
    return res.json({ data: { workspaces } });
  }

  const workspaces = await prisma.workspace.findMany({
    where: {
      organizationId: orgId,
      memberships: {
        some: {
          userId: req.user!.id,
          scope: "WORKSPACE",
          status: "ACTIVE"
        }
      }
    },
    orderBy: { createdAt: "desc" }
  });

  return res.json({ data: { workspaces } });
});

workspacesRouter.patch(
  "/workspaces/:workspaceId",
  requireAuth,
  requirePermission("workspace.write", {
    scope: "WORKSPACE",
    idSource: { source: "params", key: "workspaceId" }
  }),
  async (req: AuthedRequest, res) => {
    const parsed = updateWorkspaceSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.flatten() });
    }

    const workspaceId = req.params.workspaceId;
    const workspace = await prisma.workspace.findUnique({
      where: { id: workspaceId }
    });

    if (!workspace) {
      return res.status(404).json({ error: "Workspace not found" });
    }

    if (parsed.data.slug && parsed.data.slug !== workspace.slug) {
      const exists = await prisma.workspace.findFirst({
        where: {
          organizationId: workspace.organizationId,
          slug: parsed.data.slug
        }
      });
      if (exists) {
        return res.status(409).json({ error: "Workspace slug already in use" });
      }
    }

    const updated = await prisma.workspace.update({
      where: { id: workspaceId },
      data: {
        name: parsed.data.name ?? undefined,
        slug: parsed.data.slug ?? undefined
      }
    });

    void enqueueAudit({
      action: "workspace.updated",
      actorType: "user",
      actorUserId: req.user!.id,
      orgId: updated.organizationId,
      workspaceId: updated.id,
      entityType: "workspace",
      entityId: updated.id,
      metadata: {
        name: updated.name,
        slug: updated.slug
      },
      ip: req.context?.ip ?? null,
      userAgent: req.context?.userAgent ?? null
    });

    return res.json({ data: { workspace: updated } });
  }
);
