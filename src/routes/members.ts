import express from "express";
import { z } from "zod";
import { prisma } from "../db/prisma.js";
import { requireAuth, type AuthedRequest } from "../middleware/auth.js";
import { requirePermission } from "../middleware/permissions.js";
import { enqueueAudit } from "../lib/audit.js";

export const membersRouter = express.Router();

const updateMembershipRolesSchema = z.object({
  roleIds: z.array(z.string().min(1)).min(1)
});

membersRouter.get(
  "/orgs/:orgId/members",
  requireAuth,
  requirePermission("members.manage", {
    scope: "ORG",
    idSource: { source: "params", key: "orgId" }
  }),
  async (req: AuthedRequest, res) => {
    const orgId = req.params.orgId;

    const memberships = await prisma.membership.findMany({
      where: { organizationId: orgId, scope: "ORG" },
      include: {
        user: { select: { id: true, email: true, name: true } },
        roles: { include: { role: true } }
      }
    });

    return res.json({
      data: {
        memberships: memberships.map((m) => ({
          id: m.id,
          user: m.user,
          status: m.status,
          roles: m.roles.map((r) => ({
            id: r.role.id,
            name: r.role.name,
            scope: r.role.scope
          }))
        }))
      }
    });
  }
);

async function loadOrgMembershipForRoleUpdate(
  req: AuthedRequest,
  res: express.Response,
  next: express.NextFunction
) {
  const membershipId = req.params.id;
  const membership = await prisma.membership.findUnique({
    where: { id: membershipId }
  });
  if (!membership) {
    return res.status(404).json({ error: "Membership not found" });
  }
  if (membership.scope !== "ORG") {
    return res.status(400).json({ error: "Only org memberships can be updated" });
  }
  req.membership = {
    id: membership.id,
    organizationId: membership.organizationId,
    scope: membership.scope
  };
  req.body = { ...(req.body ?? {}), orgId: membership.organizationId };
  return next();
}

membersRouter.patch(
  "/memberships/:id/roles",
  requireAuth,
  loadOrgMembershipForRoleUpdate,
  requirePermission("members.manage", {
    scope: "ORG",
    idSource: { source: "body", key: "orgId" }
  }),
  async (req: AuthedRequest, res) => {
    const parsed = updateMembershipRolesSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.flatten() });
    }

    const membershipId = req.params.id;
    const membership = req.membership!;

    const roles = await prisma.role.findMany({
      where: { id: { in: parsed.data.roleIds }, scope: "ORG", orgId: null }
    });

    if (roles.length !== parsed.data.roleIds.length) {
      return res.status(400).json({ error: "Invalid roles" });
    }

    await prisma.$transaction(async (tx) => {
      await tx.membershipRole.deleteMany({
        where: { membershipId }
      });
      await tx.membershipRole.createMany({
        data: roles.map((role) => ({
          membershipId,
          roleId: role.id
        }))
      });
    });

    void enqueueAudit({
      action: "membership.role_changed",
      actorType: "user",
      actorUserId: req.user!.id,
      orgId: membership.organizationId,
      entityType: "membership",
      entityId: membership.id,
      metadata: { roleIds: parsed.data.roleIds },
      ip: req.context?.ip ?? null,
      userAgent: req.context?.userAgent ?? null
    });

    return res.json({ data: { ok: true } });
  }
);
