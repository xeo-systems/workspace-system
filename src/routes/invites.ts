import crypto from "crypto";
import express from "express";
import { z } from "zod";
import { prisma } from "../db/prisma.js";
import { requireAuth, type AuthedRequest } from "../middleware/auth.js";
import { requirePermission } from "../middleware/permissions.js";
import { enqueueAudit } from "../lib/audit.js";

export const invitesRouter = express.Router();

const createInviteSchema = z.object({
  email: z.string().email(),
  roleName: z.string().min(1).optional()
});

const acceptInviteSchema = z.object({
  token: z.string().min(20)
});

function hashToken(token: string) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

invitesRouter.post(
  "/orgs/:orgId/invites",
  requireAuth,
  requirePermission("members.invite", {
    scope: "ORG",
    idSource: { source: "params", key: "orgId" }
  }),
  async (req: AuthedRequest, res) => {
    const parsed = createInviteSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.flatten() });
    }

    const { email, roleName } = parsed.data;
    const orgId = req.params.orgId;

    const role = await prisma.role.findFirst({
      where: { orgId: null, scope: "ORG", name: roleName ?? "member" }
    });

    if (!role) {
      return res.status(400).json({ error: "Invalid role" });
    }

    const existing = await prisma.invitation.findFirst({
      where: { orgId, email, status: "PENDING" }
    });
    if (existing) {
      return res.status(409).json({ error: "Invite already pending" });
    }

    const token = crypto.randomBytes(32).toString("hex");
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    const invite = await prisma.invitation.create({
      data: {
        orgId,
        email,
        tokenHash,
        roleName: role.name,
        roleScope: "ORG",
        expiresAt,
        status: "PENDING",
        createdByUserId: req.user!.id
      }
    });

    void enqueueAudit({
      action: "invite.created",
      actorType: "user",
      actorUserId: req.user!.id,
      orgId,
      entityType: "invitation",
      entityId: invite.id,
      metadata: { email, roleName: role.name },
      ip: req.context?.ip ?? null,
      userAgent: req.context?.userAgent ?? null
    });

    return res.status(201).json({
      data: {
        invite: {
          id: invite.id,
          orgId: invite.orgId,
          email: invite.email,
          roleName: invite.roleName,
          expiresAt: invite.expiresAt,
          status: invite.status
        },
        token
      }
    });
  }
);

invitesRouter.post("/invites/accept", async (req, res) => {
  const parsed = acceptInviteSchema.safeParse(req.body ?? {});
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const tokenHash = hashToken(parsed.data.token);

  try {
    const result = await prisma.$transaction(async (tx) => {
      const invite = await tx.invitation.findFirst({
        where: { tokenHash }
      });

      if (!invite) {
        throw new Error("INVITE_NOT_FOUND");
      }

      if (invite.status !== "PENDING") {
        throw new Error("INVITE_ALREADY_HANDLED");
      }

      if (invite.expiresAt < new Date()) {
        await tx.invitation.update({
          where: { id: invite.id },
          data: { status: "EXPIRED" }
        });
        throw new Error("INVITE_EXPIRED");
      }

      const user = await tx.user.findUnique({
        where: { email: invite.email }
      });

      if (!user) {
        throw new Error("INVITE_USER_NOT_FOUND");
      }

      const role = await tx.role.findFirst({
        where: { orgId: null, scope: "ORG", name: invite.roleName }
      });

      if (!role) {
        throw new Error("INVITE_ROLE_NOT_FOUND");
      }

      const claim = await tx.invitation.updateMany({
        where: { id: invite.id, status: "PENDING" },
        data: { status: "ACCEPTED" }
      });

      if (claim.count === 0) {
        throw new Error("INVITE_ALREADY_HANDLED");
      }

      let membership = await tx.membership.findFirst({
        where: {
          userId: user.id,
          organizationId: invite.orgId,
          scope: "ORG"
        }
      });

      if (!membership) {
        membership = await tx.membership.create({
          data: {
            userId: user.id,
            organizationId: invite.orgId,
            scope: "ORG",
            status: "ACTIVE"
          }
        });
      } else if (membership.status !== "ACTIVE") {
        membership = await tx.membership.update({
          where: { id: membership.id },
          data: { status: "ACTIVE" }
        });
      }

      await tx.membershipRole.upsert({
        where: {
          membershipId_roleId: { membershipId: membership.id, roleId: role.id }
        },
        update: {},
        create: { membershipId: membership.id, roleId: role.id }
      });

      return {
        invite,
        user,
        membership
      };
    });

    void enqueueAudit({
      action: "invite.accepted",
      actorType: "user",
      actorUserId: result.user.id,
      orgId: result.invite.orgId,
      entityType: "invitation",
      entityId: result.invite.id,
      metadata: { email: result.invite.email, roleName: result.invite.roleName },
      ip: req.ip ?? null,
      userAgent: req.header("user-agent") ?? null
    });

    return res.json({ data: { membershipId: result.membership.id } });
  } catch (err) {
    if (err instanceof Error) {
      if (err.message === "INVITE_NOT_FOUND") {
        return res.status(404).json({ error: "Invite not found" });
      }
      if (err.message === "INVITE_EXPIRED") {
        return res.status(400).json({ error: "Invite expired" });
      }
      if (err.message === "INVITE_USER_NOT_FOUND") {
        return res.status(400).json({ error: "User not found for invite email" });
      }
      if (err.message === "INVITE_ROLE_NOT_FOUND") {
        return res.status(400).json({ error: "Role not found" });
      }
      if (err.message === "INVITE_ALREADY_HANDLED") {
        return res.status(409).json({ error: "Invite already handled" });
      }
    }
    return res.status(500).json({ error: "Failed to accept invite" });
  }
});
