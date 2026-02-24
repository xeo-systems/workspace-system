import express from "express";
import { z } from "zod";
import { prisma } from "../db/prisma.js";
import { requireAuth, type AuthedRequest } from "../middleware/auth.js";
import { enqueueAudit } from "../lib/audit.js";

export const orgsRouter = express.Router();

const createOrgSchema = z.object({
  name: z.string().min(1),
  slug: z.string().min(2).regex(/^[a-z0-9-]+$/)
});

orgsRouter.post("/orgs", requireAuth, async (req: AuthedRequest, res) => {
  const parsed = createOrgSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const { name, slug } = parsed.data;

  const existing = await prisma.organization.findUnique({ where: { slug } });
  if (existing) {
    return res.status(409).json({ error: "Org slug already in use" });
  }

  const result = await prisma.$transaction(async (tx) => {
    const ownerRole = await tx.role.findFirst({
      where: { orgId: null, scope: "ORG", name: "owner" }
    });

    if (!ownerRole) {
      throw new Error("OWNER_ROLE_MISSING");
    }

    const org = await tx.organization.create({
      data: { name, slug }
    });

    const membership = await tx.membership.create({
      data: {
        userId: req.user!.id,
        organizationId: org.id,
        scope: "ORG",
        status: "ACTIVE"
      }
    });

    await tx.membershipRole.create({
      data: { membershipId: membership.id, roleId: ownerRole.id }
    });

    return { org };
  }).catch((err) => {
    if (err instanceof Error && err.message === "OWNER_ROLE_MISSING") {
      return null;
    }
    throw err;
  });

  if (!result) {
    return res.status(500).json({ error: "Owner role not configured" });
  }

  void enqueueAudit({
    action: "org.created",
    actorType: "user",
    actorUserId: req.user!.id,
    orgId: result.org.id,
    entityType: "organization",
    entityId: result.org.id,
    metadata: { name: result.org.name, slug: result.org.slug },
    ip: req.context?.ip ?? null,
    userAgent: req.context?.userAgent ?? null
  });

  return res.status(201).json({ data: { org: result.org } });
});

orgsRouter.get("/orgs", requireAuth, async (req: AuthedRequest, res) => {
  const orgs = await prisma.organization.findMany({
    where: {
      memberships: {
        some: {
          userId: req.user!.id,
          scope: "ORG",
          status: "ACTIVE"
        }
      }
    },
    orderBy: { createdAt: "desc" }
  });

  return res.json({ data: { orgs } });
});
