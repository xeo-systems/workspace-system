import crypto from "crypto";
import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { prisma } from "./db/prisma.js";
import { auditQueue, jobQueue } from "./queues/index.js";
import { authConfig } from "./config/auth.js";
import { RateLimiterRedis } from "rate-limiter-flexible";
import { Redis } from "ioredis";

export const app = express();

app.use(express.json());
app.use((req, res, next) => {
  res.on("finish", () => {
    const status = res.statusCode;
    if (status >= 500 || status === 401 || status === 403) {
      const userId = (req as AuthedRequest).user?.id ?? "anonymous";
      const ip = req.ip ?? "";
      console.error(
        `[req] ${status} ${req.method} ${req.originalUrl} user=${userId} ip=${ip}`
      );
    }
  });
  next();
});
app.use((req, _res, next) => {
  (req as AuthedRequest).context = {
    ip: req.ip ?? null,
    userAgent: req.header("user-agent") ?? null
  };
  next();
});

type AuthedRequest = express.Request & {
  user?: { id: string; email: string; name: string | null };
  context?: { ip?: string | null; userAgent?: string | null };
  job?: {
    id: string;
    orgId: string;
    workspaceId: string | null;
    type: string;
    status: string;
  };
};

const signupSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  name: z.string().min(1).optional()
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8)
});

const refreshSchema = z.object({
  refreshToken: z.string().min(20)
});

const logoutSchema = z.object({
  refreshToken: z.string().min(20)
});

const createOrgSchema = z.object({
  name: z.string().min(1),
  slug: z.string().min(2).regex(/^[a-z0-9-]+$/)
});

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

const enqueueJobSchema = z.object({
  orgId: z.string().min(1),
  workspaceId: z.string().min(1).optional(),
  type: z.string().min(1),
  payload: z.unknown().optional(),
  idempotencyKey: z.string().min(1),
  maxAttempts: z.number().int().min(1).max(10).optional()
});

const createInviteSchema = z.object({
  email: z.string().email(),
  roleName: z.string().min(1).optional()
});

const acceptInviteSchema = z.object({
  token: z.string().min(20)
});

const updateMembershipRolesSchema = z.object({
  roleIds: z.array(z.string().min(1)).min(1)
});

function hashRefreshToken(token: string) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function createAccessToken(user: { id: string; email: string }) {
  return jwt.sign(
    { sub: user.id, email: user.email },
    authConfig.jwtSecret,
    { expiresIn: authConfig.accessTokenTtl }
  );
}

function createRefreshToken() {
  return crypto.randomBytes(48).toString("hex");
}

function hashToken(token: string) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function refreshExpiryDate() {
  const ms = authConfig.refreshTokenTtlDays * 24 * 60 * 60 * 1000;
  return new Date(Date.now() + ms);
}

async function requireAuth(
  req: AuthedRequest,
  res: express.Response,
  next: express.NextFunction
) {
  const header = req.header("authorization");
  const token = header?.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const payload = jwt.verify(token, authConfig.jwtSecret) as {
      sub: string;
      email: string;
    };
    const user = await prisma.user.findUnique({
      where: { id: payload.sub },
      select: { id: true, email: true, name: true }
    });
    if (!user) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    req.user = user;
    return next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

const rateLimiter = (() => {
  const redisUrl = process.env.REDIS_URL;
  if (!redisUrl) return null;
  const client = new Redis(redisUrl, { enableOfflineQueue: false });
  return new RateLimiterRedis({
    storeClient: client,
    keyPrefix: "rl",
    points: 5,
    duration: 60
  });
})();

async function rateLimit(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (!rateLimiter) return next();
  try {
    const key = req.ip ?? "unknown";
    await rateLimiter.consume(key);
    return next();
  } catch {
    return res.status(429).json({ error: "Too many requests" });
  }
}

type AuditEvent = {
  orgId: string | null;
  workspaceId?: string | null;
  actorUserId?: string | null;
  actorType: "user" | "system";
  action: string;
  entityType?: string | null;
  entityId?: string | null;
  metadata?: Record<string, unknown> | null;
  ip?: string | null;
  userAgent?: string | null;
};

async function enqueueAudit(event: AuditEvent) {
  if (!event.orgId) {
    return;
  }
  try {
    await auditQueue.add("audit", {
      ...event,
      workspaceId: event.workspaceId ?? null,
      actorUserId: event.actorUserId ?? null,
      entityType: event.entityType ?? null,
      entityId: event.entityId ?? null,
      metadata: event.metadata ?? null,
      ip: event.ip ?? null,
      userAgent: event.userAgent ?? null
    });
  } catch {
    // best-effort
  }
}

async function resolveOrgForUser(userId: string) {
  const membership = await prisma.membership.findFirst({
    where: { userId, scope: "ORG", status: "ACTIVE" },
    orderBy: { createdAt: "asc" }
  });
  return membership?.organizationId ?? null;
}

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

function requirePermission(
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

function requireJobPermission(permissionKey: string) {
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

async function hasOrgRole(
  userId: string,
  orgId: string,
  roleNames: string[]
): Promise<boolean> {
  const role = await prisma.membershipRole.findFirst({
    where: {
      membership: {
        userId,
        organizationId: orgId,
        scope: "ORG",
        status: "ACTIVE"
      },
      role: {
        scope: "ORG",
        name: { in: roleNames },
        orgId: null
      }
    }
  });
  return Boolean(role);
}

app.get("/health", async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    await jobQueue.getJobCounts();
    res.json({ status: "ok" });
  } catch (err) {
    res.status(500).json({ status: "error" });
  }
});

app.post("/auth/signup", rateLimit, async (req, res) => {
  const parsed = signupSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const { email, password, name } = parsed.data;
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    return res.status(409).json({ error: "Email already in use" });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const user = await prisma.user.create({
    data: { email, name: name ?? null, passwordHash },
    select: { id: true, email: true, name: true }
  });

  const refreshToken = createRefreshToken();
  await prisma.session.create({
    data: {
      userId: user.id,
      refreshTokenHash: hashRefreshToken(refreshToken),
      expiresAt: refreshExpiryDate()
    }
  });

  const accessToken = createAccessToken(user);

  return res.status(201).json({
    data: { user, accessToken, refreshToken }
  });
});

app.post("/auth/login", rateLimit, async (req: AuthedRequest, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const { email, password } = parsed.data;
  const user = await prisma.user.findUnique({
    where: { email },
    select: { id: true, email: true, name: true, passwordHash: true }
  });
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const refreshToken = createRefreshToken();
  await prisma.session.create({
    data: {
      userId: user.id,
      refreshTokenHash: hashRefreshToken(refreshToken),
      expiresAt: refreshExpiryDate()
    }
  });

  const accessToken = createAccessToken(user);

  void enqueueAudit({
    action: "login",
    actorType: "user",
    actorUserId: user.id,
    orgId: await resolveOrgForUser(user.id),
    ip: req.context?.ip ?? null,
    userAgent: req.context?.userAgent ?? null
  });

  return res.json({
    data: {
      user: { id: user.id, email: user.email, name: user.name },
      accessToken,
      refreshToken
    }
  });
});

app.post("/auth/refresh", async (req, res) => {
  const parsed = refreshSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const hash = hashRefreshToken(parsed.data.refreshToken);
  const session = await prisma.session.findFirst({
    where: {
      refreshTokenHash: hash,
      revokedAt: null,
      expiresAt: { gt: new Date() }
    },
    include: { user: { select: { id: true, email: true, name: true } } }
  });

  if (!session) {
    return res.status(401).json({ error: "Invalid refresh token" });
  }

  const newRefreshToken = createRefreshToken();
  const updatedSession = await prisma.session.update({
    where: { id: session.id },
    data: {
      refreshTokenHash: hashRefreshToken(newRefreshToken),
      expiresAt: refreshExpiryDate()
    },
    include: { user: { select: { id: true, email: true, name: true } } }
  });

  const accessToken = createAccessToken(updatedSession.user);

  return res.json({
    data: {
      user: updatedSession.user,
      accessToken,
      refreshToken: newRefreshToken
    }
  });
});

app.post("/auth/logout", async (req, res) => {
  const parsed = logoutSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const hash = hashRefreshToken(parsed.data.refreshToken);
  await prisma.session.updateMany({
    where: { refreshTokenHash: hash, revokedAt: null },
    data: { revokedAt: new Date() }
  });

  return res.json({ data: { ok: true } });
});

app.get("/me", requireAuth, async (req: AuthedRequest, res) => {
  return res.json({ data: { user: req.user } });
});

app.post("/orgs", requireAuth, async (req: AuthedRequest, res) => {
  const parsed = createOrgSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const { name, slug } = parsed.data;

  const existing = await prisma.organization.findUnique({ where: { slug } });
  if (existing) {
    return res.status(409).json({ error: "Org slug already in use" });
  }

  const ownerRole = await prisma.role.findFirst({
    where: { orgId: null, scope: "ORG", name: "owner" }
  });

  if (!ownerRole) {
    return res.status(500).json({ error: "Owner role not configured" });
  }

  const org = await prisma.organization.create({
    data: { name, slug }
  });

  const membership = await prisma.membership.create({
    data: {
      userId: req.user!.id,
      organizationId: org.id,
      scope: "ORG",
      status: "ACTIVE"
    }
  });

  await prisma.membershipRole.create({
    data: { membershipId: membership.id, roleId: ownerRole.id }
  });

  void enqueueAudit({
    action: "org.created",
    actorType: "user",
    actorUserId: req.user!.id,
    orgId: org.id,
    entityType: "organization",
    entityId: org.id,
    metadata: { name: org.name, slug: org.slug },
    ip: req.context?.ip ?? null,
    userAgent: req.context?.userAgent ?? null
  });

  return res.status(201).json({ data: { org } });
});

app.get("/orgs", requireAuth, async (req: AuthedRequest, res) => {
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

app.post(
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

app.post("/invites/accept", async (req, res) => {
  const parsed = acceptInviteSchema.safeParse(req.body ?? {});
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const tokenHash = hashToken(parsed.data.token);

  const invite = await prisma.invitation.findFirst({
    where: { tokenHash, status: "PENDING" }
  });

  if (!invite) {
    return res.status(404).json({ error: "Invite not found" });
  }

  if (invite.expiresAt < new Date()) {
    await prisma.invitation.update({
      where: { id: invite.id },
      data: { status: "EXPIRED" }
    });
    return res.status(400).json({ error: "Invite expired" });
  }

  const user = await prisma.user.findUnique({
    where: { email: invite.email }
  });

  if (!user) {
    return res.status(400).json({ error: "User not found for invite email" });
  }

  let membership = await prisma.membership.findFirst({
    where: {
      userId: user.id,
      organizationId: invite.orgId,
      scope: "ORG"
    }
  });

  if (!membership) {
    membership = await prisma.membership.create({
      data: {
        userId: user.id,
        organizationId: invite.orgId,
        scope: "ORG",
        status: "ACTIVE"
      }
    });
  }

  const role = await prisma.role.findFirst({
    where: { orgId: null, scope: "ORG", name: invite.roleName }
  });

  if (!role) {
    return res.status(400).json({ error: "Role not found" });
  }

  await prisma.membershipRole.upsert({
    where: {
      membershipId_roleId: { membershipId: membership.id, roleId: role.id }
    },
    update: {},
    create: { membershipId: membership.id, roleId: role.id }
  });

  await prisma.invitation.update({
    where: { id: invite.id },
    data: { status: "ACCEPTED" }
  });

  void enqueueAudit({
    action: "invite.accepted",
    actorType: "user",
    actorUserId: user.id,
    orgId: invite.orgId,
    entityType: "invitation",
    entityId: invite.id,
    metadata: { email: invite.email, roleName: invite.roleName },
    ip: req.ip ?? null,
    userAgent: req.header("user-agent") ?? null
  });

  return res.json({ data: { membershipId: membership.id } });
});

app.get(
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

app.patch("/memberships/:id/roles", requireAuth, async (req: AuthedRequest, res) => {
    const parsed = updateMembershipRolesSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.flatten() });
    }

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

    const hasManagePermission = await prisma.membershipRole.findFirst({
      where: {
        membership: {
          userId: req.user!.id,
          organizationId: membership.organizationId,
          scope: "ORG",
          status: "ACTIVE"
        },
        role: {
          scope: "ORG",
          permissions: {
            some: { permission: { key: "members.manage" } }
          }
        }
      }
    });

    if (!hasManagePermission) {
      return res.status(403).json({ error: "Forbidden" });
    }

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
  });

app.post("/workspaces", requireAuth, async (req: AuthedRequest, res) => {
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

  const adminRole = await prisma.role.findFirst({
    where: { orgId: null, scope: "WORKSPACE", name: "admin" }
  });

  if (!adminRole) {
    return res.status(500).json({ error: "Workspace admin role not configured" });
  }

  const workspace = await prisma.workspace.create({
    data: { organizationId: orgId, name, slug }
  });

  const membership = await prisma.membership.create({
    data: {
      userId: req.user!.id,
      organizationId: orgId,
      workspaceId: workspace.id,
      scope: "WORKSPACE",
      status: "ACTIVE"
    }
  });

  await prisma.membershipRole.create({
    data: { membershipId: membership.id, roleId: adminRole.id }
  });

  void enqueueAudit({
    action: "workspace.created",
    actorType: "user",
    actorUserId: req.user!.id,
    orgId: orgId,
    workspaceId: workspace.id,
    entityType: "workspace",
    entityId: workspace.id,
    metadata: { name: workspace.name, slug: workspace.slug },
    ip: req.context?.ip ?? null,
    userAgent: req.context?.userAgent ?? null
  });

  return res.status(201).json({ data: { workspace } });
});

app.get("/workspaces", requireAuth, async (req: AuthedRequest, res) => {
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

app.patch(
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

app.get(
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
      where: { orgId: req.params.orgId } as any,
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: limit + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {})
    });

    const nextCursor = rows.length > limit ? rows[limit].id : null;
    const items = rows.slice(0, limit);

    return res.json({ data: { items, nextCursor } });
  }
);

app.get(
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
      where: { workspaceId: req.params.workspaceId } as any,
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: limit + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {})
    });

    const nextCursor = rows.length > limit ? rows[limit].id : null;
    const items = rows.slice(0, limit);

    return res.json({ data: { items, nextCursor } });
  }
);

app.post(
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

    const existing = await prisma.job.findUnique({
      where: { orgId_type_idempotencyKey: { orgId, type, idempotencyKey } }
    });

    if (existing) {
      return res.json({ data: { job: existing } });
    }

    const job = await prisma.job.create({
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

app.get(
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

app.get(
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
