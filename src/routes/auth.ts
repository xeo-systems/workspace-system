import express from "express";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { prisma } from "../db/prisma.js";
import {
  createAccessToken,
  createRefreshToken,
  hashRefreshToken,
  refreshExpiryDate,
  requireAuth,
  rateLimit,
  type AuthedRequest
} from "../middleware/auth.js";
import { enqueueAudit } from "../lib/audit.js";

export const authRouter = express.Router();

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

async function resolveOrgForUser(userId: string) {
  const membership = await prisma.membership.findFirst({
    where: { userId, scope: "ORG", status: "ACTIVE" },
    orderBy: { createdAt: "asc" }
  });
  return membership?.organizationId ?? null;
}

authRouter.post("/auth/signup", rateLimit, async (req, res) => {
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

authRouter.post("/auth/login", rateLimit, async (req: AuthedRequest, res) => {
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

authRouter.post("/auth/refresh", async (req, res) => {
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

authRouter.post("/auth/logout", async (req, res) => {
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

authRouter.get("/me", requireAuth, async (req: AuthedRequest, res) => {
  return res.json({ data: { user: req.user } });
});
