import crypto from "crypto";
import type express from "express";
import jwt from "jsonwebtoken";
import { RateLimiterRedis } from "rate-limiter-flexible";
import { Redis } from "ioredis";
import { prisma } from "../db/prisma.js";
import { authConfig } from "../config/auth.js";

export type AuthedRequest = express.Request & {
  user?: { id: string; email: string; name: string | null };
  context?: { ip?: string | null; userAgent?: string | null };
  job?: {
    id: string;
    orgId: string;
    workspaceId: string | null;
    type: string;
    status: string;
  };
  membership?: {
    id: string;
    organizationId: string;
    scope: "ORG" | "WORKSPACE";
  };
};

export function hashRefreshToken(token: string) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function createAccessToken(user: { id: string; email: string }) {
  return jwt.sign(
    { sub: user.id, email: user.email },
    authConfig.jwtSecret,
    { expiresIn: authConfig.accessTokenTtl }
  );
}

export function createRefreshToken() {
  return crypto.randomBytes(48).toString("hex");
}

export function refreshExpiryDate() {
  const ms = authConfig.refreshTokenTtlDays * 24 * 60 * 60 * 1000;
  return new Date(Date.now() + ms);
}

export async function requireAuth(
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

export async function rateLimit(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  if (!rateLimiter) return next();
  try {
    const key = req.ip ?? "unknown";
    await rateLimiter.consume(key);
    return next();
  } catch {
    return res.status(429).json({ error: "Too many requests" });
  }
}
