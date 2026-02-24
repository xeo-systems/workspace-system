import type { SignOptions } from "jsonwebtoken";
import { z } from "zod";

export type AuthConfig = {
  jwtSecret: string;
  accessTokenTtl: SignOptions["expiresIn"];
  refreshTokenTtlDays: number;
};

export const authConfig: AuthConfig = {
  jwtSecret: process.env.JWT_SECRET ?? "",
  accessTokenTtl: (process.env.ACCESS_TOKEN_TTL ?? "15m") as SignOptions["expiresIn"],
  refreshTokenTtlDays: Number(process.env.REFRESH_TOKEN_TTL_DAYS ?? "7")
};

const envSchema = z.object({
  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().min(1),
  JWT_SECRET: z.string().min(1),
  PORT: z.coerce.number().int().min(1)
});

export function getEnv() {
  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    console.error("Invalid environment configuration:", parsed.error.flatten().fieldErrors);
    process.exit(1);
  }
  return parsed.data;
}
