import crypto from "crypto";
import type express from "express";
import pino from "pino";

export const logger = pino({
  level: process.env.LOG_LEVEL ?? "info"
});

export function getRequestId(req: express.Request) {
  const incoming = req.header("x-request-id");
  if (incoming && typeof incoming === "string") {
    return incoming;
  }
  return crypto.randomUUID();
}
