import "dotenv/config";
import { app } from "./app.js";
import { prisma } from "./db/prisma.js";
import { getEnv } from "./config/auth.js";
import type { Server } from "http";

const env = getEnv();
const basePort = Number(env.PORT ?? 3000);
const maxPortAttempts = 20;
let server: Server;

function listenWithRetry(startPort: number) {
  let current = startPort;
  let attempts = 0;

  const tryListen = () => {
    server = app.listen(current, () => {
      console.log(`API listening on :${current}`);
    });

    server.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EADDRINUSE" && attempts < maxPortAttempts) {
        attempts += 1;
        current += 1;
        console.warn(`Port ${current - 1} in use, trying ${current}...`);
        setImmediate(tryListen);
        return;
      }
      console.error("Failed to start server", err);
      process.exit(1);
    });
  };

  tryListen();
}

listenWithRetry(basePort);

let shuttingDown = false;
async function shutdown(signal: string) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`Received ${signal}, shutting down...`);
  server.close(async () => {
    try {
      await prisma.$disconnect();
    } finally {
      process.exit(0);
    }
  });

  setTimeout(() => {
    process.exit(1);
  }, 10000).unref();
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
