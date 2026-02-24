import "dotenv/config";
import { app } from "./app.js";
import { prisma } from "./db/prisma.js";
import { getEnv } from "./config/auth.js";

const env = getEnv();
const port = Number(env.PORT ?? 3000);

const server = app.listen(port, () => {
  console.log(`API listening on :${port}`);
});

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
