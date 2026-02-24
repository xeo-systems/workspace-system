import { Queue } from "bullmq";
import { redisConfig } from "../config/redis.js";

export const jobQueue = new Queue("jobs", {
  connection: { url: redisConfig.url }
});

export const auditQueue = new Queue("audit", {
  connection: { url: redisConfig.url }
});
