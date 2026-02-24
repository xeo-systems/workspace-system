export type RedisConfig = {
  url: string;
};

export const redisConfig: RedisConfig = {
  url: process.env.REDIS_URL ?? "redis://localhost:6379"
};
