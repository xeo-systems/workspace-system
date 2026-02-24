export type Tokens = {
  accessToken: string;
  refreshToken: string;
};

export type User = { id: string; email: string; name: string | null };

const ACCESS_KEY = "accessToken";
const REFRESH_KEY = "refreshToken";

let memoryTokens: Tokens | null = null;
let cachedUser: User | null = null;
let userPromise: Promise<User | null> | null = null;

export function loadTokens(): Tokens | null {
  if (memoryTokens) return memoryTokens;
  if (typeof window === "undefined") return null;
  const accessToken = localStorage.getItem(ACCESS_KEY);
  const refreshToken = localStorage.getItem(REFRESH_KEY);
  if (!accessToken || !refreshToken) return null;
  memoryTokens = { accessToken, refreshToken };
  return memoryTokens;
}

export function setTokens(tokens: Tokens) {
  memoryTokens = tokens;
  if (typeof window !== "undefined") {
    localStorage.setItem(ACCESS_KEY, tokens.accessToken);
    localStorage.setItem(REFRESH_KEY, tokens.refreshToken);
  }
}

export function clearTokens() {
  memoryTokens = null;
  cachedUser = null;
  userPromise = null;
  if (typeof window !== "undefined") {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
  }
}

export function getAccessToken(): string | null {
  return loadTokens()?.accessToken ?? null;
}

export function getRefreshToken(): string | null {
  return loadTokens()?.refreshToken ?? null;
}

export function cacheUser(user: User | null) {
  cachedUser = user;
  userPromise = null;
}

export function getCachedUser(): User | null {
  return cachedUser;
}

export async function refreshTokens(apiBaseUrl: string): Promise<Tokens | null> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return null;

  const res = await fetch(`${apiBaseUrl}/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refreshToken })
  });

  if (!res.ok) {
    clearTokens();
    return null;
  }

  const json = (await res.json()) as { data?: { accessToken: string; refreshToken: string } };
  if (!json.data?.accessToken || !json.data?.refreshToken) {
    clearTokens();
    return null;
  }

  const tokens = {
    accessToken: json.data.accessToken,
    refreshToken: json.data.refreshToken
  };
  setTokens(tokens);
  return tokens;
}

export async function fetchMe(apiBaseUrl: string): Promise<User | null> {
  if (cachedUser) return cachedUser;
  if (userPromise) return userPromise;

  userPromise = (async () => {
    const token = getAccessToken();
    if (!token) return null;

    const res = await fetch(`${apiBaseUrl}/me`, {
      headers: { Authorization: `Bearer ${token}` }
    });

    if (!res.ok) {
      return null;
    }

    const json = (await res.json()) as { data?: { user: User } };
    cachedUser = json.data?.user ?? null;
    return cachedUser;
  })();

  return userPromise;
}
