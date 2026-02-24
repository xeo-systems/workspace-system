import {
  clearTokens,
  getAccessToken,
  refreshTokens,
  setTokens,
  type Tokens,
  type User,
  cacheUser
} from "./auth";

export class AuthError extends Error {
  constructor(message = "Unauthorized, please log in again.") {
    super(message);
    this.name = "AuthError";
  }
}

const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:4000";

async function request<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init.headers as Record<string, string> | undefined)
  };

  const token = getAccessToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${apiBaseUrl}${path}`, { ...init, headers });

  if ((res.status === 401 || res.status === 403) && retry) {
    const refreshed = await refreshTokens(apiBaseUrl);
    if (refreshed) {
      return request<T>(path, init, false);
    }
    clearTokens();
    cacheUser(null);
    throw new AuthError();
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed: ${res.status}`);
  }

  return (await res.json()) as T;
}

export type Org = { id: string; name: string; slug: string; createdAt: string; updatedAt: string };
export type Workspace = {
  id: string;
  organizationId: string;
  name: string;
  slug: string;
  createdAt: string;
  updatedAt: string;
};

export type AuditLog = {
  id: string;
  orgId: string;
  workspaceId: string | null;
  actorUserId: string | null;
  actorType: string;
  action: string;
  entityType: string | null;
  entityId: string | null;
  metadata: Record<string, unknown> | null;
  ip: string | null;
  userAgent: string | null;
  createdAt: string;
};

export type Job = {
  id: string;
  orgId: string;
  workspaceId: string | null;
  type: string;
  payload: Record<string, unknown> | null;
  idempotencyKey: string;
  status: string;
  attempts: number;
  maxAttempts: number;
  error: string | null;
  result: Record<string, unknown> | null;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
};

export async function signup(email: string, password: string, name?: string): Promise<Tokens> {
  const res = await request<{ data: { accessToken: string; refreshToken: string } }>(
    "/auth/signup",
    {
      method: "POST",
      body: JSON.stringify({ email, password, name })
    },
    false
  );
  const tokens = { accessToken: res.data.accessToken, refreshToken: res.data.refreshToken };
  setTokens(tokens);
  cacheUser(null);
  return tokens;
}

export async function login(email: string, password: string): Promise<Tokens> {
  const res = await request<{ data: { accessToken: string; refreshToken: string } }>(
    "/auth/login",
    {
      method: "POST",
      body: JSON.stringify({ email, password })
    },
    false
  );
  const tokens = { accessToken: res.data.accessToken, refreshToken: res.data.refreshToken };
  setTokens(tokens);
  cacheUser(null);
  return tokens;
}

export async function getMe(): Promise<User> {
  const res = await request<{ data: { user: User } }>("/me");
  cacheUser(res.data.user);
  return res.data.user;
}

export async function listOrgs(): Promise<Org[]> {
  const res = await request<{ data: { orgs: Org[] } }>("/orgs");
  return res.data.orgs;
}

export async function createOrg(name: string, slug: string): Promise<Org> {
  const res = await request<{ data: { org: Org } }>("/orgs", {
    method: "POST",
    body: JSON.stringify({ name, slug })
  });
  return res.data.org;
}

export async function listWorkspaces(orgId: string): Promise<Workspace[]> {
  const res = await request<{ data: { workspaces: Workspace[] } }>(`/workspaces?orgId=${orgId}`);
  return res.data.workspaces;
}

export async function createWorkspace(orgId: string, name: string, slug: string): Promise<Workspace> {
  const res = await request<{ data: { workspace: Workspace } }>("/workspaces", {
    method: "POST",
    body: JSON.stringify({ orgId, name, slug })
  });
  return res.data.workspace;
}

export async function listOrgAudit(orgId: string): Promise<AuditLog[]> {
  const res = await request<{ data: { items: AuditLog[] } }>(`/audit/org/${orgId}`);
  return res.data.items;
}

export async function listWorkspaceAudit(workspaceId: string): Promise<AuditLog[]> {
  const res = await request<{ data: { items: AuditLog[] } }>(`/audit/workspace/${workspaceId}`);
  return res.data.items;
}

export async function createInvite(params: {
  orgId: string;
  email: string;
  roleName?: string;
}): Promise<{ token: string }> {
  const res = await request<{ data: { token: string } }>(
    `/orgs/${params.orgId}/invites`,
    {
      method: "POST",
      body: JSON.stringify({ email: params.email, roleName: params.roleName })
    }
  );
  return { token: res.data.token };
}

export async function acceptInvite(params: { token: string }): Promise<void> {
  await request<{ data: { membershipId: string } }>("/invites/accept", {
    method: "POST",
    body: JSON.stringify({ token: params.token })
  });
}

export async function enqueueJob(params: {
  orgId: string;
  workspaceId?: string;
  type: string;
  payload?: Record<string, unknown>;
  idempotencyKey: string;
}): Promise<Job> {
  const res = await request<{ data: { job: Job } }>("/jobs/enqueue", {
    method: "POST",
    body: JSON.stringify(params)
  });
  return res.data.job;
}

export async function listJobs(orgId: string): Promise<Job[]> {
  const res = await request<{ data: { items: Job[] } }>(`/jobs?orgId=${orgId}`);
  return res.data.items;
}

export async function getJob(jobId: string): Promise<Job> {
  const res = await request<{ data: { job: Job } }>(`/jobs/${jobId}`);
  return res.data.job;
}
