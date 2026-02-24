"use client";

import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import AuthGuard from "../components/AuthGuard";
import FormField from "../components/FormField";
import StatusBanner from "../components/StatusBanner";
import { createWorkspace, listWorkspaces, type Workspace } from "../lib/api";

export default function WorkspacesPage() {
  const searchParams = useSearchParams();
  const orgId = useMemo(() => searchParams.get("orgId") ?? "", [searchParams]);
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!orgId) return;
    setLoading(true);
    listWorkspaces(orgId)
      .then(setWorkspaces)
      .catch((err) => setError((err as Error).message))
      .finally(() => setLoading(false));
  }, [orgId]);

  async function onCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const ws = await createWorkspace(orgId, name, slug);
      setWorkspaces([ws, ...workspaces]);
      setName("");
      setSlug("");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthGuard>
      <div>
        <h1>Workspaces</h1>
        <p>Org ID: {orgId || "(missing)"}</p>
        {!orgId ? (
          <p>Provide ?orgId=... in the URL.</p>
        ) : (
          <>
            <StatusBanner loading={loading} error={error} />
            <form onSubmit={onCreate} style={{ display: "flex", gap: 12, alignItems: "end" }}>
              <FormField label="Name" value={name} onChange={setName} />
              <FormField label="Slug" value={slug} onChange={setSlug} />
              <button type="submit" disabled={loading}>
                Create
              </button>
            </form>
            <ul>
              {workspaces.map((w) => (
                <li key={w.id}>
                  {w.name} ({w.slug})
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
    </AuthGuard>
  );
}
