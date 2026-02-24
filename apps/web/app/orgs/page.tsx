"use client";

import { useEffect, useState } from "react";
import AuthGuard from "../components/AuthGuard";
import FormField from "../components/FormField";
import StatusBanner from "../components/StatusBanner";
import { createOrg, listOrgs, type Org } from "../lib/api";

export default function OrgsPage() {
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    listOrgs()
      .then(setOrgs)
      .catch((err) => setError((err as Error).message))
      .finally(() => setLoading(false));
  }, []);

  async function onCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const org = await createOrg(name, slug);
      setOrgs([org, ...orgs]);
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
        <h1>Organizations</h1>
        <StatusBanner loading={loading} error={error} />
        <form onSubmit={onCreate} style={{ display: "flex", gap: 12, alignItems: "end" }}>
          <FormField label="Name" value={name} onChange={setName} />
          <FormField label="Slug" value={slug} onChange={setSlug} />
          <button type="submit" disabled={loading}>
            Create
          </button>
        </form>
        <ul>
          {orgs.map((o) => (
            <li key={o.id}>
              {o.name} ({o.slug})
            </li>
          ))}
        </ul>
      </div>
    </AuthGuard>
  );
}
