"use client";

import { useState } from "react";
import AuthGuard from "../components/AuthGuard";
import FormField from "../components/FormField";
import StatusBanner from "../components/StatusBanner";
import { listOrgAudit, type AuditLog } from "../lib/api";

export default function AuditPage() {
  const [orgId, setOrgId] = useState("");
  const [items, setItems] = useState<AuditLog[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onLoad(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const logs = await listOrgAudit(orgId);
      setItems(logs);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthGuard>
      <div>
        <h1>Audit (Org)</h1>
        <StatusBanner loading={loading} error={error} />
        <form onSubmit={onLoad} style={{ display: "flex", gap: 12, alignItems: "end" }}>
          <FormField label="Org ID" value={orgId} onChange={setOrgId} />
          <button type="submit" disabled={loading}>
            Load
          </button>
        </form>
        <ul>
          {items.map((a) => (
            <li key={a.id}>
              {a.action} ({a.entityType ?? "-"}) {a.entityId ?? ""} — {a.createdAt}
            </li>
          ))}
        </ul>
      </div>
    </AuthGuard>
  );
}
