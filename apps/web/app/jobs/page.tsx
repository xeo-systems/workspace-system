"use client";

import Link from "next/link";
import { useState } from "react";
import AuthGuard from "../components/AuthGuard";
import FormField from "../components/FormField";
import StatusBanner from "../components/StatusBanner";
import { enqueueJob, listJobs, type Job } from "../lib/api";

export default function JobsPage() {
  const [orgId, setOrgId] = useState("");
  const [type, setType] = useState("echo");
  const [idempotencyKey, setIdempotencyKey] = useState("");
  const [payload, setPayload] = useState("{\"msg\":\"hi\"}");
  const [jobs, setJobs] = useState<Job[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onEnqueue(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const parsed = JSON.parse(payload || "{}");
      const job = await enqueueJob({
        orgId,
        type,
        idempotencyKey: idempotencyKey || `${Date.now()}`,
        payload: parsed
      });
      setJobs([job, ...jobs]);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  async function onLoad(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const items = await listJobs(orgId);
      setJobs(items);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <AuthGuard>
      <div>
        <h1>Jobs</h1>
        <StatusBanner loading={loading} error={error} />
        <form onSubmit={onEnqueue} style={{ display: "flex", gap: 12, alignItems: "end" }}>
          <FormField label="Org ID" value={orgId} onChange={setOrgId} />
          <FormField label="Type" value={type} onChange={setType} />
          <FormField label="Idempotency Key" value={idempotencyKey} onChange={setIdempotencyKey} />
          <FormField label="Payload (JSON)" value={payload} onChange={setPayload} />
          <button type="submit" disabled={loading}>
            Enqueue
          </button>
          <button type="button" onClick={onLoad} disabled={loading}>
            Refresh
          </button>
        </form>
        <ul>
          {jobs.map((j) => (
            <li key={j.id}>
              <Link href={`/jobs/${j.id}`}>{j.type}</Link> — {j.status} — {j.createdAt}
            </li>
          ))}
        </ul>
      </div>
    </AuthGuard>
  );
}
