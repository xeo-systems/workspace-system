"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import AuthGuard from "../../components/AuthGuard";
import StatusBanner from "../../components/StatusBanner";
import { getJob, type Job } from "../../lib/api";

export default function JobDetailPage() {
  const params = useParams();
  const jobId = typeof params?.jobId === "string" ? params.jobId : "";
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!jobId) return;
    setLoading(true);
    getJob(jobId)
      .then(setJob)
      .catch((err) => setError((err as Error).message))
      .finally(() => setLoading(false));
  }, [jobId]);

  return (
    <AuthGuard>
      <div>
        <h1>Job Detail</h1>
        <StatusBanner loading={loading} error={error} />
        {job ? (
          <pre style={{ background: "#f6f6f6", padding: 12 }}>
            {JSON.stringify(job, null, 2)}
          </pre>
        ) : null}
      </div>
    </AuthGuard>
  );
}
