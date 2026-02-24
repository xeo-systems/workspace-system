"use client";

import { useState } from "react";
import AuthGuard from "../components/AuthGuard";
import FormField from "../components/FormField";
import StatusBanner from "../components/StatusBanner";
import { acceptInvite, createInvite } from "../lib/api";

export default function InvitesPage() {
  const [orgId, setOrgId] = useState("");
  const [email, setEmail] = useState("");
  const [roleName, setRoleName] = useState("member");
  const [inviteToken, setInviteToken] = useState<string | null>(null);
  const [acceptToken, setAcceptToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await createInvite({ orgId, email, roleName });
      setInviteToken(res.token);
      setEmail("");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  async function onAccept(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await acceptInvite({ token: acceptToken });
      setAcceptToken("");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  async function copyToken() {
    if (!inviteToken) return;
    await navigator.clipboard.writeText(inviteToken);
  }

  return (
    <AuthGuard>
      <div>
        <h1>Invites</h1>
        <StatusBanner loading={loading} error={error} />

        <section style={{ marginBottom: 24 }}>
          <h2>Create Invite</h2>
          <form onSubmit={onCreate} style={{ display: "flex", gap: 12, alignItems: "end" }}>
            <FormField label="Org ID" value={orgId} onChange={setOrgId} />
            <FormField label="Email" value={email} onChange={setEmail} />
            <FormField label="Role" value={roleName} onChange={setRoleName} />
            <button type="submit" disabled={loading}>
              Create
            </button>
          </form>
          {inviteToken ? (
            <div style={{ marginTop: 12 }}>
              <p style={{ color: "#b45309" }}>
                This token is shown once. Copy it now.
              </p>
              <code style={{ display: "block", padding: 8, background: "#f6f6f6" }}>
                {inviteToken}
              </code>
              <button onClick={copyToken} style={{ marginTop: 8 }}>
                Copy token
              </button>
            </div>
          ) : null}
        </section>

        <section>
          <h2>Accept Invite</h2>
          <form onSubmit={onAccept} style={{ display: "flex", gap: 12, alignItems: "end" }}>
            <FormField label="Invite Token" value={acceptToken} onChange={setAcceptToken} />
            <button type="submit" disabled={loading}>
              Accept
            </button>
          </form>
        </section>
      </div>
    </AuthGuard>
  );
}
