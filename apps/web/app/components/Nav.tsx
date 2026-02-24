"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { fetchMe, getCachedUser, clearTokens, type User } from "../lib/auth";

const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:4000";

export default function Nav() {
  const pathname = usePathname();
  const router = useRouter();
  const [user, setUser] = useState<User | null>(getCachedUser());

  useEffect(() => {
    if (user) return;
    fetchMe(apiBaseUrl).then((u) => {
      if (u) setUser(u);
    });
  }, [user]);

  const links = [
    { href: "/orgs", label: "Orgs" },
    { href: "/workspaces", label: "Workspaces" },
    { href: "/audit", label: "Audit" },
    { href: "/jobs", label: "Jobs" },
    { href: "/invites", label: "Invites" }
  ];

  return (
    <nav style={{ display: "flex", gap: 12, alignItems: "center" }}>
      <Link href="/">Home</Link>
      {links.map((l) => (
        <Link
          key={l.href}
          href={l.href}
          style={{ fontWeight: pathname?.startsWith(l.href) ? "bold" : "normal" }}
        >
          {l.label}
        </Link>
      ))}
      <span style={{ flex: 1 }} />
      {user ? (
        <span style={{ fontSize: 12, color: "#444" }}>{user.email}</span>
      ) : null}
      <Link href="/login">Login</Link>
      <button
        onClick={() => {
          clearTokens();
          router.replace("/login");
        }}
      >
        Logout
      </button>
    </nav>
  );
}
