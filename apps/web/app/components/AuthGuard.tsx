"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { getMe, AuthError } from "../lib/api";
import { getAccessToken } from "../lib/auth";
import StatusBanner from "./StatusBanner";

export default function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const token = getAccessToken();
    if (!token) {
      router.replace("/login");
      return;
    }

    setError(null);
    getMe()
      .then(() => setReady(true))
      .catch((err) => {
        if (err instanceof AuthError) {
          setError(err.message);
          router.replace("/login");
        } else {
          setError((err as Error).message);
          setReady(true);
        }
      });
  }, [router]);

  if (!ready) return <StatusBanner loading />;

  return (
    <>
      <StatusBanner error={error} />
      {children}
    </>
  );
}
