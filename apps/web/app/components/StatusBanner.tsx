"use client";

export default function StatusBanner({
  loading,
  error
}: {
  loading?: boolean;
  error?: string | null;
}) {
  if (!loading && !error) return null;

  const message = loading ? "Loading..." : error;

  return (
    <div
      style={{
        margin: "12px 0",
        padding: "8px 12px",
        borderRadius: 6,
        background: loading ? "#f5f5f5" : "#ffe9e9",
        border: "1px solid #ddd",
        color: "#333"
      }}
    >
      {message}
    </div>
  );
}
