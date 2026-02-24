import Nav from "./components/Nav";

export const metadata = {
  title: "Workspace UI"
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, fontFamily: "system-ui, sans-serif" }}>
        <div style={{ padding: 16, borderBottom: "1px solid #eee" }}>
          <Nav />
        </div>
        <main style={{ padding: 16, maxWidth: 960, margin: "0 auto" }}>{children}</main>
      </body>
    </html>
  );
}
