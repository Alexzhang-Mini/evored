import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "BypassEvo — AI-Driven WAF Bypass Research & Exploit Framework",
  description: "Two-Stage Pipeline: WAF Bypass Discovery × Genetic Algorithm × RAG Memory × Exploit Optimization",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="zh">
      <head>
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Noto+Sans+SC:wght@300;400;500;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="min-h-screen bg-[#050505] antialiased">
        {children}
      </body>
    </html>
  );
}
