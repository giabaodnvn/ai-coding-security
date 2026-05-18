import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Claude Safe — Enterprise Dashboard",
  description: "AI Coding Security Governance Platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
