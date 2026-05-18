"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { User } from "@/lib/types";

export default function SettingsPage() {
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => { api.me().then(setUser).catch(() => null); }, []);

  const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";

  return (
    <div className="p-8 space-y-8 max-w-2xl">
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="text-sm text-gray-400 mt-1">Account and integration configuration</p>
      </div>

      {/* Profile */}
      <section className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
        <h2 className="text-sm font-semibold text-gray-300">Profile</h2>
        {user ? (
          <div className="space-y-3 text-sm">
            <Row label="Name"  value={user.name} />
            <Row label="Email" value={user.email} />
            <Row label="Role"  value={<span className="capitalize text-indigo-300">{user.role}</span>} />
          </div>
        ) : (
          <p className="text-sm text-gray-500">Loading…</p>
        )}
      </section>

      {/* claude-safe CLI integration */}
      <section className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
        <h2 className="text-sm font-semibold text-gray-300">CLI Integration</h2>
        <p className="text-sm text-gray-400">
          Configure your <code className="text-indigo-300">claude-safe</code> CLI to send audit events to this dashboard.
        </p>
        <div className="space-y-3 text-sm">
          <Row label="API Endpoint" value={<code className="text-green-300">{apiUrl}/api/events</code>} />
          <Row label="Method"       value={<code className="text-green-300">POST</code>} />
        </div>
        <div className="bg-gray-800 rounded-lg p-4 mt-2">
          <p className="text-xs text-gray-400 mb-2">Example curl:</p>
          <pre className="text-xs text-green-300 overflow-x-auto whitespace-pre-wrap">{`curl -X POST ${apiUrl}/api/events \\
  -H "Content-Type: application/json" \\
  -d '{
    "user_email": "${user?.email ?? "dev@example.com"}",
    "tool_name": "Bash",
    "input": "echo hello",
    "risk_level": "SAFE",
    "risk_score": 0,
    "blocked": false,
    "reason": "",
    "findings": []
  }'`}</pre>
        </div>
      </section>

      {/* Seed accounts */}
      <section className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-3">
        <h2 className="text-sm font-semibold text-gray-300">Demo Accounts</h2>
        <p className="text-xs text-gray-500">All accounts use password: <code className="text-indigo-300">password123</code></p>
        {[
          { email: "admin@example.com",   role: "admin" },
          { email: "analyst@example.com", role: "analyst" },
          { email: "dev1@example.com",    role: "developer" },
        ].map((a) => (
          <div key={a.email} className="flex items-center justify-between text-sm">
            <span className="text-gray-300">{a.email}</span>
            <span className="text-xs text-gray-500 capitalize">{a.role}</span>
          </div>
        ))}
      </section>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-gray-500">{label}</span>
      <span className="text-gray-200">{value}</span>
    </div>
  );
}
