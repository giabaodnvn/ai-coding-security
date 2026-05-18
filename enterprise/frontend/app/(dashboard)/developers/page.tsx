"use client";
import { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { api } from "@/lib/api";
import { RiskBadge, BlockedBadge } from "@/components/ui/Badge";
import type { Developer, ScanEvent } from "@/lib/types";

export default function DevelopersPage() {
  const [devs, setDevs] = useState<Developer[]>([]);
  const [selected, setSelected] = useState<{ developer: Developer; events: ScanEvent[] } | null>(null);

  useEffect(() => { api.developers().then(setDevs); }, []);

  async function viewActivity(id: string) {
    const data = await api.developerActivity(id);
    setSelected(data);
  }

  return (
    <div className="p-8 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Developers</h1>
        <p className="text-sm text-gray-400 mt-1">Activity and risk overview per developer</p>
      </div>

      {/* Bar chart */}
      {devs.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Scans per developer</h2>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={devs}>
              <XAxis dataKey="name" tick={{ fontSize: 11, fill: "#6b7280" }} />
              <YAxis tick={{ fontSize: 11, fill: "#6b7280" }} />
              <Tooltip contentStyle={{ background: "#111827", border: "1px solid #374151", borderRadius: 8 }} />
              <Bar dataKey="total_scans"   fill="#6366f1" radius={[4,4,0,0]} name="Total" />
              <Bar dataKey="blocked_scans" fill="#ef4444" radius={[4,4,0,0]} name="Blocked" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="border-b border-gray-800">
            <tr className="text-left text-xs text-gray-500 uppercase tracking-wider">
              <th className="px-4 py-3">Developer</th>
              <th className="px-4 py-3">Total Scans</th>
              <th className="px-4 py-3">Blocked</th>
              <th className="px-4 py-3">Avg Risk</th>
              <th className="px-4 py-3">Last Active</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {devs.map((d) => (
              <tr key={d.id} className="hover:bg-gray-800/50 transition-colors">
                <td className="px-4 py-3">
                  <div className="font-medium text-white">{d.name}</div>
                  <div className="text-xs text-gray-500">{d.email}</div>
                </td>
                <td className="px-4 py-3 text-gray-300">{d.total_scans}</td>
                <td className="px-4 py-3 text-red-400">{d.blocked_scans}</td>
                <td className="px-4 py-3 text-gray-300">{Math.round(d.avg_risk_score)}/100</td>
                <td className="px-4 py-3 text-gray-500">{d.last_active ? new Date(d.last_active).toLocaleDateString() : "—"}</td>
                <td className="px-4 py-3">
                  <button onClick={() => viewActivity(d.id)}
                    className="text-xs text-indigo-400 hover:text-indigo-300 transition">View Activity</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Activity drawer */}
      {selected && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl">
          <div className="px-5 py-4 border-b border-gray-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-gray-300">
              Activity — {selected.developer.name}
            </h2>
            <button onClick={() => setSelected(null)} className="text-xs text-gray-500 hover:text-white">Close</button>
          </div>
          <div className="divide-y divide-gray-800">
            {selected.events.map((ev) => (
              <div key={ev.id} className="px-5 py-3 flex items-center gap-4">
                <BlockedBadge blocked={ev.blocked} />
                <RiskBadge level={ev.risk_level} />
                <span className="text-xs font-mono text-gray-400">{ev.tool_name}</span>
                <span className="text-xs text-gray-300 truncate flex-1">{ev.input}</span>
                <span className="text-xs text-gray-600">{new Date(ev.created_at).toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
