"use client";
import { useEffect, useState } from "react";
import { Activity, AlertTriangle, Users, ShieldOff } from "lucide-react";
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import StatCard from "@/components/dashboard/StatCard";
import { RiskBadge, BlockedBadge } from "@/components/ui/Badge";
import { api } from "@/lib/api";
import type { DashboardStats } from "@/lib/types";

const PIE_COLORS: Record<string, string> = {
  CRITICAL: "#a855f7", HIGH: "#ef4444", MEDIUM: "#eab308", LOW: "#3b82f6", SAFE: "#22c55e",
};

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.stats().then(setStats).catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="p-8 text-red-400">{error}</div>;
  if (!stats) return <div className="p-8 text-gray-400">Loading…</div>;

  const pieData = Object.entries(stats.risk_distribution).map(([name, value]) => ({ name, value }));

  return (
    <div className="p-8 space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        <p className="text-sm text-gray-400 mt-1">Security overview — today</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Scans Today"       value={stats.total_events_today} icon={Activity}      color="indigo" />
        <StatCard title="Blocked Today"     value={stats.blocked_today}      icon={ShieldOff}     color="red"    />
        <StatCard title="Active Developers" value={stats.active_developers}  icon={Users}         color="green"  />
        <StatCard title="Avg Risk Score"    value={`${Math.round(stats.avg_risk_score)}/100`} icon={AlertTriangle} color="yellow" />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Events over time */}
        <div className="lg:col-span-2 bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Events — last 14 days</h2>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={stats.events_over_time}>
              <XAxis dataKey="date" tick={{ fontSize: 11, fill: "#6b7280" }} tickFormatter={(v) => v.slice(5)} />
              <YAxis tick={{ fontSize: 11, fill: "#6b7280" }} />
              <Tooltip contentStyle={{ background: "#111827", border: "1px solid #374151", borderRadius: 8 }} />
              <Line type="monotone" dataKey="total"   stroke="#6366f1" strokeWidth={2} dot={false} name="Total" />
              <Line type="monotone" dataKey="blocked" stroke="#ef4444" strokeWidth={2} dot={false} name="Blocked" />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Risk distribution pie */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Risk Distribution</h2>
          <ResponsiveContainer width="100%" height={160}>
            <PieChart>
              <Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={70} dataKey="value">
                {pieData.map((entry) => (
                  <Cell key={entry.name} fill={PIE_COLORS[entry.name] ?? "#6b7280"} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: "#111827", border: "1px solid #374151", borderRadius: 8 }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="space-y-1 mt-2">
            {pieData.map((e) => (
              <div key={e.name} className="flex justify-between text-xs text-gray-400">
                <span style={{ color: PIE_COLORS[e.name] }}>{e.name}</span>
                <span>{e.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent incidents */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl">
        <div className="px-5 py-4 border-b border-gray-800">
          <h2 className="text-sm font-semibold text-gray-300">Recent Incidents</h2>
        </div>
        <div className="divide-y divide-gray-800">
          {stats.recent_incidents.length === 0 && (
            <p className="px-5 py-4 text-sm text-gray-500">No incidents.</p>
          )}
          {stats.recent_incidents.map((ev) => (
            <div key={ev.id} className="px-5 py-3 flex items-center gap-4">
              <BlockedBadge blocked={ev.blocked} />
              <RiskBadge level={ev.risk_level} />
              <span className="text-xs text-gray-400 font-mono">{ev.tool_name}</span>
              <span className="text-xs text-gray-300 truncate flex-1">{ev.input}</span>
              <span className="text-xs text-gray-500 shrink-0">{ev.user_email ?? "—"}</span>
              <span className="text-xs text-gray-600 shrink-0">{new Date(ev.created_at).toLocaleString()}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
