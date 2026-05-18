"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { RiskBadge } from "@/components/ui/Badge";
import type { ScanEvent } from "@/lib/types";

const LEVELS = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<ScanEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [level, setLevel] = useState("");
  const [loading, setLoading] = useState(true);
  const limit = 20;

  useEffect(() => {
    setLoading(true);
    api.incidents({ limit, offset: page * limit, ...(level ? { risk_level: level } : {}) })
      .then((d) => { setIncidents(d.incidents); setTotal(d.total); })
      .finally(() => setLoading(false));
  }, [page, level]);

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Incidents</h1>
          <p className="text-sm text-gray-400 mt-1">{total} blocked events total</p>
        </div>
        <select
          value={level}
          onChange={(e) => { setLevel(e.target.value); setPage(0); }}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500"
        >
          {LEVELS.map((l) => <option key={l} value={l}>{l || "All levels"}</option>)}
        </select>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="border-b border-gray-800">
            <tr className="text-left text-xs text-gray-500 uppercase tracking-wider">
              <th className="px-4 py-3">Risk</th>
              <th className="px-4 py-3">Tool</th>
              <th className="px-4 py-3">Input</th>
              <th className="px-4 py-3">Developer</th>
              <th className="px-4 py-3">Reason</th>
              <th className="px-4 py-3">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {loading && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-500">Loading…</td></tr>
            )}
            {!loading && incidents.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-500">No incidents found.</td></tr>
            )}
            {incidents.map((ev) => (
              <tr key={ev.id} className="hover:bg-gray-800/50 transition-colors">
                <td className="px-4 py-3"><RiskBadge level={ev.risk_level} /></td>
                <td className="px-4 py-3 font-mono text-gray-300">{ev.tool_name}</td>
                <td className="px-4 py-3 text-gray-300 max-w-xs truncate">{ev.input}</td>
                <td className="px-4 py-3 text-gray-400">{ev.user_email ?? "—"}</td>
                <td className="px-4 py-3 text-gray-400 max-w-xs truncate">{ev.reason || "—"}</td>
                <td className="px-4 py-3 text-gray-500 whitespace-nowrap">{new Date(ev.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {total > limit && (
          <div className="px-4 py-3 border-t border-gray-800 flex items-center justify-between text-sm text-gray-400">
            <span>Page {page + 1} of {Math.ceil(total / limit)}</span>
            <div className="flex gap-2">
              <button disabled={page === 0} onClick={() => setPage(p => p - 1)}
                className="px-3 py-1 rounded bg-gray-800 disabled:opacity-40 hover:bg-gray-700">Prev</button>
              <button disabled={(page + 1) * limit >= total} onClick={() => setPage(p => p + 1)}
                className="px-3 py-1 rounded bg-gray-800 disabled:opacity-40 hover:bg-gray-700">Next</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
