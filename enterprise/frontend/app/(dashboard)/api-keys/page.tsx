"use client";
import { useEffect, useState } from "react";
import { Plus, Trash2, Copy, Check } from "lucide-react";
import { api } from "@/lib/api";
import type { APIKey } from "@/lib/types";

export default function APIKeysPage() {
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [newKey, setNewKey] = useState<{ id: string; key: string; prefix: string } | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => { api.apiKeys().then(setKeys).catch(() => null); }, []);

  async function create() {
    if (!name.trim()) { setError("Name is required"); return; }
    setError("");
    try {
      const result = await api.createAPIKey(name.trim());
      setNewKey(result);
      setKeys((ks) => [
        { id: result.id, user_id: "", name: name.trim(), key_prefix: result.prefix, last_used: null, created_at: new Date().toISOString() },
        ...ks,
      ]);
      setName("");
      setCreating(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Create failed");
    }
  }

  async function del(id: string) {
    if (!confirm("Revoke this API key?")) return;
    await api.deleteAPIKey(id);
    setKeys((ks) => ks.filter((k) => k.id !== id));
  }

  function copyKey() {
    if (!newKey) return;
    navigator.clipboard.writeText(newKey.key);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="p-8 space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">API Keys</h1>
          <p className="text-sm text-gray-400 mt-1">
            Authenticate the <code className="text-indigo-300">claude-safe</code> CLI to send events to this dashboard
          </p>
        </div>
        <button
          onClick={() => { setCreating(true); setNewKey(null); setError(""); }}
          className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium px-4 py-2 rounded-lg transition"
        >
          <Plus size={16} /> New Key
        </button>
      </div>

      {/* Create form */}
      {creating && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-3">
          <h2 className="text-sm font-semibold text-gray-300">New API Key</h2>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Key name (e.g. dev-laptop)"
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500"
          />
          {error && <p className="text-sm text-red-400">{error}</p>}
          <div className="flex gap-2">
            <button onClick={create} className="bg-indigo-600 hover:bg-indigo-500 text-white text-sm px-4 py-2 rounded-lg transition">Create</button>
            <button onClick={() => setCreating(false)} className="bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm px-4 py-2 rounded-lg transition">Cancel</button>
          </div>
        </div>
      )}

      {/* New key reveal — shown once */}
      {newKey && (
        <div className="bg-green-950 border border-green-800 rounded-xl p-5 space-y-3">
          <p className="text-sm font-semibold text-green-300">Key created — copy it now, it won&apos;t be shown again</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 bg-gray-900 rounded-lg px-3 py-2 text-xs text-green-300 font-mono break-all">
              {newKey.key}
            </code>
            <button onClick={copyKey} className="shrink-0 p-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 transition">
              {copied ? <Check size={16} className="text-green-400" /> : <Copy size={16} />}
            </button>
          </div>
          <p className="text-xs text-gray-500">
            Set <code className="text-indigo-300">CLAUDE_SAFE_API_KEY={newKey.key}</code> and{" "}
            <code className="text-indigo-300">CLAUDE_SAFE_ENTERPRISE_URL=http://localhost:8080</code> in your environment.
          </p>
        </div>
      )}

      {/* Key list */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="border-b border-gray-800">
            <tr className="text-left text-xs text-gray-500 uppercase tracking-wider">
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Key</th>
              <th className="px-4 py-3">Last Used</th>
              <th className="px-4 py-3">Created</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {keys.length === 0 && (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-500">No API keys yet.</td></tr>
            )}
            {keys.map((k) => (
              <tr key={k.id} className="hover:bg-gray-800/50 transition-colors">
                <td className="px-4 py-3 font-medium text-white">{k.name}</td>
                <td className="px-4 py-3 font-mono text-xs text-gray-400">{k.key_prefix}</td>
                <td className="px-4 py-3 text-gray-500">
                  {k.last_used ? new Date(k.last_used).toLocaleDateString() : "Never"}
                </td>
                <td className="px-4 py-3 text-gray-500">{new Date(k.created_at).toLocaleDateString()}</td>
                <td className="px-4 py-3">
                  <button onClick={() => del(k.id)} className="p-1.5 rounded text-gray-500 hover:text-red-400 hover:bg-gray-800 transition">
                    <Trash2 size={14} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* CLI usage */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-3">
        <h2 className="text-sm font-semibold text-gray-300">CLI Configuration</h2>
        <p className="text-sm text-gray-400">Add these to your shell profile or <code className="text-indigo-300">.env</code> file:</p>
        <pre className="text-xs text-green-300 bg-gray-800 rounded-lg p-4 overflow-x-auto">{`export CLAUDE_SAFE_ENTERPRISE_URL=http://localhost:8080
export CLAUDE_SAFE_API_KEY=cs_<your-key>`}</pre>
        <p className="text-xs text-gray-500">
          The CLI will automatically send scan events to this dashboard when both variables are set.
        </p>
      </div>
    </div>
  );
}
