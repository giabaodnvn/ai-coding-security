"use client";
import { useEffect, useState } from "react";
import { Plus, Pencil, Trash2 } from "lucide-react";
import { api } from "@/lib/api";
import type { Policy } from "@/lib/types";

const DEFAULT_CONFIG = {
  block_dangerous_commands: true,
  block_secrets: true,
  max_risk_level: "medium",
  allow_sudo: false,
};

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [editing, setEditing] = useState<Policy | null>(null);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ name: "", description: "", config: JSON.stringify(DEFAULT_CONFIG, null, 2) });
  const [error, setError] = useState("");

  useEffect(() => { api.policies().then(setPolicies); }, []);

  function openCreate() {
    setForm({ name: "", description: "", config: JSON.stringify(DEFAULT_CONFIG, null, 2) });
    setCreating(true); setEditing(null); setError("");
  }

  function openEdit(p: Policy) {
    setForm({ name: p.name, description: p.description, config: JSON.stringify(p.config, null, 2) });
    setEditing(p); setCreating(false); setError("");
  }

  async function save() {
    setError("");
    let config: object;
    try { config = JSON.parse(form.config); } catch { setError("Invalid JSON config"); return; }
    try {
      if (editing) {
        const updated = await api.updatePolicy(editing.id, { ...form, config });
        setPolicies((ps) => ps.map((p) => (p.id === updated.id ? updated : p)));
      } else {
        const created = await api.createPolicy({ ...form, config });
        setPolicies((ps) => [created, ...ps]);
      }
      setEditing(null); setCreating(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed");
    }
  }

  async function del(id: string) {
    if (!confirm("Delete this policy?")) return;
    await api.deletePolicy(id);
    setPolicies((ps) => ps.filter((p) => p.id !== id));
  }

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Policies</h1>
          <p className="text-sm text-gray-400 mt-1">Manage security policies for your team</p>
        </div>
        <button onClick={openCreate}
          className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium px-4 py-2 rounded-lg transition">
          <Plus size={16} /> New Policy
        </button>
      </div>

      {/* Form panel */}
      {(creating || editing) && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
          <h2 className="text-sm font-semibold text-gray-300">{editing ? "Edit Policy" : "Create Policy"}</h2>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-gray-400">Name</label>
              <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
                className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500" />
            </div>
            <div>
              <label className="text-xs text-gray-400">Description</label>
              <input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })}
                className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500" />
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-400">Config (JSON)</label>
            <textarea value={form.config} onChange={(e) => setForm({ ...form, config: e.target.value })} rows={6}
              className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-green-300 font-mono focus:outline-none focus:border-indigo-500" />
          </div>
          {error && <p className="text-sm text-red-400">{error}</p>}
          <div className="flex gap-3">
            <button onClick={save} className="bg-indigo-600 hover:bg-indigo-500 text-white text-sm px-4 py-2 rounded-lg transition">Save</button>
            <button onClick={() => { setCreating(false); setEditing(null); }}
              className="bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm px-4 py-2 rounded-lg transition">Cancel</button>
          </div>
        </div>
      )}

      {/* List */}
      <div className="space-y-3">
        {policies.map((p) => (
          <div key={p.id} className="bg-gray-900 border border-gray-800 rounded-xl p-5 flex items-start justify-between gap-4">
            <div className="flex-1 min-w-0">
              <h3 className="font-semibold text-white">{p.name}</h3>
              {p.description && <p className="text-sm text-gray-400 mt-0.5">{p.description}</p>}
              <pre className="text-xs text-gray-500 mt-2 overflow-x-auto">{JSON.stringify(p.config, null, 2)}</pre>
            </div>
            <div className="flex gap-2 shrink-0">
              <button onClick={() => openEdit(p)} className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition"><Pencil size={15} /></button>
              <button onClick={() => del(p.id)}   className="p-2 rounded-lg text-gray-400 hover:text-red-400 hover:bg-gray-800 transition"><Trash2 size={15} /></button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
