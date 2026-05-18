"use client";
import { useEffect, useState } from "react";
import { Plus, Trash2, CheckCircle, XCircle } from "lucide-react";
import { api } from "@/lib/api";
import type { Webhook } from "@/lib/types";

const EVENT_OPTIONS = ["blocked", "scan"];

export default function WebhooksPage() {
  const [hooks, setHooks] = useState<Webhook[]>([]);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ name: "", url: "", secret: "", events: ["blocked"] });
  const [error, setError] = useState("");

  useEffect(() => { api.webhooks().then(setHooks).catch(() => null); }, []);

  function toggleEvent(ev: string) {
    setForm((f) => ({
      ...f,
      events: f.events.includes(ev) ? f.events.filter((e) => e !== ev) : [...f.events, ev],
    }));
  }

  async function create() {
    if (!form.name.trim() || !form.url.trim()) { setError("Name and URL are required"); return; }
    setError("");
    try {
      const wh = await api.createWebhook(form);
      setHooks((hs) => [wh, ...hs]);
      setForm({ name: "", url: "", secret: "", events: ["blocked"] });
      setCreating(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Create failed");
    }
  }

  async function del(id: string) {
    if (!confirm("Delete this webhook?")) return;
    await api.deleteWebhook(id);
    setHooks((hs) => hs.filter((h) => h.id !== id));
  }

  return (
    <div className="p-8 space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Webhooks</h1>
          <p className="text-sm text-gray-400 mt-1">Notify external systems when security events occur</p>
        </div>
        <button
          onClick={() => { setCreating(true); setError(""); }}
          className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium px-4 py-2 rounded-lg transition"
        >
          <Plus size={16} /> New Webhook
        </button>
      </div>

      {/* Create form */}
      {creating && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
          <h2 className="text-sm font-semibold text-gray-300">New Webhook</h2>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-gray-400">Name</label>
              <input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="e.g. Slack Security Alerts"
                className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div>
              <label className="text-xs text-gray-400">Endpoint URL</label>
              <input
                value={form.url}
                onChange={(e) => setForm({ ...form, url: e.target.value })}
                placeholder="https://hooks.example.com/..."
                className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-400">Secret (optional — used for HMAC signature)</label>
            <input
              value={form.secret}
              onChange={(e) => setForm({ ...form, secret: e.target.value })}
              placeholder="webhook-secret"
              className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500"
            />
          </div>
          <div>
            <label className="text-xs text-gray-400 block mb-2">Events</label>
            <div className="flex gap-3">
              {EVENT_OPTIONS.map((ev) => (
                <label key={ev} className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.events.includes(ev)}
                    onChange={() => toggleEvent(ev)}
                    className="accent-indigo-500"
                  />
                  <span className="text-sm text-gray-300 capitalize">{ev}</span>
                </label>
              ))}
            </div>
          </div>
          {error && <p className="text-sm text-red-400">{error}</p>}
          <div className="flex gap-2">
            <button onClick={create} className="bg-indigo-600 hover:bg-indigo-500 text-white text-sm px-4 py-2 rounded-lg transition">Save</button>
            <button onClick={() => setCreating(false)} className="bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm px-4 py-2 rounded-lg transition">Cancel</button>
          </div>
        </div>
      )}

      {/* Webhook list */}
      <div className="space-y-3">
        {hooks.length === 0 && !creating && (
          <div className="bg-gray-900 border border-gray-800 rounded-xl px-5 py-8 text-center text-gray-500 text-sm">
            No webhooks configured.
          </div>
        )}
        {hooks.map((wh) => (
          <div key={wh.id} className="bg-gray-900 border border-gray-800 rounded-xl p-5 flex items-start justify-between gap-4">
            <div className="flex-1 min-w-0 space-y-1.5">
              <div className="flex items-center gap-2">
                {wh.active
                  ? <CheckCircle size={14} className="text-green-400 shrink-0" />
                  : <XCircle size={14} className="text-gray-500 shrink-0" />}
                <span className="font-medium text-white">{wh.name}</span>
              </div>
              <p className="text-xs text-gray-400 font-mono truncate">{wh.url}</p>
              <div className="flex gap-1.5 flex-wrap">
                {wh.events.map((ev) => (
                  <span key={ev} className="text-xs px-2 py-0.5 rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 capitalize">
                    {ev}
                  </span>
                ))}
              </div>
              <p className="text-xs text-gray-600">Created {new Date(wh.created_at).toLocaleDateString()}</p>
            </div>
            <button onClick={() => del(wh.id)} className="p-2 rounded-lg text-gray-400 hover:text-red-400 hover:bg-gray-800 transition shrink-0">
              <Trash2 size={15} />
            </button>
          </div>
        ))}
      </div>

      {/* Signature verification docs */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-3">
        <h2 className="text-sm font-semibold text-gray-300">Signature Verification</h2>
        <p className="text-sm text-gray-400">
          When a secret is configured, each request includes a <code className="text-indigo-300">X-Claude-Safe-Signature</code> header.
        </p>
        <pre className="text-xs text-green-300 bg-gray-800 rounded-lg p-4 overflow-x-auto">{`// Node.js example
const crypto = require('crypto');
const sig = req.headers['x-claude-safe-signature']; // "sha256=<hex>"
const expected = 'sha256=' + crypto
  .createHmac('sha256', process.env.WEBHOOK_SECRET)
  .update(JSON.stringify(req.body))
  .digest('hex');
const valid = crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));`}</pre>
      </div>
    </div>
  );
}
