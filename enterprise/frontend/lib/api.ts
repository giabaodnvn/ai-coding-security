const API = process.env.NEXT_PUBLIC_API_URL || "";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
  const res = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options?.headers,
    },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || "Request failed");
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

export const api = {
  login: (email: string, password: string) =>
    request<{ token: string; user: import("./types").User }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  me: () => request<import("./types").User>("/api/auth/me"),

  stats: () => request<import("./types").DashboardStats>("/api/stats"),

  incidents: (params?: { limit?: number; offset?: number; risk_level?: string }) => {
    const q = new URLSearchParams(params as Record<string, string>).toString();
    return request<{ incidents: import("./types").ScanEvent[]; total: number }>(`/api/incidents${q ? "?" + q : ""}`);
  },

  auditLogs: (params?: { limit?: number; offset?: number }) => {
    const q = new URLSearchParams(params as Record<string, string>).toString();
    return request<{ events: import("./types").ScanEvent[]; total: number }>(`/api/audit-logs${q ? "?" + q : ""}`);
  },

  developers: () => request<import("./types").Developer[]>("/api/developers"),

  developerActivity: (id: string) =>
    request<{ developer: import("./types").Developer; events: import("./types").ScanEvent[] }>(`/api/developers/${id}/activity`),

  policies: () => request<import("./types").Policy[]>("/api/policies"),

  createPolicy: (data: { name: string; description: string; config: object }) =>
    request<import("./types").Policy>("/api/policies", { method: "POST", body: JSON.stringify(data) }),

  updatePolicy: (id: string, data: { name: string; description: string; config: object }) =>
    request<import("./types").Policy>(`/api/policies/${id}`, { method: "PUT", body: JSON.stringify(data) }),

  deletePolicy: (id: string) =>
    request<void>(`/api/policies/${id}`, { method: "DELETE" }),

  apiKeys: () => request<import("./types").APIKey[]>("/api/api-keys"),

  createAPIKey: (name: string) =>
    request<{ id: string; key: string; prefix: string }>("/api/api-keys", {
      method: "POST",
      body: JSON.stringify({ name }),
    }),

  deleteAPIKey: (id: string) =>
    request<void>(`/api/api-keys/${id}`, { method: "DELETE" }),

  webhooks: () => request<import("./types").Webhook[]>("/api/webhooks"),

  createWebhook: (data: { name: string; url: string; secret: string; events: string[] }) =>
    request<import("./types").Webhook>("/api/webhooks", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  deleteWebhook: (id: string) =>
    request<void>(`/api/webhooks/${id}`, { method: "DELETE" }),
};
