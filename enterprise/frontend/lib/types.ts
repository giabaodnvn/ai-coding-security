export interface User {
  id: string;
  email: string;
  name: string;
  role: "admin" | "analyst" | "developer";
  created_at: string;
}

export interface ScanEvent {
  id: string;
  user_id: string | null;
  user_email: string | null;
  user_name: string | null;
  tool_name: string;
  input: string;
  risk_level: string;
  risk_score: number;
  blocked: boolean;
  reason: string;
  findings: unknown[];
  created_at: string;
}

export interface Policy {
  id: string;
  name: string;
  description: string;
  config: Record<string, unknown>;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface Developer {
  id: string;
  email: string;
  name: string;
  total_scans: number;
  blocked_scans: number;
  avg_risk_score: number;
  last_active: string | null;
}

export interface TimePoint {
  date: string;
  total: number;
  blocked: number;
}

export interface APIKey {
  id: string;
  user_id: string;
  name: string;
  key_prefix: string;
  last_used: string | null;
  created_at: string;
}

export interface Webhook {
  id: string;
  user_id: string;
  name: string;
  url: string;
  events: string[];
  active: boolean;
  created_at: string;
}

export interface DashboardStats {
  total_events_today: number;
  blocked_today: number;
  active_developers: number;
  avg_risk_score: number;
  risk_distribution: Record<string, number>;
  events_over_time: TimePoint[];
  recent_incidents: ScanEvent[];
}
