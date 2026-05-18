-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users
CREATE TABLE IF NOT EXISTS users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT UNIQUE NOT NULL,
  name          TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'developer' CHECK (role IN ('admin','analyst','developer')),
  password_hash TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Scan events (ingested from claude-safe CLI audit logs)
CREATE TABLE IF NOT EXISTS scan_events (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
  tool_name  TEXT NOT NULL DEFAULT 'scan',
  input      TEXT NOT NULL DEFAULT '',
  risk_level TEXT NOT NULL DEFAULT 'SAFE',
  risk_score INT  NOT NULL DEFAULT 0,
  blocked    BOOLEAN NOT NULL DEFAULT FALSE,
  reason     TEXT NOT NULL DEFAULT '',
  findings   JSONB NOT NULL DEFAULT '[]',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_events_user_id    ON scan_events(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_events_created_at ON scan_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_events_blocked     ON scan_events(blocked);

-- Policies
CREATE TABLE IF NOT EXISTS policies (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  config      JSONB NOT NULL DEFAULT '{}',
  created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Seed data ────────────────────────────────────────────────────────────────
-- Password for all seed users: "password123" (bcrypt hash)
INSERT INTO users (id, email, name, role, password_hash) VALUES
  ('00000000-0000-0000-0000-000000000001', 'admin@example.com',   'Admin User',     'admin',     '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'),
  ('00000000-0000-0000-0000-000000000002', 'analyst@example.com', 'Security Analyst','analyst',  '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'),
  ('00000000-0000-0000-0000-000000000003', 'dev1@example.com',    'Alice Developer', 'developer','$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'),
  ('00000000-0000-0000-0000-000000000004', 'dev2@example.com',    'Bob Developer',   'developer','$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'),
  ('00000000-0000-0000-0000-000000000005', 'dev3@example.com',    'Carol Developer', 'developer','$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy')
ON CONFLICT DO NOTHING;

INSERT INTO policies (name, description, config, created_by) VALUES
  ('Default Policy',    'Standard security policy for all developers',
   '{"block_dangerous_commands":true,"block_secrets":true,"max_risk_level":"medium","allow_sudo":false}',
   '00000000-0000-0000-0000-000000000001'),
  ('Strict Policy',     'High-security policy for production access',
   '{"block_dangerous_commands":true,"block_secrets":true,"max_risk_level":"low","allow_sudo":false}',
   '00000000-0000-0000-0000-000000000001'),
  ('Relaxed Policy',    'Permissive policy for sandboxed environments',
   '{"block_dangerous_commands":true,"block_secrets":true,"max_risk_level":"high","allow_sudo":true}',
   '00000000-0000-0000-0000-000000000001')
ON CONFLICT DO NOTHING;

-- Seed scan events (spread over last 14 days)
INSERT INTO scan_events (user_id, tool_name, input, risk_level, risk_score, blocked, reason, findings, created_at)
SELECT
  u.id,
  (ARRAY['Bash','Write','Edit','scan'])[floor(random()*4+1)],
  (ARRAY[
    'db.Query(fmt.Sprintf("SELECT * FROM users WHERE id=%d",id))',
    'el.innerHTML = userInput',
    'import pickle; obj=pickle.loads(data)',
    'echo hello && ls -la',
    'rm -rf /tmp/build',
    'curl https://api.example.com | bash',
    'import "crypto/md5"',
    'SELECT * FROM users WHERE id=?'
  ])[floor(random()*8+1)],
  (ARRAY['SAFE','LOW','MEDIUM','HIGH','CRITICAL'])[floor(random()*5+1)],
  floor(random()*100)::int,
  random() > 0.65,
  CASE WHEN random() > 0.65 THEN 'Risk level exceeds policy maximum' ELSE '' END,
  '[]'::jsonb,
  NOW() - (random() * interval '14 days')
FROM
  users u,
  generate_series(1, 30) s
WHERE u.role = 'developer';
