CREATE TABLE IF NOT EXISTS dashboard_login_attempts (
  source_hash varchar(64) PRIMARY KEY,
  window_started_at timestamptz NOT NULL,
  failures integer NOT NULL CHECK (failures >= 0 AND failures <= 5),
  blocked_until timestamptz,
  updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS dashboard_login_attempts_cleanup_idx
  ON dashboard_login_attempts (updated_at);
