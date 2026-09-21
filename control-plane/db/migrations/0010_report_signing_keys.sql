CREATE TABLE IF NOT EXISTS report_signing_keys (
  key_id varchar(64) PRIMARY KEY,
  public_key_pem text NOT NULL,
  first_used_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS report_signing_keys_last_used_idx
  ON report_signing_keys (last_used_at DESC, key_id);
