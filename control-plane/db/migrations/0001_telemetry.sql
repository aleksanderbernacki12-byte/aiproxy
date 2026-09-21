DO $$ BEGIN
  CREATE TYPE telemetry_verification_status AS ENUM (
    'VERIFIED',
    'INVALID_SIGNATURE',
    'COMPROMISED_CHAIN'
  );
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS telemetry_public_keys (
  key_id varchar(64) PRIMARY KEY,
  public_key_pem text NOT NULL,
  label varchar(160),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);

CREATE TABLE IF NOT EXISTS telemetry_event_ids (
  event_id uuid PRIMARY KEY,
  received_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS telemetry_buffer (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid NOT NULL UNIQUE REFERENCES telemetry_event_ids(event_id),
  event_timestamp timestamptz NOT NULL,
  key_id varchar(64) NOT NULL,
  payload jsonb NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  processing_attempts integer NOT NULL DEFAULT 0,
  last_error text
);

CREATE INDEX IF NOT EXISTS telemetry_buffer_chain_order_idx
  ON telemetry_buffer (key_id, event_timestamp, received_at, id);

CREATE TABLE IF NOT EXISTS telemetry_chain_heads (
  key_id varchar(64) PRIMARY KEY,
  latest_event_hash varchar(64) NOT NULL,
  sequence bigint NOT NULL,
  last_event_timestamp timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS telemetry_events (
  id bigserial PRIMARY KEY,
  event_id uuid NOT NULL UNIQUE REFERENCES telemetry_event_ids(event_id),
  event_timestamp timestamptz NOT NULL,
  client_id_hash varchar(64) NOT NULL,
  application_id varchar(160) NOT NULL,
  routing jsonb NOT NULL,
  compliance_flags jsonb NOT NULL,
  metrics jsonb NOT NULL,
  hash_algorithm varchar(32) NOT NULL,
  request_response_hash varchar(64) NOT NULL,
  previous_event_hash varchar(64) NOT NULL,
  event_hash varchar(64) NOT NULL,
  signature_algorithm varchar(64) NOT NULL,
  key_id varchar(64) NOT NULL,
  signature text NOT NULL,
  status telemetry_verification_status NOT NULL,
  status_reason text,
  chain_sequence bigint,
  received_at timestamptz NOT NULL,
  processed_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS telemetry_events_chain_idx
  ON telemetry_events (key_id, chain_sequence);

CREATE INDEX IF NOT EXISTS telemetry_events_status_timestamp_idx
  ON telemetry_events (status, event_timestamp DESC);
