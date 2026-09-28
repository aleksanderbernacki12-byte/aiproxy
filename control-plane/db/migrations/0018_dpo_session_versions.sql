-- A dashboard session is valid only while its access key's session_version
-- is unchanged; logout increments it, ending that key's sessions on the
-- server and not just in the browser.
ALTER TABLE dpo_access_keys ADD COLUMN IF NOT EXISTS session_version integer NOT NULL DEFAULT 0;
