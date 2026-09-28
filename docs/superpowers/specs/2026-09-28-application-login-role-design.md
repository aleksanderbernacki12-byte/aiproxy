# Separate application login role

Date: 2026-09-28
Status: approved (owner, 2026-09-28)

## Problem

The application logs in as the database owner and switches to the restricted
role `aiproxy_app_<hash>` (0019) on every connection. Row-level security does
not apply to the owner, so if the switch fails the connection runs with full
access. Readiness reports `NOT_READY` in that case, but the database itself
does not stop it.

## Design

- `scripts/migrate.mjs`, after applying migrations, ensures the login role
  `<database name>_login` when `APP_DATABASE_PASSWORD` is set (at least 32
  printable ASCII characters). The name is readable so Compose and operators
  can write it into the connection string, and unique because database names
  are unique in a cluster. Re-running updates the password, which is how it is
  rotated; an existing role of that name that is not a member of the
  application role is refused, never taken over.
- The role is `LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE`
  and only a member of `aiproxy_app_<hash>`. Without the role switch it cannot
  read or write any table, so a failed switch denies every query instead of
  bypassing row-level security.
- The password is sent as a SCRAM-SHA-256 verifier computed client-side, so the
  plaintext never appears in server statement logs.
- Logic lives in `scripts/lib/application-login.mjs` so tests reuse it.
- The application needs no code change: its `DATABASE_URL` points at the login
  role; migrations and the operator CLI scripts keep the owner URL.
- Compose requires `APP_DATABASE_PASSWORD`, passes it to the migration service
  and connects the app as the login role.
- Readiness still accepts an owner login (no forced migration of existing
  deployments); the README recommends the login role.

## Verification

- Integration: the login role without a switch is denied table access; after
  the switch `current_user` is the application role and tenant isolation holds;
  re-running with a new password rotates it.
- E2E runs the whole application as the login role.
- The shared-cluster test creates a login role per database.
