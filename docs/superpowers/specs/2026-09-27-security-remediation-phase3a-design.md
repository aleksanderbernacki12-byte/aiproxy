# Security remediation, Phase 3A — private, atomic disk cache

Date: 2026-09-27
Status: approved (owner delegated Phase 3 decisions, 2026-09-27)

## Purpose

Closes review finding #13 of `docs/reviews/2026-09-12-v0.74.1-system-review.md`.
Phase 3 is split like Phase 2: 3A (#13, this), 3B (#12 resource limits),
3C (#14 per-request config snapshot).

Problems in `internal/cache`:

1. The directory is created `0755` and entries written `0644`: with a normal
   umask other local users can read cached LLM responses.
2. `Set` writes the final file in place, so a concurrent `Get` can read a
   half-written response.
3. `Get`'s expiry path stats, then removes the file and index entry outside
   the lock. A `Set` landing in between has its fresh entry deleted, and the
   size index can drift from the files on disk.

## Design

- **Permissions.** `New` creates the directory `0700` and then `chmod`s it to
  `0700`, so a directory created by an older version is migrated.
  `loadExisting` `chmod`s every existing entry to `0600`. New entries are
  created `0600`. Permission checks in tests are skipped on Windows, where
  POSIX mode bits do not apply (same convention as the telemetry tests).
- **Atomic writes.** `Set` writes to `os.CreateTemp(dir, ".tmp-*")` (created
  `0600`), closes it, then renames it over the final path. Readers see the old
  entry or the new one, never a partial one. `loadExisting` removes leftover
  `.tmp-*` files from a crash and never indexes them.
- **Consistent locking.** The slow part (dumping and writing the temp file)
  stays unlocked. The rename plus index update, the expiry removal plus index
  update, eviction, and `Clear` all run under `c.mu`. `Get`'s expiry path
  re-stats under the lock and only removes the file if it is still expired, so
  a fresh concurrent `Set` is never deleted.
- **Validation warnings.** `aiproxy validate` warns when the cache is enabled
  with no `cache_ttl_seconds` or no `cache_max_size_bytes`, since both default
  to unbounded.

Out of scope: a configurable cache directory (still `.aiproxy_cache` in the
working directory) and encryption at rest.

## Testing

- New directory is `0700`, new entry `0600` (non-Windows).
- An existing `0755` directory with a `0644` entry is migrated by `New`.
- Leftover `.tmp-*` files are removed by `New` and not counted in size.
- 8 readers `Get` while a writer repeatedly `Set`s two different bodies: every
  hit parses and equals one of the two bodies (never partial), under `-race`.
- `validate` warns for cache enabled without TTL and without size cap.
- Existing cache tests keep passing.
