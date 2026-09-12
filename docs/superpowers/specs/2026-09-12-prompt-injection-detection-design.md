# Prompt injection detection — design spec

Date: 2026-09-12
Status: approved, pending implementation plan

## Purpose

aiproxy's existing built-in rules (`internal/cli`'s `builtinRules`) catch leaked
secrets — API keys, tokens, private key material — using precise, low-ambiguity
regex formats (`AKIA[0-9A-Z]{16}` can barely ever false-positive). This feature
adds a second, adjacent category of built-in detection: known prompt-injection
and jailbreak phrasings in the text flowing through the proxy, in either
direction. This is a fundamentally different kind of pattern than a secret key
— natural-language phrasing is inherently ambiguous, so false positives are a
real, accepted cost of this category in a way they essentially aren't for the
existing secret patterns. That difference in risk profile is the reason this
feature also closes a gap in the existing mechanism (no dry-run support for any
built-in rule, secrets included) rather than just adding patterns to it as-is.

## Scope for v1

- Five named heuristics (see Patterns below), each a plain `rules.BodyRegexRule`
  — no new detection mechanism, no scoring/composite matching. Precedent
  established at brainstorming time: aiproxy's only existing multi-signal
  security check (`internal/anomaly`) deliberately lives *outside* the rules
  engine as its own package with its own state; a composite prompt-injection
  matcher would need the same treatment (a new `Matcher` interface in
  `internal/rules`) and was explicitly rejected as out of scope for v1 in favor
  of the simpler, zero-engine-change regex-list approach every existing secret
  rule already uses.
- Applies bidirectionally (request and response) for free, since built-in rules
  share the same `bodyRules` list `Evaluate`/`EvaluateResponse` both read —
  not a new decision, just the existing mechanism's natural consequence.
- All five default to `Block`, same as every secret rule.
- `builtin_rule_actions` gains a new accepted value, `"dry_run"`, alongside the
  existing `"block"`/`"redact"`/`"off"` — applies uniformly to **every**
  built-in rule (secrets included), not just the five new ones, closing an
  existing gap the brainstorming session explicitly surfaced: today only
  `custom_rules`/`path_rules` support dry-run at all.
- No new top-level config field. No per-target/per-key scoping decisions beyond
  what `BodyRegexRule.Targets`/`Keys` already provide for free (unused by
  default, same as every existing built-in).

## Patterns

Five new named rules, mirroring `builtinRules`' existing `{name, pattern}`
shape exactly, added to a new, separate `builtinPromptInjectionRules` slice
(kept apart from `builtinRules` in code — and in the README's own table —
since they are a conceptually distinct catalog: secrets vs. injection
phrasings; both catalogs are merged into one combined name-space for
`builtin_rule_actions` validation purposes, since that config knob already
covers "any built-in rule," not "any built-in secret rule").

| Rule name | Pattern (Go `regexp`, RE2) | Catches |
|---|---|---|
| `prompt-injection-ignore-instructions` | `(?i)(ignore\|disregard\|forget)\s+(all\s+)?(previous\|prior\|above\|preceding)\s+(instructions?\|prompts?\|rules?\|guidelines?)` | "ignore previous instructions", "disregard all prior prompts" |
| `prompt-injection-system-exfiltration` | `(?i)(repeat\|reveal\|print\|show\|output)\s+(your\s+)?(system\s+prompt\|initial\s+instructions?\|the\s+instructions?\s+above)` | "reveal your system prompt", "print the instructions above" |
| `prompt-injection-role-override` | `(?i:you\s+are\s+now\s+(in\s+)?(developer\s+mode\|an?\s+unrestricted\s+AI\|jailbroken))\|you\s+are\s+now\s+DAN\b` | "you are now in developer mode", "you are now DAN" |
| `prompt-injection-fake-system-turn` | `\[?(SYSTEM\|ADMIN\|ROOT)\]?\s*:\s*(override\|new\s+instructions?)` — deliberately case-**sensitive** | injected fake `[SYSTEM]: override` / `ADMIN: new instructions` turns |
| `prompt-injection-restriction-bypass` | `(?i)(bypass\|override\|disable)\s+(your\s+)?(safety\|content)\s+(guidelines?\|filters?\|restrictions?)` | "bypass your safety guidelines", "disable content filters" |

Two deliberate, non-obvious regex design choices, both to control false
positives on ordinary text:

- **`prompt-injection-role-override`'s "DAN" alternative is case-sensitive**,
  scoped separately from the rest of that rule's case-insensitive
  alternatives via Go regexp's `(?i:...)` flag-scoped group (one single
  `*regexp.Regexp`, not two — `BodyRegexRule.Pattern` only has room for one).
  "DAN" (Do Anything Now) is a well-known, specific jailbreak persona name in
  prompt injection research; matching it case-insensitively would also fire on
  the ordinary given name "Dan" ("you are now Dan, my new assistant").
  Requiring the literal all-caps form keeps the well-known jailbreak signal
  while making the name collision require an unusual (all-caps) spelling to
  trigger.
- **`prompt-injection-fake-system-turn` is entirely case-sensitive** (no
  `(?i)`), unlike every other rule in this feature. A forged system-level
  delimiter is typically written in a visually distinct way (all-caps and/or
  bracketed) specifically so it reads as authoritative to the model; ordinary
  lowercase text containing "system:" (a JSON key, "system: online" status
  text, etc.) is extremely common and would otherwise dominate false positives
  on this pattern specifically.

None of these patterns can be made false-positive-proof — natural language is
inherently ambiguous, unlike a secret key's fixed format. This is the direct
reason `dry_run` is being added to `builtin_rule_actions` in the same release:
an operator can watch real traffic against these patterns before trusting them
enough to actually block on.

## Config surface

No schema change — `builtin_rule_actions` stays a `map[string]string`. New
accepted value:

```jsonc
{
  "builtin_rule_actions": {
    "prompt-injection-ignore-instructions": "dry_run",
    "aws-access-key": "redact"
  }
}
```

`resolveBuiltinRuleActions` (`internal/cli/cli.go`) grows a third return value,
`dryRun map[string]bool`, populated exactly like the existing `off` map:
`raw == "dry_run"` sets `dryRun[name] = true` and leaves `actions[name]` at its
default (`rules.Block`) — `dry_run` and `redact`/`block` are mutually
exclusive per rule in this config shape (a single string value), matching how
`"off"` already works; a rule can't simultaneously be "dry-run as redact" vs
"dry-run as block" without a schema change, which is out of scope for v1 since
the dry-run log/stats/webhook output already reports which rule matched
regardless of what its live action would have been.

`buildEngine` sets `BodyRegexRule.DryRun: dryRun[b.name]` when registering
every built-in rule (both catalogs) — the existing `Engine`/`stats` dry-run
machinery (`DryRunMatch`, `RecordDryRunBlock`/`RecordDryRunRedact`,
`dry_run_block`/`dry_run_redact` webhook events) requires zero changes, since
it already keys purely by rule name and has no notion of "custom vs. built-in."

Validation error message extended: `"Invalid action for built-in rule %s: must
be \"block\", \"redact\", \"off\", or \"dry_run\", got %q"` (replacing the
current three-option message) — the single shared function `runValidate` and
`buildEngine` both already call, so there is no split-brain risk to reason
about here the way there was for `semantic_cache_threshold`'s two independent
validation paths.

## Code organization

- `internal/cli/cli.go`: five new compiled `regexp.Regexp` package vars
  (`ignorePreviousInstructionsPattern`, etc., matching the existing
  `awsAccessKeyPattern`-style naming), a new `builtinPromptInjectionRules`
  slice, the existing anonymous `struct{name string; pattern *regexp.Regexp}`
  type promoted to a named type `builtinRuleDef` (a small, mechanical,
  behavior-preserving rename needed so `builtinRules` and
  `builtinPromptInjectionRules` can share one type and be combined into one
  name-space by a new `allBuiltinRules() []builtinRuleDef` helper — used by
  `builtinRuleNames`, `resolveBuiltinRuleActions`, and `buildEngine`'s
  registration loop instead of `builtinRules` directly).
- `internal/cli/promptinjection_internal_test.go` (new, `package cli` —
  white-box): direct tests against the five actual compiled pattern
  variables — matching-known-phrasings and NOT-matching-adjacent-benign-text
  for each. This is a deliberately **new** testing precedent for the `cli`
  package specifically (today 100% `package cli_test`, black-box only), but
  not a new precedent for the *project* — `internal/proxy` already keeps both
  a black-box (`coalesce_test.go`) and white-box (`drainmode_test.go`) split
  for exactly this reason (testing something unexported directly). It exists
  because the pre-existing secret patterns have **no** direct regex-level test
  coverage anywhere in the repo today (confirmed by inspection — `cli_test.go`
  never references `AKIA`/`sk-ant-`/etc., and `proxy_test.go`'s AWS-key-shaped
  tests exercise the rules *engine* using their own separately-retyped inline
  pattern, never the real `cli.go` variable) — an accepted gap for a rigid,
  unambiguous key format, but not an acceptable one for a natural-language
  heuristic being shipped with `Block` as its default action.
- `internal/cli/cli_test.go`: extend the existing `builtin_rule_actions`
  validation tests with `dry_run` cases (valid value accepted; still-invalid
  strings still rejected with the updated message); one test proving
  `dry_run` works on a pre-existing *secret* rule too, not just an injection
  rule, to prove the closed gap is general.
- `internal/proxy/promptinjection_test.go` (new, `package proxy_test` —
  black-box, mirrors the existing AWS-key-style integration tests): real HTTP
  round-trip tests proving (a) each of the five patterns actually blocks a
  request built through the real `cli.Execute`-driven engine (not a
  hand-retyped pattern copy, closing the same gap described above at the
  integration level) when the corresponding rule fires, (b) `dry_run` lets a
  request carrying a matching phrase through unblocked while still
  incrementing `dry_run_blocked`/logging/webhook, (c) the response direction
  is covered (an upstream response containing a matching phrase is also
  caught, proving the bidirectional-for-free claim).
- `README.md`: new `## Built-in prompt-injection patterns` section, own table,
  right after `## Built-in secret patterns`, explicitly noting the
  false-positive trade-off and pointing at `dry_run` as the way to evaluate a
  pattern against real traffic before trusting it to block.

## Testing plan

- `internal/cli/promptinjection_internal_test.go`: for each of the 5 patterns,
  at least one real matching phrase and at least one adjacent-but-benign
  phrase that must NOT match (e.g. "ignore previous instructions" matches;
  "the ignore-list contains three previous entries" must not; "you are now
  Dan" must not match role-override while "you are now DAN" does).
- `internal/cli/cli_test.go`: `dry_run` accepted as a `builtin_rule_actions`
  value (construction succeeds, `aiproxy validate` reports success and shows
  it in the summary); an unrelated invalid string still rejected with the
  four-option message; `dry_run` applied to `aws-access-key` (a pre-existing
  secret rule) proven to also work, not just the new injection rules.
- `internal/proxy/promptinjection_test.go`: full HTTP round-trip per pattern
  (block on match, 200 on non-matching traffic), one `dry_run` end-to-end test
  (request forwards normally, `dry_run_blocked` stat/log/webhook fire), one
  response-direction test (upstream reply containing a matching phrase is
  blocked the same way a request would be).
