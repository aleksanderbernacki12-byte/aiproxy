package proxy

import "net/http"

// serveDashboard answers dashboardPath with a static HTML page — see
// dashboardPath's doc comment for the auth story. The page is a plain
// string constant, never templated with server-side data: every number
// it shows comes from the browser's own periodic fetch of statsPath,
// so there is nothing here for a request to inject into.
func (s *Server) serveDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardHTML))
}

// dashboardHTML is the entire dashboard page: inline CSS, inline JS,
// no external stylesheets/scripts/fonts — consistent with the rest of
// this project's stdlib-only, no-external-framework discipline. It
// polls GET statsPath (the same JSON stats.go/toStatsSnapshotJSON
// already serve) every few seconds and renders it into a handful of
// summary cards plus per-target/per-rule/per-client tables, each
// shown only when the snapshot actually has data for it — the same
// "omit an empty section" reasoning Snapshot.String()/PerTargetString
// already use for the printed summary.
const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>aiproxy dashboard</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #0b0d12;
    --panel: #151822;
    --border: #262b38;
    --text: #e6e8ee;
    --muted: #8b93a7;
    --accent: #5b9dff;
    --bad: #ff6b6b;
    --good: #4fd18b;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 24px;
    background: var(--bg);
    color: var(--text);
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }
  h1 { font-size: 18px; margin: 0 0 4px; }
  h2 { font-size: 14px; margin: 28px 0 10px; color: var(--muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; }
  #meta { color: var(--muted); font-size: 12px; margin-bottom: 20px; }
  #error {
    display: none;
    background: #2a1518;
    border: 1px solid var(--bad);
    color: var(--bad);
    padding: 12px 16px;
    border-radius: 8px;
    margin-bottom: 20px;
    font-size: 13px;
  }
  .cards { display: flex; flex-wrap: wrap; gap: 12px; }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 18px;
    min-width: 130px;
  }
  .card .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; }
  .card .value { font-size: 22px; font-weight: 600; margin-top: 4px; }
  .card .value.bad { color: var(--bad); }
  .card .value.good { color: var(--good); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: right; padding: 8px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; }
  th:first-child, td:first-child { text-align: left; }
  th { color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.03em; }
  tbody tr:hover { background: rgba(255,255,255,0.03); }
  .section { display: none; }
  .empty { color: var(--muted); font-size: 13px; }
</style>
</head>
<body>
<h1>aiproxy dashboard</h1>
<div id="meta">loading&hellip;</div>
<div id="error"></div>

<div class="cards" id="cards"></div>

<div class="section" id="section-target">
  <h2>Per target</h2>
  <table><thead><tr>
    <th>Target</th><th>Allowed</th><th>Blocked</th><th>Redacted</th><th>Rate limited</th><th>Token limited</th>
    <th>Cache hits</th><th>Tokens</th><th>Est. cost</th><th>Failover</th><th>Avg latency</th>
  </tr></thead><tbody id="target-body"></tbody></table>
</div>

<div class="section" id="section-rule">
  <h2>Per rule</h2>
  <table><thead><tr>
    <th>Rule</th><th>Blocked</th><th>Redacted</th><th>Resp. blocked</th><th>Resp. redacted</th>
    <th>Dry-run block</th><th>Dry-run redact</th>
  </tr></thead><tbody id="rule-body"></tbody></table>
</div>

<div class="section" id="section-client">
  <h2>Per client</h2>
  <table><thead><tr>
    <th>Client</th><th>Allowed</th><th>Blocked</th><th>Redacted</th><th>Rate limited</th><th>Token limited</th>
    <th>Tokens</th>
  </tr></thead><tbody id="client-body"></tbody></table>
</div>

<script>
(function () {
  "use strict";
  var REFRESH_MS = 3000;

  function fmtNum(n) {
    return (typeof n === "number" ? n : 0).toLocaleString();
  }
  function fmtCost(n) {
    return "$" + (typeof n === "number" ? n : 0).toFixed(4);
  }
  function fmtLatency(lat) {
    if (!lat || !lat.count) return "—";
    return ((lat.sum_seconds / lat.count) * 1000).toFixed(1) + "ms";
  }
  function el(tag, text) {
    var e = document.createElement(tag);
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function card(label, value, cls) {
    var c = el("div"); c.className = "card";
    var l = el("div", label); l.className = "label";
    var v = el("div", value); v.className = "value" + (cls ? " " + cls : "");
    c.appendChild(l); c.appendChild(v);
    return c;
  }

  function renderCards(s) {
    var cards = document.getElementById("cards");
    cards.innerHTML = "";
    cards.appendChild(card("Allowed", fmtNum(s.allowed)));
    cards.appendChild(card("Blocked", fmtNum(s.blocked), s.blocked > 0 ? "bad" : ""));
    cards.appendChild(card("Redacted", fmtNum(s.redacted)));
    cards.appendChild(card("Rate limited", fmtNum(s.rate_limited)));
    if (s.token_rate_limited) cards.appendChild(card("Token rate limited", fmtNum(s.token_rate_limited), "bad"));
    cards.appendChild(card("Cache hits", fmtNum(s.cache_hits)));
    cards.appendChild(card("Total tokens", fmtNum(s.total_tokens)));
    if (s.response_blocked) cards.appendChild(card("Resp. blocked", fmtNum(s.response_blocked), "bad"));
    if (s.response_redacted) cards.appendChild(card("Resp. redacted", fmtNum(s.response_redacted)));
    if (s.unauthorized) cards.appendChild(card("Unauthorized", fmtNum(s.unauthorized), "bad"));
    if (s.ip_denied) cards.appendChild(card("IP denied", fmtNum(s.ip_denied), "bad"));
    if (s.failover) cards.appendChild(card("Failover", fmtNum(s.failover)));
    if (typeof s.estimated_cost === "number") cards.appendChild(card("Estimated cost", fmtCost(s.estimated_cost)));
    if (typeof s.cost_budget === "number") {
      var exceeded = typeof s.estimated_cost === "number" && s.estimated_cost >= s.cost_budget;
      cards.appendChild(card("Cost budget", fmtCost(s.cost_budget) + (exceeded ? " (EXCEEDED)" : ""), exceeded ? "bad" : "good"));
    }
    cards.appendChild(card("Avg latency", fmtLatency(s.latency)));
  }

  function renderTable(sectionId, bodyId, entries, cols) {
    var section = document.getElementById(sectionId);
    var body = document.getElementById(bodyId);
    var names = Object.keys(entries || {}).sort();
    if (names.length === 0) { section.style.display = "none"; return; }
    section.style.display = "block";
    body.innerHTML = "";
    names.forEach(function (name) {
      var row = el("tr");
      row.appendChild(el("td", name));
      cols.forEach(function (c) { row.appendChild(el("td", c(entries[name]))); });
      body.appendChild(row);
    });
  }

  function renderTargets(perTarget) {
    renderTable("section-target", "target-body", perTarget, [
      function (t) { return fmtNum(t.allowed); },
      function (t) { return fmtNum(t.blocked); },
      function (t) { return fmtNum(t.redacted); },
      function (t) { return fmtNum(t.rate_limited); },
      function (t) { return fmtNum(t.token_rate_limited); },
      function (t) { return fmtNum(t.cache_hits); },
      function (t) { return fmtNum(t.total_tokens); },
      function (t) { return typeof t.estimated_cost === "number" ? fmtCost(t.estimated_cost) : "—"; },
      function (t) { return fmtNum(t.failover); },
      function (t) { return fmtLatency(t.latency); }
    ]);
  }

  function renderRules(perRule) {
    renderTable("section-rule", "rule-body", perRule, [
      function (r) { return fmtNum(r.blocked); },
      function (r) { return fmtNum(r.redacted); },
      function (r) { return fmtNum(r.response_blocked); },
      function (r) { return fmtNum(r.response_redacted); },
      function (r) { return fmtNum(r.dry_run_blocked); },
      function (r) { return fmtNum(r.dry_run_redacted); }
    ]);
  }

  function renderClients(perClient) {
    renderTable("section-client", "client-body", perClient, [
      function (c) { return fmtNum(c.allowed); },
      function (c) { return fmtNum(c.blocked); },
      function (c) { return fmtNum(c.redacted); },
      function (c) { return fmtNum(c.rate_limited); },
      function (c) { return fmtNum(c.token_rate_limited); },
      function (c) { return fmtNum(c.total_tokens); }
    ]);
  }

  function showError(msg) {
    var box = document.getElementById("error");
    box.textContent = msg;
    box.style.display = "block";
  }
  function clearError() {
    document.getElementById("error").style.display = "none";
  }

  function refresh() {
    fetch("/_aiproxy/stats", { credentials: "same-origin" })
      .then(function (resp) {
        if (!resp.ok) {
          throw new Error(
            "HTTP " + resp.status + " fetching stats" +
            (resp.status === 403 ? " — this browser's IP is not allowed to reach the proxy." : "")
          );
        }
        return resp.json();
      })
      .then(function (s) {
        clearError();
        renderCards(s);
        renderTargets(s.per_target);
        renderRules(s.per_rule);
        renderClients(s.per_client);
        document.getElementById("meta").textContent = "last updated " + new Date().toLocaleTimeString() + " — refreshing every " + (REFRESH_MS / 1000) + "s";
      })
      .catch(function (err) {
        // A plain network-level failure here (not caught by the !resp.ok
        // branch above, which only runs once a Response is actually
        // delivered to JS) is most likely proxy_api_key being set: browsers
        // intercept an HTTP 407 response at the network stack itself,
        // since that status is conventionally reserved for the browser's
        // own configured forward proxy, not an origin server's response —
        // so fetch() never delivers a Response for it at all, just a
        // generic failure. Use curl or the Prometheus endpoint instead in
        // that case.
        showError(
          "Failed to load stats (" + err.message + "). If this proxy requires " +
          "Proxy-Authorization, that's expected — a browser can't attach it here. " +
          "Use curl or the Prometheus endpoint instead."
        );
        document.getElementById("meta").textContent = "last update failed at " + new Date().toLocaleTimeString();
      });
  }

  refresh();
  setInterval(refresh, REFRESH_MS);
})();
</script>
</body>
</html>
`
