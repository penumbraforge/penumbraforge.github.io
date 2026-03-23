/**
 * VaultBank — Vulnerable Banking Portal
 * Penumbra Forge Security Labs — RED-02
 *
 * INTENTIONALLY VULNERABLE: Customer lookup endpoint concatenates
 * user input into SQL query strings. The actual SQL execution
 * happens client-side via sql.js (SQLite WASM) — this Worker
 * serves the application UI and simulates server responses.
 */

const RATE_LIMIT = 100;          // max requests per window
const RATE_WINDOW = 3600000;     // 1 hour in ms
const rateBuckets = new Map();

function isRateLimited(ip) {
  const now = Date.now();
  let bucket = rateBuckets.get(ip);

  if (!bucket || now - bucket.start > RATE_WINDOW) {
    bucket = { start: now, count: 0 };
    rateBuckets.set(ip, bucket);
  }

  bucket.count++;

  /* Cleanup old buckets periodically */
  if (rateBuckets.size > 10000) {
    for (const [k, v] of rateBuckets) {
      if (now - v.start > RATE_WINDOW) rateBuckets.delete(k);
    }
  }

  return bucket.count > RATE_LIMIT;
}

function rateLimitPage() {
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rate Limited</title>
<style>
  body { background:#0d1117; color:#c9d1d9; font-family:'Courier New',monospace; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }
  .box { text-align:center; max-width:480px; padding:48px 32px; border:1px solid #30363d; border-radius:12px; background:#161b22; }
  h1 { font-size:20px; color:#f85149; margin-bottom:16px; }
  p { font-size:14px; line-height:1.7; color:#8b949e; }
</style></head>
<body><div class="box">
  <h1>Rate Limited</h1>
  <p>You've been rate limited. Labs allow 100 requests per hour per IP. Try again in a few minutes.</p>
</div></body></html>`;
}

const STYLES = `
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#0d1117; color:#c9d1d9; }

  .vb-header { background:#161b22; border-bottom:1px solid #30363d; padding:14px 32px; display:flex; align-items:center; justify-content:space-between; }
  .vb-logo { font-size:20px; font-weight:700; color:#58a6ff; letter-spacing:-0.5px; text-decoration:none; }
  .vb-logo span { color:#8b949e; font-weight:300; }
  .vb-nav { display:flex; gap:20px; }
  .vb-nav a { color:#8b949e; text-decoration:none; font-size:13px; }
  .vb-nav a:hover { color:#c9d1d9; }
  .vb-nav a.active { color:#58a6ff; }
  .vb-user { display:flex; align-items:center; gap:8px; font-size:13px; color:#8b949e; }
  .vb-user-dot { width:8px; height:8px; border-radius:50%; background:#3fb950; }

  .vb-container { max-width:900px; margin:0 auto; padding:32px; }

  .vb-card { background:#161b22; border:1px solid #30363d; border-radius:10px; padding:24px; margin-bottom:20px; }
  .vb-card h2 { font-size:16px; color:#c9d1d9; margin-bottom:16px; font-weight:500; }
  .vb-card h3 { font-size:14px; color:#8b949e; margin-bottom:12px; font-weight:400; }

  .vb-balance { display:flex; gap:24px; margin-bottom:24px; }
  .vb-bal-item { background:#0d1117; border:1px solid #30363d; border-radius:8px; padding:16px 20px; flex:1; }
  .vb-bal-label { font-size:11px; color:#8b949e; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:4px; }
  .vb-bal-amount { font-size:24px; color:#c9d1d9; font-weight:300; }
  .vb-bal-amount.positive { color:#3fb950; }

  .vb-table { width:100%; border-collapse:collapse; font-size:13px; margin-bottom:16px; }
  .vb-table th { text-align:left; padding:10px 12px; color:#8b949e; font-weight:400; border-bottom:1px solid #30363d; font-size:11px; text-transform:uppercase; letter-spacing:0.5px; }
  .vb-table td { padding:10px 12px; border-bottom:1px solid #21262d; color:#c9d1d9; }
  .vb-table tr:hover { background:rgba(88,166,255,0.04); }
  .vb-amount-pos { color:#3fb950; }
  .vb-amount-neg { color:#f85149; }

  .vb-search-box { display:flex; gap:8px; }
  .vb-search-box input { flex:1; padding:10px 14px; background:#0d1117; border:1px solid #30363d; border-radius:8px; color:#c9d1d9; font-size:14px; outline:none; }
  .vb-search-box input:focus { border-color:#58a6ff; }
  .vb-search-box button { padding:10px 20px; background:#238636; color:#fff; border:none; border-radius:8px; font-size:13px; font-weight:500; cursor:pointer; }
  .vb-search-box button:hover { background:#2ea043; }

  .vb-result { margin-top:16px; padding:16px; background:#0d1117; border:1px solid #30363d; border-radius:8px; }
  .vb-result-header { font-size:12px; color:#8b949e; margin-bottom:8px; }
  .vb-error { color:#f85149; background:rgba(248,81,73,0.1); border:1px solid rgba(248,81,73,0.2); border-radius:8px; padding:12px; margin-top:12px; font-family:monospace; font-size:12px; white-space:pre-wrap; }
  .vb-data-row { display:flex; gap:16px; padding:8px 0; border-bottom:1px solid #21262d; font-size:13px; }
  .vb-data-label { color:#8b949e; min-width:120px; }
  .vb-data-value { color:#c9d1d9; }

  .vb-footer { text-align:center; padding:32px; color:#484f58; font-size:11px; border-top:1px solid #21262d; margin-top:48px; }
  .vb-status-bar { background:#161b22; border-bottom:1px solid #30363d; padding:8px 32px; font-size:11px; color:#484f58; display:flex; justify-content:space-between; }
  .vb-status-secure { color:#3fb950; display:flex; align-items:center; gap:4px; }
`;

function renderApp(url) {
  const path = new URL(url).pathname;
  const params = new URL(url).searchParams;

  if (path === '/lookup' || path === '/lookup/') {
    return renderLookup(params.get('q') || '', params.get('raw') === '1');
  }
  return renderDashboard();
}

function renderDashboard() {
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VaultBank — Dashboard</title><style>${STYLES}</style></head>
<body>
  <div class="vb-status-bar">
    <span>VaultBank Enterprise v4.2.1</span>
    <span class="vb-status-secure">&#x1f512; TLS 1.3 — 256-bit encryption</span>
  </div>
  <div class="vb-header">
    <a href="/" class="vb-logo">Vault<span>Bank</span></a>
    <div class="vb-nav">
      <a href="/" class="active">Dashboard</a>
      <a href="/lookup">Customer Lookup</a>
      <a href="#">Transfers</a>
      <a href="#">Reports</a>
      <a href="#">Settings</a>
    </div>
    <div class="vb-user"><div class="vb-user-dot"></div>Sarah Chen (Teller)</div>
  </div>
  <div class="vb-container">
    <div class="vb-balance">
      <div class="vb-bal-item">
        <div class="vb-bal-label">Total Assets Under Management</div>
        <div class="vb-bal-amount positive">$14,287,432.00</div>
      </div>
      <div class="vb-bal-item">
        <div class="vb-bal-label">Active Accounts</div>
        <div class="vb-bal-amount">2,847</div>
      </div>
      <div class="vb-bal-item">
        <div class="vb-bal-label">Today's Transactions</div>
        <div class="vb-bal-amount">143</div>
      </div>
    </div>

    <div class="vb-card">
      <h2>Recent Transactions</h2>
      <table class="vb-table">
        <thead><tr><th>Date</th><th>Account</th><th>Description</th><th>Amount</th></tr></thead>
        <tbody>
          <tr><td>2026-03-22</td><td>****4521</td><td>Wire Transfer — Acme Corp</td><td class="vb-amount-neg">-$12,500.00</td></tr>
          <tr><td>2026-03-22</td><td>****7832</td><td>Direct Deposit — Payroll</td><td class="vb-amount-pos">+$4,200.00</td></tr>
          <tr><td>2026-03-21</td><td>****4521</td><td>ACH Payment — Utilities</td><td class="vb-amount-neg">-$847.32</td></tr>
          <tr><td>2026-03-21</td><td>****1094</td><td>Check Deposit #4482</td><td class="vb-amount-pos">+$2,100.00</td></tr>
          <tr><td>2026-03-20</td><td>****7832</td><td>Vendor Payment — CloudHost Inc</td><td class="vb-amount-neg">-$599.00</td></tr>
        </tbody>
      </table>
    </div>

    <div class="vb-card">
      <h2>Quick Actions</h2>
      <div style="display:flex;gap:10px;">
        <a href="/lookup" style="padding:10px 20px;background:#238636;color:#fff;border-radius:8px;text-decoration:none;font-size:13px;">Customer Lookup</a>
        <a href="#" style="padding:10px 20px;background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:8px;text-decoration:none;font-size:13px;">New Transfer</a>
        <a href="#" style="padding:10px 20px;background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:8px;text-decoration:none;font-size:13px;">Generate Report</a>
      </div>
    </div>
  </div>
  <div class="vb-footer">© 2026 VaultBank Financial Services — FDIC Insured — Member SIPC<br>All data is simulated. This is a Penumbra Forge Security Lab.</div>
</body></html>`;
}

function renderLookup(query, raw) {
  let resultHtml = '';

  if (query) {
    // ═══════════════════════════════════════════════════
    // ⚠ INTENTIONALLY VULNERABLE — DO NOT FIX
    // The query is concatenated directly into what would be
    // a SQL query. The actual SQL execution happens client-side
    // via sql.js — this Worker returns the "query" that would
    // be executed so the client can run it in the WASM SQLite.
    // ═══════════════════════════════════════════════════
    const sqlQuery = `SELECT id, name, email, account_number, balance FROM customers WHERE name LIKE '%${query}%' OR account_number LIKE '%${query}%'`;

    resultHtml = `
      <div class="vb-result">
        <div class="vb-result-header">Query executed:</div>
        <div style="font-family:monospace;font-size:12px;color:#58a6ff;background:#0d1117;padding:10px;border-radius:6px;margin-bottom:12px;word-break:break-all;">${escHtml(sqlQuery)}</div>
        <div id="sql-results">Loading results...</div>
      </div>
      <script>
        // Initialize sql.js and run the query client-side
        if (!window.sqliteLoaded) {
          window.sqliteLoaded = true;
          var s = document.createElement('script');
          s.src = 'https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.10.3/sql-wasm.js';
          s.onload = function() { initDb(); };
          document.head.appendChild(s);
        } else if (window.db) {
          runQuery();
        }

        function initDb() {
          initSqlJs({ locateFile: function(f) { return 'https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.10.3/' + f; } }).then(function(SQL) {
            window.db = new SQL.Database();
            db.run("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT, account_number TEXT, balance REAL, ssn TEXT)");
            db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT)");
            db.run("INSERT INTO customers VALUES (1, 'John Anderson', 'j.anderson@email.com', '4521-8834-2201', 24500.00, '***-**-4521')");
            db.run("INSERT INTO customers VALUES (2, 'Maria Santos', 'm.santos@email.com', '7832-1209-5543', 18200.00, '***-**-7832')");
            db.run("INSERT INTO customers VALUES (3, 'David Kim', 'd.kim@email.com', '1094-4478-3321', 52100.00, '***-**-1094')");
            db.run("INSERT INTO customers VALUES (4, 'Lisa Chen', 'l.chen@email.com', '9921-5567-8832', 8750.00, '***-**-9921')");
            db.run("INSERT INTO customers VALUES (5, 'Robert Taylor', 'r.taylor@email.com', '3345-2211-9988', 31400.00, '***-**-3345')");
            db.run("INSERT INTO users VALUES (1, 'admin', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'administrator')");
            db.run("INSERT INTO users VALUES (2, 'sarah.chen', 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', 'teller')");
            db.run("INSERT INTO users VALUES (3, 'api_service', '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', 'service')");
            runQuery();
          });
        }

        function runQuery() {
          var resultsEl = document.getElementById('sql-results');
          try {
            var stmt = db.exec(${JSON.stringify(sqlQuery)});
            if (stmt.length === 0) {
              resultsEl.innerHTML = '<div style="color:#8b949e;font-size:13px;padding:8px 0;">No results found.</div>';
              return;
            }
            var cols = stmt[0].columns;
            var rows = stmt[0].values;
            var html = '<table class="vb-table"><thead><tr>';
            cols.forEach(function(c) { html += '<th>' + c + '</th>'; });
            html += '</tr></thead><tbody>';
            rows.forEach(function(r) {
              html += '<tr>';
              r.forEach(function(v) { html += '<td>' + (v !== null ? v : 'NULL') + '</td>'; });
              html += '</tr>';
            });
            html += '</tbody></table>';
            resultsEl.innerHTML = html;

            // Notify parent frame
            window.parent.postMessage({ type: 'sql-result', query: ${JSON.stringify(sqlQuery)}, rows: rows.length, cols: cols }, '*');
          } catch(e) {
            resultsEl.innerHTML = '<div class="vb-error">SQL Error: ' + e.message + '</div>';
            window.parent.postMessage({ type: 'sql-error', query: ${JSON.stringify(sqlQuery)}, error: e.message }, '*');
          }
        }
      <\\/script>`;
  }

  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Customer Lookup — VaultBank</title><style>${STYLES}</style></head>
<body>
  <div class="vb-status-bar">
    <span>VaultBank Enterprise v4.2.1</span>
    <span class="vb-status-secure">&#x1f512; TLS 1.3 — 256-bit encryption</span>
  </div>
  <div class="vb-header">
    <a href="/" class="vb-logo">Vault<span>Bank</span></a>
    <div class="vb-nav">
      <a href="/">Dashboard</a>
      <a href="/lookup" class="active">Customer Lookup</a>
      <a href="#">Transfers</a>
      <a href="#">Reports</a>
      <a href="#">Settings</a>
    </div>
    <div class="vb-user"><div class="vb-user-dot"></div>Sarah Chen (Teller)</div>
  </div>
  <div class="vb-container">
    <div class="vb-card">
      <h2>Customer Lookup</h2>
      <h3>Search by name or account number</h3>
      <form class="vb-search-box" action="/lookup" method="GET">
        <input type="text" name="q" value="${query.replace(/"/g, '&quot;')}" placeholder="Enter customer name or account number..." autocomplete="off">
        <button type="submit">Search</button>
      </form>
      ${resultHtml}
    </div>

    <div class="vb-card" style="opacity:0.6;">
      <h2>Access Log</h2>
      <table class="vb-table">
        <thead><tr><th>Time</th><th>User</th><th>Action</th><th>IP</th></tr></thead>
        <tbody>
          <tr><td>14:32:01</td><td>sarah.chen</td><td>Customer lookup: "${escHtml(query || '—')}"</td><td>10.0.4.22</td></tr>
          <tr><td>14:28:15</td><td>sarah.chen</td><td>Dashboard view</td><td>10.0.4.22</td></tr>
          <tr><td>14:15:03</td><td>admin</td><td>Report generated</td><td>10.0.1.5</td></tr>
        </tbody>
      </table>
    </div>
  </div>
  <div class="vb-footer">© 2026 VaultBank Financial Services — FDIC Insured — Member SIPC<br>All data is simulated. This is a Penumbra Forge Security Lab.</div>
  <script>
    document.querySelectorAll('form').forEach(function(f) {
      f.addEventListener('submit', function(e) {
        e.preventDefault();
        var q = f.querySelector('input[name=q]').value;
        window.location = '/lookup?q=' + encodeURIComponent(q);
      });
    });
  </script>
</body></html>`;
}

function escHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export default {
  async fetch(request) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET', 'Access-Control-Allow-Headers': 'Content-Type' } });
    }

    /* ── Rate limiting ── */
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (isRateLimited(ip)) {
      return new Response(rateLimitPage(), {
        status: 429,
        headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
      });
    }

    const html = renderApp(request.url);
    return new Response(html, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=UTF-8',
        'X-Powered-By': 'Express',
        'Access-Control-Allow-Origin': '*',
      },
    });
  },
};
