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
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#f0fdf4; color:#1f2937; }

  .vb-topbar { background:#022c22; color:#6ee7b7; padding:8px 32px; font-size:11px; display:flex; justify-content:space-between; align-items:center; }
  .vb-topbar-secure { display:flex; align-items:center; gap:6px; }
  .vb-topbar-secure svg { width:12px; height:12px; }

  .vb-header { background:#fff; border-bottom:1px solid #d1fae5; padding:0 32px; display:flex; align-items:center; justify-content:space-between; height:64px; position:sticky; top:0; z-index:100; box-shadow:0 1px 3px rgba(0,0,0,0.04); }
  .vb-header-left { display:flex; align-items:center; gap:32px; }
  .vb-logo { display:flex; align-items:center; gap:10px; text-decoration:none; }
  .vb-logo-icon { width:34px; height:34px; border-radius:8px; background:linear-gradient(135deg,#059669,#10b981); display:flex; align-items:center; justify-content:center; }
  .vb-logo-icon svg { width:20px; height:20px; }
  .vb-logo-text { font-size:20px; font-weight:700; color:#065f46; letter-spacing:-0.5px; }
  .vb-logo-text span { color:#059669; }
  .vb-nav { display:flex; gap:4px; }
  .vb-nav a { color:#6b7280; text-decoration:none; font-size:14px; font-weight:500; padding:8px 14px; border-radius:8px; transition:all 150ms; }
  .vb-nav a:hover { color:#065f46; background:#ecfdf5; }
  .vb-nav a.active { color:#059669; background:#ecfdf5; }
  .vb-user { display:flex; align-items:center; gap:10px; font-size:13px; color:#6b7280; }
  .vb-user-avatar { width:34px; height:34px; border-radius:50%; background:#d1fae5; color:#059669; display:flex; align-items:center; justify-content:center; font-size:12px; font-weight:700; }
  .vb-user-dot { width:8px; height:8px; border-radius:50%; background:#10b981; }

  .vb-container { max-width:1060px; margin:0 auto; padding:24px 24px 0; }

  .vb-card { background:#fff; border:1px solid #d1fae5; border-radius:12px; padding:24px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,0.04); }
  .vb-card h2 { font-size:17px; color:#065f46; margin-bottom:4px; font-weight:600; }
  .vb-card h3 { font-size:13px; color:#6b7280; margin-bottom:16px; font-weight:400; }

  .vb-balance { display:flex; gap:16px; margin-bottom:24px; }
  .vb-bal-item { background:#ecfdf5; border:1px solid #d1fae5; border-radius:10px; padding:18px 20px; flex:1; }
  .vb-bal-label { font-size:11px; color:#6b7280; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:6px; }
  .vb-bal-amount { font-size:26px; color:#065f46; font-weight:700; }
  .vb-bal-amount.positive { color:#059669; }

  .vb-table { width:100%; border-collapse:collapse; font-size:13px; margin-bottom:16px; }
  .vb-table th { text-align:left; padding:10px 12px; color:#6b7280; font-weight:500; border-bottom:2px solid #d1fae5; font-size:11px; text-transform:uppercase; letter-spacing:0.5px; }
  .vb-table td { padding:10px 12px; border-bottom:1px solid #f0fdf4; color:#1f2937; }
  .vb-table tr:hover { background:#f0fdf4; }
  .vb-amount-pos { color:#059669; font-weight:600; }
  .vb-amount-neg { color:#ef4444; font-weight:600; }

  .vb-search-box { display:flex; gap:8px; }
  .vb-search-box input { flex:1; padding:12px 16px; background:#f9fafb; border:2px solid #d1fae5; border-radius:10px; color:#1f2937; font-size:15px; outline:none; transition:border-color 200ms,box-shadow 200ms; }
  .vb-search-box input:focus { border-color:#059669; box-shadow:0 0 0 3px rgba(5,150,105,0.15); background:#fff; }
  .vb-search-box button { padding:12px 24px; background:#059669; color:#fff; border:none; border-radius:10px; font-size:14px; font-weight:600; cursor:pointer; transition:background 150ms; }
  .vb-search-box button:hover { background:#047857; }

  .vb-result { margin-top:16px; padding:16px; background:#f0fdf4; border:1px solid #d1fae5; border-radius:10px; }
  .vb-result-header { font-size:12px; color:#6b7280; margin-bottom:8px; }
  .vb-error { color:#ef4444; background:#fef2f2; border:1px solid #fecaca; border-radius:8px; padding:12px; margin-top:12px; font-family:monospace; font-size:12px; white-space:pre-wrap; }
  .vb-data-row { display:flex; gap:16px; padding:8px 0; border-bottom:1px solid #d1fae5; font-size:13px; }
  .vb-data-label { color:#6b7280; min-width:120px; }
  .vb-data-value { color:#1f2937; }

  .vb-footer { text-align:center; padding:32px 24px; color:#9ca3af; font-size:12px; border-top:1px solid #d1fae5; margin-top:48px; background:#fff; }
  .vb-status-badge { display:inline-flex; align-items:center; gap:6px; padding:4px 12px; background:#ecfdf5; border:1px solid #a7f3d0; border-radius:20px; font-size:11px; color:#059669; font-weight:500; }
  .vb-quick-actions { display:flex; gap:10px; flex-wrap:wrap; }
  .vb-quick-actions a { padding:10px 20px; border-radius:10px; text-decoration:none; font-size:13px; font-weight:500; transition:all 150ms; }
  .vb-quick-actions a.primary { background:#059669; color:#fff; }
  .vb-quick-actions a.primary:hover { background:#047857; }
  .vb-quick-actions a.secondary { background:#f9fafb; color:#374151; border:1px solid #e5e7eb; }
  .vb-quick-actions a.secondary:hover { background:#f3f4f6; }

  .vb-audit-log { opacity:0.6; }
  .vb-audit-log:hover { opacity:1; transition:opacity 200ms; }
`;

function renderApp(url) {
  const path = new URL(url).pathname;
  const params = new URL(url).searchParams;

  if (path === '/lookup' || path === '/lookup/') {
    return renderLookup(params.get('q') || '', params.get('raw') === '1');
  }
  if (path === '/transfers' || path === '/transfers/') {
    return renderTransfers();
  }
  if (path === '/settings' || path === '/settings/') {
    return renderSettings();
  }
  return renderDashboard();
}

function shell(title, activePage, content) {
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} — VaultBank</title><style>${STYLES}</style></head>
<body>
  <div class="vb-topbar">
    <span>VaultBank Enterprise v4.2.1 — Banking Portal</span>
    <div class="vb-topbar-secure">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
      TLS 1.3 — 256-bit encryption — FDIC Insured
    </div>
  </div>
  <div class="vb-header">
    <div class="vb-header-left">
      <a href="/" class="vb-logo">
        <div class="vb-logo-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg></div>
        <div class="vb-logo-text">Vault<span>Bank</span></div>
      </a>
      <div class="vb-nav">
        <a href="/"${activePage==='dashboard'?' class="active"':''}>Dashboard</a>
        <a href="/lookup"${activePage==='lookup'?' class="active"':''}>Customer Lookup</a>
        <a href="/transfers"${activePage==='transfers'?' class="active"':''}>Transfers</a>
        <a href="/settings"${activePage==='settings'?' class="active"':''}>Settings</a>
      </div>
    </div>
    <div class="vb-user">
      <div class="vb-user-dot"></div>
      <span>Sarah Chen (Teller)</span>
      <div class="vb-user-avatar">SC</div>
    </div>
  </div>
  <div class="vb-container">${content}</div>
  <div class="vb-footer">
    &copy; 2026 VaultBank Financial Services — FDIC Insured — Member SIPC
    <div style="margin-top:4px;">All data is simulated. This is a Penumbra Forge Security Lab.</div>
  </div>
  <script>
  document.cookie="session=eyJ1c2VyIjoic2FyYWguY2hlbiIsInJvbGUiOiJ0ZWxsZXIifQ==;path=/";

  /* ── Alert override ── */
  var _origAlert = window.alert;
  window.alert = function(msg) {
    try {
      window.parent.postMessage({ type: 'xss-fired', executed: true, payload: String(msg) }, '*');
    } catch(e) {}
  };

  /* ── Cookie access detection ── */
  (function() {
    var _origCookie = document.cookie;
    var _reported = false;
    Object.defineProperty(document, 'cookie', {
      get: function() {
        if (!_reported) {
          _reported = true;
          try {
            window.parent.postMessage({ type: 'cookie-accessed', value: _origCookie }, '*');
          } catch(e) {}
        }
        return _origCookie;
      },
      set: function(v) { /* allow sets but don't persist */ }
    });
  })();

  /* ── Navigation tracking ── */
  try {
    var params = new URLSearchParams(window.location.search);
    window.parent.postMessage({
      type: 'vaultbank-nav',
      path: window.location.pathname,
      query: params.get('q') || '',
      url: window.location.href
    }, '*');
  } catch(e) {}

  /* ── Form submission ── */
  document.querySelectorAll('form').forEach(function(f) {
    f.addEventListener('submit', function(e) {
      e.preventDefault();
      var q = f.querySelector('input[name=q]');
      if (q) window.location = '/lookup?q=' + encodeURIComponent(q.value);
    });
  });
  </script>
</body></html>`;
}

function renderDashboard() {
  return shell('Dashboard', 'dashboard', `
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
        <thead><tr><th>Date</th><th>Account</th><th>Description</th><th>Amount</th><th>Status</th></tr></thead>
        <tbody>
          <tr><td>2026-03-22</td><td>****4521</td><td>Wire Transfer — Acme Corp</td><td class="vb-amount-neg">-$12,500.00</td><td><span class="vb-status-badge">Completed</span></td></tr>
          <tr><td>2026-03-22</td><td>****7832</td><td>Direct Deposit — Payroll</td><td class="vb-amount-pos">+$4,200.00</td><td><span class="vb-status-badge">Completed</span></td></tr>
          <tr><td>2026-03-21</td><td>****4521</td><td>ACH Payment — Utilities</td><td class="vb-amount-neg">-$847.32</td><td><span class="vb-status-badge">Completed</span></td></tr>
          <tr><td>2026-03-21</td><td>****1094</td><td>Check Deposit #4482</td><td class="vb-amount-pos">+$2,100.00</td><td><span class="vb-status-badge">Completed</span></td></tr>
          <tr><td>2026-03-20</td><td>****7832</td><td>Vendor Payment — CloudHost Inc</td><td class="vb-amount-neg">-$599.00</td><td><span class="vb-status-badge">Completed</span></td></tr>
        </tbody>
      </table>
    </div>

    <div class="vb-card">
      <h2>Quick Actions</h2>
      <div class="vb-quick-actions">
        <a href="/lookup" class="primary">Customer Lookup</a>
        <a href="/transfers" class="secondary">New Transfer</a>
        <a href="#" class="secondary">Generate Report</a>
        <a href="#" class="secondary">Account Alerts</a>
      </div>
    </div>
  `);
}

function renderTransfers() {
  return shell('Transfers', 'transfers', `
    <div class="vb-card">
      <h2>New Transfer</h2>
      <h3>Initiate a wire transfer or ACH payment</h3>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;">
        <div>
          <label style="display:block;font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">From Account</label>
          <select style="width:100%;padding:12px 16px;border:2px solid #d1fae5;border-radius:10px;font-size:14px;color:#1f2937;background:#f9fafb;outline:none;">
            <option>****4521 — Checking ($24,500.00)</option>
            <option>****7832 — Savings ($18,200.00)</option>
          </select>
        </div>
        <div>
          <label style="display:block;font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">To Account</label>
          <input type="text" placeholder="Enter routing + account number" style="width:100%;padding:12px 16px;border:2px solid #d1fae5;border-radius:10px;font-size:14px;color:#1f2937;background:#f9fafb;outline:none;">
        </div>
      </div>
      <div style="margin-bottom:16px;">
        <label style="display:block;font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">Amount</label>
        <input type="text" placeholder="$0.00" style="width:200px;padding:12px 16px;border:2px solid #d1fae5;border-radius:10px;font-size:14px;color:#1f2937;background:#f9fafb;outline:none;">
      </div>
      <button style="padding:12px 28px;background:#059669;color:#fff;border:none;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;">Submit Transfer</button>
    </div>

    <div class="vb-card">
      <h2>Pending Transfers</h2>
      <table class="vb-table">
        <thead><tr><th>Date</th><th>Recipient</th><th>Amount</th><th>Status</th></tr></thead>
        <tbody>
          <tr><td>2026-03-22</td><td>Acme Corp (****8832)</td><td class="vb-amount-neg">-$5,000.00</td><td><span style="color:#f59e0b;background:#fffbeb;padding:3px 10px;border-radius:6px;font-size:11px;font-weight:600;">Pending</span></td></tr>
        </tbody>
      </table>
    </div>
  `);
}

function renderSettings() {
  return shell('Security Settings', 'settings', `
    <div class="vb-card">
      <h2>Security Settings</h2>
      <h3>Manage authentication and access controls</h3>
      <div style="border-bottom:1px solid #f0fdf4;padding:16px 0;display:flex;justify-content:space-between;align-items:center;">
        <div>
          <div style="font-weight:600;font-size:14px;color:#065f46;">Two-Factor Authentication</div>
          <div style="font-size:12px;color:#6b7280;">SMS verification enabled</div>
        </div>
        <span style="color:#059669;font-weight:600;font-size:12px;background:#ecfdf5;padding:4px 12px;border-radius:6px;">Enabled</span>
      </div>
      <div style="border-bottom:1px solid #f0fdf4;padding:16px 0;display:flex;justify-content:space-between;align-items:center;">
        <div>
          <div style="font-weight:600;font-size:14px;color:#065f46;">Session Timeout</div>
          <div style="font-size:12px;color:#6b7280;">Auto-logout after inactivity</div>
        </div>
        <span style="font-size:13px;color:#374151;">15 minutes</span>
      </div>
      <div style="padding:16px 0;display:flex;justify-content:space-between;align-items:center;">
        <div>
          <div style="font-weight:600;font-size:14px;color:#065f46;">Login Notifications</div>
          <div style="font-size:12px;color:#6b7280;">Email alerts on new device login</div>
        </div>
        <span style="color:#059669;font-weight:600;font-size:12px;background:#ecfdf5;padding:4px 12px;border-radius:6px;">Enabled</span>
      </div>
    </div>
    <div class="vb-card">
      <h2>Active Sessions</h2>
      <table class="vb-table">
        <thead><tr><th>Device</th><th>IP Address</th><th>Location</th><th>Last Active</th></tr></thead>
        <tbody>
          <tr><td>Chrome — macOS</td><td>10.0.4.22</td><td>Portland, OR</td><td>Now</td></tr>
          <tr><td>Firefox — Windows</td><td>10.0.3.15</td><td>Seattle, WA</td><td>2 hours ago</td></tr>
        </tbody>
      </table>
    </div>
  `);
}

function renderLookup(query, raw) {
  let resultHtml = '';

  if (query) {
    // ═══════════════════════════════════════════════════
    // INTENTIONALLY VULNERABLE — DO NOT FIX
    // The query is concatenated directly into what would be
    // a SQL query. The actual SQL execution happens client-side
    // via sql.js — this Worker returns the "query" that would
    // be executed so the client can run it in the WASM SQLite.
    // ═══════════════════════════════════════════════════
    const sqlQuery = `SELECT id, name, email, account_number, balance FROM customers WHERE name LIKE '%${query}%' OR account_number LIKE '%${query}%'`;

    resultHtml = `
      <div class="vb-result">
        <div class="vb-result-header">Query executed:</div>
        <div style="font-family:monospace;font-size:12px;color:#059669;background:#ecfdf5;padding:12px;border-radius:8px;margin-bottom:12px;word-break:break-all;border:1px solid #d1fae5;">${escHtml(sqlQuery)}</div>
        <div id="sql-results"><div style="color:#6b7280;font-size:13px;padding:12px;">Loading results...</div></div>
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
              resultsEl.innerHTML = '<div style="color:#6b7280;font-size:13px;padding:12px;">No results found.</div>';
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
      <\/script>`;
  }

  return shell('Customer Lookup', 'lookup', `
    <div class="vb-card">
      <h2>Customer Lookup</h2>
      <h3>Search by name or account number</h3>
      <form class="vb-search-box" action="/lookup" method="GET">
        <input type="text" name="q" value="${query.replace(/"/g, '&quot;')}" placeholder="Enter customer name or account number..." autocomplete="off">
        <button type="submit">Search</button>
      </form>
      ${resultHtml}
    </div>

    <div class="vb-card vb-audit-log">
      <h2>Access Log</h2>
      <table class="vb-table">
        <thead><tr><th>Time</th><th>User</th><th>Action</th><th>IP Address</th></tr></thead>
        <tbody>
          <tr><td>14:32:01</td><td>sarah.chen</td><td>Customer lookup: "${escHtml(query || '—')}"</td><td>10.0.4.22</td></tr>
          <tr><td>14:28:15</td><td>sarah.chen</td><td>Dashboard view</td><td>10.0.4.22</td></tr>
          <tr><td>14:15:03</td><td>admin</td><td>Report generated</td><td>10.0.1.5</td></tr>
          <tr><td>13:45:22</td><td>j.martinez</td><td>Customer lookup: "Anderson"</td><td>10.0.4.18</td></tr>
        </tbody>
      </table>
    </div>
  `);
}

function escHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    /* ── Rate limiting ── */
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (isRateLimited(ip)) {
      return new Response(rateLimitPage(), {
        status: 429,
        headers: { 'Content-Type': 'text/html; charset=UTF-8', ...corsHeaders },
      });
    }

    /* ── Validation endpoint ── */
    if (url.pathname === '/api/validate' && request.method === 'POST') {
      try {
        const body = await request.json();
        if (body.type === 'sqli-check' && typeof body.query === 'string') {
          const query = body.query;
          // Check if the query was manipulated to return unauthorized data
          const hasUnion = /UNION\s+(ALL\s+)?SELECT/i.test(query);
          const hasOrBypass = /'\s*OR\s+['"]?1['"]?\s*=\s*['"]?1/i.test(query) || /'\s*OR\s+TRUE/i.test(query);
          const hasCommentBypass = /--/.test(query) || /\/\*/.test(query);
          const accessedUsersTable = /FROM\s+users/i.test(query) || /users/i.test(query);
          const droppedTable = /DROP\s+TABLE/i.test(query);
          const injected = hasUnion || hasOrBypass || hasCommentBypass || droppedTable;

          return new Response(JSON.stringify({
            injected,
            hasUnion,
            hasOrBypass,
            hasCommentBypass,
            accessedUsersTable,
            droppedTable,
            rowCount: body.rowCount || 0,
          }), {
            status: 200,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
          });
        }
        return new Response(JSON.stringify({ error: 'Invalid request type' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: 'Invalid JSON' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }
    }

    const html = renderApp(request.url);
    return new Response(html, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=UTF-8',
        'X-Powered-By': 'Express',
        'X-XSS-Protection': '0',
        ...corsHeaders,
      },
    });
  },
};
