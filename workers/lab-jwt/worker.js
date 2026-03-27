/**
 * DevPortal — Vulnerable API Developer Portal
 * Penumbra Forge Security Labs — RED-04
 *
 * INTENTIONALLY VULNERABLE: JWT validation accepts alg:none
 * and is susceptible to RS256->HS256 algorithm confusion.
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
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#fffbeb; color:#1f2937; }

  .dp-topbar { background:#451a03; color:#fbbf24; padding:6px 12px; font-size:10px; display:flex; justify-content:space-between; align-items:center; }

  .dp-header { background:#fff; border-bottom:1px solid #fef3c7; padding:0 16px; display:flex; align-items:center; justify-content:space-between; height:64px; position:sticky; top:0; z-index:100; box-shadow:0 1px 3px rgba(0,0,0,0.04); flex-wrap:nowrap; overflow:hidden; }
  .dp-header-left { display:flex; align-items:center; gap:12px; }
  .dp-logo { display:flex; align-items:center; gap:10px; text-decoration:none; }
  .dp-logo-icon { width:26px; height:26px; border-radius:8px; background:linear-gradient(135deg,#f59e0b,#fbbf24); display:flex; align-items:center; justify-content:center; }
  .dp-logo-icon svg { width:16px; height:16px; }
  .dp-logo-text { font-size:16px; font-weight:700; color:#78350f; letter-spacing:-0.5px; }
  .dp-logo-text span { color:#f59e0b; }
  .dp-nav { display:flex; gap:4px; }
  .dp-nav a { color:#6b7280; text-decoration:none; font-size:12px; font-weight:500; padding:6px 10px; border-radius:8px; transition:all 150ms; }
  .dp-nav a:hover { color:#78350f; background:#fef3c7; }
  .dp-nav a.active { color:#f59e0b; background:#fef3c7; }
  .dp-user { display:flex; align-items:center; gap:10px; font-size:12px; color:#6b7280; }
  .dp-user-avatar { width:28px; height:28px; border-radius:50%; background:#fef3c7; color:#f59e0b; display:flex; align-items:center; justify-content:center; font-size:11px; font-weight:700; }

  .dp-container { max-width:100%; margin:0 auto; padding:16px 16px 0; }

  @media (max-width:500px) {
    .dp-nav { display:none; }
    .dp-user-avatar { display:none; }
  }

  .dp-card { background:#fff; border:1px solid #fef3c7; border-radius:12px; padding:24px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,0.04); }
  .dp-card h2 { font-size:17px; color:#78350f; margin-bottom:4px; font-weight:600; }
  .dp-card h3 { font-size:13px; color:#6b7280; margin-bottom:16px; font-weight:400; }

  .dp-api-key { display:flex; align-items:center; gap:12px; padding:12px 16px; background:#fffbeb; border:1px solid #fef3c7; border-radius:10px; margin-bottom:10px; }
  .dp-api-key code { font-family:monospace; font-size:13px; color:#f59e0b; flex:1; }
  .dp-api-key-label { font-size:10px; color:#6b7280; text-transform:uppercase; letter-spacing:0.5px; min-width:60px; font-weight:600; }
  .dp-api-key-copy { padding:4px 10px; background:#fef3c7; border:1px solid #fde68a; border-radius:6px; font-size:11px; color:#78350f; cursor:pointer; }

  .dp-endpoint { padding:12px 16px; border:1px solid #fef3c7; border-radius:10px; margin-bottom:8px; display:flex; align-items:center; gap:12px; transition:all 150ms; }
  .dp-endpoint:hover { background:#fffbeb; }
  .dp-method { font-family:monospace; font-size:11px; font-weight:700; padding:4px 10px; border-radius:6px; min-width:52px; text-align:center; }
  .dp-method-get { color:#059669; background:#ecfdf5; }
  .dp-method-post { color:#3b82f6; background:#eff6ff; }
  .dp-method-delete { color:#ef4444; background:#fef2f2; }
  .dp-path { font-family:monospace; font-size:13px; color:#1f2937; flex:1; }
  .dp-desc { font-size:12px; color:#6b7280; }
  .dp-auth-badge { font-family:monospace; font-size:10px; padding:3px 8px; border-radius:6px; color:#f59e0b; background:#fef3c7; font-weight:600; }

  .dp-playground { margin-top:16px; }
  .dp-playground label { display:block; font-size:11px; color:#6b7280; margin-bottom:6px; text-transform:uppercase; letter-spacing:0.5px; font-weight:600; }
  .dp-playground textarea, .dp-playground input { width:100%; padding:12px 16px; background:#f9fafb; border:2px solid #fef3c7; border-radius:10px; color:#1f2937; font-family:monospace; font-size:13px; outline:none; margin-bottom:12px; transition:border-color 200ms,box-shadow 200ms; }
  .dp-playground textarea:focus, .dp-playground input:focus { border-color:#f59e0b; box-shadow:0 0 0 3px rgba(245,158,11,0.15); background:#fff; }
  .dp-playground button { padding:10px 22px; background:#f59e0b; color:#fff; border:none; border-radius:10px; font-size:13px; font-weight:600; cursor:pointer; margin-right:8px; transition:background 150ms; }
  .dp-playground button:hover { background:#d97706; }
  .dp-playground button.secondary { background:#f9fafb; color:#374151; border:1px solid #e5e7eb; }
  .dp-playground button.secondary:hover { background:#f3f4f6; }

  .dp-response { margin-top:16px; padding:16px; background:#f9fafb; border:1px solid #e5e7eb; border-radius:10px; font-family:monospace; font-size:12px; line-height:1.6; white-space:pre-wrap; word-break:break-all; }
  .dp-response-ok { color:#059669; border-color:#d1fae5; background:#f0fdf4; }
  .dp-response-err { color:#ef4444; border-color:#fecaca; background:#fef2f2; }
  .dp-response-label { font-size:10px; color:#6b7280; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:6px; font-weight:600; }

  .dp-stats { display:flex; gap:16px; margin-bottom:24px; }
  .dp-stat { background:#fffbeb; border:1px solid #fef3c7; border-radius:10px; padding:18px 20px; flex:1; }
  .dp-stat-num { font-size:26px; color:#78350f; font-weight:700; }
  .dp-stat-label { font-size:11px; color:#6b7280; text-transform:uppercase; letter-spacing:0.5px; margin-top:4px; }

  .dp-usage-bar { height:8px; background:#fef3c7; border-radius:4px; overflow:hidden; margin-top:8px; }
  .dp-usage-fill { height:100%; border-radius:4px; }

  .dp-footer { text-align:center; padding:16px 12px; color:#9ca3af; font-size:11px; border-top:1px solid #fef3c7; margin-top:48px; background:#fff; flex-wrap:wrap; }
`;

// Simulated RSA public key (for algorithm confusion lab)
const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxklLgs0xAv5p4bQAAAAEXAMPLEKEY0NOTREAL
DCaHqhSA0razP7DFP7a1oF//J4GENeg75thViD+ebLeYxOVQ6vlBKljzD0b3NAAA
AwEAAQ==
-----END PUBLIC KEY-----`;

// Pre-built JWTs for the lab
function makeJWT(header, payload) {
  const h = _btoa(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const p = _btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return h + '.' + p + '.fake_signature_for_lab';
}

const GUEST_TOKEN = makeJWT(
  { alg: 'RS256', typ: 'JWT' },
  { sub: '1001', name: 'Developer', role: 'user', iat: 1711100000, exp: 1711200000 }
);

function shell(title, activePage, content) {
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} — DevPortal</title><style>${STYLES}</style></head>
<body>
  <div class="dp-topbar">
    <span>DevPortal API v3.4.1 — Developer Dashboard</span>
    <span>Region: us-west-2 &middot; Latency: 12ms</span>
  </div>
  <div class="dp-header">
    <div class="dp-header-left">
      <a href="/" class="dp-logo">
        <div class="dp-logo-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg></div>
        <div class="dp-logo-text">Dev<span>Portal</span></div>
      </a>
      <div class="dp-nav">
        <a href="/"${activePage==='docs'?' class="active"':''}>Docs</a>
        <a href="/auth"${activePage==='auth'?' class="active"':''}>Auth</a>
        <a href="/usage"${activePage==='usage'?' class="active"':''}>Usage</a>
        <a href="/sdks"${activePage==='sdks'?' class="active"':''}>SDKs</a>
        <a href="/status"${activePage==='status'?' class="active"':''}>Status</a>
      </div>
    </div>
    <div class="dp-user">
      <span>developer@devportal.io</span>
      <div class="dp-user-avatar">DV</div>
    </div>
  </div>
  <div class="dp-container">${content}</div>
  <div class="dp-footer">
    &copy; 2026 DevPortal API Services — v3.4.1
    <div style="margin-top:4px;">All data is simulated. This is a Penumbra Forge Security Lab.</div>
  </div>
  <script>
  document.cookie="session=eyJ1c2VyIjoiZGV2ZWxvcGVyIiwicm9sZSI6InVzZXIifQ==;path=/";

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
      type: 'devportal-nav',
      path: window.location.pathname,
      action: params.get('action') || '',
      url: window.location.href
    }, '*');
  } catch(e) {}

  /* ── Form submission ── */
  document.querySelectorAll('form').forEach(function(f) {
    f.addEventListener('submit', function(e) {
      e.preventDefault();
      var params = new URLSearchParams(new FormData(f));
      window.location = f.action + '?' + params.toString();
    });
  });
  </script>
</body></html>`;
}

function renderApp(url) {
  const path = new URL(url).pathname;
  const params = new URL(url).searchParams;

  if (path === '/auth' || path === '/auth/') return renderAuth(params);
  if (path === '/api/admin') return handleAdmin(url);
  if (path === '/api/public-key') return PUBLIC_KEY;
  if (path === '/usage' || path === '/usage/') return renderUsage();
  if (path === '/sdks' || path === '/sdks/') return renderSdks();
  if (path === '/status' || path === '/status/') return renderStatus();
  return renderDocs();
}

function renderDocs() {
  return shell('API Documentation', 'docs', `
    <div class="dp-stats">
      <div class="dp-stat"><div class="dp-stat-num">12</div><div class="dp-stat-label">Endpoints</div></div>
      <div class="dp-stat"><div class="dp-stat-num">4.2M</div><div class="dp-stat-label">API Calls Today</div></div>
      <div class="dp-stat"><div class="dp-stat-num">99.97%</div><div class="dp-stat-label">Uptime</div></div>
      <div class="dp-stat"><div class="dp-stat-num">12ms</div><div class="dp-stat-label">Avg Latency</div></div>
    </div>

    <div class="dp-card">
      <h2>API Keys</h2>
      <h3>Manage your API credentials</h3>
      <div class="dp-api-key">
        <span class="dp-api-key-label">Live</span>
        <code>dp_live_7x9k4m2n8p3q1r5t</code>
        <span class="dp-api-key-copy">Copy</span>
      </div>
      <div class="dp-api-key">
        <span class="dp-api-key-label">Test</span>
        <code>dp_test_a1b2c3d4e5f6g7h8</code>
        <span class="dp-api-key-copy">Copy</span>
      </div>
    </div>

    <div class="dp-card">
      <h2>Endpoints</h2>
      <h3>Available API endpoints and their authentication requirements</h3>
      <div class="dp-endpoint">
        <span class="dp-method dp-method-post">POST</span>
        <span class="dp-path">/api/auth/login</span>
        <span class="dp-desc">Authenticate and receive JWT</span>
      </div>
      <div class="dp-endpoint">
        <span class="dp-method dp-method-get">GET</span>
        <span class="dp-path">/api/auth/public-key</span>
        <span class="dp-desc">RSA public key for JWT verification</span>
      </div>
      <div class="dp-endpoint">
        <span class="dp-method dp-method-get">GET</span>
        <span class="dp-path">/api/users/me</span>
        <span class="dp-desc">Current user profile</span>
        <span class="dp-auth-badge">AUTH</span>
      </div>
      <div class="dp-endpoint">
        <span class="dp-method dp-method-get">GET</span>
        <span class="dp-path">/api/admin</span>
        <span class="dp-desc">Admin dashboard data</span>
        <span class="dp-auth-badge">ADMIN</span>
      </div>
      <div class="dp-endpoint">
        <span class="dp-method dp-method-get">GET</span>
        <span class="dp-path">/api/users</span>
        <span class="dp-desc">List all users</span>
        <span class="dp-auth-badge">ADMIN</span>
      </div>
      <div class="dp-endpoint">
        <span class="dp-method dp-method-delete">DEL</span>
        <span class="dp-path">/api/users/:id</span>
        <span class="dp-desc">Delete a user</span>
        <span class="dp-auth-badge">ADMIN</span>
      </div>
    </div>

    <div class="dp-card">
      <h2>Authentication</h2>
      <h3>This API uses RS256-signed JSON Web Tokens</h3>
      <p style="font-size:13px;color:#6b7280;line-height:1.8;margin-bottom:16px;">
        Send a POST to <code style="color:#f59e0b;background:#fef3c7;padding:2px 6px;border-radius:4px;">/api/auth/login</code> with credentials to receive a JWT.
        Include the token in the <code style="color:#f59e0b;background:#fef3c7;padding:2px 6px;border-radius:4px;">Authorization: Bearer &lt;token&gt;</code> header for authenticated requests.
        The RS256 public key is available at <code style="color:#f59e0b;background:#fef3c7;padding:2px 6px;border-radius:4px;">/api/auth/public-key</code>.
      </p>
      <a href="/auth" style="display:inline-block;padding:12px 24px;background:#f59e0b;color:#fff;border-radius:10px;text-decoration:none;font-size:14px;font-weight:600;">Open Auth Playground</a>
    </div>
  `);
}

function renderUsage() {
  return shell('API Usage', 'usage', `
    <div class="dp-card">
      <h2>API Usage</h2>
      <h3>Request volume over the last 7 days</h3>
      <div style="display:flex;gap:8px;align-items:flex-end;height:120px;margin-bottom:16px;">
        <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;">
          <div style="background:linear-gradient(180deg,#f59e0b,#fbbf24);width:100%;height:45%;border-radius:6px 6px 0 0;"></div>
          <span style="font-size:10px;color:#6b7280;">Mon</span>
        </div>
        <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;">
          <div style="background:linear-gradient(180deg,#f59e0b,#fbbf24);width:100%;height:68%;border-radius:6px 6px 0 0;"></div>
          <span style="font-size:10px;color:#6b7280;">Tue</span>
        </div>
        <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;">
          <div style="background:linear-gradient(180deg,#f59e0b,#fbbf24);width:100%;height:82%;border-radius:6px 6px 0 0;"></div>
          <span style="font-size:10px;color:#6b7280;">Wed</span>
        </div>
        <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;">
          <div style="background:linear-gradient(180deg,#f59e0b,#fbbf24);width:100%;height:55%;border-radius:6px 6px 0 0;"></div>
          <span style="font-size:10px;color:#6b7280;">Thu</span>
        </div>
        <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;">
          <div style="background:linear-gradient(180deg,#f59e0b,#fbbf24);width:100%;height:90%;border-radius:6px 6px 0 0;"></div>
          <span style="font-size:10px;color:#6b7280;">Fri</span>
        </div>
        <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;">
          <div style="background:linear-gradient(180deg,#f59e0b,#fbbf24);width:100%;height:35%;border-radius:6px 6px 0 0;"></div>
          <span style="font-size:10px;color:#6b7280;">Sat</span>
        </div>
        <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;">
          <div style="background:linear-gradient(180deg,#f59e0b,#fbbf24);width:100%;height:28%;border-radius:6px 6px 0 0;"></div>
          <span style="font-size:10px;color:#6b7280;">Sun</span>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;">
        <div style="background:#fffbeb;padding:14px;border-radius:10px;border:1px solid #fef3c7;">
          <div style="font-size:11px;color:#6b7280;text-transform:uppercase;">This Week</div>
          <div style="font-size:20px;font-weight:700;color:#78350f;">29.4M</div>
        </div>
        <div style="background:#fffbeb;padding:14px;border-radius:10px;border:1px solid #fef3c7;">
          <div style="font-size:11px;color:#6b7280;text-transform:uppercase;">Rate Limit</div>
          <div style="font-size:20px;font-weight:700;color:#78350f;">10K/min</div>
        </div>
        <div style="background:#fffbeb;padding:14px;border-radius:10px;border:1px solid #fef3c7;">
          <div style="font-size:11px;color:#6b7280;text-transform:uppercase;">Error Rate</div>
          <div style="font-size:20px;font-weight:700;color:#059669;">0.03%</div>
        </div>
      </div>
    </div>
  `);
}

function renderSdks() {
  return shell('SDKs', 'sdks', `
    <div class="dp-card">
      <h2>Official SDKs</h2>
      <h3>Client libraries for popular languages</h3>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div style="border:1px solid #fef3c7;border-radius:10px;padding:16px;display:flex;align-items:center;gap:12px;">
          <div style="width:40px;height:40px;border-radius:8px;background:#fef3c7;display:flex;align-items:center;justify-content:center;font-weight:700;color:#f59e0b;">JS</div>
          <div><div style="font-weight:600;font-size:14px;color:#78350f;">JavaScript</div><div style="font-size:12px;color:#6b7280;">npm install devportal-sdk</div></div>
        </div>
        <div style="border:1px solid #fef3c7;border-radius:10px;padding:16px;display:flex;align-items:center;gap:12px;">
          <div style="width:40px;height:40px;border-radius:8px;background:#eff6ff;display:flex;align-items:center;justify-content:center;font-weight:700;color:#3b82f6;">PY</div>
          <div><div style="font-weight:600;font-size:14px;color:#78350f;">Python</div><div style="font-size:12px;color:#6b7280;">pip install devportal</div></div>
        </div>
        <div style="border:1px solid #fef3c7;border-radius:10px;padding:16px;display:flex;align-items:center;gap:12px;">
          <div style="width:40px;height:40px;border-radius:8px;background:#f0fdf4;display:flex;align-items:center;justify-content:center;font-weight:700;color:#059669;">GO</div>
          <div><div style="font-weight:600;font-size:14px;color:#78350f;">Go</div><div style="font-size:12px;color:#6b7280;">go get devportal.io/sdk</div></div>
        </div>
        <div style="border:1px solid #fef3c7;border-radius:10px;padding:16px;display:flex;align-items:center;gap:12px;">
          <div style="width:40px;height:40px;border-radius:8px;background:#fef2f2;display:flex;align-items:center;justify-content:center;font-weight:700;color:#ef4444;">RB</div>
          <div><div style="font-weight:600;font-size:14px;color:#78350f;">Ruby</div><div style="font-size:12px;color:#6b7280;">gem install devportal</div></div>
        </div>
      </div>
    </div>
  `);
}

function renderStatus() {
  return shell('Status', 'status', `
    <div class="dp-card">
      <h2>System Status</h2>
      <h3>All systems operational</h3>
      <div style="margin-bottom:16px;">
        <div style="display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid #fef3c7;">
          <span style="font-weight:500;color:#1f2937;">API Gateway</span>
          <span style="color:#059669;font-weight:600;font-size:12px;background:#ecfdf5;padding:4px 12px;border-radius:6px;">Operational</span>
        </div>
        <div style="display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid #fef3c7;">
          <span style="font-weight:500;color:#1f2937;">Authentication Service</span>
          <span style="color:#059669;font-weight:600;font-size:12px;background:#ecfdf5;padding:4px 12px;border-radius:6px;">Operational</span>
        </div>
        <div style="display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid #fef3c7;">
          <span style="font-weight:500;color:#1f2937;">Database Cluster</span>
          <span style="color:#059669;font-weight:600;font-size:12px;background:#ecfdf5;padding:4px 12px;border-radius:6px;">Operational</span>
        </div>
        <div style="display:flex;justify-content:space-between;padding:12px 0;">
          <span style="font-weight:500;color:#1f2937;">CDN Edge Nodes</span>
          <span style="color:#059669;font-weight:600;font-size:12px;background:#ecfdf5;padding:4px 12px;border-radius:6px;">Operational</span>
        </div>
      </div>
      <div style="font-size:12px;color:#6b7280;">Last incident: 14 days ago &middot; Avg response time: 12ms</div>
    </div>
  `);
}

function renderAuth(params) {
  const action = params.get('action') || '';
  let resultHtml = '';

  if (action === 'login') {
    resultHtml = `
      <div class="dp-response-label">Response — 200 OK</div>
      <div class="dp-response dp-response-ok">{
  "token": "${GUEST_TOKEN}",
  "user": {
    "id": 1001,
    "name": "Developer",
    "role": "user"
  },
  "message": "Authentication successful"
}</div>`;
  } else if (action === 'verify') {
    const token = params.get('token') || '';
    const parts = token.split('.');
    if (parts.length === 3 || (parts.length === 2 && token.endsWith('.'))) {
      try {
        const header = JSON.parse(_atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
        const payload = JSON.parse(_atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

        // ═══════════════════════════════════════════════════
        // INTENTIONALLY VULNERABLE — DO NOT FIX
        // Accepts alg:none without signature verification
        // Accepts HS256 (symmetric) when expecting RS256 (asymmetric)
        // Does not validate the algorithm matches expectations
        // ═══════════════════════════════════════════════════
        let verified = false;
        let verifyNote = '';

        if (header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE') {
          verified = true;
          verifyNote = 'Algorithm: none — signature verification skipped';
        } else if (header.alg === 'HS256') {
          verified = true;
          verifyNote = 'Algorithm: HS256 — verified with public key as HMAC secret';
        } else {
          verified = true;
          verifyNote = 'Algorithm: ' + header.alg + ' — signature accepted';
        }

        const isAdmin = payload.role === 'admin' || payload.admin === true;

        resultHtml = `
          <div class="dp-response-label">Token Verification — ${verified ? 'VALID' : 'INVALID'}</div>
          <div class="dp-response ${verified ? 'dp-response-ok' : 'dp-response-err'}">{
  "valid": ${verified},
  "note": "${verifyNote}",
  "header": ${JSON.stringify(header, null, 2).split('\n').join('\n  ')},
  "payload": ${JSON.stringify(payload, null, 2).split('\n').join('\n  ')},
  "access_level": "${isAdmin ? 'ADMINISTRATOR' : 'user'}",
  "admin_panel": ${isAdmin ? '"Access granted — /api/admin"' : '"Access denied"'}
}</div>`;

        // Send result to parent frame
        resultHtml += `<script>
          window.parent.postMessage({
            type: 'jwt-result',
            alg: ${JSON.stringify(header.alg)},
            role: ${JSON.stringify(payload.role || '')},
            isAdmin: ${isAdmin},
            algNone: ${header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE'},
            algConfusion: ${header.alg === 'HS256'}
          }, '*');
        <\/script>`;
      } catch(e) {
        resultHtml = `<div class="dp-response dp-response-err">Invalid token format: ${escHtml(e.message)}</div>`;
      }
    } else {
      resultHtml = `<div class="dp-response dp-response-err">Invalid JWT format. Expected header.payload.signature</div>`;
    }
  }

  return shell('Auth Playground', 'auth', `
    <div class="dp-card">
      <h2>Authentication Playground</h2>
      <h3>Test JWT authentication flow</h3>

      <div style="display:flex;gap:10px;margin-bottom:20px;">
        <a href="/auth?action=login" style="padding:12px 24px;background:#f59e0b;color:#fff;border-radius:10px;text-decoration:none;font-size:14px;font-weight:600;">Login as Developer</a>
        <a href="/api/public-key" target="_blank" style="padding:12px 24px;background:#f9fafb;color:#374151;border:1px solid #e5e7eb;border-radius:10px;text-decoration:none;font-size:14px;font-weight:500;">View Public Key</a>
      </div>

      ${resultHtml}

      <div class="dp-playground" style="margin-top:24px;">
        <label>Verify Token</label>
        <form action="/auth" method="GET">
          <input type="hidden" name="action" value="verify">
          <textarea name="token" rows="4" placeholder="Paste a JWT token to verify...">${params.get('token') || ''}</textarea>
          <button type="submit">Verify Token</button>
          <button type="button" class="secondary" onclick="this.form.querySelector('textarea').value='${GUEST_TOKEN}'">Paste Guest Token</button>
        </form>
      </div>
    </div>

    <div class="dp-card" style="opacity:0.7;">
      <h2>Admin Panel</h2>
      <h3>Requires role: administrator</h3>
      <p style="font-size:13px;color:#6b7280;line-height:1.6;">Submit a valid admin JWT via the verify endpoint above to access the admin panel. Current token role: <code style="color:#f59e0b;background:#fef3c7;padding:2px 6px;border-radius:4px;">user</code></p>
    </div>
  `);
}

function escHtml(s) {
  return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function _btoa(str) {
  return globalThis.btoa(str);
}

function _atob(str) {
  return globalThis.atob(str);
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
        if (body.type === 'jwt-check' && typeof body.token === 'string') {
          const token = body.token;
          const parts = token.split('.');
          let result = { valid: false, isAdmin: false, algNone: false, algConfusion: false };

          if (parts.length >= 2) {
            try {
              const header = JSON.parse(_atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
              const payload = JSON.parse(_atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

              result.valid = true;
              result.alg = header.alg;
              result.algNone = header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE';
              result.algConfusion = header.alg === 'HS256';
              result.isAdmin = payload.role === 'admin' || payload.admin === true;
              result.role = payload.role || '';
            } catch(e) {
              result.error = e.message;
            }
          }

          return new Response(JSON.stringify(result), {
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

    // Plain text endpoints
    if (url.pathname === '/api/public-key') {
      return new Response(PUBLIC_KEY, {
        headers: { 'Content-Type': 'text/plain', ...corsHeaders },
      });
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
