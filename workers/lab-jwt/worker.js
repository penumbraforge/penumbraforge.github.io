/**
 * DevPortal — Vulnerable API Developer Portal
 * Penumbra Forge Security Labs — RED-04
 *
 * INTENTIONALLY VULNERABLE: JWT validation accepts alg:none
 * and is susceptible to RS256→HS256 algorithm confusion.
 */

const STYLES = `
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#0a0f0a; color:#b5ceb5; }

  .dp-header { background:#0f170f; border-bottom:1px solid #1a2e1a; padding:14px 32px; display:flex; align-items:center; justify-content:space-between; }
  .dp-logo { font-size:20px; font-weight:700; color:#6bcf8f; letter-spacing:-0.5px; text-decoration:none; }
  .dp-logo span { color:#4a7a4a; font-weight:300; }
  .dp-nav { display:flex; gap:20px; }
  .dp-nav a { color:#4a7a4a; text-decoration:none; font-size:13px; }
  .dp-nav a:hover { color:#b5ceb5; }
  .dp-nav a.active { color:#6bcf8f; }

  .dp-container { max-width:900px; margin:0 auto; padding:32px; }

  .dp-card { background:#0f170f; border:1px solid #1a2e1a; border-radius:10px; padding:24px; margin-bottom:20px; }
  .dp-card h2 { font-size:16px; color:#b5ceb5; margin-bottom:4px; font-weight:500; }
  .dp-card h3 { font-size:13px; color:#4a7a4a; margin-bottom:16px; font-weight:400; }

  .dp-api-key { display:flex; align-items:center; gap:8px; padding:12px 16px; background:#0a0f0a; border:1px solid #1a2e1a; border-radius:8px; margin-bottom:12px; }
  .dp-api-key code { font-family:monospace; font-size:13px; color:#6bcf8f; flex:1; }
  .dp-api-key-label { font-size:10px; color:#4a7a4a; text-transform:uppercase; letter-spacing:0.5px; min-width:60px; }

  .dp-endpoint { padding:12px 16px; border:1px solid #1a2e1a; border-radius:8px; margin-bottom:8px; display:flex; align-items:center; gap:12px; }
  .dp-method { font-family:monospace; font-size:11px; font-weight:600; padding:3px 8px; border-radius:4px; min-width:48px; text-align:center; }
  .dp-method-get { color:#6bcf8f; background:rgba(107,207,143,0.1); }
  .dp-method-post { color:#58a6ff; background:rgba(88,166,255,0.1); }
  .dp-method-delete { color:#f85149; background:rgba(248,81,73,0.1); }
  .dp-path { font-family:monospace; font-size:13px; color:#b5ceb5; flex:1; }
  .dp-desc { font-size:12px; color:#4a7a4a; }
  .dp-auth-badge { font-family:monospace; font-size:9px; padding:2px 6px; border-radius:3px; color:#f0883e; background:rgba(240,136,62,0.1); }

  .dp-playground { margin-top:16px; }
  .dp-playground label { display:block; font-size:11px; color:#4a7a4a; margin-bottom:6px; text-transform:uppercase; letter-spacing:0.5px; }
  .dp-playground textarea, .dp-playground input { width:100%; padding:10px 14px; background:#0a0f0a; border:1px solid #1a2e1a; border-radius:8px; color:#b5ceb5; font-family:monospace; font-size:13px; outline:none; margin-bottom:12px; }
  .dp-playground textarea:focus, .dp-playground input:focus { border-color:#6bcf8f; }
  .dp-playground button { padding:10px 20px; background:#238636; color:#fff; border:none; border-radius:8px; font-size:13px; font-weight:500; cursor:pointer; margin-right:8px; }
  .dp-playground button:hover { background:#2ea043; }
  .dp-playground button.secondary { background:#1a2e1a; color:#b5ceb5; border:1px solid #2d4a2d; }

  .dp-response { margin-top:16px; padding:16px; background:#0a0f0a; border:1px solid #1a2e1a; border-radius:8px; font-family:monospace; font-size:12px; line-height:1.6; white-space:pre-wrap; word-break:break-all; }
  .dp-response-ok { color:#6bcf8f; }
  .dp-response-err { color:#f85149; }
  .dp-response-label { font-size:10px; color:#4a7a4a; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:6px; }

  .dp-stats { display:flex; gap:16px; margin-bottom:20px; }
  .dp-stat { background:#0a0f0a; border:1px solid #1a2e1a; border-radius:8px; padding:14px 18px; flex:1; }
  .dp-stat-num { font-size:22px; color:#b5ceb5; font-weight:300; }
  .dp-stat-label { font-size:10px; color:#4a7a4a; text-transform:uppercase; letter-spacing:0.5px; }

  .dp-footer { text-align:center; padding:32px; color:#2d4a2d; font-size:11px; border-top:1px solid #1a2e1a; margin-top:48px; }
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

function renderApp(url) {
  const path = new URL(url).pathname;
  const params = new URL(url).searchParams;

  if (path === '/auth' || path === '/auth/') return renderAuth(params);
  if (path === '/api/admin') return handleAdmin(url);
  if (path === '/api/public-key') return PUBLIC_KEY;
  return renderDocs();
}

function renderDocs() {
  return page('API Documentation', `
    <div class="dp-stats">
      <div class="dp-stat"><div class="dp-stat-num">12</div><div class="dp-stat-label">Endpoints</div></div>
      <div class="dp-stat"><div class="dp-stat-num">4.2M</div><div class="dp-stat-label">API Calls Today</div></div>
      <div class="dp-stat"><div class="dp-stat-num">99.97%</div><div class="dp-stat-label">Uptime</div></div>
    </div>

    <div class="dp-card">
      <h2>API Keys</h2>
      <div class="dp-api-key">
        <span class="dp-api-key-label">Live</span>
        <code>dp_live_7x9k4m2n8p3q1r5t</code>
      </div>
      <div class="dp-api-key">
        <span class="dp-api-key-label">Test</span>
        <code>dp_test_a1b2c3d4e5f6g7h8</code>
      </div>
    </div>

    <div class="dp-card">
      <h2>Endpoints</h2>
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
        <span class="dp-auth-badge">auth required</span>
      </div>
      <div class="dp-endpoint">
        <span class="dp-method dp-method-get">GET</span>
        <span class="dp-path">/api/admin</span>
        <span class="dp-desc">Admin dashboard data</span>
        <span class="dp-auth-badge">admin only</span>
      </div>
      <div class="dp-endpoint">
        <span class="dp-method dp-method-get">GET</span>
        <span class="dp-path">/api/users</span>
        <span class="dp-desc">List all users</span>
        <span class="dp-auth-badge">admin only</span>
      </div>
      <div class="dp-endpoint">
        <span class="dp-method dp-method-delete">DEL</span>
        <span class="dp-path">/api/users/:id</span>
        <span class="dp-desc">Delete a user</span>
        <span class="dp-auth-badge">admin only</span>
      </div>
    </div>

    <div class="dp-card">
      <h2>Authentication</h2>
      <h3>This API uses RS256-signed JSON Web Tokens</h3>
      <p style="font-size:13px;color:#4a7a4a;line-height:1.6;margin-bottom:12px;">
        Send a POST to <code style="color:#6bcf8f;">/api/auth/login</code> with credentials to receive a JWT.
        Include the token in the <code style="color:#6bcf8f;">Authorization: Bearer &lt;token&gt;</code> header for authenticated requests.
        The RS256 public key is available at <code style="color:#6bcf8f;">/api/auth/public-key</code>.
      </p>
      <a href="/auth" style="display:inline-block;padding:10px 20px;background:#238636;color:#fff;border-radius:8px;text-decoration:none;font-size:13px;">Open Auth Playground →</a>
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
        // ⚠ INTENTIONALLY VULNERABLE — DO NOT FIX
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
        <\\/script>`;
      } catch(e) {
        resultHtml = `<div class="dp-response dp-response-err">Invalid token format: ${escHtml(e.message)}</div>`;
      }
    } else {
      resultHtml = `<div class="dp-response dp-response-err">Invalid JWT format. Expected header.payload.signature</div>`;
    }
  }

  return page('Auth Playground', `
    <div class="dp-card">
      <h2>Authentication Playground</h2>
      <h3>Test JWT authentication flow</h3>

      <div style="margin-bottom:20px;">
        <a href="/auth?action=login" style="padding:10px 20px;background:#238636;color:#fff;border-radius:8px;text-decoration:none;font-size:13px;display:inline-block;">Login as Developer (get JWT)</a>
        <a href="/api/public-key" target="_blank" style="padding:10px 20px;background:#1a2e1a;color:#b5ceb5;border:1px solid #2d4a2d;border-radius:8px;text-decoration:none;font-size:13px;display:inline-block;margin-left:8px;">View Public Key</a>
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
      <h2>&#x1f512; Admin Panel</h2>
      <h3>Requires role: administrator</h3>
      <p style="font-size:13px;color:#4a7a4a;">Submit a valid admin JWT via the verify endpoint above to access the admin panel. Current token role: <code style="color:#f0883e;">user</code></p>
    </div>
  `);
}

function page(title, content) {
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} — DevPortal</title><style>${STYLES}</style></head>
<body>
  <div class="dp-header">
    <a href="/" class="dp-logo">Dev<span>Portal</span></a>
    <div class="dp-nav">
      <a href="/" class="${title.includes('Doc') ? 'active' : ''}">Docs</a>
      <a href="/auth" class="${title.includes('Auth') ? 'active' : ''}">Auth</a>
      <a href="#">SDKs</a>
      <a href="#">Status</a>
      <a href="#">Support</a>
    </div>
  </div>
  <div class="dp-container">${content}</div>
  <div class="dp-footer">© 2026 DevPortal API Services — v3.4.1<br>All data is simulated. This is a Penumbra Forge Security Lab.</div>
  <script>
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

function escHtml(s) {
  return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function _btoa(str) {
  // Workers have global btoa but it only takes strings
  return globalThis.btoa(str);
}

function _atob(str) {
  return globalThis.atob(str);
}

export default {
  async fetch(request) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*' } });
    }

    const url = new URL(request.url);

    // Plain text endpoints
    if (url.pathname === '/api/public-key') {
      return new Response(PUBLIC_KEY, {
        headers: { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' },
      });
    }

    const html = renderApp(request.url);
    return new Response(html, {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
    });
  },
};
