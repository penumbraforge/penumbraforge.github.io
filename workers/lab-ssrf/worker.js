/**
 * CloudSnap — Vulnerable Image Hosting Platform
 * Penumbra Forge Security Labs — RED-03
 *
 * INTENTIONALLY VULNERABLE: URL import feature fetches user-provided
 * URLs server-side without validation. An internal metadata endpoint
 * simulates cloud instance credentials accessible via SSRF.
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
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#faf5ff; color:#1f2937; }

  .cs-topbar { background:#2e1065; color:#c4b5fd; padding:6px 12px; font-size:10px; display:flex; justify-content:space-between; align-items:center; }

  .cs-header { background:#fff; border-bottom:1px solid #ede9fe; padding:0 16px; display:flex; align-items:center; justify-content:space-between; height:64px; position:sticky; top:0; z-index:100; box-shadow:0 1px 3px rgba(0,0,0,0.04); flex-wrap:nowrap; overflow:hidden; }
  .cs-header-left { display:flex; align-items:center; gap:12px; }
  .cs-logo { display:flex; align-items:center; gap:10px; text-decoration:none; }
  .cs-logo-icon { width:26px; height:26px; border-radius:8px; background:linear-gradient(135deg,#8b5cf6,#a78bfa); display:flex; align-items:center; justify-content:center; }
  .cs-logo-icon svg { width:16px; height:16px; }
  .cs-logo-text { font-size:16px; font-weight:700; color:#4c1d95; letter-spacing:-0.5px; }
  .cs-logo-text span { color:#8b5cf6; }
  .cs-nav { display:flex; gap:4px; }
  .cs-nav a { color:#6b7280; text-decoration:none; font-size:12px; font-weight:500; padding:6px 10px; border-radius:8px; transition:all 150ms; }
  .cs-nav a:hover { color:#4c1d95; background:#f5f3ff; }
  .cs-nav a.active { color:#8b5cf6; background:#f5f3ff; }
  .cs-user { display:flex; align-items:center; gap:10px; font-size:12px; color:#6b7280; }
  .cs-user-avatar { width:28px; height:28px; border-radius:50%; background:#ede9fe; color:#8b5cf6; display:flex; align-items:center; justify-content:center; font-size:11px; font-weight:700; }

  .cs-container { max-width:100%; margin:0 auto; padding:16px 16px 0; }

  @media (max-width:500px) {
    .cs-nav { display:none; }
    .cs-user-avatar { display:none; }
  }

  .cs-card { background:#fff; border:1px solid #ede9fe; border-radius:12px; padding:24px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,0.04); }
  .cs-card h2 { font-size:17px; color:#4c1d95; margin-bottom:4px; font-weight:600; }
  .cs-card h3 { font-size:13px; color:#6b7280; margin-bottom:16px; font-weight:400; }

  .cs-stats { display:flex; gap:16px; margin-bottom:24px; }
  .cs-stat { background:#f5f3ff; border:1px solid #ede9fe; border-radius:10px; padding:18px 20px; flex:1; }
  .cs-stat-num { font-size:26px; color:#4c1d95; font-weight:700; }
  .cs-stat-label { font-size:11px; color:#6b7280; text-transform:uppercase; letter-spacing:0.5px; margin-top:4px; }

  .cs-upload-zone { border:2px dashed #ddd6fe; border-radius:12px; padding:48px; text-align:center; color:#6b7280; font-size:14px; transition:all 200ms; }
  .cs-upload-zone:hover { border-color:#8b5cf6; background:#faf5ff; }
  .cs-upload-icon { margin-bottom:12px; }

  .cs-tabs { display:flex; gap:0; margin-bottom:16px; }
  .cs-tab { padding:10px 20px; font-size:13px; font-weight:500; cursor:pointer; border:1px solid #ede9fe; background:#faf5ff; color:#6b7280; transition:all 150ms; }
  .cs-tab:first-child { border-radius:10px 0 0 10px; }
  .cs-tab:last-child { border-radius:0 10px 10px 0; }
  .cs-tab.active { background:#8b5cf6; color:#fff; border-color:#8b5cf6; }

  .cs-url-input { display:flex; gap:8px; }
  .cs-url-input input { flex:1; padding:12px 16px; background:#f9fafb; border:2px solid #ede9fe; border-radius:10px; color:#1f2937; font-size:14px; outline:none; font-family:monospace; transition:border-color 200ms,box-shadow 200ms; }
  .cs-url-input input:focus { border-color:#8b5cf6; box-shadow:0 0 0 3px rgba(139,92,246,0.15); background:#fff; }
  .cs-url-input button { padding:12px 24px; background:#8b5cf6; color:#fff; border:none; border-radius:10px; font-size:14px; font-weight:600; cursor:pointer; transition:background 150ms; white-space:nowrap; }
  .cs-url-input button:hover { background:#7c3aed; }

  .cs-preview { margin-top:16px; }
  .cs-preview-label { font-size:12px; color:#6b7280; margin-bottom:8px; }
  .cs-preview-box { background:#f9fafb; border:1px solid #ede9fe; border-radius:10px; padding:16px; min-height:100px; }
  .cs-preview-box img { max-width:100%; border-radius:8px; }
  .cs-preview-meta { font-family:monospace; font-size:11px; color:#6b7280; line-height:1.6; white-space:pre-wrap; word-break:break-all; }
  .cs-error { color:#ef4444; background:#fef2f2; border:1px solid #fecaca; border-radius:8px; padding:12px; margin-top:12px; font-family:monospace; font-size:12px; }
  .cs-success { color:#8b5cf6; background:#f5f3ff; border:1px solid #ddd6fe; border-radius:10px; padding:16px; margin-top:12px; font-size:13px; }

  .cs-gallery { display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr)); gap:16px; }
  .cs-thumb { background:#fff; border:1px solid #ede9fe; border-radius:10px; overflow:hidden; transition:all 200ms; cursor:pointer; }
  .cs-thumb:hover { transform:translateY(-2px); box-shadow:0 8px 20px rgba(0,0,0,0.06); border-color:#c4b5fd; }
  .cs-thumb-img { height:130px; display:flex; align-items:center; justify-content:center; font-size:36px; }
  .cs-thumb-info { padding:10px 12px; border-top:1px solid #f5f3ff; }
  .cs-thumb-name { font-size:12px; color:#1f2937; font-weight:500; margin-bottom:2px; }
  .cs-thumb-size { font-size:10px; color:#9ca3af; }

  .cs-footer { text-align:center; padding:16px 12px; color:#9ca3af; font-size:11px; border-top:1px solid #ede9fe; margin-top:48px; background:#fff; flex-wrap:wrap; }
`;

const IMAGES = [
  { name: 'sunset-mountain.jpg', size: '2.4 MB', color: '#f59e0b', icon: 'M' },
  { name: 'city-skyline.jpg', size: '3.1 MB', color: '#3b82f6', icon: 'C' },
  { name: 'ocean-wave.jpg', size: '1.8 MB', color: '#06b6d4', icon: 'O' },
  { name: 'forest-path.jpg', size: '2.7 MB', color: '#059669', icon: 'F' },
  { name: 'desert-dune.jpg', size: '2.2 MB', color: '#f97316', icon: 'D' },
  { name: 'northern-lights.jpg', size: '4.1 MB', color: '#8b5cf6', icon: 'N' },
  { name: 'canyon-vista.jpg', size: '3.5 MB', color: '#ef4444', icon: 'V' },
  { name: 'lake-reflection.jpg', size: '2.9 MB', color: '#0ea5e9', icon: 'L' },
];

// Simulated internal metadata (like AWS EC2 metadata)
const METADATA = {
  '/': 'ami-id\nami-launch-index\nami-manifest-path\nhostname\ninstance-id\ninstance-type\nlocal-ipv4\npublic-ipv4\niam/',
  '/iam/': 'security-credentials/',
  '/iam/security-credentials/': 'cloudsnap-prod-role',
  '/iam/security-credentials/cloudsnap-prod-role': JSON.stringify({
    Code: 'Success',
    LastUpdated: '2026-03-22T14:30:00Z',
    Type: 'AWS-HMAC',
    AccessKeyId: 'ASIAZEXAMPLE7PROD',
    SecretAccessKey: 'wJalrXUtnFEMI/EXAMPLE/PRODKEY',
    Token: 'FwoGZXIvYXdzEBYaDHx5EXAMPLE_SESSION_TOKEN...',
    Expiration: '2026-03-22T20:30:00Z',
  }, null, 2),
};

function shell(title, activePage, content) {
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} — CloudSnap</title><style>${STYLES}</style></head>
<body>
  <div class="cs-topbar">
    <span>CloudSnap v2.8.0 — Image Hosting Platform</span>
    <span>Storage: 16.3 MB of 5 GB used</span>
  </div>
  <div class="cs-header">
    <div class="cs-header-left">
      <a href="/" class="cs-logo">
        <div class="cs-logo-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2"><path d="M18 10h-1.26A8 8 0 109 20h9a5 5 0 000-10z"/></svg></div>
        <div class="cs-logo-text">Cloud<span>Snap</span></div>
      </a>
      <div class="cs-nav">
        <a href="/"${activePage==='gallery'?' class="active"':''}>Gallery</a>
        <a href="/import"${activePage==='import'?' class="active"':''}>Import</a>
        <a href="/shared"${activePage==='shared'?' class="active"':''}>Shared</a>
        <a href="/profile"${activePage==='profile'?' class="active"':''}>Profile</a>
      </div>
    </div>
    <div class="cs-user">
      <span>dev@cloudsnap.io</span>
      <div class="cs-user-avatar">DV</div>
    </div>
  </div>
  <div class="cs-container">${content}</div>
  <div class="cs-footer">
    &copy; 2026 CloudSnap — Cloud Image Hosting
    <div style="margin-top:4px;">All data is simulated. This is a Penumbra Forge Security Lab.</div>
  </div>
  <script>
  document.cookie="session=eyJ1c2VyIjoiZGV2QGNsb3Vkc25hcC5pbyIsInBsYW4iOiJwcm8ifQ==;path=/";

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
      type: 'cloudsnap-nav',
      path: window.location.pathname,
      fetchUrl: params.get('url') || '',
      url: window.location.href
    }, '*');
  } catch(e) {}

  /* ── Form submission ── */
  document.querySelectorAll('form').forEach(function(f) {
    f.addEventListener('submit', function(e) {
      e.preventDefault();
      var url = f.querySelector('input[name=url]');
      if (url) window.location = '/import?url=' + encodeURIComponent(url.value);
    });
  });
  </script>
</body></html>`;
}

function renderApp(url) {
  const path = new URL(url).pathname;
  const params = new URL(url).searchParams;

  if (path === '/import' || path === '/import/') {
    return renderImport(params.get('url') || '');
  }
  if (path.startsWith('/internal/metadata')) {
    return handleMetadata(path.replace('/internal/metadata', '') || '/');
  }
  if (path === '/shared' || path === '/shared/') {
    return renderShared();
  }
  if (path === '/profile' || path === '/profile/') {
    return renderProfile();
  }
  return renderGallery();
}

function handleMetadata(subpath) {
  const data = METADATA[subpath] || METADATA[subpath + '/'] || 'Not found';
  return data;
}

function renderGallery() {
  const thumbs = IMAGES.map(img => `
    <div class="cs-thumb">
      <div class="cs-thumb-img" style="background:linear-gradient(135deg,${img.color}22,${img.color}44);">
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="${img.color}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
      </div>
      <div class="cs-thumb-info">
        <div class="cs-thumb-name">${img.name}</div>
        <div class="cs-thumb-size">${img.size}</div>
      </div>
    </div>
  `).join('');

  return shell('Gallery', 'gallery', `
    <div class="cs-stats">
      <div class="cs-stat"><div class="cs-stat-num">${IMAGES.length}</div><div class="cs-stat-label">Total Images</div></div>
      <div class="cs-stat"><div class="cs-stat-num">16.3 MB</div><div class="cs-stat-label">Storage Used</div></div>
      <div class="cs-stat"><div class="cs-stat-num">3</div><div class="cs-stat-label">Shared Albums</div></div>
      <div class="cs-stat"><div class="cs-stat-num">142</div><div class="cs-stat-label">Total Views</div></div>
    </div>

    <div class="cs-card">
      <h2>Your Images</h2>
      <h3>${IMAGES.length} images uploaded</h3>
      <div class="cs-gallery">${thumbs}</div>
    </div>

    <div class="cs-card">
      <h2>Upload</h2>
      <div class="cs-upload-zone">
        <div class="cs-upload-icon"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#8b5cf6" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg></div>
        Drag & drop images here or <a href="/import" style="color:#8b5cf6;font-weight:600;">import from URL</a>
      </div>
    </div>
  `);
}

function renderShared() {
  return shell('Shared Albums', 'shared', `
    <div class="cs-card">
      <h2>Shared Albums</h2>
      <h3>Albums shared with you and your public albums</h3>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;">
        <div style="background:#f5f3ff;border:1px solid #ede9fe;border-radius:10px;padding:20px;">
          <div style="font-weight:600;font-size:14px;color:#4c1d95;margin-bottom:4px;">Vacation Photos</div>
          <div style="font-size:12px;color:#6b7280;">12 images &middot; Shared with 3 people</div>
        </div>
        <div style="background:#f5f3ff;border:1px solid #ede9fe;border-radius:10px;padding:20px;">
          <div style="font-weight:600;font-size:14px;color:#4c1d95;margin-bottom:4px;">Product Shots</div>
          <div style="font-size:12px;color:#6b7280;">8 images &middot; Public album</div>
        </div>
        <div style="background:#f5f3ff;border:1px solid #ede9fe;border-radius:10px;padding:20px;">
          <div style="font-weight:600;font-size:14px;color:#4c1d95;margin-bottom:4px;">Team Assets</div>
          <div style="font-size:12px;color:#6b7280;">24 images &middot; Shared with team</div>
        </div>
      </div>
    </div>
  `);
}

function renderProfile() {
  return shell('Profile', 'profile', `
    <div class="cs-card">
      <h2>Profile</h2>
      <div style="display:flex;align-items:center;gap:16px;margin-bottom:20px;">
        <div class="cs-user-avatar" style="width:56px;height:56px;font-size:18px;">DV</div>
        <div>
          <div style="font-weight:600;font-size:16px;color:#4c1d95;">Dev User</div>
          <div style="font-size:13px;color:#6b7280;">dev@cloudsnap.io</div>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div style="background:#f5f3ff;border:1px solid #ede9fe;border-radius:10px;padding:14px;">
          <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:0.5px;">Plan</div>
          <div style="font-size:16px;font-weight:700;color:#8b5cf6;margin-top:2px;">Pro</div>
        </div>
        <div style="background:#f5f3ff;border:1px solid #ede9fe;border-radius:10px;padding:14px;">
          <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:0.5px;">Member Since</div>
          <div style="font-size:16px;font-weight:700;color:#4c1d95;margin-top:2px;">Jan 2026</div>
        </div>
      </div>
    </div>
  `);
}

function renderImport(fetchUrl) {
  let resultHtml = '';

  if (fetchUrl) {
    // ═══════════════════════════════════════════════════
    // INTENTIONALLY VULNERABLE — DO NOT FIX
    // The URL is fetched server-side without validation.
    // Internal URLs like /internal/metadata are accessible.
    // ═══════════════════════════════════════════════════

    // Check if it's an internal URL (simulate SSRF)
    let responseData = '';
    let isInternal = false;

    if (fetchUrl.includes('169.254.169.254') || fetchUrl.includes('metadata') || fetchUrl.includes('localhost') || fetchUrl.includes('127.0.0.1') || fetchUrl.includes('/internal/')) {
      isInternal = true;
      // Resolve the path
      let metaPath = '/';
      try {
        const parsed = new URL(fetchUrl.startsWith('http') ? fetchUrl : 'http://localhost' + fetchUrl);
        metaPath = parsed.pathname.replace('/latest/meta-data', '').replace('/internal/metadata', '') || '/';
      } catch(e) {
        metaPath = fetchUrl.replace(/.*metadata/, '') || '/';
      }
      responseData = handleMetadata(metaPath);

      resultHtml = `
        <div class="cs-success">
          <div style="margin-bottom:8px;font-size:12px;color:#6b7280;">Server-side fetch: <code style="color:#8b5cf6;background:#ede9fe;padding:2px 6px;border-radius:4px;">${escHtml(fetchUrl)}</code></div>
          <div class="cs-preview-meta">${escHtml(responseData)}</div>
        </div>`;

      // Notify parent
      resultHtml += `<script>
        window.parent.postMessage({
          type: 'ssrf-result',
          url: ${JSON.stringify(fetchUrl)},
          response: ${JSON.stringify(responseData)},
          isInternal: true,
          hasCredentials: ${JSON.stringify(responseData.includes('AccessKeyId'))}
        }, '*');
      <\/script>`;
    } else {
      resultHtml = `
        <div class="cs-preview">
          <div class="cs-preview-label">Preview from: ${escHtml(fetchUrl)}</div>
          <div class="cs-preview-box">
            <img src="${escHtml(fetchUrl)}" alt="Imported image" onerror="this.parentElement.innerHTML='<div class=cs-error>Failed to load image from this URL.</div>'">
          </div>
        </div>`;
    }
  }

  return shell('Import from URL', 'import', `
    <div class="cs-card">
      <h2>Import from URL</h2>
      <h3>Fetch an image from any URL and add it to your gallery</h3>
      <div class="cs-tabs">
        <div class="cs-tab">Upload File</div>
        <div class="cs-tab active">Import from URL</div>
      </div>
      <form class="cs-url-input" action="/import" method="GET">
        <input type="text" name="url" value="${(fetchUrl || '').replace(/"/g, '&quot;')}" placeholder="https://example.com/photo.jpg" autocomplete="off">
        <button type="submit">Fetch Image</button>
      </form>
      ${resultHtml}
    </div>

    <div class="cs-card" style="opacity:0.6;">
      <h2>Import History</h2>
      <div style="font-size:13px;color:#6b7280;padding:16px 0;">
        <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #f5f3ff;">
          <span>https://images.unsplash.com/photo-abc123</span>
          <span style="color:#059669;font-size:12px;">Success</span>
        </div>
        <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #f5f3ff;">
          <span>https://cdn.example.com/banner.png</span>
          <span style="color:#059669;font-size:12px;">Success</span>
        </div>
        <div style="display:flex;justify-content:space-between;padding:8px 0;">
          <span>https://broken-link.test/img.jpg</span>
          <span style="color:#ef4444;font-size:12px;">Failed</span>
        </div>
      </div>
    </div>
  `);
}

function escHtml(s) {
  return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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
        if (body.type === 'ssrf-check' && typeof body.url === 'string') {
          const targetUrl = body.url;
          const isInternal = targetUrl.includes('169.254.169.254') ||
            targetUrl.includes('metadata') ||
            targetUrl.includes('localhost') ||
            targetUrl.includes('127.0.0.1') ||
            targetUrl.includes('/internal/');
          const hasCredentials = body.response ? body.response.includes('AccessKeyId') : false;

          return new Response(JSON.stringify({
            isInternal,
            hasCredentials,
            accessedMetadata: isInternal,
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

    // Internal metadata endpoint (plain text response for SSRF)
    if (url.pathname.startsWith('/internal/metadata')) {
      const subpath = url.pathname.replace('/internal/metadata', '') || '/';
      const data = handleMetadata(subpath);
      return new Response(data, {
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
