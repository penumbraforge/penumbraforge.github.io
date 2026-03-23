/**
 * CloudSnap — Vulnerable Image Hosting Platform
 * Penumbra Forge Security Labs — RED-03
 *
 * INTENTIONALLY VULNERABLE: URL import feature fetches user-provided
 * URLs server-side without validation. An internal metadata endpoint
 * simulates cloud instance credentials accessible via SSRF.
 */

const STYLES = `
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#13111a; color:#d4d0e0; }

  .cs-header { background:linear-gradient(135deg,#1a1625,#201a30); border-bottom:1px solid #2d2640; padding:14px 32px; display:flex; align-items:center; justify-content:space-between; }
  .cs-logo { font-size:20px; font-weight:700; color:#c4a8d8; letter-spacing:-0.5px; text-decoration:none; }
  .cs-logo span { color:#8a7aaa; font-weight:300; }
  .cs-nav { display:flex; gap:20px; }
  .cs-nav a { color:#8a7aaa; text-decoration:none; font-size:13px; }
  .cs-nav a:hover { color:#d4d0e0; }
  .cs-nav a.active { color:#c4a8d8; }
  .cs-user { font-size:13px; color:#8a7aaa; }

  .cs-container { max-width:900px; margin:0 auto; padding:32px; }

  .cs-card { background:#1a1625; border:1px solid #2d2640; border-radius:10px; padding:24px; margin-bottom:20px; }
  .cs-card h2 { font-size:16px; color:#d4d0e0; margin-bottom:4px; font-weight:500; }
  .cs-card h3 { font-size:13px; color:#8a7aaa; margin-bottom:16px; font-weight:400; }

  .cs-upload-zone { border:2px dashed #2d2640; border-radius:10px; padding:40px; text-align:center; margin-bottom:16px; color:#8a7aaa; font-size:14px; }
  .cs-upload-zone-icon { font-size:36px; margin-bottom:8px; opacity:0.5; }

  .cs-tabs { display:flex; gap:0; margin-bottom:16px; }
  .cs-tab { padding:10px 20px; font-size:13px; cursor:pointer; border:1px solid #2d2640; background:#13111a; color:#8a7aaa; }
  .cs-tab:first-child { border-radius:8px 0 0 8px; }
  .cs-tab:last-child { border-radius:0 8px 8px 0; }
  .cs-tab.active { background:#2d2640; color:#c4a8d8; }

  .cs-url-input { display:flex; gap:8px; }
  .cs-url-input input { flex:1; padding:10px 14px; background:#13111a; border:1px solid #2d2640; border-radius:8px; color:#d4d0e0; font-size:14px; outline:none; font-family:monospace; }
  .cs-url-input input:focus { border-color:#c4a8d8; }
  .cs-url-input button { padding:10px 20px; background:#7c3aed; color:#fff; border:none; border-radius:8px; font-size:13px; font-weight:500; cursor:pointer; }
  .cs-url-input button:hover { background:#6d28d9; }

  .cs-preview { margin-top:16px; }
  .cs-preview-label { font-size:12px; color:#8a7aaa; margin-bottom:8px; }
  .cs-preview-box { background:#13111a; border:1px solid #2d2640; border-radius:8px; padding:16px; min-height:100px; }
  .cs-preview-box img { max-width:100%; border-radius:6px; }
  .cs-preview-meta { font-family:monospace; font-size:11px; color:#8a7aaa; line-height:1.6; white-space:pre-wrap; word-break:break-all; }
  .cs-error { color:#f87171; background:rgba(248,113,113,0.1); border:1px solid rgba(248,113,113,0.2); border-radius:8px; padding:12px; margin-top:12px; font-family:monospace; font-size:12px; }
  .cs-success { color:#a78bfa; background:rgba(167,139,250,0.08); border:1px solid rgba(167,139,250,0.15); border-radius:8px; padding:12px; margin-top:12px; font-size:13px; }

  .cs-gallery { display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:12px; }
  .cs-thumb { background:#1a1625; border:1px solid #2d2640; border-radius:8px; overflow:hidden; }
  .cs-thumb-img { height:120px; background:#2d2640; display:flex; align-items:center; justify-content:center; font-size:32px; }
  .cs-thumb-info { padding:8px 10px; }
  .cs-thumb-name { font-size:12px; color:#d4d0e0; margin-bottom:2px; }
  .cs-thumb-size { font-size:10px; color:#8a7aaa; }

  .cs-footer { text-align:center; padding:32px; color:#4a4060; font-size:11px; border-top:1px solid #2d2640; margin-top:48px; }
`;

const IMAGES = [
  { name: 'sunset-mountain.jpg', size: '2.4 MB', emoji: '🏔️' },
  { name: 'city-skyline.jpg', size: '3.1 MB', emoji: '🌃' },
  { name: 'ocean-wave.jpg', size: '1.8 MB', emoji: '🌊' },
  { name: 'forest-path.jpg', size: '2.7 MB', emoji: '🌲' },
  { name: 'desert-dune.jpg', size: '2.2 MB', emoji: '🏜️' },
  { name: 'northern-lights.jpg', size: '4.1 MB', emoji: '🌌' },
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

function renderApp(url) {
  const path = new URL(url).pathname;
  const params = new URL(url).searchParams;

  if (path === '/import' || path === '/import/') {
    return renderImport(params.get('url') || '');
  }
  if (path.startsWith('/internal/metadata')) {
    return handleMetadata(path.replace('/internal/metadata', '') || '/');
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
      <div class="cs-thumb-img">${img.emoji}</div>
      <div class="cs-thumb-info">
        <div class="cs-thumb-name">${img.name}</div>
        <div class="cs-thumb-size">${img.size}</div>
      </div>
    </div>
  `).join('');

  return page('Gallery', `
    <div class="cs-card">
      <h2>Your Images</h2>
      <h3>${IMAGES.length} images · 16.3 MB total</h3>
      <div class="cs-gallery">${thumbs}</div>
    </div>
    <div class="cs-card">
      <h2>Upload</h2>
      <div class="cs-upload-zone">
        <div class="cs-upload-zone-icon">&#x1f4f7;</div>
        Drag & drop images here or <a href="/import" style="color:#c4a8d8;">import from URL</a>
      </div>
    </div>
  `);
}

function renderImport(fetchUrl) {
  let resultHtml = '';

  if (fetchUrl) {
    // ═══════════════════════════════════════════════════
    // ⚠ INTENTIONALLY VULNERABLE — DO NOT FIX
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
          <div style="margin-bottom:8px;font-size:12px;color:#8a7aaa;">Server-side fetch: <code style="color:#c4a8d8;">${escHtml(fetchUrl)}</code></div>
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
      <\\/script>`;
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

  return page('Import from URL', `
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
  `);
}

function page(title, content) {
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} — CloudSnap</title><style>${STYLES}</style></head>
<body>
  <div class="cs-header">
    <a href="/" class="cs-logo">Cloud<span>Snap</span></a>
    <div class="cs-nav">
      <a href="/">Gallery</a>
      <a href="/import" class="${title.includes('Import') ? 'active' : ''}">Import</a>
      <a href="#">Shared</a>
      <a href="#">Settings</a>
    </div>
    <div class="cs-user">dev@cloudsnap.io</div>
  </div>
  <div class="cs-container">${content}</div>
  <div class="cs-footer">© 2026 CloudSnap — Cloud Image Hosting<br>All data is simulated. This is a Penumbra Forge Security Lab.</div>
  <script>
    document.querySelectorAll('form').forEach(function(f) {
      f.addEventListener('submit', function(e) {
        e.preventDefault();
        var url = f.querySelector('input[name=url]').value;
        window.location = '/import?url=' + encodeURIComponent(url);
      });
    });
  </script>
</body></html>`;
}

function escHtml(s) {
  return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export default {
  async fetch(request) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*' } });
    }

    const url = new URL(request.url);

    // Internal metadata endpoint (plain text response for SSRF)
    if (url.pathname.startsWith('/internal/metadata')) {
      const subpath = url.pathname.replace('/internal/metadata', '') || '/';
      const data = handleMetadata(subpath);
      return new Response(data, {
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
