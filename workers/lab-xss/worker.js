/**
 * ShopStack — Vulnerable E-Commerce App
 * Penumbra Forge Security Labs — RED-01
 *
 * INTENTIONALLY VULNERABLE: Search endpoint reflects user input
 * via innerHTML without encoding. This is a real XSS vulnerability
 * running in an isolated Worker for educational purposes.
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

const PRODUCTS = [
  { id: 1, name: 'ProVision 4K Security Camera', price: '$149.99', oldPrice: '$199.99', rating: 4.9, reviews: 2341, brand: 'SecureView', category: 'Security', badge: 'Sale' },
  { id: 2, name: 'SmartGuard Keyless Entry System', price: '$89.99', rating: 4.5, reviews: 876, brand: 'HomeFort', category: 'Home' },
  { id: 3, name: 'NetPulse Traffic Analyzer Pro', price: '$199.99', rating: 4.8, reviews: 412, brand: 'CyberTools', category: 'Network' },
  { id: 4, name: 'SentinelOne Endpoint Monitor', price: '$299.99', rating: 4.7, reviews: 1089, brand: 'SentinelTech', category: 'Security' },
  { id: 5, name: 'CloudVault Encrypted NAS', price: '$349.99', oldPrice: '$449.99', rating: 4.6, reviews: 567, brand: 'DataFort', category: 'Storage', badge: 'Sale' },
  { id: 6, name: 'PhishGuard Email Filter', price: '$79.99', rating: 4.4, reviews: 234, brand: 'MailShield', category: 'Email' },
  { id: 7, name: 'ZeroDay Vulnerability Scanner', price: '$599.99', rating: 4.9, reviews: 1567, brand: 'PenTools', category: 'Security' },
  { id: 8, name: 'ThreatMap Network Visualizer', price: '$129.99', rating: 4.3, reviews: 345, brand: 'NetViz', category: 'Network' },
];

/* Category gradient map */
function categoryGradient(category) {
  switch (category) {
    case 'Security': return 'linear-gradient(135deg, #7c3aed 0%, #6366f1 100%)';
    case 'Home':     return 'linear-gradient(135deg, #059669 0%, #10b981 100%)';
    case 'Network':  return 'linear-gradient(135deg, #2563eb 0%, #3b82f6 100%)';
    case 'Storage':  return 'linear-gradient(135deg, #6366f1 0%, #818cf8 100%)';
    case 'Email':    return 'linear-gradient(135deg, #0891b2 0%, #06b6d4 100%)';
    default:         return 'linear-gradient(135deg, #6366f1 0%, #818cf8 100%)';
  }
}

/* Category icon (SVG-based, no emoji) */
function categoryIcon(category) {
  switch (category) {
    case 'Security': return '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
    case 'Home':     return '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>';
    case 'Network':  return '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>';
    case 'Storage':  return '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>';
    case 'Email':    return '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>';
    default:         return '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>';
  }
}

/* Star rating HTML */
function starsHtml(rating, reviews) {
  const full = Math.floor(rating);
  const half = rating - full >= 0.5;
  let s = '';
  for (let i = 0; i < full; i++) s += '<span style="color:#f59e0b;">&#9733;</span>';
  if (half) s += '<span style="color:#f59e0b;">&#9733;</span>';
  const empty = 5 - full - (half ? 1 : 0);
  for (let i = 0; i < empty; i++) s += '<span style="color:#d1d5db;">&#9733;</span>';
  return `${s} <span style="color:#6b7280;font-size:12px;">(${reviews.toLocaleString()})</span>`;
}

const STYLES = `
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f3f4f6; color: #1f2937; line-height: 1.5; }

  /* Promo banner */
  .promo-banner { background: #1e1b4b; color: #e0e7ff; padding: 10px 24px; text-align: center; font-size: 13px; font-weight: 500; letter-spacing: 0.3px; }

  /* Header / Nav */
  .header { background: #fff; border-bottom: 1px solid #e5e7eb; padding: 0 32px; display: flex; align-items: center; justify-content: space-between; height: 64px; position: sticky; top: 0; z-index: 100; }
  .header-left { display: flex; align-items: center; gap: 32px; }
  .logo { display: flex; align-items: center; gap: 10px; text-decoration: none; }
  .logo-icon { width: 32px; height: 32px; border-radius: 8px; background: linear-gradient(135deg, #6366f1, #8b5cf6); display: flex; align-items: center; justify-content: center; color: #fff; font-weight: 800; font-size: 16px; }
  .logo-text { font-size: 20px; font-weight: 700; color: #1f2937; letter-spacing: -0.5px; }
  .logo-text span { color: #6366f1; }
  .nav { display: flex; gap: 4px; }
  .nav a { color: #6b7280; text-decoration: none; font-size: 14px; font-weight: 500; padding: 8px 14px; border-radius: 8px; transition: all 150ms; }
  .nav a:hover { color: #1f2937; background: #f3f4f6; }
  .nav a.active { color: #6366f1; background: #eef2ff; }

  .header-right { display: flex; align-items: center; gap: 16px; }
  .avatar { width: 34px; height: 34px; border-radius: 50%; background: #e0e7ff; color: #6366f1; display: flex; align-items: center; justify-content: center; font-size: 13px; font-weight: 700; cursor: pointer; }
  .cart-icon { position: relative; cursor: pointer; color: #6b7280; }
  .cart-icon svg { display: block; }
  .cart-badge { position: absolute; top: -6px; right: -8px; background: #6366f1; color: #fff; font-size: 10px; font-weight: 700; width: 18px; height: 18px; border-radius: 50%; display: flex; align-items: center; justify-content: center; }

  /* Container */
  .container { max-width: 1060px; margin: 0 auto; padding: 24px 24px 0; }

  /* Search section */
  .search-section { background: #fff; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04); }
  .search-section h2 { font-size: 17px; margin-bottom: 12px; color: #111827; font-weight: 600; }
  .search-box { display: flex; gap: 8px; }
  .search-box input { flex: 1; padding: 12px 16px; border: 2px solid #e5e7eb; border-radius: 10px; font-size: 15px; outline: none; transition: border-color 200ms, box-shadow 200ms; background: #f9fafb; color: #1f2937; }
  .search-box input:focus { border-color: #6366f1; box-shadow: 0 0 0 3px rgba(99,102,241,0.15); background: #fff; }
  .search-box button { padding: 12px 24px; background: #6366f1; color: #fff; border: none; border-radius: 10px; font-size: 14px; font-weight: 600; cursor: pointer; transition: background 150ms; }
  .search-box button:hover { background: #4f46e5; }

  /* Results area */
  .results { margin-top: 16px; padding: 16px; background: #f9fafb; border-radius: 10px; border: 1px solid #f3f4f6; }
  .results-header { font-size: 14px; color: #6b7280; margin-bottom: 12px; }
  .results-header strong { color: #1f2937; }
  .results-bar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
  .sort-select { padding: 6px 12px; border: 1px solid #e5e7eb; border-radius: 6px; font-size: 13px; color: #374151; background: #fff; outline: none; cursor: pointer; }
  .sort-select:focus { border-color: #6366f1; }

  /* Product grid */
  .products { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 20px; }
  .product { background: #fff; border-radius: 12px; overflow: hidden; border: 1px solid #e5e7eb; transition: all 200ms; cursor: pointer; }
  .product:hover { transform: translateY(-3px); box-shadow: 0 10px 25px rgba(0,0,0,0.08); border-color: #c7d2fe; }
  .product-img { height: 140px; display: flex; align-items: center; justify-content: center; position: relative; }
  .product-badge { position: absolute; top: 10px; left: 10px; background: #ef4444; color: #fff; font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 6px; letter-spacing: 0.3px; text-transform: uppercase; }
  .product-body { padding: 14px 16px 16px; }
  .product-brand { font-size: 11px; color: #9ca3af; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
  .product-name { font-size: 14px; font-weight: 600; color: #111827; margin-bottom: 6px; line-height: 1.4; }
  .product-rating { font-size: 13px; margin-bottom: 8px; line-height: 1; }
  .product-price { display: flex; align-items: baseline; gap: 8px; margin-bottom: 12px; }
  .product-price .current { font-size: 18px; color: #111827; font-weight: 700; }
  .product-price .old { font-size: 13px; color: #9ca3af; text-decoration: line-through; }
  .product-atc { display: block; width: 100%; padding: 10px; background: #6366f1; color: #fff; border: none; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; text-align: center; transition: background 150ms; }
  .product-atc:hover { background: #4f46e5; }

  /* Category tag */
  .product-category { font-size: 11px; color: #6b7280; background: #f3f4f6; padding: 3px 10px; border-radius: 6px; display: inline-block; margin-bottom: 8px; }

  /* Breadcrumbs */
  .breadcrumb { font-size: 13px; color: #9ca3af; margin-bottom: 16px; }
  .breadcrumb a { color: #6366f1; text-decoration: none; }
  .breadcrumb a:hover { text-decoration: underline; }
  .breadcrumb span { margin: 0 6px; }

  /* Footer */
  .footer { text-align: center; padding: 32px 24px; color: #9ca3af; font-size: 12px; border-top: 1px solid #e5e7eb; margin-top: 48px; background: #fff; }
  .footer a { color: #6b7280; text-decoration: none; }
  .footer a:hover { color: #6366f1; }
  .footer-links { margin-top: 6px; }
  .footer-links a { margin: 0 12px; }

  /* Section title */
  .section-title { font-size: 17px; font-weight: 600; color: #111827; margin-bottom: 16px; }
`;

function shell(title, activePage, content) {
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} — ShopStack</title><style>${STYLES}</style></head>
<body>
  <div class="promo-banner">FREE SHIPPING on orders over $75 &mdash; Limited time offer</div>
  <div class="header">
    <div class="header-left">
      <a href="/" class="logo">
        <div class="logo-icon">S</div>
        <div class="logo-text">Shop<span>Stack</span></div>
      </a>
      <div class="nav">
        <a href="/"${activePage==='home'?' class="active"':''}>Home</a>
        <a href="/search"${activePage==='search'?' class="active"':''}>Products</a>
        <a href="/categories"${activePage==='categories'?' class="active"':''}>Deals</a>
        <a href="/account"${activePage==='account'?' class="active"':''}>Support</a>
      </div>
    </div>
    <div class="header-right">
      <a href="/cart" class="cart-icon" aria-label="Cart">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="21" r="1"/><circle cx="20" cy="21" r="1"/><path d="M1 1h4l2.68 13.39a2 2 0 002 1.61h9.72a2 2 0 002-1.61L23 6H6"/></svg>
        <span class="cart-badge">2</span>
      </a>
      <div class="avatar" title="Guest User">GU</div>
    </div>
  </div>
  <div class="container">${content}</div>
  <div class="footer">
    <div>&copy; 2026 ShopStack Inc. All rights reserved.</div>
    <div class="footer-links"><a href="#">Privacy</a><a href="#">Terms</a><a href="#">Contact</a></div>
  </div>
  <script>
  document.cookie="session=eyJhZG1pbiI6ZmFsc2UsInVzZXIiOiJndWVzdCJ9;path=/";

  /* ── XSS detection: override alert ── */
  var _origAlert = window.alert;
  window.alert = function(msg) {
    try {
      window.parent.postMessage({ type: 'xss-fired', executed: true, payload: String(msg) }, '*');
    } catch(e) {}
    // Don't actually show alert (would block iframe)
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

  /* ── Navigation tracking for lab objectives ── */
  try {
    var params = new URLSearchParams(window.location.search);
    var q = params.get('q');
    window.parent.postMessage({
      type: 'shopstack-nav',
      path: window.location.pathname,
      query: q || '',
      url: window.location.href
    }, '*');
  } catch(e) {}

  /* ── Form submission handler ── */
  document.querySelectorAll('form').forEach(function(f) {
    f.addEventListener('submit', function(e) {
      e.preventDefault();
      var input = f.querySelector('input[name=q]');
      if (input) window.location = '/search?q=' + encodeURIComponent(input.value);
    });
  });
  </script>
</body></html>`;
}

function renderProductCard(p) {
  const gradient = categoryGradient(p.category);
  const icon = categoryIcon(p.category);
  const badge = p.badge ? `<div class="product-badge">${p.badge}</div>` : '';
  const oldPrice = p.oldPrice ? `<span class="old">${p.oldPrice}</span>` : '';
  return `
    <div class="product" onclick="window.location='/product/${p.id}'">
      <div class="product-img" style="background:${gradient};">
        ${icon}
        ${badge}
      </div>
      <div class="product-body">
        <div class="product-brand">by ${p.brand}</div>
        <div class="product-name">${p.name}</div>
        <span class="product-category">${p.category}</span>
        <div class="product-rating">${starsHtml(p.rating, p.reviews)}</div>
        <div class="product-price">
          <span class="current">${p.price}</span>
          ${oldPrice}
        </div>
        <button class="product-atc" onclick="event.stopPropagation();">Add to Cart</button>
      </div>
    </div>`;
}

function renderCategories() {
  const cats = [
    { name: 'Security', count: 3, desc: 'Cameras, monitors, scanners' },
    { name: 'Network', count: 2, desc: 'Analyzers, visualizers' },
    { name: 'Home', count: 1, desc: 'Smart locks, entry systems' },
    { name: 'Storage', count: 1, desc: 'NAS, encrypted drives' },
    { name: 'Email', count: 1, desc: 'Filters, anti-phishing' },
  ];
  const cards = cats.map(c => {
    const gradient = categoryGradient(c.name);
    const icon = categoryIcon(c.name);
    return `<div class="product" onclick="window.location='/search?q=${encodeURIComponent(c.name)}'">
      <div class="product-img" style="background:${gradient};">${icon}</div>
      <div class="product-body">
        <div class="product-name">${c.name}</div>
        <div style="font-size:12px;color:#6b7280;margin-bottom:8px;">${c.desc}</div>
        <div style="font-size:13px;color:#6366f1;font-weight:600;">${c.count} product${c.count!==1?'s':''}</div>
      </div>
    </div>`;
  }).join('');
  return shell('Deals', 'categories', `
    <div class="breadcrumb"><a href="/">Home</a><span>/</span>Deals</div>
    <h2 class="section-title">Browse by Category</h2>
    <div class="products">${cards}</div>`);
}

function renderCart() {
  const items = [
    { product: PRODUCTS[0], qty: 1 },
    { product: PRODUCTS[6], qty: 1 },
  ];
  const subtotal = 149.99 + 599.99;
  const itemRows = items.map(item => {
    const p = item.product;
    const gradient = categoryGradient(p.category);
    return `<div style="display:flex;align-items:center;gap:16px;padding:16px;border-bottom:1px solid #f3f4f6;">
      <div style="width:56px;height:56px;border-radius:10px;background:${gradient};display:flex;align-items:center;justify-content:center;flex-shrink:0;">${categoryIcon(p.category)}</div>
      <div style="flex:1;">
        <div style="font-weight:600;font-size:14px;color:#111827;">${p.name}</div>
        <div style="font-size:12px;color:#9ca3af;">by ${p.brand} &middot; Qty: ${item.qty}</div>
      </div>
      <div style="font-size:16px;color:#111827;font-weight:700;">${p.price}</div>
    </div>`;
  }).join('');

  return shell('Cart', 'cart', `
    <div class="breadcrumb"><a href="/">Home</a><span>/</span>Cart</div>
    <h2 class="section-title">Your Cart (${items.length} items)</h2>
    <div style="background:#fff;border-radius:12px;border:1px solid #e5e7eb;margin-bottom:16px;overflow:hidden;">
      ${itemRows}
    </div>
    <div style="background:#fff;border-radius:12px;border:1px solid #e5e7eb;padding:20px;display:flex;justify-content:space-between;align-items:center;">
      <div>
        <div style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:2px;">Subtotal</div>
        <div style="font-size:28px;font-weight:700;color:#111827;">$${subtotal.toFixed(2)}</div>
        <div style="font-size:12px;color:#059669;margin-top:4px;">Free shipping applied</div>
      </div>
      <button style="padding:14px 36px;background:#6366f1;color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;">Checkout</button>
    </div>`);
}

function renderAccount() {
  return shell('Support', 'account', `
    <div class="breadcrumb"><a href="/">Home</a><span>/</span>Account</div>
    <h2 class="section-title">My Account</h2>
    <div style="background:#fff;border-radius:12px;border:1px solid #e5e7eb;padding:24px;margin-bottom:16px;">
      <div style="display:flex;align-items:center;gap:16px;margin-bottom:20px;">
        <div class="avatar" style="width:52px;height:52px;font-size:16px;">GU</div>
        <div>
          <div style="font-weight:600;font-size:15px;color:#111827;">Guest User</div>
          <div style="font-size:13px;color:#9ca3af;">guest@shopstack.com</div>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div style="padding:14px;background:#f9fafb;border-radius:10px;border:1px solid #f3f4f6;">
          <div style="font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.5px;">Orders</div>
          <div style="font-size:22px;font-weight:700;color:#111827;margin-top:2px;">7</div>
        </div>
        <div style="padding:14px;background:#f9fafb;border-radius:10px;border:1px solid #f3f4f6;">
          <div style="font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.5px;">Wishlist</div>
          <div style="font-size:22px;font-weight:700;color:#111827;margin-top:2px;">3</div>
        </div>
      </div>
    </div>
    <div style="background:#fff;border-radius:12px;border:1px solid #e5e7eb;padding:24px;">
      <h3 style="font-size:15px;font-weight:600;color:#111827;margin-bottom:14px;">Recent Orders</h3>
      <div style="border-bottom:1px solid #f3f4f6;padding:12px 0;display:flex;justify-content:space-between;align-items:center;font-size:13px;">
        <span style="color:#374151;">Order #4821 &mdash; ProVision 4K Security Camera</span>
        <span style="color:#059669;font-weight:600;font-size:12px;background:#ecfdf5;padding:3px 10px;border-radius:6px;">Delivered</span>
      </div>
      <div style="border-bottom:1px solid #f3f4f6;padding:12px 0;display:flex;justify-content:space-between;align-items:center;font-size:13px;">
        <span style="color:#374151;">Order #4790 &mdash; PhishGuard Email Filter</span>
        <span style="color:#059669;font-weight:600;font-size:12px;background:#ecfdf5;padding:3px 10px;border-radius:6px;">Delivered</span>
      </div>
      <div style="padding:12px 0;display:flex;justify-content:space-between;align-items:center;font-size:13px;">
        <span style="color:#374151;">Order #4755 &mdash; NetPulse Traffic Analyzer Pro</span>
        <span style="color:#2563eb;font-weight:600;font-size:12px;background:#eff6ff;padding:3px 10px;border-radius:6px;">Shipped</span>
      </div>
    </div>`);
}

function renderProduct(id) {
  const p = PRODUCTS.find(pr => pr.id === parseInt(id)) || PRODUCTS[0];
  const gradient = categoryGradient(p.category);
  const icon = categoryIcon(p.category);
  const oldPrice = p.oldPrice ? `<span style="font-size:16px;color:#9ca3af;text-decoration:line-through;margin-left:12px;">${p.oldPrice}</span>` : '';
  const badge = p.badge ? `<span style="background:#fef2f2;color:#ef4444;font-size:12px;font-weight:600;padding:4px 12px;border-radius:6px;margin-left:12px;">${p.badge}</span>` : '';

  return shell(p.name, '', `
    <div class="breadcrumb"><a href="/">Home</a><span>/</span><a href="/search?q=${encodeURIComponent(p.category)}">${p.category}</a><span>/</span>${p.name}</div>
    <div style="display:flex;gap:36px;margin-top:8px;">
      <div style="width:340px;height:340px;border-radius:16px;background:${gradient};display:flex;align-items:center;justify-content:center;flex-shrink:0;">
        <svg width="100" height="100" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.9)" stroke-width="1" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      </div>
      <div style="flex:1;">
        <div style="font-size:12px;color:#9ca3af;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">by ${p.brand}</div>
        <h1 style="font-size:26px;color:#111827;margin-bottom:10px;font-weight:700;line-height:1.3;">${p.name}</h1>
        <div style="margin-bottom:12px;">${starsHtml(p.rating, p.reviews)}</div>
        <div style="display:flex;align-items:baseline;margin-bottom:16px;">
          <span style="font-size:32px;color:#111827;font-weight:700;">${p.price}</span>
          ${oldPrice}
          ${badge}
        </div>
        <p style="font-size:14px;color:#6b7280;line-height:1.8;margin-bottom:20px;">Premium quality ${p.name.toLowerCase()} designed for professionals and enthusiasts. Ships free within 2 business days. 30-day return policy included.</p>
        <div style="display:flex;gap:10px;">
          <button style="padding:14px 36px;background:#6366f1;color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;">Add to Cart</button>
          <button style="padding:14px 22px;background:#f3f4f6;color:#374151;border:1px solid #e5e7eb;border-radius:10px;font-size:14px;cursor:pointer;">Save to Wishlist</button>
        </div>
      </div>
    </div>`);
}

function renderPage(url) {
  const path = new URL(url).pathname;
  const params = new URL(url).searchParams;

  if (path === '/search' || path === '/search/') return renderSearch(params.get('q') || '');
  if (path === '/categories' || path === '/categories/') return renderCategories();
  if (path === '/cart' || path === '/cart/') return renderCart();
  if (path === '/account' || path === '/account/') return renderAccount();
  if (path.startsWith('/product/')) return renderProduct(path.split('/')[2]);

  return renderHome();
}

function renderHome() {
  let productCards = PRODUCTS.map(p => renderProductCard(p)).join('');

  return shell('Home', 'home', `
    <div class="search-section">
      <h2>Find what you need</h2>
      <form class="search-box" action="/search" method="GET">
        <input type="text" name="q" placeholder="Search security tools, hardware, software..." autocomplete="off">
        <button type="submit">Search</button>
      </form>
    </div>
    <h2 class="section-title">Featured Products</h2>
    <div class="products">${productCards}</div>`);
}

function renderSearch(query) {
  let matchingProducts = query
    ? PRODUCTS.filter(p => p.name.toLowerCase().includes(query.toLowerCase()) || p.category.toLowerCase().includes(query.toLowerCase()) || p.brand.toLowerCase().includes(query.toLowerCase()))
    : [];

  let productCards = matchingProducts.map(p => renderProductCard(p)).join('');

  if (matchingProducts.length === 0 && query) {
    productCards = '<p style="color:#9ca3af;font-size:14px;padding:16px 0;">No products found matching your search. Try a different term.</p>';
  }

  // ═══════════════════════════════════════════════════
  // INTENTIONALLY VULNERABLE — DO NOT FIX
  // The query is reflected directly into innerHTML
  // without encoding. This is the XSS vulnerability
  // that lab participants must find and exploit.
  // ═══════════════════════════════════════════════════
  const resultsHeader = query
    ? `<div class="results-header">Showing results for: <strong>${query}</strong></div>`
    : '<div class="results-header">Enter a search term above</div>';

  const sortDropdown = query
    ? `<select class="sort-select"><option>Relevance</option><option>Price: Low to High</option><option>Price: High to Low</option><option>Rating</option><option>Newest</option></select>`
    : '';

  return shell('Search', 'search', `
    <div class="breadcrumb"><a href="/">Home</a><span>/</span><a href="/search">Products</a>${query ? '<span>/</span>Results' : ''}</div>
    <div class="search-section">
      <h2>Search Products</h2>
      <form class="search-box" action="/search" method="GET">
        <input type="text" name="q" value="${query.replace(/"/g, '&quot;')}" placeholder="Search security tools, hardware, software..." autocomplete="off">
        <button type="submit">Search</button>
      </form>
      <div class="results">
        <div class="results-bar">
          ${resultsHeader}
          ${sortDropdown}
        </div>
        <div class="products">${productCards}</div>
      </div>
    </div>`);
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // CORS headers for lab iframe communication
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
        if (body.type === 'xss-check' && typeof body.payload === 'string') {
          const payload = body.payload;
          // Check if payload contains characters that would execute as HTML/JS
          const reflected = true; // search always reflects the query
          const hasHtmlChars = /<[^>]*>/i.test(payload) || /javascript:/i.test(payload) || /on\w+\s*=/i.test(payload);
          // The search page reflects without encoding, so anything with HTML is unencoded
          const unencoded = hasHtmlChars;

          return new Response(JSON.stringify({ reflected, unencoded }), {
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

    // Serve the vulnerable app
    const html = renderPage(request.url);

    return new Response(html, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=UTF-8',
        // Intentionally weak headers for the lab
        'X-Powered-By': 'Express',
        'X-XSS-Protection': '0',
        // No CSP header — intentionally missing
        ...corsHeaders,
      },
    });
  },
};
