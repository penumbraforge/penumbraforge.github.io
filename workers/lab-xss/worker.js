/**
 * ShopStack — Vulnerable E-Commerce App
 * Penumbra Forge Security Labs — RED-01
 *
 * INTENTIONALLY VULNERABLE: Search endpoint reflects user input
 * via innerHTML without encoding. This is a real XSS vulnerability
 * running in an isolated Worker for educational purposes.
 */

const PRODUCTS = [
  { id: 1, name: 'Mechanical Keyboard Pro', price: '$149.99', rating: 4.8, category: 'Electronics', img: '⌨️' },
  { id: 2, name: 'Ultrawide Monitor 34"', price: '$599.99', rating: 4.6, category: 'Electronics', img: '🖥️' },
  { id: 3, name: 'Noise-Cancelling Headphones', price: '$279.99', rating: 4.9, category: 'Audio', img: '🎧' },
  { id: 4, name: 'Ergonomic Standing Desk', price: '$449.99', rating: 4.5, category: 'Furniture', img: '🪑' },
  { id: 5, name: 'USB-C Docking Station', price: '$89.99', rating: 4.3, category: 'Electronics', img: '🔌' },
  { id: 6, name: 'Webcam 4K HDR', price: '$129.99', rating: 4.7, category: 'Electronics', img: '📷' },
  { id: 7, name: 'Wireless Mouse', price: '$59.99', rating: 4.4, category: 'Electronics', img: '🖱️' },
  { id: 8, name: 'LED Desk Lamp', price: '$39.99', rating: 4.2, category: 'Furniture', img: '💡' },
];

const STYLES = `
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8f9fa; color: #333; }
  .header { background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 16px 32px; display: flex; align-items: center; justify-content: space-between; }
  .logo { color: #ff6b6b; font-size: 22px; font-weight: 700; letter-spacing: -0.5px; text-decoration: none; }
  .logo span { color: #fff; font-weight: 300; }
  .nav { display: flex; gap: 24px; }
  .nav a { color: rgba(255,255,255,0.7); text-decoration: none; font-size: 14px; }
  .nav a:hover { color: #fff; }
  .nav a.active { color: #ff6b6b; }
  .cart-badge { background: #ff6b6b; color: #fff; font-size: 10px; padding: 2px 6px; border-radius: 10px; margin-left: 4px; }

  .container { max-width: 960px; margin: 0 auto; padding: 24px; }

  .search-section { background: #fff; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
  .search-section h2 { font-size: 18px; margin-bottom: 12px; color: #222; }
  .search-box { display: flex; gap: 8px; }
  .search-box input { flex: 1; padding: 12px 16px; border: 2px solid #e9ecef; border-radius: 8px; font-size: 15px; outline: none; transition: border-color 200ms; }
  .search-box input:focus { border-color: #ff6b6b; }
  .search-box button { padding: 12px 24px; background: #ff6b6b; color: #fff; border: none; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; }
  .search-box button:hover { background: #ee5a5a; }

  .results { margin-top: 16px; padding: 16px; background: #f8f9fa; border-radius: 8px; }
  .results-header { font-size: 14px; color: #666; margin-bottom: 12px; }

  .products { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 16px; }
  .product { background: #fff; border-radius: 10px; padding: 16px; border: 1px solid #e9ecef; transition: all 200ms; cursor: pointer; }
  .product:hover { border-color: #ff6b6b; transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
  .product-img { font-size: 32px; margin-bottom: 8px; }
  .product-name { font-size: 14px; font-weight: 600; color: #222; margin-bottom: 4px; }
  .product-price { font-size: 16px; color: #ff6b6b; font-weight: 700; margin-bottom: 4px; }
  .product-rating { font-size: 12px; color: #999; }
  .product-category { font-size: 11px; color: #aaa; background: #f0f0f0; padding: 2px 8px; border-radius: 4px; display: inline-block; margin-top: 4px; }

  .breadcrumb { font-size: 13px; color: #999; margin-bottom: 16px; }
  .breadcrumb a { color: #ff6b6b; text-decoration: none; }

  .footer { text-align: center; padding: 32px; color: #aaa; font-size: 12px; border-top: 1px solid #e9ecef; margin-top: 48px; }

  .promo-banner { background: linear-gradient(135deg, #ff6b6b, #ee5a5a); color: #fff; padding: 12px 24px; text-align: center; font-size: 13px; font-weight: 500; }
`;

function renderPage(url) {
  const path = new URL(url).pathname;
  const params = new URL(url).searchParams;

  if (path === '/search' || path === '/search/') {
    return renderSearch(params.get('q') || '');
  }

  return renderHome();
}

function renderHome() {
  let productCards = PRODUCTS.map(p => `
    <div class="product" onclick="window.location='/search?q=${encodeURIComponent(p.name)}'">
      <div class="product-img">${p.img}</div>
      <div class="product-name">${p.name}</div>
      <div class="product-price">${p.price}</div>
      <div class="product-rating">★ ${p.rating} / 5.0</div>
      <span class="product-category">${p.category}</span>
    </div>
  `).join('');

  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ShopStack</title><style>${STYLES}</style></head>
<body>
  <div class="promo-banner">🔥 Spring Sale — 20% off all electronics with code SPRING26</div>
  <div class="header">
    <a href="/" class="logo">Shop<span>Stack</span></a>
    <div class="nav">
      <a href="/" class="active">Products</a>
      <a href="/search">Search</a>
      <a href="#">Categories</a>
      <a href="#">Cart <span class="cart-badge">2</span></a>
      <a href="#">Account</a>
    </div>
  </div>
  <div class="container">
    <div class="search-section">
      <h2>Find what you need</h2>
      <form class="search-box" action="/search" method="GET">
        <input type="text" name="q" placeholder="Search products..." autocomplete="off">
        <button type="submit">Search</button>
      </form>
    </div>
    <h2 style="font-size:16px;margin-bottom:16px;color:#222;">Featured Products</h2>
    <div class="products">${productCards}</div>
  </div>
  <div class="footer">© 2026 ShopStack Inc. — All rights reserved. | <a href="#" style="color:#999;">Privacy</a> | <a href="#" style="color:#999;">Terms</a></div>
</body></html>`;
}

function renderSearch(query) {
  // Filter matching products
  let matchingProducts = query
    ? PRODUCTS.filter(p => p.name.toLowerCase().includes(query.toLowerCase()))
    : [];

  let productCards = matchingProducts.map(p => `
    <div class="product">
      <div class="product-img">${p.img}</div>
      <div class="product-name">${p.name}</div>
      <div class="product-price">${p.price}</div>
      <div class="product-rating">★ ${p.rating} / 5.0</div>
      <span class="product-category">${p.category}</span>
    </div>
  `).join('');

  if (matchingProducts.length === 0 && query) {
    productCards = '<p style="color:#999;font-size:14px;padding:12px 0;">No products found matching your search.</p>';
  }

  // ═══════════════════════════════════════════════════
  // ⚠ INTENTIONALLY VULNERABLE — DO NOT FIX
  // The query is reflected directly into innerHTML
  // without encoding. This is the XSS vulnerability
  // that lab participants must find and exploit.
  // ═══════════════════════════════════════════════════
  const resultsHeader = query
    ? `<div class="results-header">Showing results for: <strong>${query}</strong></div>`
    : '<div class="results-header">Enter a search term above</div>';

  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Search — ShopStack</title><style>${STYLES}</style></head>
<body>
  <div class="promo-banner">🔥 Spring Sale — 20% off all electronics with code SPRING26</div>
  <div class="header">
    <a href="/" class="logo">Shop<span>Stack</span></a>
    <div class="nav">
      <a href="/">Products</a>
      <a href="/search" class="active">Search</a>
      <a href="#">Categories</a>
      <a href="#">Cart <span class="cart-badge">2</span></a>
      <a href="#">Account</a>
    </div>
  </div>
  <div class="container">
    <div class="breadcrumb"><a href="/">Home</a> › <a href="/search">Search</a>${query ? ' › Results' : ''}</div>
    <div class="search-section">
      <h2>Search Products</h2>
      <form class="search-box" action="/search" method="GET">
        <input type="text" name="q" value="${query.replace(/"/g, '&quot;')}" placeholder="Search products..." autocomplete="off">
        <button type="submit">Search</button>
      </form>
      <div class="results">
        ${resultsHeader}
        <div class="products">${productCards}</div>
      </div>
    </div>
  </div>
  <div class="footer">© 2026 ShopStack Inc. — All rights reserved. | <a href="#" style="color:#999;">Privacy</a> | <a href="#" style="color:#999;">Terms</a></div>
  <script>
    // Simulated session cookie for the lab
    document.cookie = "session=eyJhZG1pbiI6ZmFsc2UsInVzZXIiOiJndWVzdCJ9; path=/";

    // Notify parent frame of events for the lab inspector
    document.querySelectorAll('form').forEach(function(f) {
      f.addEventListener('submit', function(e) {
        e.preventDefault();
        var q = f.querySelector('input[name=q]').value;
        window.location = '/search?q=' + encodeURIComponent(q);
      });
    });
  </script>
</body></html>`;
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

    // Serve the vulnerable app
    const html = renderPage(request.url);

    return new Response(html, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=UTF-8',
        // Intentionally weak headers for the lab
        'X-Powered-By': 'Express',
        // No CSP — part of the vulnerability
        ...corsHeaders,
      },
    });
  },
};
