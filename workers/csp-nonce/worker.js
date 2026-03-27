/**
 * CSP Nonce Injection Worker — Penumbra Forge
 *
 * Deployed on a Cloudflare route (penumbraforge.com/*), this Worker:
 *   1. Passes the request to the origin (GitHub Pages via Cloudflare DNS)
 *   2. For HTML responses, injects a unique nonce into inline <script> tags
 *   3. Sets a strict CSP with that nonce — no 'unsafe-inline'
 *   4. Adds all security headers to every response
 *
 * Deploy:
 *   cd workers/csp-nonce && npx wrangler deploy
 *   Then add Worker Route in dashboard: penumbraforge.com/* → csp-nonce
 *   Remove any existing CSP / security header Transform Rules.
 *
 * Rollback:
 *   Remove the Worker Route in dashboard to restore normal traffic.
 */

const SECURITY_HEADERS = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'X-Permitted-Cross-Domain-Policies': 'none',
};

function buildCSP(nonce) {
  return [
    "default-src 'none'",
    `script-src 'nonce-${nonce}' 'strict-dynamic' https: 'self'`,
    "connect-src 'self' https://cloudflareinsights.com https://*.penumbraforge.workers.dev https://api.pwnedpasswords.com https://challenges.cloudflare.com",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' https://fonts.gstatic.com https://fonts.googleapis.com",
    "frame-src https://challenges.cloudflare.com https://*.penumbraforge.workers.dev",
    "base-uri 'self'",
    "form-action 'none'",
  ].join('; ');
}

export default {
  async fetch(request) {
    /* Fetch from origin — Cloudflare resolves DNS to GitHub Pages.
       Using fetch(request) on a route does NOT re-enter the Worker. */
    const response = await fetch(request);

    const contentType = response.headers.get('content-type') || '';

    /* Non-HTML: add security headers, pass through */
    if (!contentType.includes('text/html')) {
      const headers = new Headers(response.headers);
      applySecurityHeaders(headers, contentType);
      return new Response(response.body, {
        status: response.status,
        headers,
      });
    }

    /* HTML: inject nonces into inline script tags */
    const nonce = generateNonce();

    const transformed = new HTMLRewriter()
      .on('script', new NonceInjector(nonce))
      .transform(response);

    const headers = new Headers(transformed.headers);
    applySecurityHeaders(headers, contentType);
    headers.set('Content-Security-Policy', buildCSP(nonce));

    /* Prevent CDN from caching the nonced HTML */
    headers.set('Cache-Control', 'public, max-age=0, must-revalidate');

    return new Response(transformed.body, {
      status: transformed.status,
      headers,
    });
  },
};

function applySecurityHeaders(headers, contentType) {
  Object.entries(SECURITY_HEADERS).forEach(([k, v]) => headers.set(k, v));
  /* Fonts and stylesheets need cross-origin CORP for cross-origin loading */
  if (contentType.includes('font') || contentType.includes('css')) {
    headers.set('Cross-Origin-Resource-Policy', 'cross-origin');
  }
}

class NonceInjector {
  constructor(nonce) {
    this.nonce = nonce;
  }

  element(el) {
    el.setAttribute('nonce', this.nonce);
  }
}

function generateNonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes))
    .replace(/[+/=]/g, '')
    .substring(0, 22);
}
