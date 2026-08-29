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

const AI_ENDPOINT_PATHS = new Set([
  '/tools/local-chat',
  '/tools/local-rag',
  '/tools/ai-regex-builder',
  '/tools/ai-command-explainer',
  '/tools/ai-security-copilot',
]);

const TOOL_API_ORIGINS = new Map([
  ['/tools/one-time-secret', 'https://one-time-secret.penumbraforge.workers.dev'],
  ['/tools/ct-monitor', 'https://ct-monitor.penumbraforge.workers.dev'],
  ['/tools/privacy-scan', 'https://privacy-scan.penumbraforge.workers.dev'],
  ['/tools/site-score', 'https://site-score.penumbraforge.workers.dev'],
]);

function normalizedPath(pathname) {
  const withoutIndex = pathname.replace(/\/index\.html$/, '/');
  return withoutIndex.length > 1 ? withoutIndex.replace(/\/+$/, '') : withoutIndex;
}

function buildCSP(nonce, pathname) {
  const path = normalizedPath(pathname);
  const scriptSources = ["'nonce-" + nonce + "'", "'strict-dynamic'", "'self'"];
  const connectSources = [
    "'self'",
    'https://cloudflareinsights.com',
    'https://challenges.cloudflare.com',
  ];
  const imageSources = ["'self'", 'data:', 'blob:'];
  const workerSources = ["'self'"];
  const childSources = ["'self'"];

  if (path === '/tools/breach-checker') {
    connectSources.push('https://api.pwnedpasswords.com');
  }
  if (path === '/tools/ip-toolkit') {
    connectSources.push('https://api.ipify.org', 'https://httpbin.org');
  }
  if (path === '/snake') {
    connectSources.push('https://tools.penumbraforge.com');
  }
  if (path === '/tools/meta-tag-generator') {
    imageSources.push('https:');
  }
  if (TOOL_API_ORIGINS.has(path)) {
    connectSources.push(TOOL_API_ORIGINS.get(path));
  }

  /*
   * These pages explicitly let the visitor choose a remote HTTPS endpoint.
   * Restrict the broader connection source to those routes; local development
   * endpoints are likewise allowed only there and in API Request Builder.
   */
  if (AI_ENDPOINT_PATHS.has(path)) {
    scriptSources.push("'wasm-unsafe-eval'");
    connectSources.push(
      'https:',
      'http://localhost:*',
      'http://127.0.0.1:*',
      'ws://localhost:*',
      'ws://127.0.0.1:*'
    );
    workerSources.push('blob:');
    childSources.push('blob:');
  }
  if (path === '/tools/api-request-builder') {
    connectSources.push(
      'https:',
      'http://localhost:*',
      'http://127.0.0.1:*',
      'ws://localhost:*',
      'ws://127.0.0.1:*'
    );
  }

  return [
    "default-src 'none'",
    'script-src ' + scriptSources.join(' '),
    'connect-src ' + connectSources.join(' '),
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    'img-src ' + imageSources.join(' '),
    "font-src 'self' data: https://fonts.gstatic.com",
    "media-src 'self' blob:",
    "manifest-src 'self'",
    'worker-src ' + workerSources.join(' '),
    'child-src ' + childSources.join(' '),
    "frame-src https://challenges.cloudflare.com",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'none'",
    "frame-ancestors 'none'",
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
    headers.set('Content-Security-Policy', buildCSP(nonce, new URL(request.url).pathname));

    /* A nonce belongs to one response and must not be stored or replayed. */
    headers.set('Cache-Control', 'private, no-store');

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
