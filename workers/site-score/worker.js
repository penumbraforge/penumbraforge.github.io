/**
 * Site Score Worker — Penumbra Forge
 *
 * Fetches HTTP headers for a given URL and returns them as JSON.
 * Protected by Cloudflare Turnstile and per-IP rate limiting.
 */

const RATE_LIMIT = 10;          // max requests per window
const RATE_WINDOW = 3600000;    // 1 hour in ms
const rateBuckets = new Map();

export default {
  async fetch(request, env) {
    /* ── CORS preflight ── */
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(env),
      });
    }

    /* ── Only POST ── */
    if (request.method !== 'POST') {
      return json({ error: 'Method not allowed' }, 405, env);
    }

    /* ── Origin check ── */
    const origin = request.headers.get('Origin') || '';
    if (env.ALLOWED_ORIGIN && !origin.startsWith(env.ALLOWED_ORIGIN)) {
      return json({ error: 'Forbidden' }, 403, env);
    }

    /* ── Rate limiting ── */
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (isRateLimited(ip)) {
      return json({ error: 'Rate limited. Try again later.' }, 429, env);
    }

    /* ── Parse body ── */
    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: 'Invalid JSON body' }, 400, env);
    }

    const { url, token } = body;

    /* ── Verify Turnstile ── */
    if (env.TURNSTILE_SECRET) {
      const verified = await verifyTurnstile(token, ip, env.TURNSTILE_SECRET);
      if (!verified) {
        return json({ error: 'Turnstile verification failed' }, 403, env);
      }
    }

    /* ── Validate URL ── */
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return json({ error: 'Invalid URL' }, 400, env);
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return json({ error: 'Only HTTP and HTTPS URLs are supported' }, 400, env);
    }

    /* ── SSRF protection: block private IPs ── */
    const hostname = parsed.hostname;
    if (isPrivateHost(hostname)) {
      return json({ error: 'Cannot scan private/internal addresses' }, 400, env);
    }

    /* ── Fetch target headers ── */
    let targetHeaders;
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);

      const resp = await fetch(parsed.href, {
        method: 'GET',
        redirect: 'follow',
        signal: controller.signal,
        headers: {
          'User-Agent': 'PenumbraForge-SiteScore/1.0 (+https://penumbraforge.com/tools/site-score/)',
        },
      });

      clearTimeout(timeout);

      targetHeaders = {};
      for (const [key, value] of resp.headers.entries()) {
        targetHeaders[key] = value;
      }
      targetHeaders['_status'] = resp.status;
      targetHeaders['_url'] = resp.url;
    } catch (err) {
      return json({ error: 'Failed to fetch URL: ' + (err.message || 'timeout or unreachable') }, 502, env);
    }

    return json({ headers: targetHeaders }, 200, env);
  },
};

/* ── Helpers ── */

function corsHeaders(env) {
  return {
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
}

function json(data, status, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(env),
    },
  });
}

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

async function verifyTurnstile(token, ip, secret) {
  if (!token) return false;

  try {
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret,
        response: token,
        remoteip: ip,
      }),
    });

    const data = await resp.json();
    return data.success === true;
  } catch {
    return false;
  }
}

function isPrivateHost(hostname) {
  /* Block localhost */
  if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') return true;
  if (hostname.endsWith('.local') || hostname.endsWith('.internal')) return true;

  /* Block private IPv4 ranges */
  const parts = hostname.split('.');
  if (parts.length === 4 && parts.every(p => /^\d+$/.test(p))) {
    const a = parseInt(parts[0], 10);
    const b = parseInt(parts[1], 10);
    if (a === 10) return true;                           // 10.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return true;   // 172.16.0.0/12
    if (a === 192 && b === 168) return true;             // 192.168.0.0/16
    if (a === 169 && b === 254) return true;             // 169.254.0.0/16 (link-local)
    if (a === 0) return true;                            // 0.0.0.0/8
    if (a === 100 && b >= 64 && b <= 127) return true;  // 100.64.0.0/10 (CGNAT)
  }

  /* Block IPv6 private ranges */
  if (hostname.startsWith('[fc') || hostname.startsWith('[fd') || hostname.startsWith('[fe80')) return true;

  return false;
}
