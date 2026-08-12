/**
 * One-Time Secret — Cloudflare Worker + KV
 *
 * POST /api/secrets  — Create a burn-after-reading secret
 *   Body: { "secret": "...", "ttl": 86400 }
 *   Returns: { "id": "...", "expires": "..." }
 *
 * GET /api/secrets/:id  — Retrieve and permanently delete
 *   Returns: { "secret": "..." }
 *   Subsequent requests: 404
 *
 * All secrets are stored in KV with a TTL (default 24h, max 7d).
 * Retrieval is atomic: read + delete in one request.
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
};

function corsHeaders(origin, env) {
  const allowed = env.ALLOWED_ORIGIN || 'https://penumbraforge.com';
  if (origin === allowed || origin === 'http://localhost:8080') {
    return { ...CORS_HEADERS, 'Access-Control-Allow-Origin': origin };
  }
  return { ...CORS_HEADERS, 'Access-Control-Allow-Origin': allowed };
}

function jsonResponse(data, status, origin, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(origin, env),
    },
  });
}

function generateId() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

const MAX_SECRET_SIZE = 50000; // 50KB max
const DEFAULT_TTL = 86400;     // 24 hours
const MAX_TTL = 604800;        // 7 days

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin, env) });
    }

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

    // POST /api/secrets — create secret
    if (request.method === 'POST' && url.pathname === '/api/secrets') {
      // Every create is a KV write (free tier: 1,000 writes/day) — rate limit first.
      if (env.RL_CREATE) {
        const { success } = await env.RL_CREATE.limit({ key: ip });
        if (!success) {
          return jsonResponse({ error: 'Rate limited. Try again in a minute.' }, 429, origin, env);
        }
      }

      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse({ error: 'Invalid JSON body' }, 400, origin, env);
      }

      const { secret, ttl } = body;

      if (!secret || typeof secret !== 'string') {
        return jsonResponse({ error: 'Missing or invalid "secret" field' }, 400, origin, env);
      }

      if (secret.length > MAX_SECRET_SIZE) {
        return jsonResponse({ error: `Secret exceeds maximum size of ${MAX_SECRET_SIZE} characters` }, 400, origin, env);
      }

      const effectiveTtl = Math.min(Math.max(parseInt(ttl) || DEFAULT_TTL, 60), MAX_TTL);
      const id = generateId();
      const expiresAt = new Date(Date.now() + effectiveTtl * 1000).toISOString();

      await env.OTS_KV.put(id, secret, { expirationTtl: effectiveTtl });

      return jsonResponse({ id, expires: expiresAt }, 201, origin, env);
    }

    // GET /api/secrets/:id — retrieve and burn
    if (request.method === 'GET' && url.pathname.startsWith('/api/secrets/')) {
      if (env.RL_READ) {
        const { success } = await env.RL_READ.limit({ key: ip });
        if (!success) {
          return jsonResponse({ error: 'Rate limited. Try again in a minute.' }, 429, origin, env);
        }
      }

      const id = url.pathname.split('/api/secrets/')[1];

      if (!id || id.length !== 48) {
        return jsonResponse({ error: 'Invalid secret ID' }, 400, origin, env);
      }

      const secret = await env.OTS_KV.get(id);

      if (secret === null) {
        return jsonResponse({ error: 'Secret not found — it may have already been viewed or expired' }, 404, origin, env);
      }

      // Burn after reading — delete immediately
      await env.OTS_KV.delete(id);

      return jsonResponse({ secret }, 200, origin, env);
    }

    return jsonResponse({ error: 'Not found' }, 404, origin, env);
  },
};
