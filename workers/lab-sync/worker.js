/**
 * Forge Key Sync Worker — Penumbra Forge Security Labs
 *
 * Stores and retrieves AES-256-GCM encrypted progress blobs
 * addressed by a SHA-256 hash of the user's Forge Key prefix.
 * The Worker never sees the plaintext progress or the Forge Key.
 */

const RATE_LIMIT = 30;
const RATE_WINDOW = 3600000;
const rateBuckets = new Map();

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    const origin = request.headers.get('Origin') || '';
    if (env.ALLOWED_ORIGIN && !origin.startsWith(env.ALLOWED_ORIGIN)) {
      return json({ error: 'Forbidden' }, 403, env);
    }

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (isRateLimited(ip)) {
      return json({ error: 'Rate limited' }, 429, env);
    }

    if (request.method !== 'POST') {
      return json({ error: 'Method not allowed' }, 405, env);
    }

    let body;
    try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400, env); }

    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/save') {
      return handleSave(body, env);
    } else if (path === '/load') {
      return handleLoad(body, env);
    } else {
      return json({ error: 'Not found' }, 404, env);
    }
  },
};

async function handleSave(body, env) {
  const { storageKey, ciphertext, iv } = body;

  if (!storageKey || !ciphertext || !iv) {
    return json({ error: 'Missing required fields: storageKey, ciphertext, iv' }, 400, env);
  }

  if (typeof storageKey !== 'string' || storageKey.length !== 64) {
    return json({ error: 'Invalid storage key format' }, 400, env);
  }

  if (ciphertext.length > 500000) {
    return json({ error: 'Payload too large' }, 413, env);
  }

  await env.FORGE_KEYS.put(storageKey, JSON.stringify({ ciphertext, iv }), {
    expirationTtl: 86400 * 365, // 1 year TTL
  });

  return json({ ok: true }, 200, env);
}

async function handleLoad(body, env) {
  const { storageKey } = body;

  if (!storageKey || typeof storageKey !== 'string' || storageKey.length !== 64) {
    return json({ error: 'Invalid storage key' }, 400, env);
  }

  const data = await env.FORGE_KEYS.get(storageKey);

  if (!data) {
    return json({ error: 'No data found for this Forge Key' }, 404, env);
  }

  try {
    const parsed = JSON.parse(data);
    return json({ ciphertext: parsed.ciphertext, iv: parsed.iv }, 200, env);
  } catch {
    return json({ error: 'Corrupted data' }, 500, env);
  }
}

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
    headers: { 'Content-Type': 'application/json', ...corsHeaders(env) },
  });
}

function isRateLimited(ip) {
  const now = Date.now();
  let b = rateBuckets.get(ip);
  if (!b || now - b.start > RATE_WINDOW) { b = { start: now, count: 0 }; rateBuckets.set(ip, b); }
  b.count++;
  if (rateBuckets.size > 10000) { for (const [k, v] of rateBuckets) { if (now - v.start > RATE_WINDOW) rateBuckets.delete(k); } }
  return b.count > RATE_LIMIT;
}
