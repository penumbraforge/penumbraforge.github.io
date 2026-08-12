/**
 * CT Monitor Worker — Penumbra Forge
 *
 * Proxies crt.sh Certificate Transparency log queries.
 * Returns recent certificates issued for a domain.
 */

const RATE_LIMIT = 15;
const RATE_WINDOW = 3600000;
const rateBuckets = new Map();

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env) });
    }

    if (request.method !== 'POST') {
      return json({ error: 'Method not allowed' }, 405, env);
    }

    const origin = request.headers.get('Origin') || '';
    if (env.ALLOWED_ORIGIN && !origin.startsWith(env.ALLOWED_ORIGIN)) {
      return json({ error: 'Forbidden' }, 403, env);
    }

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (env.RL_BURST) {
      const { success } = await env.RL_BURST.limit({ key: ip });
      if (!success) {
        return json({ error: 'Rate limited. Try again in a minute.' }, 429, env);
      }
    }
    if (isRateLimited(ip)) {
      return json({ error: 'Rate limited. Try again later.' }, 429, env);
    }

    let body;
    try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400, env); }

    const { domain, token } = body;

    if (env.TURNSTILE_SECRET && token) {
      const verified = await verifyTurnstile(token, ip, env.TURNSTILE_SECRET);
      if (!verified) {
        return json({ error: 'Turnstile verification failed' }, 403, env);
      }
    }

    /* Validate domain */
    if (!domain || !/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
      return json({ error: 'Invalid domain name' }, 400, env);
    }

    /* Strip any subdomain prefix — search base domain and wildcards */
    const cleanDomain = domain.replace(/^www\./, '').toLowerCase();

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15000);

      const resp = await fetch(
        `https://crt.sh/?q=%25.${encodeURIComponent(cleanDomain)}&output=json`,
        {
          signal: controller.signal,
          headers: { 'User-Agent': 'PenumbraForge-CTMonitor/1.0 (+https://penumbraforge.com/tools/ct-monitor/)' },
        }
      );

      clearTimeout(timeout);

      if (!resp.ok) {
        return json({ error: 'crt.sh returned ' + resp.status }, 502, env);
      }

      const certs = await resp.json();

      /* Deduplicate and format */
      const seen = new Set();
      const results = [];

      for (const cert of certs) {
        const id = cert.id || cert.min_cert_id;
        if (seen.has(id)) continue;
        seen.add(id);

        results.push({
          id: id,
          issuer: cert.issuer_name || '',
          commonName: cert.common_name || '',
          nameValue: cert.name_value || '',
          notBefore: cert.not_before || '',
          notAfter: cert.not_after || '',
          serialNumber: cert.serial_number || '',
          entryTimestamp: cert.entry_timestamp || '',
        });

        if (results.length >= 100) break;
      }

      /* Sort by most recent first */
      results.sort((a, b) => new Date(b.entryTimestamp || b.notBefore) - new Date(a.entryTimestamp || a.notBefore));

      return json({
        domain: cleanDomain,
        totalFound: certs.length,
        certificates: results,
      }, 200, env);

    } catch (err) {
      return json({ error: 'Failed to query CT logs: ' + (err.message || 'timeout') }, 502, env);
    }
  },
};

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

async function verifyTurnstile(token, ip, secret) {
  if (!token) return false;
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret, response: token, remoteip: ip }),
    });
    return (await r.json()).success === true;
  } catch { return false; }
}
