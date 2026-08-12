/**
 * Privacy Scan Worker — Penumbra Forge
 *
 * Fetches a URL's HTML and extracts privacy-relevant signals:
 * third-party scripts, trackers, cookies, fingerprinting, analytics.
 */

const RATE_LIMIT = 10;
const RATE_WINDOW = 3600000;
const rateBuckets = new Map();

const KNOWN_TRACKERS = {
  'google-analytics.com': { name: 'Google Analytics', category: 'analytics', severity: 'high' },
  'googletagmanager.com': { name: 'Google Tag Manager', category: 'tag-manager', severity: 'high' },
  'googlesyndication.com': { name: 'Google Ads', category: 'advertising', severity: 'high' },
  'doubleclick.net': { name: 'DoubleClick (Google)', category: 'advertising', severity: 'high' },
  'facebook.net': { name: 'Facebook Pixel', category: 'tracking', severity: 'high' },
  'connect.facebook.net': { name: 'Facebook SDK', category: 'tracking', severity: 'high' },
  'facebook.com/tr': { name: 'Facebook Tracking Pixel', category: 'tracking', severity: 'high' },
  'hotjar.com': { name: 'Hotjar', category: 'session-recording', severity: 'critical' },
  'fullstory.com': { name: 'FullStory', category: 'session-recording', severity: 'critical' },
  'mouseflow.com': { name: 'Mouseflow', category: 'session-recording', severity: 'critical' },
  'clarity.ms': { name: 'Microsoft Clarity', category: 'session-recording', severity: 'high' },
  'segment.com': { name: 'Segment', category: 'analytics', severity: 'medium' },
  'segment.io': { name: 'Segment', category: 'analytics', severity: 'medium' },
  'mixpanel.com': { name: 'Mixpanel', category: 'analytics', severity: 'medium' },
  'amplitude.com': { name: 'Amplitude', category: 'analytics', severity: 'medium' },
  'heapanalytics.com': { name: 'Heap Analytics', category: 'analytics', severity: 'medium' },
  'intercom.io': { name: 'Intercom', category: 'analytics', severity: 'medium' },
  'hubspot.com': { name: 'HubSpot', category: 'marketing', severity: 'medium' },
  'tiktok.com': { name: 'TikTok Pixel', category: 'tracking', severity: 'high' },
  'snap.licdn.com': { name: 'LinkedIn Insight', category: 'tracking', severity: 'high' },
  'ads-twitter.com': { name: 'Twitter Ads', category: 'advertising', severity: 'high' },
  'pinterest.com/ct': { name: 'Pinterest Tag', category: 'tracking', severity: 'medium' },
  'newrelic.com': { name: 'New Relic', category: 'monitoring', severity: 'low' },
  'sentry.io': { name: 'Sentry', category: 'monitoring', severity: 'low' },
  'datadoghq.com': { name: 'Datadog', category: 'monitoring', severity: 'low' },
  'cloudflareinsights.com': { name: 'Cloudflare Analytics', category: 'analytics', severity: 'low' },
  'plausible.io': { name: 'Plausible Analytics', category: 'analytics', severity: 'low' },
  'cdn.mxpnl.com': { name: 'Mixpanel CDN', category: 'analytics', severity: 'medium' },
  'quantserve.com': { name: 'Quantcast', category: 'tracking', severity: 'high' },
  'scorecardresearch.com': { name: 'Comscore', category: 'tracking', severity: 'high' },
  'taboola.com': { name: 'Taboola', category: 'advertising', severity: 'high' },
  'outbrain.com': { name: 'Outbrain', category: 'advertising', severity: 'high' },
  'criteo.com': { name: 'Criteo', category: 'advertising', severity: 'high' },
  'adroll.com': { name: 'AdRoll', category: 'advertising', severity: 'high' },
};

const FINGERPRINT_SIGNALS = [
  { regex: /canvas\.toDataURL|getImageData|toBlob/i, name: 'Canvas Fingerprinting', severity: 'critical' },
  { regex: /AudioContext|OfflineAudioContext|createOscillator/i, name: 'Audio Fingerprinting', severity: 'critical' },
  { regex: /webgl.*getParameter|UNMASKED_VENDOR|UNMASKED_RENDERER/i, name: 'WebGL Fingerprinting', severity: 'high' },
  { regex: /navigator\.plugins|navigator\.mimeTypes/i, name: 'Plugin Enumeration', severity: 'medium' },
  { regex: /screen\.colorDepth|screen\.pixelDepth|devicePixelRatio/i, name: 'Screen Fingerprinting', severity: 'medium' },
];

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

    const { url, token } = body;

    if (env.TURNSTILE_SECRET && token) {
      const verified = await verifyTurnstile(token, ip, env.TURNSTILE_SECRET);
      if (!verified) {
        return json({ error: 'Turnstile verification failed' }, 403, env);
      }
    }

    let parsed;
    try { parsed = new URL(url); } catch { return json({ error: 'Invalid URL' }, 400, env); }
    if (!['http:', 'https:'].includes(parsed.protocol)) return json({ error: 'Only HTTP/HTTPS' }, 400, env);
    if (isPrivateHost(parsed.hostname)) return json({ error: 'Cannot scan private addresses' }, 400, env);

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 12000);

      const resp = await safeFetch(parsed.href, {
        method: 'GET',
        signal: controller.signal,
        headers: { 'User-Agent': 'PenumbraForge-PrivacyScan/1.0 (+https://penumbraforge.com/tools/privacy-scan/)' },
      });

      clearTimeout(timeout);

      /* Cap the body read — an adversarial page must not be able to feed us
         hundreds of MB (isolate memory limit is 128MB). 2MB of HTML is plenty
         to find trackers; anything longer is truncated. */
      const html = await readCapped(resp, 2 * 1024 * 1024);
      const cookies = resp.headers.get('set-cookie') || '';
      const responseHeaders = {};
      for (const [k, v] of resp.headers.entries()) responseHeaders[k] = v;

      /* Extract third-party domains from scripts, iframes, images */
      const siteDomain = parsed.hostname.replace(/^www\./, '');
      const thirdParty = new Set();
      const srcRegex = /(?:src|href|action)\s*=\s*["'](https?:\/\/[^"']+)/gi;
      let match;
      while ((match = srcRegex.exec(html)) !== null) {
        try {
          const u = new URL(match[1]);
          const host = u.hostname.replace(/^www\./, '');
          if (host !== siteDomain && !host.endsWith('.' + siteDomain)) {
            thirdParty.add(host);
          }
        } catch {}
      }

      /* Identify known trackers */
      const trackers = [];
      const trackerDomains = new Set();
      for (const host of thirdParty) {
        for (const [pattern, info] of Object.entries(KNOWN_TRACKERS)) {
          if (host.includes(pattern) && !trackerDomains.has(info.name)) {
            trackerDomains.add(info.name);
            trackers.push({ ...info, domain: host });
          }
        }
      }

      /* Check for fingerprinting signals */
      const fingerprinting = [];
      for (const sig of FINGERPRINT_SIGNALS) {
        if (sig.regex.test(html)) {
          fingerprinting.push({ name: sig.name, severity: sig.severity });
        }
      }

      /* Parse cookies */
      const cookieList = [];
      if (cookies) {
        cookies.split(/,(?=\s*\w+=)/).forEach(c => {
          const name = (c.split('=')[0] || '').trim();
          if (!name) return;
          const httpOnly = /httponly/i.test(c);
          const secure = /;\s*secure/i.test(c);
          const sameSite = (c.match(/samesite=(\w+)/i) || [])[1] || 'not set';
          const maxAge = c.match(/max-age=(\d+)/i);
          const expires = c.match(/expires=([^;]+)/i);
          let duration = 'session';
          if (maxAge) {
            const days = Math.round(parseInt(maxAge[1]) / 86400);
            duration = days > 365 ? days + ' days (long-lived)' : days + ' days';
          } else if (expires) {
            duration = expires[1].trim();
          }
          cookieList.push({ name, httpOnly, secure, sameSite, duration });
        });
      }

      /* Privacy headers check */
      const privacyHeaders = {
        dnt: responseHeaders['tk'] || null,
        gpc: responseHeaders['sec-gpc'] || null,
        p3p: responseHeaders['p3p'] || null,
      };

      return json({
        url: resp.url,
        thirdPartyCount: thirdParty.size,
        thirdPartyDomains: Array.from(thirdParty).slice(0, 50),
        trackers,
        fingerprinting,
        cookies: cookieList,
        privacyHeaders,
        hasAnalytics: trackers.some(t => t.category === 'analytics'),
        hasSessionRecording: trackers.some(t => t.category === 'session-recording'),
        hasAdvertising: trackers.some(t => t.category === 'advertising'),
      }, 200, env);

    } catch (err) {
      return json({ error: 'Failed to fetch: ' + (err.message || 'timeout') }, 502, env);
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

/* Follow redirects manually, re-validating every hop against the private-host
   blocklist. `redirect: 'follow'` would happily follow a 302 to 169.254.169.254. */
async function safeFetch(urlStr, init, maxHops = 5) {
  let current = urlStr;
  for (let hop = 0; hop < maxHops; hop++) {
    const u = new URL(current);
    if (!['http:', 'https:'].includes(u.protocol)) {
      throw new Error('Redirect to unsupported protocol blocked');
    }
    if (isPrivateHost(u.hostname)) {
      throw new Error('Redirect to private/internal address blocked');
    }
    const resp = await fetch(u.href, { ...init, redirect: 'manual' });
    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      const loc = resp.headers.get('location');
      if (!loc) return resp;
      current = new URL(loc, u).href;
      continue;
    }
    return resp;
  }
  throw new Error('Too many redirects');
}

/* Stream the body up to maxBytes, then stop reading. */
async function readCapped(resp, maxBytes) {
  if (!resp.body) return '';
  const reader = resp.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      chunks.push(value.subarray(0, value.byteLength - (total - maxBytes)));
      await reader.cancel();
      break;
    }
    chunks.push(value);
  }
  const buf = new Uint8Array(Math.min(total, maxBytes));
  let offset = 0;
  for (const c of chunks) { buf.set(c, offset); offset += c.byteLength; }
  return new TextDecoder('utf-8', { fatal: false }).decode(buf);
}

function isPrivateHost(h) {
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1') return true;
  if (h.endsWith('.local') || h.endsWith('.internal')) return true;
  const p = h.split('.');
  if (p.length === 4 && p.every(x => /^\d+$/.test(x))) {
    const a = +p[0], b = +p[1];
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || a === 0 || (a === 100 && b >= 64 && b <= 127)) return true;
  }
  return false;
}
