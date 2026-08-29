/* ============================================================
   Penumbra Forge — network-backed MCP tools
   These require server-side fetch, so they run in the MCP
   server (Cloudflare Worker + local Node) only — NOT in the
   browser URL-invoke layer (CORS). They give agents real
   capabilities they can't do inline: breach-checking, live
   security-header grading, and DNS. The MCP host receives each tool argument.
   For breach_check, only a five-character SHA-1 prefix is sent onward from
   that host to the HIBP range API.
   ============================================================ */
const enc = new TextEncoder();

function publicHttpsUrl(input) {
  let value = String(input || '').trim();
  if (!value) throw new Error('Provide an HTTPS URL.');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) value = 'https://' + value;
  let url;
  try { url = new URL(value); } catch { throw new Error('Invalid URL.'); }
  if (url.protocol !== 'https:') throw new Error('Only HTTPS URLs are allowed.');
  if (url.username || url.password) throw new Error('URLs with embedded credentials are not allowed.');
  if (url.port && url.port !== '443') throw new Error('Only the default HTTPS port is allowed.');

  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!host || !host.includes('.') ||
      host === 'localhost' ||
      /(?:^|\.)(?:localhost|local|internal|home|lan)$/.test(host) ||
      /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) ||
      host.includes(':')) {
    throw new Error('Local, internal, and literal-IP destinations are not allowed.');
  }
  url.hash = '';
  return url;
}

async function fetchPublicHttps(input, init) {
  let url = publicHttpsUrl(input);
  for (let redirects = 0; redirects <= 5; redirects++) {
    const response = await fetch(url, { ...init, redirect: 'manual' });
    if (response.status < 300 || response.status >= 400) return response;
    const location = response.headers.get('location');
    if (!location) return response;
    if (redirects === 5) throw new Error('Too many redirects.');
    url = publicHttpsUrl(new URL(location, url).toString());
  }
  throw new Error('Too many redirects.');
}

async function sha1hex(str) {
  const buf = await crypto.subtle.digest('SHA-1', enc.encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

async function breachCheck(a) {
  const pw = a.password || a.text || '';
  if (!pw) throw new Error('Provide a password to check.');
  const h = await sha1hex(pw); const prefix = h.slice(0, 5), suffix = h.slice(5);
  const res = await fetch('https://api.pwnedpasswords.com/range/' + prefix, { headers: { 'Add-Padding': 'true' } });
  if (!res.ok) throw new Error('HIBP request failed: ' + res.status);
  const body = await res.text();
  let count = 0;
  for (const line of body.split('\n')) { const [suf, c] = line.trim().split(':'); if (suf === suffix) { count = parseInt(c, 10) || 0; break; } }
  return { breached: count > 0, count, note: count > 0 ? 'Seen in ' + count.toLocaleString() + ' known breaches — do not use.' : 'Not found in Pwned Passwords.', privacy: 'The MCP host received the password; only the first five SHA-1 hex characters were sent onward to the HIBP range API.' };
}

const SEC_HEADERS = [
  ['strict-transport-security', 'HSTS'], ['content-security-policy', 'CSP'], ['x-frame-options', 'X-Frame-Options'],
  ['x-content-type-options', 'X-Content-Type-Options'], ['referrer-policy', 'Referrer-Policy'], ['permissions-policy', 'Permissions-Policy'],
  ['cross-origin-opener-policy', 'COOP'], ['cross-origin-resource-policy', 'CORP']
];
async function headersGrade(a) {
  const res = await fetchPublicHttps(a.url || a.input, { method: 'GET' });
  const present = {}, missing = [];
  for (const [k, label] of SEC_HEADERS) { const v = res.headers.get(k); if (v) present[label] = v.slice(0, 200); else missing.push(label); }
  const score = Math.round((Object.keys(present).length / SEC_HEADERS.length) * 100);
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 55 ? 'C' : score >= 35 ? 'D' : 'F';
  return {
    url: res.url,
    status: res.status,
    headerChecklist: { grade, score, checked: SEC_HEADERS.length },
    present,
    missing,
    server: res.headers.get('server') || null,
    note: 'This fixed response-header checklist does not test TLS, certificate trust, application behavior, or overall security.'
  };
}

async function dnsLookup(a) {
  const name = a.name || a.input; const type = (a.type || 'A').toUpperCase();
  if (!name) throw new Error('Provide a domain name.');
  const res = await fetch('https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(name) + '&type=' + type, { headers: { accept: 'application/dns-json' } });
  if (!res.ok) throw new Error('DoH request failed: ' + res.status);
  const j = await res.json();
  return { name, type, answers: (j.Answer || []).map(x => ({ name: x.name, type: x.type, ttl: x.TTL, data: x.data })), status: j.Status };
}

async function httpProbe(a) {
  const res = await fetchPublicHttps(a.url || a.input, { method: 'GET' });
  const headers = {}; res.headers.forEach((v, k) => headers[k] = v);
  return { finalUrl: res.url, status: res.status, statusText: res.statusText, redirected: res.redirected, contentType: res.headers.get('content-type'), headers };
}

export const NET_TOOLS = {
  breach_check: { description: 'Check Pwned Passwords with k-anonymity. The MCP host receives the password and sends only its five-character SHA-1 prefix onward to HIBP.', schema: { password: 'string' }, run: breachCheck },
  security_headers: { description: 'Fetch a public HTTPS URL and run a fixed eight-header checklist (not an overall security grade).', schema: { url: 'https URL' }, run: headersGrade },
  dns: { description: 'DNS lookup over HTTPS (A/AAAA/MX/TXT/NS/CNAME…).', schema: { name: 'domain', type: 'A|AAAA|MX|TXT|NS|CNAME' }, run: dnsLookup },
  http_probe: { description: 'Fetch a public HTTPS URL and return status, redirects, and response headers.', schema: { url: 'https URL' }, run: httpProbe }
};
