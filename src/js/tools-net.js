/* ============================================================
   Penumbra Forge — network-backed MCP tools
   These require server-side fetch, so they run in the MCP
   server (Cloudflare Worker + local Node) only — NOT in the
   browser URL-invoke layer (CORS). They give agents real
   capabilities they can't do inline: breach-checking, live
   security-header grading, and DNS.  Privacy: breach_check
   uses k-anonymity — only a 5-char hash prefix is ever sent.
   ============================================================ */
const enc = new TextEncoder();
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
  return { breached: count > 0, count, note: count > 0 ? 'Seen in ' + count.toLocaleString() + ' known breaches — do not use.' : 'Not found in Pwned Passwords.', privacy: 'k-anonymity: only the first 5 chars of the SHA-1 hash were sent.' };
}

const SEC_HEADERS = [
  ['strict-transport-security', 'HSTS'], ['content-security-policy', 'CSP'], ['x-frame-options', 'X-Frame-Options'],
  ['x-content-type-options', 'X-Content-Type-Options'], ['referrer-policy', 'Referrer-Policy'], ['permissions-policy', 'Permissions-Policy'],
  ['cross-origin-opener-policy', 'COOP'], ['cross-origin-resource-policy', 'CORP']
];
async function headersGrade(a) {
  let url = a.url || a.input || ''; if (!/^https?:\/\//.test(url)) url = 'https://' + url;
  const res = await fetch(url, { method: 'GET', redirect: 'follow' });
  const present = {}, missing = [];
  for (const [k, label] of SEC_HEADERS) { const v = res.headers.get(k); if (v) present[label] = v.slice(0, 200); else missing.push(label); }
  const score = Math.round((Object.keys(present).length / SEC_HEADERS.length) * 100);
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 55 ? 'C' : score >= 35 ? 'D' : 'F';
  return { url: res.url, status: res.status, grade, score, present, missing, server: res.headers.get('server') || null };
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
  let url = a.url || a.input || ''; if (!/^https?:\/\//.test(url)) url = 'https://' + url;
  const res = await fetch(url, { method: 'GET', redirect: 'follow' });
  const headers = {}; res.headers.forEach((v, k) => headers[k] = v);
  return { finalUrl: res.url, status: res.status, statusText: res.statusText, redirected: res.redirected, contentType: res.headers.get('content-type'), headers };
}

export const NET_TOOLS = {
  breach_check: { description: 'Check if a password appears in known breaches (HIBP, k-anonymity — private).', schema: { password: 'string' }, run: breachCheck },
  security_headers: { description: 'Fetch a URL and grade its HTTP security headers (A–F).', schema: { url: 'https URL' }, run: headersGrade },
  dns: { description: 'DNS lookup over HTTPS (A/AAAA/MX/TXT/NS/CNAME…).', schema: { name: 'domain', type: 'A|AAAA|MX|TXT|NS|CNAME' }, run: dnsLookup },
  http_probe: { description: 'Fetch a URL and return status, redirects, and response headers.', schema: { url: 'https URL' }, run: httpProbe }
};
