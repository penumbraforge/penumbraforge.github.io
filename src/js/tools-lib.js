/* ============================================================
   Penumbra Forge — tools-lib
   One isomorphic, zero-dependency brain shared by the tool pages,
   the URL-invoke layer, and the MCP server. Runs in browsers,
   Node, and Cloudflare Workers (uses WebCrypto + TextEncoder only).
   Every function is pure and returns structured data.
   ============================================================ */

const subtle = (globalThis.crypto && globalThis.crypto.subtle) || null;
const enc = new TextEncoder();
const dec = new TextDecoder();

// ---- bytes / base64 / hex (binary-safe, no atob/Buffer) ----
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
export function strToBytes(s) { return enc.encode(s); }
export function bytesToStr(b) { return dec.decode(b instanceof Uint8Array ? b : new Uint8Array(b)); }
export function bytesToB64(bytes, url) {
  bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = '', i;
  for (i = 0; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  const rem = bytes.length - i;
  if (rem === 1) { const n = bytes[i] << 16; out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + '=='; }
  else if (rem === 2) { const n = (bytes[i] << 16) | (bytes[i + 1] << 8); out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + '='; }
  if (url) out = out.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return out;
}
export function b64ToBytes(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/').replace(/[^A-Za-z0-9+/]/g, '');
  const pad = str.length % 4; if (pad) str += '='.repeat(4 - pad);
  const bytes = [];
  for (let i = 0; i < str.length; i += 4) {
    const n = (B64.indexOf(str[i]) << 18) | (B64.indexOf(str[i + 1]) << 12) | ((str[i + 2] === '=' ? 0 : B64.indexOf(str[i + 2])) << 6) | (str[i + 3] === '=' ? 0 : B64.indexOf(str[i + 3]));
    bytes.push((n >> 16) & 255); if (str[i + 2] !== '=') bytes.push((n >> 8) & 255); if (str[i + 3] !== '=') bytes.push(n & 255);
  }
  return new Uint8Array(bytes);
}
export function bytesToHex(bytes) { bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes); let h = ''; for (let i = 0; i < bytes.length; i++) h += bytes[i].toString(16).padStart(2, '0'); return h; }
export function hexToBytes(hex) { hex = hex.replace(/[^0-9a-fA-F]/g, ''); const b = new Uint8Array(hex.length >> 1); for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16); return b; }

export function base64(text, mode) {
  if (mode === 'decode') return { output: bytesToStr(b64ToBytes(text)) };
  return { output: bytesToB64(strToBytes(text)) };
}
export function base64url(text, mode) {
  if (mode === 'decode') return { output: bytesToStr(b64ToBytes(text)) };
  return { output: bytesToB64(strToBytes(text), true) };
}
export function hex(text, mode) {
  if (mode === 'decode') return { output: bytesToStr(hexToBytes(text)) };
  return { output: bytesToHex(strToBytes(text)) };
}
export function urlcodec(text, mode) {
  return { output: mode === 'decode' ? decodeURIComponent(text) : encodeURIComponent(text) };
}

// ---- hashing (WebCrypto + pure MD5) ----
export async function hash(text, algo) {
  algo = (algo || 'SHA-256').toUpperCase();
  if (algo === 'MD5') return { algorithm: 'MD5', output: md5(text) };
  const buf = await subtle.digest(algo, strToBytes(text));
  return { algorithm: algo, output: bytesToHex(new Uint8Array(buf)) };
}
export async function hmac(text, key, algo) {
  algo = (algo || 'SHA-256').toUpperCase();
  const k = await subtle.importKey('raw', strToBytes(key), { name: 'HMAC', hash: algo }, false, ['sign']);
  const sig = await subtle.sign('HMAC', k, strToBytes(text));
  return { algorithm: 'HMAC-' + algo, output: bytesToHex(new Uint8Array(sig)) };
}

// ---- JWT decode (no verification) ----
export function jwtDecode(token) {
  const parts = String(token).trim().split('.');
  if (parts.length < 2) throw new Error('Not a JWT (expected header.payload.signature).');
  const header = JSON.parse(bytesToStr(b64ToBytes(parts[0])));
  const payload = JSON.parse(bytesToStr(b64ToBytes(parts[1])));
  const now = Math.floor(Date.now() / 1000);
  const notes = [];
  if (payload.exp) notes.push(payload.exp < now ? 'EXPIRED' : 'expires ' + new Date(payload.exp * 1000).toISOString());
  if (header.alg === 'none') notes.push('alg:none — unsigned, unsafe if accepted');
  return { header, payload, signature: parts[2] || null, notes, verified: false };
}

// ---- UUID ----
export function uuidV4() { const b = crypto.getRandomValues(new Uint8Array(16)); b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80; const h = bytesToHex(b); return { output: `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`, version: 4 }; }
export function uuidV7() {
  const ts = Date.now(); const b = crypto.getRandomValues(new Uint8Array(16));
  b[0] = (ts / 2 ** 40) & 255; b[1] = (ts / 2 ** 32) & 255; b[2] = (ts / 2 ** 24) & 255; b[3] = (ts / 2 ** 16) & 255; b[4] = (ts / 2 ** 8) & 255; b[5] = ts & 255;
  b[6] = (b[6] & 0x0f) | 0x70; b[8] = (b[8] & 0x3f) | 0x80; const h = bytesToHex(b);
  return { output: `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`, version: 7, timestamp: new Date(ts).toISOString() };
}
export function uuidInspect(uuid) {
  const h = String(uuid).replace(/[^0-9a-fA-F]/g, ''); if (h.length !== 32) throw new Error('Not a valid UUID.');
  const version = parseInt(h[12], 16); const variant = parseInt(h[16], 16);
  const out = { version, variant: variant >= 8 ? 'RFC 4122' : 'other' };
  if (version === 7) { const ts = parseInt(h.slice(0, 12), 16); out.timestamp = new Date(ts).toISOString(); }
  return out;
}

// ---- Shannon entropy ----
export function entropy(text) {
  const bytes = strToBytes(text); if (!bytes.length) return { bitsPerByte: 0, verdict: 'empty' };
  const freq = {}; for (const b of bytes) freq[b] = (freq[b] || 0) + 1;
  let h = 0; for (const k in freq) { const p = freq[k] / bytes.length; h -= p * Math.log2(p); }
  const verdict = h < 1 ? 'highly structured / padding' : h < 3.5 ? 'text or code' : h < 6 ? 'mixed / structured binary' : h < 7.5 ? 'likely compressed' : 'likely encrypted or random';
  return { bitsPerByte: Math.round(h * 1000) / 1000, bytes: bytes.length, distinct: Object.keys(freq).length, verdict };
}

// ---- epoch / time ----
export function epoch(value) {
  let ms; const v = String(value).trim();
  if (/^\d+$/.test(v)) { const n = Number(v); ms = v.length >= 13 ? n : v.length >= 10 ? n * 1000 : n * 1000; }
  else { ms = Date.parse(v); if (isNaN(ms)) throw new Error('Unrecognised date/timestamp.'); }
  const d = new Date(ms);
  return { iso: d.toISOString(), utc: d.toUTCString(), unixSeconds: Math.floor(ms / 1000), unixMillis: ms };
}

// ---- password ----
export function password(opts) {
  opts = opts || {}; const len = Math.max(4, Math.min(256, opts.length || 24));
  let set = ''; if (opts.lower !== false) set += 'abcdefghijklmnopqrstuvwxyz'; if (opts.upper !== false) set += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'; if (opts.digits !== false) set += '0123456789'; if (opts.symbols !== false) set += '!@#$%^&*()-_=+[]{};:,.<>?';
  if (!set) set = 'abcdefghijklmnopqrstuvwxyz';
  const r = crypto.getRandomValues(new Uint32Array(len)); let out = '';
  for (let i = 0; i < len; i++) out += set[r[i] % set.length];
  const bits = Math.round(len * Math.log2(set.length));
  return { output: out, length: len, entropyBits: bits, strength: bits < 50 ? 'weak' : bits < 80 ? 'fair' : bits < 120 ? 'strong' : 'very strong' };
}

// ---- json ----
export function jsonTool(text, mode) {
  let parsed;
  try { parsed = JSON.parse(text); } catch (e) { throw new Error('Invalid JSON: ' + e.message); }
  if (mode === 'minify') return { output: JSON.stringify(parsed), valid: true };
  if (mode === 'validate') return { valid: true, type: Array.isArray(parsed) ? 'array' : typeof parsed };
  return { output: JSON.stringify(parsed, null, 2), valid: true };
}

// ---- color ----
export function color(input) {
  const s = String(input).trim(); let r, g, b;
  let m = s.match(/^#?([0-9a-f]{3}|[0-9a-f]{6})$/i);
  if (m) { let h = m[1]; if (h.length === 3) h = h.split('').map(c => c + c).join(''); r = parseInt(h.slice(0, 2), 16); g = parseInt(h.slice(2, 4), 16); b = parseInt(h.slice(4, 6), 16); }
  else if ((m = s.match(/rgba?\(\s*(\d+)[,\s]+(\d+)[,\s]+(\d+)/i))) { r = +m[1]; g = +m[2]; b = +m[3]; }
  else throw new Error('Unrecognised color (use #hex or rgb()).');
  const hex = '#' + [r, g, b].map(x => x.toString(16).padStart(2, '0')).join('');
  const r1 = r / 255, g1 = g / 255, b1 = b / 255, mx = Math.max(r1, g1, b1), mn = Math.min(r1, g1, b1); let h = 0, sl = 0; const l = (mx + mn) / 2;
  if (mx !== mn) { const d = mx - mn; sl = l > 0.5 ? d / (2 - mx - mn) : d / (mx + mn); h = mx === r1 ? (g1 - b1) / d + (g1 < b1 ? 6 : 0) : mx === g1 ? (b1 - r1) / d + 2 : (r1 - g1) / d + 4; h *= 60; }
  return { hex, rgb: `rgb(${r}, ${g}, ${b})`, hsl: `hsl(${Math.round(h)}, ${Math.round(sl * 100)}%, ${Math.round(l * 100)}%)` };
}

// ---- CIDR / subnet (IPv4) ----
export function cidr(input) {
  const [ip, prefixStr] = String(input).trim().split('/'); const prefix = parseInt(prefixStr, 10);
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => p < 0 || p > 255 || isNaN(p)) || isNaN(prefix) || prefix < 0 || prefix > 32) throw new Error('Invalid IPv4 CIDR (e.g. 10.0.0.0/24).');
  const ipNum = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (ipNum & mask) >>> 0, broadcast = (network | (~mask >>> 0)) >>> 0;
  const toIp = n => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  const hosts = prefix >= 31 ? (prefix === 32 ? 1 : 2) : broadcast - network - 1;
  return { network: toIp(network), broadcast: toIp(broadcast), netmask: toIp(mask), firstHost: toIp(prefix >= 31 ? network : network + 1), lastHost: toIp(prefix >= 31 ? broadcast : broadcast - 1), usableHosts: hosts, totalAddresses: broadcast - network + 1 };
}

// ---- case convert ----
export function caseConvert(text, to) {
  const words = String(text).replace(/[-_]/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').trim().split(/\s+/).filter(Boolean);
  const lower = words.map(w => w.toLowerCase());
  switch (to) {
    case 'camel': return { output: lower.map((w, i) => i ? w[0].toUpperCase() + w.slice(1) : w).join('') };
    case 'pascal': return { output: lower.map(w => w[0].toUpperCase() + w.slice(1)).join('') };
    case 'snake': return { output: lower.join('_') };
    case 'kebab': return { output: lower.join('-') };
    case 'constant': return { output: lower.join('_').toUpperCase() };
    case 'title': return { output: lower.map(w => w[0].toUpperCase() + w.slice(1)).join(' ') };
    default: return { output: lower.join(' ') };
  }
}

// ---- pure MD5 (for legacy hashing; WebCrypto has no MD5) ----
export function md5(str) {
  function rl(n, c) { return (n << c) | (n >>> (32 - c)); }
  function ff(a, b, c, d, x, s, t) { return (rl((a + ((b & c) | (~b & d)) + x + t) | 0, s) + b) | 0; }
  function gg(a, b, c, d, x, s, t) { return (rl((a + ((b & d) | (c & ~d)) + x + t) | 0, s) + b) | 0; }
  function hh(a, b, c, d, x, s, t) { return (rl((a + (b ^ c ^ d) + x + t) | 0, s) + b) | 0; }
  function ii(a, b, c, d, x, s, t) { return (rl((a + (c ^ (b | ~d)) + x + t) | 0, s) + b) | 0; }
  const bytes = strToBytes(str); const len = bytes.length;
  const words = []; for (let i = 0; i < len; i++) words[i >> 2] = (words[i >> 2] || 0) | (bytes[i] << ((i % 4) * 8));
  words[len >> 2] = (words[len >> 2] || 0) | (0x80 << ((len % 4) * 8)); words[(((len + 8) >> 6) + 1) * 16 - 2] = len * 8;
  let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
  for (let i = 0; i < words.length; i += 16) {
    const oa = a, ob = b, oc = c, od = d; const w = k => words[i + k] | 0;
    a = ff(a, b, c, d, w(0), 7, -680876936); d = ff(d, a, b, c, w(1), 12, -389564586); c = ff(c, d, a, b, w(2), 17, 606105819); b = ff(b, c, d, a, w(3), 22, -1044525330);
    a = ff(a, b, c, d, w(4), 7, -176418897); d = ff(d, a, b, c, w(5), 12, 1200080426); c = ff(c, d, a, b, w(6), 17, -1473231341); b = ff(b, c, d, a, w(7), 22, -45705983);
    a = ff(a, b, c, d, w(8), 7, 1770035416); d = ff(d, a, b, c, w(9), 12, -1958414417); c = ff(c, d, a, b, w(10), 17, -42063); b = ff(b, c, d, a, w(11), 22, -1990404162);
    a = ff(a, b, c, d, w(12), 7, 1804603682); d = ff(d, a, b, c, w(13), 12, -40341101); c = ff(c, d, a, b, w(14), 17, -1502002290); b = ff(b, c, d, a, w(15), 22, 1236535329);
    a = gg(a, b, c, d, w(1), 5, -165796510); d = gg(d, a, b, c, w(6), 9, -1069501632); c = gg(c, d, a, b, w(11), 14, 643717713); b = gg(b, c, d, a, w(0), 20, -373897302);
    a = gg(a, b, c, d, w(5), 5, -701558691); d = gg(d, a, b, c, w(10), 9, 38016083); c = gg(c, d, a, b, w(15), 14, -660478335); b = gg(b, c, d, a, w(4), 20, -405537848);
    a = gg(a, b, c, d, w(9), 5, 568446438); d = gg(d, a, b, c, w(14), 9, -1019803690); c = gg(c, d, a, b, w(3), 14, -187363961); b = gg(b, c, d, a, w(8), 20, 1163531501);
    a = gg(a, b, c, d, w(13), 5, -1444681467); d = gg(d, a, b, c, w(2), 9, -51403784); c = gg(c, d, a, b, w(7), 14, 1735328473); b = gg(b, c, d, a, w(12), 20, -1926607734);
    a = hh(a, b, c, d, w(5), 4, -378558); d = hh(d, a, b, c, w(8), 11, -2022574463); c = hh(c, d, a, b, w(11), 16, 1839030562); b = hh(b, c, d, a, w(14), 23, -35309556);
    a = hh(a, b, c, d, w(1), 4, -1530992060); d = hh(d, a, b, c, w(4), 11, 1272893353); c = hh(c, d, a, b, w(7), 16, -155497632); b = hh(b, c, d, a, w(10), 23, -1094730640);
    a = hh(a, b, c, d, w(13), 4, 681279174); d = hh(d, a, b, c, w(0), 11, -358537222); c = hh(c, d, a, b, w(3), 16, -722521979); b = hh(b, c, d, a, w(6), 23, 76029189);
    a = hh(a, b, c, d, w(9), 4, -640364487); d = hh(d, a, b, c, w(12), 11, -421815835); c = hh(c, d, a, b, w(15), 16, 530742520); b = hh(b, c, d, a, w(2), 23, -995338651);
    a = ii(a, b, c, d, w(0), 6, -198630844); d = ii(d, a, b, c, w(7), 10, 1126891415); c = ii(c, d, a, b, w(14), 15, -1416354905); b = ii(b, c, d, a, w(5), 21, -57434055);
    a = ii(a, b, c, d, w(12), 6, 1700485571); d = ii(d, a, b, c, w(3), 10, -1894986606); c = ii(c, d, a, b, w(10), 15, -1051523); b = ii(b, c, d, a, w(1), 21, -2054922799);
    a = ii(a, b, c, d, w(8), 6, 1873313359); d = ii(d, a, b, c, w(15), 10, -30611744); c = ii(c, d, a, b, w(6), 15, -1560198380); b = ii(b, c, d, a, w(13), 21, 1309151649);
    a = ii(a, b, c, d, w(4), 6, -145523070); d = ii(d, a, b, c, w(11), 10, -1120210379); c = ii(c, d, a, b, w(2), 15, 718787259); b = ii(b, c, d, a, w(9), 21, -343485551);
    a = (a + oa) | 0; b = (b + ob) | 0; c = (c + oc) | 0; d = (d + od) | 0;
  }
  return [a, b, c, d].map(n => { let s = ''; for (let j = 0; j < 4; j++) s += ((n >> (j * 8)) & 255).toString(16).padStart(2, '0'); return s; }).join('');
}

// ---- slugify ----
export function slugify(text) {
  return { output: String(text).normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 200) };
}

// ---- JWT sign / verify (HS256/384/512) ----
const HS = { HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512' };
export async function jwtSign(payload, secret, alg) {
  alg = alg || 'HS256'; if (!HS[alg]) throw new Error('Unsupported alg (HS256/384/512).');
  const obj = typeof payload === 'string' ? JSON.parse(payload) : payload;
  const h = bytesToB64(strToBytes(JSON.stringify({ alg, typ: 'JWT' })), true);
  const p = bytesToB64(strToBytes(JSON.stringify(obj)), true);
  const k = await subtle.importKey('raw', strToBytes(secret), { name: 'HMAC', hash: HS[alg] }, false, ['sign']);
  const sig = new Uint8Array(await subtle.sign('HMAC', k, strToBytes(h + '.' + p)));
  return { output: h + '.' + p + '.' + bytesToB64(sig, true) };
}
export async function jwtVerify(token, secret) {
  const parts = String(token).split('.'); if (parts.length !== 3) throw new Error('Not a JWT.');
  const header = JSON.parse(bytesToStr(b64ToBytes(parts[0])));
  if (!HS[header.alg]) return { valid: false, reason: 'alg ' + header.alg + ' not verifiable here (HS256/384/512 only).' };
  const k = await subtle.importKey('raw', strToBytes(secret), { name: 'HMAC', hash: HS[header.alg] }, false, ['verify']);
  const ok = await subtle.verify('HMAC', k, b64ToBytes(parts[2]), strToBytes(parts[0] + '.' + parts[1]));
  const payload = JSON.parse(bytesToStr(b64ToBytes(parts[1])));
  const now = Math.floor(Date.now() / 1000); const expired = !!(payload.exp && payload.exp < now);
  return { valid: ok && !expired, signatureValid: ok, expired, payload };
}

// ---- TOTP (RFC 6238) ----
function base32Decode(s) {
  s = String(s).replace(/=+$/, '').toUpperCase().replace(/\s/g, '');
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = 0, val = 0; const out = [];
  for (const c of s) { const i = A.indexOf(c); if (i < 0) continue; val = (val << 5) | i; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  return new Uint8Array(out);
}
export async function totp(secret, opts) {
  opts = opts || {}; const step = +opts.step || 30, digits = +opts.digits || 6;
  const counter = Math.floor(Date.now() / 1000 / step);
  const buf = new ArrayBuffer(8), dv = new DataView(buf);
  dv.setUint32(0, Math.floor(counter / 2 ** 32)); dv.setUint32(4, counter >>> 0);
  const k = await subtle.importKey('raw', base32Decode(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = new Uint8Array(await subtle.sign('HMAC', k, new Uint8Array(buf)));
  const off = sig[19] & 0xf;
  const bin = ((sig[off] & 0x7f) << 24) | (sig[off + 1] << 16) | (sig[off + 2] << 8) | sig[off + 3];
  return { output: (bin % 10 ** digits).toString().padStart(digits, '0'), secondsRemaining: step - Math.floor(Date.now() / 1000) % step };
}

// ---- Subresource Integrity ----
export async function sri(text, algo) {
  algo = algo || 'sha384'; const map = { sha256: 'SHA-256', sha384: 'SHA-384', sha512: 'SHA-512' };
  if (!map[algo]) throw new Error('algo must be sha256/sha384/sha512');
  const buf = await subtle.digest(map[algo], strToBytes(text));
  return { output: algo + '-' + bytesToB64(new Uint8Array(buf)) };
}

// ---- gzip compress / decompress (CompressionStream) ----
export async function gzip(text, mode) {
  if (mode === 'decompress') {
    const bytes = b64ToBytes(text);
    const ds = new DecompressionStream('gzip');
    const out = new Uint8Array(await new Response(new Response(bytes).body.pipeThrough(ds)).arrayBuffer());
    return { output: bytesToStr(out) };
  }
  const cs = new CompressionStream('gzip');
  const orig = strToBytes(text);
  const out = new Uint8Array(await new Response(new Response(orig).body.pipeThrough(cs)).arrayBuffer());
  return { output: bytesToB64(out), originalBytes: orig.length, compressedBytes: out.length, ratio: orig.length ? +(out.length / orig.length).toFixed(3) : 0 };
}

// ---- text diff (line-level LCS) ----
export function textDiff(a, b) {
  const A = String(a).split('\n'), B = String(b).split('\n');
  const m = A.length, n = B.length; const dp = Array.from({ length: m + 1 }, () => new Uint32Array(n + 1));
  for (let i = m - 1; i >= 0; i--) for (let j = n - 1; j >= 0; j--) dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const diff = []; let i = 0, j = 0, add = 0, del = 0;
  while (i < m && j < n) { if (A[i] === B[j]) { diff.push({ t: ' ', line: A[i] }); i++; j++; } else if (dp[i + 1][j] >= dp[i][j + 1]) { diff.push({ t: '-', line: A[i] }); del++; i++; } else { diff.push({ t: '+', line: B[j] }); add++; j++; } }
  while (i < m) { diff.push({ t: '-', line: A[i++] }); del++; } while (j < n) { diff.push({ t: '+', line: B[j++] }); add++; }
  return { added: add, removed: del, diff: diff.map(d => d.t + ' ' + d.line).join('\n') };
}

// ---- CSV <-> JSON ----
export function csvToJson(csv) {
  const rows = []; let row = [], field = '', q = false; const s = String(csv);
  for (let i = 0; i < s.length; i++) { const c = s[i];
    if (q) { if (c === '"') { if (s[i + 1] === '"') { field += '"'; i++; } else q = false; } else field += c; }
    else if (c === '"') q = true; else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && s[i + 1] === '\n') i++; row.push(field); rows.push(row); row = []; field = ''; }
    else field += c; }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  const head = rows.shift() || []; const data = rows.filter(r => r.length && !(r.length === 1 && r[0] === '')).map(r => { const o = {}; head.forEach((h, k) => o[h] = r[k]); return o; });
  return { output: JSON.stringify(data, null, 2), rows: data.length };
}
export function jsonToCsv(json) {
  const arr = typeof json === 'string' ? JSON.parse(json) : json;
  if (!Array.isArray(arr) || !arr.length) throw new Error('Expected a non-empty JSON array of objects.');
  const cols = Array.from(arr.reduce((s, o) => { Object.keys(o).forEach(k => s.add(k)); return s; }, new Set()));
  const esc = v => { v = v == null ? '' : String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
  return { output: [cols.join(','), ...arr.map(o => cols.map(c => esc(o[c])).join(','))].join('\n'), rows: arr.length };
}

// ---- MCP tool registry: name -> {description, schema, run} ----
export const TOOLS = {
  hash: { description: 'Compute a cryptographic hash (SHA-256/384/512, SHA-1, MD5) of text.', schema: { text: 'string', algo: 'SHA-256|SHA-384|SHA-512|SHA-1|MD5' }, run: a => hash(a.text, a.algo) },
  hmac: { description: 'Compute an HMAC of text with a key.', schema: { text: 'string', key: 'string', algo: 'SHA-256|SHA-512|SHA-1' }, run: a => hmac(a.text, a.key, a.algo) },
  base64: { description: 'Base64 encode or decode text.', schema: { text: 'string', mode: 'encode|decode' }, run: a => base64(a.text, a.mode) },
  base64url: { description: 'Base64URL encode or decode text.', schema: { text: 'string', mode: 'encode|decode' }, run: a => base64url(a.text, a.mode) },
  hex: { description: 'Hex encode or decode text.', schema: { text: 'string', mode: 'encode|decode' }, run: a => hex(a.text, a.mode) },
  url_encode: { description: 'URL-encode or decode text.', schema: { text: 'string', mode: 'encode|decode' }, run: a => urlcodec(a.text, a.mode) },
  jwt_decode: { description: 'Decode a JWT header and payload (no signature verification).', schema: { token: 'string' }, run: a => jwtDecode(a.token) },
  uuid: { description: 'Generate a UUID (v4 or v7).', schema: { version: '4|7' }, run: a => (String(a.version) === '7' ? uuidV7() : uuidV4()) },
  uuid_inspect: { description: 'Inspect a UUID (version, variant, embedded timestamp for v7).', schema: { uuid: 'string' }, run: a => uuidInspect(a.uuid) },
  entropy: { description: 'Shannon entropy (bits/byte) of text, with a verdict.', schema: { text: 'string' }, run: a => entropy(a.text) },
  epoch: { description: 'Convert between Unix timestamps and ISO dates.', schema: { value: 'string (unix seconds/millis or a date)' }, run: a => epoch(a.value) },
  password: { description: 'Generate a cryptographically-random password with an entropy estimate.', schema: { length: 'number', upper: 'bool', lower: 'bool', digits: 'bool', symbols: 'bool' }, run: a => password(a) },
  json: { description: 'Format, minify, or validate JSON.', schema: { text: 'string', mode: 'format|minify|validate' }, run: a => jsonTool(a.text, a.mode) },
  color: { description: 'Convert a color between hex, rgb, and hsl.', schema: { input: 'string (#hex or rgb())' }, run: a => color(a.input) },
  cidr: { description: 'Compute network, broadcast, mask, and host range for an IPv4 CIDR.', schema: { input: 'string (e.g. 10.0.0.0/24)' }, run: a => cidr(a.input) },
  case_convert: { description: 'Convert text between camel/pascal/snake/kebab/constant/title case.', schema: { text: 'string', to: 'camel|pascal|snake|kebab|constant|title' }, run: a => caseConvert(a.text, a.to) },
  slugify: { description: 'Turn text into a clean URL slug (Unicode-aware).', schema: { text: 'string' }, run: a => slugify(a.text) },
  jwt_sign: { description: 'Sign a JWT (HS256/384/512) from a payload and secret.', schema: { text: 'JSON payload', key: 'secret', algo: 'HS256|HS384|HS512' }, run: a => jwtSign(a.text, a.key, a.algo) },
  jwt_verify: { description: 'Verify a JWT signature (HS256/384/512) and check expiry.', schema: { token: 'string', key: 'secret' }, run: a => jwtVerify(a.token, a.key) },
  totp: { description: 'Generate the current TOTP 2FA code from a base32 secret (RFC 6238).', schema: { key: 'base32 secret', step: 'seconds (default 30)', digits: 'default 6' }, run: a => totp(a.key, a) },
  sri: { description: 'Compute a Subresource Integrity hash (sha256/384/512) for content.', schema: { text: 'string', algo: 'sha256|sha384|sha512' }, run: a => sri(a.text, a.algo) },
  gzip: { description: 'Gzip-compress or decompress text (base64 output/input).', schema: { text: 'string', mode: 'compress|decompress' }, run: a => gzip(a.text, a.mode) },
  text_diff: { description: 'Line-level diff between two texts (added/removed counts + unified diff).', schema: { text: 'text A', b: 'text B' }, run: a => textDiff(a.text, a.b) },
  csv_to_json: { description: 'Convert CSV to a JSON array of objects.', schema: { text: 'CSV' }, run: a => csvToJson(a.text) },
  json_to_csv: { description: 'Convert a JSON array of objects to CSV.', schema: { text: 'JSON array' }, run: a => jsonToCsv(a.text) }
};
