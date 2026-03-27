/**
 * Penumbra Forge — Noise Library
 *
 * Generates realistic benign log entries for injection into evidence
 * corpora, making scenarios harder to read and more replayable.
 *
 * API:
 *   NoiseLibrary.generate(count, sources, timeWindow) → array of log entries
 *
 *   count      — number of entries to generate
 *   sources    — array of source types: ['web', 'fw', 'dns', 'auth', 'ids', 'waf']
 *   timeWindow — { start: 'YYYY-MM-DD HH:MM:SS', end: 'YYYY-MM-DD HH:MM:SS' }
 *
 * All entries are benign/normal — no suspicious flags, no evidenceIds.
 * Entries are returned in chronological order.
 */

(function () {
  'use strict';

  /* ════════════════════════════════════════════════════
     Pools
     ════════════════════════════════════════════════════ */

  var IPS = [
    '72.44.128.90',   // US east coast shopper
    '98.22.156.71',   // US midwest shopper
    '203.0.113.42',   // EU shopper
    '44.192.88.12',   // AWS-hosted shopper
    '52.78.231.108',  // KR shopper
    '66.249.66.91',   // Google crawler
    '13.107.42.14',   // Bing crawler
    '104.16.55.2',    // CDN edge node
    '91.189.92.10',   // internal monitoring
    '185.220.101.33', // random scanner
    '64.62.197.152',  // US west coast shopper
    '81.2.69.144',    // UK shopper
    '195.54.160.84',  // FR shopper
    '117.20.49.50',   // AU shopper
    '59.106.212.20',  // JP shopper
    '146.190.12.34',  // CA shopper
    '159.89.49.22',   // NL shopper
    '199.241.231.58', // US corp user
    '173.245.48.71',  // Cloudflare edge
    '151.101.1.57',   // Fastly CDN
    '34.102.136.180', // GCP LB
    '54.239.28.85',   // AWS CloudFront
    '162.158.92.15',  // CF proxy
    '23.235.39.218'   // Fastly node
  ];

  var USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Android 14; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'CDN-Cache/2.1',
    'Googlebot/2.1 (+http://www.google.com/bot.html)',
    'internal-monitor/1.0'
  ];

  var SEARCH_TERMS = [
    'wireless+earbuds',
    'bluetooth+speaker',
    'laptop+stand',
    'mechanical+keyboard',
    'usb+c+hub',
    'noise+cancelling+headphones',
    'gaming+mouse',
    'webcam+hd',
    'monitor+arm',
    'desk+lamp',
    'phone+charger',
    'tablet+case',
    'smart+watch+band',
    'cable+organizer',
    'portable+battery',
    'where+to+buy+headphones',
    'best+ergonomic+chair',
    'home+office+setup',
    'coffee+maker+reviews',
    'air+purifier+small+room',
    'hdmi+cable+4k',
    'ethernet+cable',
    'surge+protector',
    'wall+mount+tv'
  ];

  var PRODUCT_IDS = [
    'wireless-earbuds-pro',
    'bluetooth-speaker-xl',
    'laptop-stand-adj',
    'mech-keyboard-tkl',
    'usb-hub-7port',
    'headphones-nc-500',
    'gaming-mouse-pro',
    'webcam-4k-auto',
    'monitor-arm-dual',
    'desk-lamp-led',
    'charger-65w-gan',
    'tablet-case-11in',
    'smartwatch-band-38',
    'cable-box-oak',
    'battery-pack-20k',
    'hdmi-cable-3m',
    'ethernet-cat6-5m',
    'surge-6outlet'
  ];

  var STATIC_FILES = [
    'css/main.css',
    'css/product.css',
    'css/checkout.css',
    'js/app.js',
    'js/cart.js',
    'js/analytics.js',
    'img/logo.png',
    'img/banner-spring.jpg',
    'fonts/inter-variable.woff2',
    'icons/sprite.svg'
  ];

  var DOMAINS = [
    'shopstack.lab.penumbraforge.com',
    'cdn.shopstack.lab',
    'api.shopstack.lab',
    'mail.penumbraforge.com',
    'auth.shopstack.lab',
    'assets.shopstack.lab',
    'metrics.shopstack.lab',
    'static.shopstack.lab'
  ];

  var EMAILS = [
    'alex.rivera@email.com',
    'morgan.lee@email.com',
    'taylor.kim@email.com',
    'jordan.patel@email.com',
    'casey.chen@email.com',
    'sam.nakamura@email.com',
    'riley.oconnor@email.com',
    'avery.santos@email.com',
    'quinn.martinez@email.com',
    'blake.johnson@email.com',
    'drew.wilson@email.com',
    'sage.thompson@email.com',
    'reese.garcia@email.com',
    'finley.davis@email.com',
    'harper.brown@email.com',
    'emery.moore@email.com',
    'rowan.clark@email.com',
    'skyler.hall@email.com',
    'dakota.lewis@email.com',
    'phoenix.wright@email.com'
  ];

  /* Random ports for DENY probes — non-privileged ranges that don't
     represent real services on this host. */
  var DENY_PORTS = [8080, 8443, 8888, 9200, 9300, 5432, 3306, 6379, 27017, 11211, 2375, 4444, 5000, 5985, 6000, 7001];

  /* NAT pool of internal addresses (LAN side) */
  var INTERNAL_IPS = [
    '10.0.1.50',  // web server
    '10.0.1.51',
    '10.0.1.52',
    '10.0.2.10',
    '10.0.2.11',
    '10.0.3.5',
    '10.0.4.55'   // health check agent
  ];

  /* ════════════════════════════════════════════════════
     PRNG — uses Math.random (not seeded; noise is
     decorative, not reproducible by design)
     ════════════════════════════════════════════════════ */

  function rng() {
    return Math.random();
  }

  function randInt(min, max) {
    return Math.floor(rng() * (max - min + 1)) + min;
  }

  function pick(arr) {
    return arr[Math.floor(rng() * arr.length)];
  }

  function randomHex(bytes) {
    var hex = '';
    for (var i = 0; i < bytes; i++) {
      var b = Math.floor(rng() * 256);
      hex += (b < 16 ? '0' : '') + b.toString(16);
    }
    return hex;
  }

  /* ════════════════════════════════════════════════════
     Timestamp Utilities
     ════════════════════════════════════════════════════ */

  /**
   * Parse "YYYY-MM-DD HH:MM:SS" → milliseconds (UTC).
   */
  function parseTs(str) {
    return new Date(str.replace(' ', 'T') + 'Z').getTime();
  }

  /**
   * Format milliseconds → "YYYY-MM-DD HH:MM:SS".
   */
  function formatTs(ms) {
    var d = new Date(ms);
    var yy = d.getUTCFullYear();
    var mo = String(d.getUTCMonth() + 1).padStart(2, '0');
    var dd = String(d.getUTCDate()).padStart(2, '0');
    var hh = String(d.getUTCHours()).padStart(2, '0');
    var mi = String(d.getUTCMinutes()).padStart(2, '0');
    var ss = String(d.getUTCSeconds()).padStart(2, '0');
    return yy + '-' + mo + '-' + dd + ' ' + hh + ':' + mi + ':' + ss;
  }

  /**
   * Generate a timestamp distributed across the window with mild clustering
   * toward "business hours" (UTC 13:00–21:00 is a rough global overlap).
   *
   * Strategy: 70% of the time pick uniformly, 30% of the time bias toward
   * any sub-hour that falls in the business band.  This keeps the
   * distribution realistic without complex date math.
   */
  function randomTimestamp(startMs, endMs) {
    var span = endMs - startMs;

    if (rng() < 0.30) {
      // mild clustering: pick a point in the first 60% of the window
      // (simulate morning rush or midday peak)
      return startMs + Math.floor(rng() * span * 0.60);
    }

    return startMs + Math.floor(rng() * span);
  }

  /* ════════════════════════════════════════════════════
     Severity Sampler
     80% info, 15% low, 5% medium
     ════════════════════════════════════════════════════ */

  function randomSeverity() {
    var r = rng();
    if (r < 0.80) return 'info';
    if (r < 0.95) return 'low';
    return 'medium';
  }

  /* ════════════════════════════════════════════════════
     ID Counter (per-source)
     ════════════════════════════════════════════════════ */

  var _counters = {};

  function resetCounters() {
    _counters = { web: 0, fw: 0, dns: 0, auth: 0, ids: 0, waf: 0 };
  }

  function nextId(source) {
    if (!_counters[source]) _counters[source] = 0;
    _counters[source] += 1;
    return 'noise-' + source + '-' + String(_counters[source]).padStart(3, '0');
  }

  /* ════════════════════════════════════════════════════
     Detail budget: ~30% of entries carry full detail
     ════════════════════════════════════════════════════ */

  function maybeDetail(obj) {
    return rng() < 0.30 ? obj : null;
  }

  /* ════════════════════════════════════════════════════
     Entry Factories — one per source
     ════════════════════════════════════════════════════ */

  function makeWebEntry(ts) {
    var ip = pick(IPS);
    var ua = pick(USER_AGENTS);
    var r = rng();

    var summary, detail, severity;
    severity = 'info';

    if (ip === '10.0.4.55' || rng() < 0.05) {
      // Health check (always internal, ~5% chance for any slot)
      ip = '10.0.4.55';
      ua = 'internal-monitor/1.0';
      summary = ip + ' GET /api/health — 200 OK — internal-monitor/1.0';
      detail = maybeDetail({
        srcIp: ip, dstIp: '10.0.1.50', dstPort: 443,
        method: 'GET', path: '/api/health',
        status: 200, bytes: 48, userAgent: ua
      });
    } else if (r < 0.15) {
      // Homepage
      var status = (rng() < 0.92) ? 200 : 304;
      summary = ip + ' GET / — ' + status + (status === 200 ? ' OK' : ' Not Modified') + ' — ' + ua.substring(0, 32);
      detail = maybeDetail({
        srcIp: ip, dstIp: '10.0.1.50', dstPort: 443,
        method: 'GET', path: '/',
        status: status, bytes: status === 200 ? randInt(15000, 22000) : 0,
        userAgent: ua
      });
    } else if (r < 0.30) {
      // Product page
      var pid = pick(PRODUCT_IDS);
      var pstatus = (rng() < 0.88) ? 200 : 404;
      summary = ip + ' GET /products/' + pid + ' — ' + pstatus + (pstatus === 200 ? ' OK' : ' Not Found');
      detail = maybeDetail({
        srcIp: ip, dstIp: '10.0.1.50', dstPort: 443,
        method: 'GET', path: '/products/' + pid,
        status: pstatus, bytes: pstatus === 200 ? randInt(8000, 14000) : 312,
        userAgent: ua
      });
      if (pstatus === 404) severity = 'low';
    } else if (r < 0.44) {
      // Search
      var term = pick(SEARCH_TERMS);
      summary = ip + ' GET /search?q=' + term + ' — 200 OK';
      detail = maybeDetail({
        srcIp: ip, dstIp: '10.0.1.50', dstPort: 443,
        method: 'GET', path: '/search', query: 'q=' + term,
        status: 200, bytes: randInt(6000, 11000), userAgent: ua
      });
    } else if (r < 0.55) {
      // Cart add
      var cartItem = pick(PRODUCT_IDS).substring(0, 8).toUpperCase().replace(/-/g, '');
      summary = ip + ' POST /cart/add — 200 OK — item=' + cartItem;
      detail = maybeDetail({
        srcIp: ip, dstIp: '10.0.1.50', dstPort: 443,
        method: 'POST', path: '/cart/add',
        status: 200, bytes: randInt(200, 400), userAgent: ua,
        body: { itemId: cartItem, qty: randInt(1, 3) }
      });
    } else if (r < 0.63) {
      // Static asset
      var sfile = pick(STATIC_FILES);
      var sstatus = (rng() < 0.55) ? 304 : 200;
      summary = ip + ' GET /static/' + sfile + ' — ' + sstatus + (sstatus === 200 ? ' OK' : ' Not Modified') + ' — CDN-Cache/2.1';
      ua = 'CDN-Cache/2.1';
      detail = maybeDetail({
        srcIp: ip, dstIp: '10.0.1.50', dstPort: 443,
        method: 'GET', path: '/static/' + sfile,
        status: sstatus, bytes: sstatus === 200 ? randInt(1000, 80000) : 0,
        userAgent: ua, cacheStatus: sstatus === 304 ? 'HIT' : 'MISS'
      });
    } else if (r < 0.72) {
      // Checkout
      summary = ip + ' POST /checkout — 200 OK';
      detail = maybeDetail({
        srcIp: ip, dstIp: '10.0.1.50', dstPort: 443,
        method: 'POST', path: '/checkout',
        status: 200, bytes: randInt(400, 900), userAgent: ua
      });
    } else {
      // Generic page (account, orders, etc.)
      var pages = ['/account/orders', '/account/profile', '/wishlist', '/products', '/about'];
      var page = pick(pages);
      summary = ip + ' GET ' + page + ' — 200 OK';
      detail = maybeDetail({
        srcIp: ip, dstIp: '10.0.1.50', dstPort: 443,
        method: 'GET', path: page,
        status: 200, bytes: randInt(5000, 12000), userAgent: ua
      });
    }

    return {
      id: nextId('web'),
      timestamp: ts,
      source: 'web',
      severity: severity,
      summary: summary,
      detail: detail,
      raw: detail ? JSON.stringify(detail, null, 2) : null,
      suspicious: false,
      evidenceId: null
    };
  }

  function makeFwEntry(ts) {
    var ip = pick(IPS);
    var r = rng();
    var summary, detail, severity;
    severity = 'info';

    if (r < 0.45) {
      // Inbound ALLOW
      var srcPort = randInt(49152, 65535);
      summary = 'ALLOW TCP ' + ip + ':' + srcPort + ' → 10.0.1.50:443';
      detail = maybeDetail({
        action: 'ALLOW', proto: 'TCP',
        srcIp: ip, srcPort: srcPort,
        dstIp: '10.0.1.50', dstPort: 443,
        rule: 'inbound-https'
      });
    } else if (r < 0.70) {
      // Outbound ALLOW (response)
      var dstPort = randInt(49152, 65535);
      summary = 'ALLOW TCP 10.0.1.50 → ' + ip + ':' + dstPort;
      detail = maybeDetail({
        action: 'ALLOW', proto: 'TCP',
        srcIp: '10.0.1.50', srcPort: 443,
        dstIp: ip, dstPort: dstPort,
        rule: 'outbound-https-response'
      });
    } else if (r < 0.88) {
      // DENY — random port probe (low severity, benign scanner noise)
      var badPort = pick(DENY_PORTS);
      var badSrcPort = randInt(1024, 65535);
      severity = 'low';
      summary = 'DENY TCP ' + ip + ':' + badSrcPort + ' → 10.0.1.50:' + badPort + ' — policy: default-deny';
      detail = maybeDetail({
        action: 'DENY', proto: 'TCP',
        srcIp: ip, srcPort: badSrcPort,
        dstIp: '10.0.1.50', dstPort: badPort,
        rule: 'default-deny'
      });
    } else {
      // NAT translation
      var natInternal = pick(INTERNAL_IPS);
      var natSrc = randInt(49152, 65535);
      summary = 'NAT TCP ' + ip + ':' + natSrc + ' → ' + natInternal + ':443';
      detail = maybeDetail({
        action: 'NAT', proto: 'TCP',
        srcIp: ip, srcPort: natSrc,
        translatedDst: natInternal, dstPort: 443,
        rule: 'nat-inbound'
      });
    }

    return {
      id: nextId('fw'),
      timestamp: ts,
      source: 'fw',
      severity: severity,
      summary: summary,
      detail: detail,
      raw: detail ? JSON.stringify(detail, null, 2) : null,
      suspicious: false,
      evidenceId: null
    };
  }

  function makeDnsEntry(ts) {
    var r = rng();
    var summary, detail;

    if (r < 0.55) {
      // A record lookup
      var domain = pick(DOMAINS);
      var resolvedIp = pick(IPS);
      var srcIp = rng() < 0.5 ? '10.0.0.2' : pick(INTERNAL_IPS);
      summary = 'A query: ' + domain + ' → ' + resolvedIp;
      detail = maybeDetail({
        queryType: 'A', domain: domain,
        srcIp: srcIp, resolver: '10.0.0.2',
        response: resolvedIp, ttl: pick([60, 120, 300, 600, 3600])
      });
    } else if (r < 0.72) {
      // MX lookup
      var mxDomain = pick(DOMAINS);
      summary = 'MX query: ' + mxDomain;
      detail = maybeDetail({
        queryType: 'MX', domain: mxDomain,
        srcIp: '10.0.0.2',
        response: 'mail.penumbraforge.com', ttl: 3600
      });
    } else if (r < 0.87) {
      // PTR (reverse lookup)
      var ptrIp = pick(IPS);
      // Format as reverse: e.g. 90.128.44.72.in-addr.arpa
      var parts = ptrIp.split('.');
      var reversed = parts[3] + '.' + parts[2] + '.' + parts[1] + '.' + parts[0] + '.in-addr.arpa';
      summary = 'PTR query: ' + ptrIp + ' (' + reversed + ')';
      detail = maybeDetail({
        queryType: 'PTR', query: reversed,
        srcIp: '10.0.0.2',
        response: pick(DOMAINS), ttl: 300
      });
    } else {
      // AAAA lookup (IPv6)
      var aaDomain = pick(DOMAINS);
      summary = 'AAAA query: ' + aaDomain + ' (NODATA)';
      detail = maybeDetail({
        queryType: 'AAAA', domain: aaDomain,
        srcIp: '10.0.0.2', response: 'NODATA', ttl: 60
      });
    }

    return {
      id: nextId('dns'),
      timestamp: ts,
      source: 'dns',
      severity: 'info',
      summary: summary,
      detail: detail,
      raw: detail ? JSON.stringify(detail, null, 2) : null,
      suspicious: false,
      evidenceId: null
    };
  }

  function makeAuthEntry(ts) {
    var r = rng();
    var email = pick(EMAILS);
    var ip = pick(IPS);
    var sess = 'sess_' + randomHex(4);
    var summary, detail, severity;
    severity = 'info';

    if (r < 0.50) {
      // Login success
      summary = 'LOGIN success — user: ' + email + ' — session: ' + sess;
      detail = maybeDetail({
        event: 'login_success', user: email,
        srcIp: ip, sessionId: sess, mfa: rng() < 0.35
      });
    } else if (r < 0.68) {
      // Logout
      summary = 'LOGOUT — session: ' + sess + ' expired';
      detail = maybeDetail({
        event: 'logout', sessionId: sess,
        srcIp: ip, reason: 'user_initiated'
      });
    } else if (r < 0.82) {
      // Session renew
      summary = 'SESSION renewed — user: ' + email;
      detail = maybeDetail({
        event: 'session_renew', user: email,
        sessionId: sess, srcIp: ip,
        expiresIn: 3600
      });
    } else {
      // Login failed — wrong password (low severity, occasional)
      severity = 'low';
      summary = 'LOGIN failed — user: ' + email + ' — wrong password';
      detail = maybeDetail({
        event: 'login_failed', user: email,
        srcIp: ip, reason: 'wrong_password',
        attemptCount: randInt(1, 2)
      });
    }

    return {
      id: nextId('auth'),
      timestamp: ts,
      source: 'auth',
      severity: severity,
      summary: summary,
      detail: detail,
      raw: detail ? JSON.stringify(detail, null, 2) : null,
      suspicious: false,
      evidenceId: null
    };
  }

  function makeIdsEntry(ts) {
    var r = rng();
    var summary, detail, severity;
    severity = 'info';

    if (r < 0.40) {
      // New user agent detected (benign)
      var ua = pick(USER_AGENTS);
      summary = 'INFO: New user agent detected — ' + ua.substring(0, 60);
      detail = maybeDetail({
        alertType: 'new_user_agent',
        userAgent: ua,
        srcIp: pick(IPS),
        firstSeen: true
      });
    } else if (r < 0.68) {
      // Traffic volume spike (normal)
      var reqMin = randInt(42, 110);
      var rangeMin = reqMin - randInt(5, 12);
      var rangeMax = reqMin + randInt(8, 20);
      summary = 'INFO: Traffic volume spike — ' + reqMin + ' req/min (normal range: ' + rangeMin + '–' + rangeMax + ')';
      detail = maybeDetail({
        alertType: 'traffic_spike',
        reqPerMin: reqMin, normalMin: rangeMin, normalMax: rangeMax,
        srcIp: pick(IPS), action: 'logged'
      });
    } else if (r < 0.85) {
      // Outbound to new IP (first-seen but benign)
      var newIp = pick(IPS);
      summary = 'LOW: Outbound connection to new IP — ' + newIp;
      severity = 'low';
      detail = maybeDetail({
        alertType: 'new_outbound_ip', dstIp: newIp,
        srcIp: '10.0.1.50', dstPort: 443,
        firstSeen: true, action: 'logged'
      });
    } else {
      // Generic low-signal IDS notice
      var notices = [
        'INFO: HTTP response size anomaly — within bounds',
        'INFO: Keep-alive session count elevated — normal load',
        'INFO: TLS 1.2 downgrade negotiation detected — legacy client',
        'INFO: Compressed payload detected on /search — expected behavior'
      ];
      summary = pick(notices);
      detail = maybeDetail({
        alertType: 'informational',
        srcIp: pick(IPS), action: 'logged'
      });
    }

    return {
      id: nextId('ids'),
      timestamp: ts,
      source: 'ids',
      severity: severity,
      summary: summary,
      detail: detail,
      raw: detail ? JSON.stringify(detail, null, 2) : null,
      suspicious: false,
      evidenceId: null
    };
  }

  function makeWafEntry(ts) {
    var r = rng();
    var ip = pick(IPS);
    var summary, detail, severity;
    severity = 'info';

    if (r < 0.60) {
      // False-positive SQL keyword in search (very common in WAF logs)
      var sqls = [
        'where+to+buy+headphones',
        'order+by+price',
        'select+all+products',
        'drop+shipping+options',
        'union+jack+backpack',
        'insert+coin+purse'
      ];
      var term = pick(sqls);
      var ruleIds = ['942100', '942110', '942120', '942130', '942140'];
      var rule = pick(ruleIds);
      summary = 'Rule ' + rule + ' — SQL keyword in parameter (FALSE POSITIVE) — ' + ip + ' GET /search?q=' + term;
      detail = maybeDetail({
        ruleId: rule, action: 'logged', falsePositive: true,
        srcIp: ip, method: 'GET',
        path: '/search', query: 'q=' + term,
        reason: 'sql_keyword_pattern'
      });
    } else if (r < 0.85) {
      // Rate limit warning (legitimate user, not blocked)
      var reqCount = randInt(38, 48);
      severity = 'low';
      summary = 'Rate limit warning — ' + ip + ' — ' + reqCount + '/50 requests in 1 minute';
      detail = maybeDetail({
        ruleType: 'rate_limit', srcIp: ip,
        requestCount: reqCount, limit: 50, windowSec: 60,
        action: 'warn', blocked: false
      });
    } else {
      // Generic WAF allow
      var path = pick(['/products', '/search', '/cart', '/checkout', '/account/orders']);
      summary = 'Rule MATCH — request passed — ' + ip + ' GET ' + path;
      detail = maybeDetail({
        action: 'pass', srcIp: ip,
        method: 'GET', path: path,
        ruleSet: 'OWASP-CRS-3.3'
      });
    }

    return {
      id: nextId('waf'),
      timestamp: ts,
      source: 'waf',
      severity: severity,
      summary: summary,
      detail: detail,
      raw: detail ? JSON.stringify(detail, null, 2) : null,
      suspicious: false,
      evidenceId: null
    };
  }

  /* ════════════════════════════════════════════════════
     Source Dispatch
     ════════════════════════════════════════════════════ */

  var FACTORIES = {
    web:  makeWebEntry,
    fw:   makeFwEntry,
    dns:  makeDnsEntry,
    auth: makeAuthEntry,
    ids:  makeIdsEntry,
    waf:  makeWafEntry
  };

  /* Source weight distribution (relative frequency when mixing) */
  var SOURCE_WEIGHTS = {
    web:  0.40,
    fw:   0.22,
    dns:  0.14,
    auth: 0.10,
    ids:  0.08,
    waf:  0.06
  };

  /**
   * Build a weighted sampler from the requested sources.
   * Returns a function that picks a source string on each call.
   */
  function buildSampler(sources) {
    var valid = sources.filter(function (s) { return FACTORIES[s]; });
    if (!valid.length) valid = ['web'];

    // Accumulate weights
    var total = 0;
    var cumulative = [];
    for (var i = 0; i < valid.length; i++) {
      var w = SOURCE_WEIGHTS[valid[i]] || (1 / valid.length);
      total += w;
      cumulative.push({ source: valid[i], upper: total });
    }

    return function () {
      var r = rng() * total;
      for (var j = 0; j < cumulative.length; j++) {
        if (r <= cumulative[j].upper) return cumulative[j].source;
      }
      return valid[valid.length - 1];
    };
  }

  /* ════════════════════════════════════════════════════
     Public API
     ════════════════════════════════════════════════════ */

  var NoiseLibrary = {
    /**
     * Generate `count` benign log entries distributed across `sources`
     * within `timeWindow`.
     *
     * @param {number} count
     * @param {string[]} sources — e.g. ['web', 'fw', 'dns', 'auth', 'ids', 'waf']
     * @param {{ start: string, end: string }} timeWindow
     * @returns {object[]} — array of log entry objects in chronological order
     */
    generate: function (count, sources, timeWindow) {
      if (!count || count < 1) return [];
      if (!sources || !sources.length) sources = ['web', 'fw', 'dns', 'auth', 'ids', 'waf'];
      if (!timeWindow || !timeWindow.start || !timeWindow.end) {
        timeWindow = {
          start: '2024-03-15 14:00:00',
          end:   '2024-03-15 15:30:00'
        };
      }

      resetCounters();

      var startMs = parseTs(timeWindow.start);
      var endMs   = parseTs(timeWindow.end);
      if (endMs <= startMs) endMs = startMs + 5400000; // fallback: +90 min

      var sampleSource = buildSampler(sources);
      var entries = [];

      for (var i = 0; i < count; i++) {
        var ts = formatTs(randomTimestamp(startMs, endMs));
        var source = sampleSource();
        var factory = FACTORIES[source];
        var e = factory(ts);

        // Apply severity distribution override (factories set their own
        // severity for logic reasons; here we only upgrade info→medium
        // for the 5% medium budget, not downgrade intentional lows).
        if (e.severity === 'info' && rng() < 0.05) {
          e.severity = 'medium';
        }

        entries.push(e);
      }

      // Sort chronologically
      entries.sort(function (a, b) {
        return a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0;
      });

      return entries;
    }
  };

  /* ════════════════════════════════════════════════════
     Register on window.PenumbraLabs (additive)
     ════════════════════════════════════════════════════ */

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.NoiseLibrary = NoiseLibrary;

}());
