/**
 * Penumbra Forge — Procedural Engine
 *
 * Randomizes lab scenarios to make them replayable and unspoilable.
 * Takes an evidence corpus and a procedural template, returns a new
 * corpus with IPs, timestamps, usernames, sessions, and domains
 * consistently replaced with randomized values.
 *
 * API:
 *   Procedural.apply(corpus, template) → randomized corpus array
 *   Procedural.seed(value)             → set seed for reproducible output
 */

(function () {
  'use strict';

  /* ════════════════════════════════════════════════════
     Seeded PRNG — xorshift32
     ════════════════════════════════════════════════════ */

  var _seed = 0;
  var _useSeeded = false;

  function xorshift32() {
    _seed ^= _seed << 13;
    _seed ^= _seed >> 17;
    _seed ^= _seed << 5;
    return (_seed >>> 0) / 4294967296;
  }

  function rng() {
    if (_useSeeded) return xorshift32();
    return Math.random();
  }

  /**
   * Random integer in [min, max] inclusive.
   */
  function randInt(min, max) {
    return Math.floor(rng() * (max - min + 1)) + min;
  }

  /**
   * Pick a random element from an array.
   */
  function pick(arr) {
    return arr[Math.floor(rng() * arr.length)];
  }

  /**
   * Shuffle an array in place (Fisher-Yates) and return it.
   */
  function shuffle(arr) {
    for (var i = arr.length - 1; i > 0; i--) {
      var j = Math.floor(rng() * (i + 1));
      var tmp = arr[i];
      arr[i] = arr[j];
      arr[j] = tmp;
    }
    return arr;
  }

  /**
   * Generate a random hex string of the given byte-count.
   */
  function randomHex(bytes) {
    var hex = '';
    for (var i = 0; i < bytes; i++) {
      var byte = Math.floor(rng() * 256);
      hex += (byte < 16 ? '0' : '') + byte.toString(16);
    }
    return hex;
  }

  /* ════════════════════════════════════════════════════
     Built-in Pools
     ════════════════════════════════════════════════════ */

  var POOLS = {
    'vps-ranges': [
      '45.33.32.156', '104.236.198.48', '185.199.108.153', '46.101.123.87', '159.89.100.42',
      '178.62.50.123', '139.59.24.68', '167.99.87.123', '206.189.136.22', '142.93.112.43',
      '68.183.24.56', '157.245.89.12', '164.92.183.45', '143.198.56.78', '134.209.113.22',
      '188.166.78.90', '165.227.45.67', '174.138.12.34', '198.199.78.90', '209.97.123.45',
      '95.179.196.78', '108.61.45.67', '45.76.123.45', '149.28.78.90', '207.148.12.34',
      '64.227.45.67', '137.184.78.90', '143.244.123.45', '170.64.12.34', '24.199.78.90'
    ],

    'realistic-emails': [
      'alex.rivera@email.com', 'morgan.lee@email.com', 'taylor.kim@email.com',
      'jordan.patel@email.com', 'casey.chen@email.com', 'sam.nakamura@email.com',
      'riley.oconnor@email.com', 'avery.santos@email.com', 'quinn.martinez@email.com',
      'blake.johnson@email.com', 'drew.wilson@email.com', 'sage.thompson@email.com',
      'reese.garcia@email.com', 'finley.davis@email.com', 'harper.brown@email.com',
      'emery.moore@email.com', 'rowan.clark@email.com', 'skyler.hall@email.com',
      'dakota.lewis@email.com', 'phoenix.wright@email.com', 'river.young@email.com',
      'logan.baker@email.com', 'charlie.adams@email.com', 'hayden.nelson@email.com',
      'ellis.campbell@email.com', 'remy.mitchell@email.com', 'kai.stewart@email.com',
      'noel.murphy@email.com', 'jude.price@email.com', 'lane.foster@email.com'
    ]
  };

  /* ════════════════════════════════════════════════════
     DGA Domain Generator
     ════════════════════════════════════════════════════ */

  var DGA_SYLLABLES = ['xr', 'kz', 'qv', 'bx', 'zt', 'mp', 'fn', 'dw', 'jc', 'hy', 'px', 'rv'];
  var DGA_WORDS = ['analytics', 'metrics', 'cdn', 'api', 'sync', 'data', 'cloud', 'net', 'hub', 'io'];
  var DGA_TLDS = ['.xyz', '.top', '.cc', '.icu', '.buzz', '.click', '.info'];

  function generateDGA() {
    var syllableCount = randInt(2, 3);
    var syllables = '';
    for (var i = 0; i < syllableCount; i++) {
      syllables += pick(DGA_SYLLABLES);
    }
    return syllables + '-' + pick(DGA_WORDS) + pick(DGA_TLDS);
  }

  /* ════════════════════════════════════════════════════
     Deep Copy
     ════════════════════════════════════════════════════ */

  function deepCopy(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  /* ════════════════════════════════════════════════════
     String Replacement Helpers
     ════════════════════════════════════════════════════ */

  /**
   * Escape a string for use inside a RegExp.
   */
  function escapeRegExp(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /**
   * Replace all occurrences of `from` with `to` in a string.
   * Returns the original string if it's not a string type.
   */
  function replaceAll(str, from, to) {
    if (typeof str !== 'string') return str;
    var pattern = new RegExp(escapeRegExp(from), 'g');
    return str.replace(pattern, to);
  }

  /**
   * Apply a replacement map to all string fields in a corpus entry.
   * Handles: summary, raw, and all string values within detail (recursive).
   */
  function applyReplacements(entry, replacements) {
    var keys = Object.keys(replacements);
    for (var k = 0; k < keys.length; k++) {
      var from = keys[k];
      var to = replacements[from];

      // summary
      if (typeof entry.summary === 'string') {
        entry.summary = replaceAll(entry.summary, from, to);
      }

      // raw
      if (typeof entry.raw === 'string') {
        entry.raw = replaceAll(entry.raw, from, to);
      }

      // detail — recurse into all string values
      if (entry.detail && typeof entry.detail === 'object') {
        replaceInObject(entry.detail, from, to);
      }
    }
  }

  /**
   * Recursively replace `from` with `to` in all string values of an object.
   */
  function replaceInObject(obj, from, to) {
    var keys = Object.keys(obj);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var val = obj[key];
      if (typeof val === 'string') {
        obj[key] = replaceAll(val, from, to);
      } else if (val && typeof val === 'object' && !Array.isArray(val)) {
        replaceInObject(val, from, to);
      } else if (Array.isArray(val)) {
        for (var j = 0; j < val.length; j++) {
          if (typeof val[j] === 'string') {
            val[j] = replaceAll(val[j], from, to);
          } else if (val[j] && typeof val[j] === 'object') {
            replaceInObject(val[j], from, to);
          }
        }
      }
    }
  }

  /* ════════════════════════════════════════════════════
     Timestamp Shifting
     ════════════════════════════════════════════════════ */

  /**
   * Shift a timestamp string by `offsetMs` milliseconds.
   * Supports formats: "YYYY-MM-DD HH:MM:SS" and ISO 8601.
   * Returns the shifted timestamp in the same format.
   */
  function shiftTimestamp(ts, offsetMs) {
    if (typeof ts !== 'string') return ts;

    // Detect format
    var isSimple = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(ts);
    var isISO = /^\d{4}-\d{2}-\d{2}T/.test(ts);

    if (!isSimple && !isISO) return ts;

    // Parse — for "YYYY-MM-DD HH:MM:SS" treat as UTC
    var dateStr = isSimple ? ts.replace(' ', 'T') + 'Z' : ts;
    var d = new Date(dateStr);
    if (isNaN(d.getTime())) return ts;

    d = new Date(d.getTime() + offsetMs);

    if (isSimple) {
      var yy = d.getUTCFullYear();
      var mm = String(d.getUTCMonth() + 1).padStart(2, '0');
      var dd = String(d.getUTCDate()).padStart(2, '0');
      var hh = String(d.getUTCHours()).padStart(2, '0');
      var mi = String(d.getUTCMinutes()).padStart(2, '0');
      var ss = String(d.getUTCSeconds()).padStart(2, '0');
      return yy + '-' + mm + '-' + dd + ' ' + hh + ':' + mi + ':' + ss;
    }

    return d.toISOString();
  }

  /* ════════════════════════════════════════════════════
     Session Token Generation
     ════════════════════════════════════════════════════ */

  /**
   * Parse a session pattern like 'sess_{random_hex_4}' and generate a token.
   */
  function generateSessionToken(pattern) {
    return pattern.replace(/\{random_hex_(\d+)\}/g, function (match, count) {
      return randomHex(parseInt(count, 10));
    });
  }

  /**
   * Find all unique session tokens in a corpus that match a given prefix pattern.
   * Returns an array of unique token strings.
   */
  function findSessionTokens(corpus, pattern) {
    // Extract the literal prefix (everything before the first '{')
    var prefix = pattern.split('{')[0];
    var tokens = {};

    for (var i = 0; i < corpus.length; i++) {
      var entry = corpus[i];
      findTokensInValue(entry.summary, prefix, tokens);
      findTokensInValue(entry.raw, prefix, tokens);
      if (entry.detail && typeof entry.detail === 'object') {
        findTokensInObject(entry.detail, prefix, tokens);
      }
    }

    return Object.keys(tokens);
  }

  function findTokensInValue(val, prefix, tokens) {
    if (typeof val !== 'string') return;
    // Match the prefix followed by word characters (hex, underscores, etc.)
    var pattern = new RegExp(escapeRegExp(prefix) + '[a-f0-9_]+', 'gi');
    var match;
    while ((match = pattern.exec(val)) !== null) {
      tokens[match[0]] = true;
    }
  }

  function findTokensInObject(obj, prefix, tokens) {
    var keys = Object.keys(obj);
    for (var i = 0; i < keys.length; i++) {
      var val = obj[keys[i]];
      if (typeof val === 'string') {
        findTokensInValue(val, prefix, tokens);
      } else if (val && typeof val === 'object' && !Array.isArray(val)) {
        findTokensInObject(val, prefix, tokens);
      } else if (Array.isArray(val)) {
        for (var j = 0; j < val.length; j++) {
          if (typeof val[j] === 'string') {
            findTokensInValue(val[j], prefix, tokens);
          } else if (val[j] && typeof val[j] === 'object') {
            findTokensInObject(val[j], prefix, tokens);
          }
        }
      }
    }
  }

  /* ════════════════════════════════════════════════════
     Noise Injection
     ════════════════════════════════════════════════════ */

  var NOISE_METHODS = ['GET', 'POST', 'HEAD', 'OPTIONS'];
  var NOISE_PATHS = [
    '/api/products', '/api/cart', '/api/health', '/api/search',
    '/images/banner.jpg', '/css/main.css', '/js/app.js',
    '/favicon.ico', '/robots.txt', '/sitemap.xml',
    '/api/user/profile', '/api/categories', '/api/reviews'
  ];
  var NOISE_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)',
    'internal-monitor/1.0',
    'Googlebot/2.1 (+http://www.google.com/bot.html)'
  ];
  var NOISE_IPS = [
    '72.44.128.90', '98.22.156.71', '44.192.88.12', '52.78.231.108',
    '91.189.92.10', '104.16.55.2', '172.217.14.99', '13.107.42.14'
  ];

  /**
   * Generate a single noise entry at the given timestamp.
   */
  function generateNoiseEntry(source, timestamp, idCounter) {
    var srcIp = pick(NOISE_IPS);
    var method = pick(NOISE_METHODS);
    var path = pick(NOISE_PATHS);
    var status = pick([200, 200, 200, 200, 301, 304, 404]);
    var bytes = randInt(48, 8192);
    var ua = pick(NOISE_USER_AGENTS);

    var detail;
    var summary;
    var severity = 'info';

    if (source === 'web') {
      detail = {
        srcIp: srcIp, dstIp: '10.0.1.50', dstPort: 443,
        method: method, path: path, status: status,
        bytes: bytes, userAgent: ua
      };
      summary = srcIp + ' ' + method + ' ' + path + ' — ' + status + ' — ' + ua.split(' ')[0];
    } else if (source === 'fw') {
      var action = pick(['ALLOW', 'ALLOW', 'ALLOW', 'DROP']);
      detail = {
        srcIp: srcIp, dstIp: '10.0.1.50',
        srcPort: randInt(1024, 65535), dstPort: pick([80, 443]),
        proto: 'TCP', action: action
      };
      summary = action + ' TCP ' + srcIp + ':' + detail.srcPort + ' → 10.0.1.50:' + detail.dstPort;
      severity = action === 'DROP' ? 'warning' : 'info';
    } else if (source === 'dns') {
      var domain = pick([
        'shopstack.lab.penumbraforge.com', 'cdn.shopstack.com',
        'api.shopstack.com', 'fonts.googleapis.com', 'www.google-analytics.com'
      ]);
      detail = {
        queryType: 'A', domain: domain, srcIp: srcIp,
        response: '10.0.1.50', ttl: pick([60, 300, 3600])
      };
      summary = 'A query ' + domain + ' from ' + srcIp;
    } else {
      // Fallback: web
      detail = {
        srcIp: srcIp, dstIp: '10.0.1.50', dstPort: 443,
        method: 'GET', path: '/api/health', status: 200,
        bytes: 48, userAgent: 'internal-monitor/1.0'
      };
      summary = srcIp + ' GET /api/health — 200 — internal-monitor/1.0';
    }

    return {
      id: source + '-noise-' + String(idCounter).padStart(3, '0'),
      timestamp: timestamp,
      source: source,
      severity: severity,
      summary: summary,
      detail: detail,
      raw: JSON.stringify(detail, null, 2),
      suspicious: false,
      evidenceId: null
    };
  }

  /* ════════════════════════════════════════════════════
     Core — Procedural.apply
     ════════════════════════════════════════════════════ */

  var Procedural = {

    /**
     * Set a seed for reproducible randomization.
     * Pass 0 or falsy to revert to Math.random().
     */
    seed: function (value) {
      if (value) {
        _seed = value >>> 0; // Ensure unsigned 32-bit
        if (_seed === 0) _seed = 1; // xorshift cannot have seed 0
        _useSeeded = true;
      } else {
        _seed = 0;
        _useSeeded = false;
      }
    },

    /**
     * Apply procedural randomization to a corpus.
     *
     * @param {Array} corpus   — array of evidence corpus entries
     * @param {Object} template — procedural config object
     * @returns {Array} — new array with randomized values
     */
    apply: function (corpus, template) {
      if (!corpus || !Array.isArray(corpus) || corpus.length === 0) return [];
      if (!template || typeof template !== 'object') return deepCopy(corpus);

      // Deep-copy the entire corpus — never modify the original
      var result = deepCopy(corpus);
      var replacements = {};

      /* ── 1. IP Replacement ──────────────────────────── */
      if (template.ips) {
        var ipKeys = Object.keys(template.ips);
        var usedIps = {};

        for (var i = 0; i < ipKeys.length; i++) {
          var originalIp = ipKeys[i];
          var ipConfig = template.ips[originalIp];
          var pool = POOLS[ipConfig.pool];

          if (!pool || pool.length === 0) continue;

          // Pick a unique replacement IP not already used
          var attempts = 0;
          var newIp;
          do {
            newIp = pick(pool);
            attempts++;
          } while (usedIps[newIp] && attempts < pool.length * 3);

          usedIps[newIp] = true;
          replacements[originalIp] = newIp;
        }
      }

      /* ── 2. Username Replacement ────────────────────── */
      if (template.usernames) {
        var userKeys = Object.keys(template.usernames);
        var usedEmails = {};

        for (var u = 0; u < userKeys.length; u++) {
          var originalUser = userKeys[u];
          var userConfig = template.usernames[originalUser];
          var emailPool = POOLS[userConfig.pool];

          if (!emailPool || emailPool.length === 0) continue;

          var uAttempts = 0;
          var newEmail;
          do {
            newEmail = pick(emailPool);
            uAttempts++;
          } while (usedEmails[newEmail] && uAttempts < emailPool.length * 3);

          usedEmails[newEmail] = true;
          replacements[originalUser] = newEmail;
        }
      }

      /* ── 3. Domain Replacement ──────────────────────── */
      if (template.domains) {
        var domainKeys = Object.keys(template.domains);

        for (var d = 0; d < domainKeys.length; d++) {
          var originalDomain = domainKeys[d];
          var domainConfig = template.domains[originalDomain];

          if (domainConfig.generator === 'dga') {
            replacements[originalDomain] = generateDGA();
          }
        }
      }

      /* ── 4. Session Token Replacement ───────────────── */
      if (template.sessions && template.sessions.pattern) {
        var pattern = template.sessions.pattern;
        var existingTokens = findSessionTokens(result, pattern);

        for (var s = 0; s < existingTokens.length; s++) {
          replacements[existingTokens[s]] = generateSessionToken(pattern);
        }
      }

      /* ── Apply all string replacements ──────────────── */
      for (var r = 0; r < result.length; r++) {
        applyReplacements(result[r], replacements);
      }

      /* ── 5. Timestamp Shift ─────────────────────────── */
      if (template.timestamps && template.timestamps.jitter_minutes) {
        var jitterRange = template.timestamps.jitter_minutes;
        var offsetMinutes = randInt(jitterRange[0], jitterRange[1]);
        var offsetMs = offsetMinutes * 60 * 1000;

        for (var t = 0; t < result.length; t++) {
          result[t].timestamp = shiftTimestamp(result[t].timestamp, offsetMs);
        }
      }

      /* ── 6. Noise Injection ─────────────────────────── */
      if (template.noise && template.noise.inject) {
        var noiseCountRange = template.noise.count || [10, 20];
        var noiseCount = randInt(noiseCountRange[0], noiseCountRange[1]);
        var noiseSources = template.noise.sources || ['web'];

        // Determine time range from existing corpus
        var firstTs = result[0] ? result[0].timestamp : '2024-01-01 00:00:00';
        var lastTs = result[result.length - 1] ? result[result.length - 1].timestamp : '2024-01-01 01:00:00';

        var firstDate = new Date(firstTs.replace(' ', 'T') + (/T/.test(firstTs) ? '' : 'Z'));
        var lastDate = new Date(lastTs.replace(' ', 'T') + (/T/.test(lastTs) ? '' : 'Z'));
        var timeSpanMs = lastDate.getTime() - firstDate.getTime();

        var noiseEntries = [];
        for (var n = 0; n < noiseCount; n++) {
          var source = pick(noiseSources);
          var randomOffsetMs = Math.floor(rng() * Math.max(timeSpanMs, 60000));
          var noiseDate = new Date(firstDate.getTime() + randomOffsetMs);

          // Format timestamp to match corpus style
          var ny = noiseDate.getUTCFullYear();
          var nmo = String(noiseDate.getUTCMonth() + 1).padStart(2, '0');
          var ndy = String(noiseDate.getUTCDate()).padStart(2, '0');
          var nhr = String(noiseDate.getUTCHours()).padStart(2, '0');
          var nmi = String(noiseDate.getUTCMinutes()).padStart(2, '0');
          var nsc = String(noiseDate.getUTCSeconds()).padStart(2, '0');
          var noiseTs = ny + '-' + nmo + '-' + ndy + ' ' + nhr + ':' + nmi + ':' + nsc;

          noiseEntries.push(generateNoiseEntry(source, noiseTs, n + 1));
        }

        // Merge noise into result maintaining chronological order
        result = result.concat(noiseEntries);
        result.sort(function (a, b) {
          if (a.timestamp < b.timestamp) return -1;
          if (a.timestamp > b.timestamp) return 1;
          return 0;
        });
      }

      return result;
    }
  };

  /* ════════════════════════════════════════════════════
     Register on namespace
     ════════════════════════════════════════════════════ */

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.Procedural = Procedural;

})();
