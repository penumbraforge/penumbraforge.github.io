/**
 * Penumbra Forge — Workstation Terminal
 *
 * Browser-based terminal emulator for the red team workstation.
 * Parses commands, fires real HTTP requests to the target Worker
 * via fetch(), and displays syntax-highlighted output.
 */

(function () {
  'use strict';

  var HISTORY_KEY = 'pf-term-history';
  var MAX_HISTORY = 200;

  /* ════════════════════════════════════════════════════
     Helpers
     ════════════════════════════════════════════════════ */

  function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

  function extractQueryParam(url, param) {
    try {
      var u = new URL(url);
      return u.searchParams.get(param);
    } catch (e) {
      return null;
    }
  }

  function loadHistory() {
    try {
      var raw = sessionStorage.getItem(HISTORY_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch (e) {
      return [];
    }
  }

  function saveHistory(history) {
    try {
      var trimmed = history.slice(-MAX_HISTORY);
      sessionStorage.setItem(HISTORY_KEY, JSON.stringify(trimmed));
    } catch (e) {
      // sessionStorage unavailable — silently ignore
    }
  }

  /* ════════════════════════════════════════════════════
     Argument Parser
     ════════════════════════════════════════════════════

     Splits a command string into tokens, respecting
     single and double quotes.
  */

  function parseArgs(input) {
    var args = [];
    var current = '';
    var inQuote = null;

    for (var i = 0; i < input.length; i++) {
      var ch = input[i];

      if (inQuote) {
        if (ch === inQuote) {
          inQuote = null;
        } else {
          current += ch;
        }
      } else if (ch === '"' || ch === "'") {
        inQuote = ch;
      } else if (ch === ' ' || ch === '\t') {
        if (current.length > 0) {
          args.push(current);
          current = '';
        }
      } else {
        current += ch;
      }
    }

    if (current.length > 0) {
      args.push(current);
    }

    return args;
  }

  /* ════════════════════════════════════════════════════
     Curl Flag Parser
     ════════════════════════════════════════════════════ */

  function parseCurlArgs(args) {
    var opts = {
      silent: false,
      headersOnly: false,
      verbose: false,
      method: 'GET',
      headers: {},
      data: null,
      url: null
    };

    var i = 0;
    while (i < args.length) {
      var arg = args[i];

      if (arg === '-s') {
        opts.silent = true;
      } else if (arg === '-I') {
        opts.headersOnly = true;
      } else if (arg === '-v') {
        opts.verbose = true;
      } else if (arg === '-X' && i + 1 < args.length) {
        i++;
        opts.method = args[i].toUpperCase();
      } else if (arg === '-H' && i + 1 < args.length) {
        i++;
        var headerStr = args[i];
        var colonIdx = headerStr.indexOf(':');
        if (colonIdx > 0) {
          var hName = headerStr.substring(0, colonIdx).trim();
          var hVal = headerStr.substring(colonIdx + 1).trim();
          opts.headers[hName] = hVal;
        }
      } else if (arg === '-d' && i + 1 < args.length) {
        i++;
        opts.data = args[i];
        if (opts.method === 'GET') {
          opts.method = 'POST';
        }
      } else if (!arg.startsWith('-')) {
        opts.url = arg;
      }

      i++;
    }

    return opts;
  }

  /* ════════════════════════════════════════════════════
     Syntax Highlighting
     ════════════════════════════════════════════════════ */

  var SECURITY_HEADERS = [
    'x-xss-protection',
    'content-security-policy',
    'x-powered-by',
    'x-content-type-options',
    'strict-transport-security',
    'x-frame-options'
  ];

  function highlightResponseLine(line, queryValue) {
    var escaped = escapeHtml(line);

    // Header lines: "Name: Value"
    var headerMatch = line.match(/^([A-Za-z0-9-]+):\s*(.*)/);
    if (headerMatch) {
      var headerName = headerMatch[1];
      var headerVal = escapeHtml(headerMatch[2]);
      var nameClass = 'term-header-name';

      // Security-relevant headers get yellow highlight
      if (SECURITY_HEADERS.indexOf(headerName.toLowerCase()) !== -1) {
        return '<span class="term-highlight">' + escapeHtml(headerName) + ': ' + headerVal + '</span>';
      }

      return '<span class="' + nameClass + '">' + escapeHtml(headerName) + '</span>: ' + headerVal;
    }

    // HTTP status line
    if (/^HTTP\/[\d.]+\s+\d+/.test(line)) {
      return '<span class="term-success">' + escaped + '</span>';
    }

    // HTML tags — mute them
    escaped = escaped.replace(/(&lt;\/?[a-zA-Z][^&]*?&gt;)/g, '<span class="term-comment">$1</span>');

    // Reflected user input — highlight in yellow
    if (queryValue && queryValue.length > 0) {
      var safeQuery = escapeHtml(queryValue).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      if (safeQuery.length > 0) {
        var re = new RegExp('(' + safeQuery + ')', 'gi');
        escaped = escaped.replace(re, '<span class="term-highlight">$1</span>');
      }
    }

    return escaped;
  }

  /* ════════════════════════════════════════════════════
     Terminal
     ════════════════════════════════════════════════════ */

  var Terminal = {
    _container: null,
    _outputEl: null,
    _inputEl: null,
    _promptEl: null,
    _workerUrl: '',
    _onAction: null,
    _history: [],
    _historyIndex: -1,
    _lastOutput: '',

    /**
     * Initialize the terminal.
     *
     * @param {Object} opts
     * @param {HTMLElement} opts.container  - DOM element to render into
     * @param {string}      opts.workerUrl  - Base URL of the target Worker
     * @param {Function}    opts.onAction   - Callback when user takes an action
     */
    init: function (opts) {
      this._container = opts.container;
      this._workerUrl = (opts.workerUrl || '').replace(/\/$/, '');
      this._onAction = opts.onAction || function () {};
      this._history = loadHistory();
      this._historyIndex = -1;
      this._lastOutput = '';

      this._render();
      this._bindEvents();
      this._printWelcome();

      return this;
    },

    /* ── DOM Construction ── */

    _render: function () {
      this._container.innerHTML = '';
      this._container.className = (this._container.className || '').replace(/\bterm-container\b/g, '').trim();
      this._container.classList.add('term-container');

      // Output area
      this._outputEl = document.createElement('div');
      this._outputEl.className = 'term-output';

      // Input line
      var inputLine = document.createElement('div');
      inputLine.className = 'term-input-line';

      this._promptEl = document.createElement('span');
      this._promptEl.className = 'term-prompt-char';
      this._promptEl.textContent = 'forge:red $';

      this._inputEl = document.createElement('input');
      this._inputEl.type = 'text';
      this._inputEl.setAttribute('autocomplete', 'off');
      this._inputEl.setAttribute('spellcheck', 'false');
      this._inputEl.setAttribute('autocorrect', 'off');
      this._inputEl.setAttribute('autocapitalize', 'off');

      inputLine.appendChild(this._promptEl);
      inputLine.appendChild(this._inputEl);

      this._container.appendChild(this._outputEl);
      this._container.appendChild(inputLine);
    },

    /* ── Event Binding ── */

    _bindEvents: function () {
      var self = this;

      this._inputEl.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          var raw = self._inputEl.value;
          self._inputEl.value = '';
          self._historyIndex = -1;
          if (raw.trim().length > 0) {
            self._history.push(raw);
            saveHistory(self._history);
          }
          self._execute(raw.trim());
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          if (self._history.length === 0) return;
          if (self._historyIndex === -1) {
            self._historyIndex = self._history.length - 1;
          } else if (self._historyIndex > 0) {
            self._historyIndex--;
          }
          self._inputEl.value = self._history[self._historyIndex] || '';
        } else if (e.key === 'ArrowDown') {
          e.preventDefault();
          if (self._historyIndex === -1) return;
          if (self._historyIndex < self._history.length - 1) {
            self._historyIndex++;
            self._inputEl.value = self._history[self._historyIndex] || '';
          } else {
            self._historyIndex = -1;
            self._inputEl.value = '';
          }
        }
      });

      // Focus input when clicking anywhere in the terminal
      this._container.addEventListener('click', function (e) {
        if (e.target.tagName !== 'A') {
          self._inputEl.focus();
        }
      });
    },

    /* ── Welcome Message ── */

    _printWelcome: function () {
      this._appendLine('# Penumbra Forge \u2014 Attacker Workstation', 'term-comment');
      this._appendLine('# Type \'help\' for available commands', 'term-comment');
      this._appendLine('', 'term-output-text');
    },

    /* ── Output Helpers ── */

    _appendLine: function (text, cls) {
      var div = document.createElement('div');
      div.innerHTML = '<span class="' + (cls || 'term-output-text') + '">' + escapeHtml(text) + '</span>';
      this._outputEl.appendChild(div);
      this._scrollToBottom();
    },

    _appendRawLine: function (html) {
      var div = document.createElement('div');
      div.innerHTML = html;
      this._outputEl.appendChild(div);
      this._scrollToBottom();
    },

    _appendPromptLine: function (command) {
      var div = document.createElement('div');
      div.innerHTML = '<span class="term-prompt">forge:red $</span> <span class="term-command">' + escapeHtml(command) + '</span>';
      this._outputEl.appendChild(div);
      this._scrollToBottom();
    },

    _scrollToBottom: function () {
      this._outputEl.scrollTop = this._outputEl.scrollHeight;
    },

    /* ════════════════════════════════════════════════════
       Command Dispatch
       ════════════════════════════════════════════════════ */

    _execute: function (raw) {
      if (raw.length === 0) {
        this._appendPromptLine('');
        return;
      }

      this._appendPromptLine(raw);

      var tokens = parseArgs(raw);
      var cmd = tokens[0].toLowerCase();
      var args = tokens.slice(1);

      switch (cmd) {
        case 'curl':    this._cmdCurl(args, raw); break;
        case 'nmap':    this._cmdNmap(args, raw); break;
        case 'dig':     this._cmdDig(args, raw); break;
        case 'whois':   this._cmdWhois(args, raw); break;
        case 'base64':  this._cmdBase64(args, raw); break;
        case 'urlencode': this._cmdUrlencode(args, raw); break;
        case 'urldecode': this._cmdUrldecode(args, raw); break;
        case 'grep':    this._cmdGrep(args, raw); break;
        case 'echo':    this._cmdEcho(args, raw); break;
        case 'clear':   this._cmdClear(); break;
        case 'help':    this._cmdHelp(); break;
        default:
          this._appendLine(cmd + ': command not found. Type \'help\' for available commands.', 'term-error');
      }
    },

    /* ════════════════════════════════════════════════════
       curl — Real HTTP requests
       ════════════════════════════════════════════════════ */

    _cmdCurl: function (args, raw) {
      var opts = parseCurlArgs(args);

      if (!opts.url) {
        this._appendLine('curl: no URL specified', 'term-error');
        return;
      }

      // Prepend workerUrl if URL doesn't start with http
      var url = opts.url;
      if (!/^https?:\/\//i.test(url)) {
        url = this._workerUrl + (url.charAt(0) === '/' ? '' : '/') + url;
      }

      var queryValue = extractQueryParam(url, 'q');
      var self = this;

      // Build fetch options
      var fetchOpts = {
        method: opts.method,
        headers: {}
      };

      var headerKeys = Object.keys(opts.headers);
      for (var h = 0; h < headerKeys.length; h++) {
        fetchOpts.headers[headerKeys[h]] = opts.headers[headerKeys[h]];
      }

      if (opts.data) {
        fetchOpts.body = opts.data;
        if (!fetchOpts.headers['Content-Type']) {
          fetchOpts.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }
      }

      // Show request headers if verbose
      if (opts.verbose) {
        self._appendRawLine('<span class="term-comment">&gt; ' + escapeHtml(opts.method + ' ' + url) + '</span>');
        for (var rh = 0; rh < headerKeys.length; rh++) {
          self._appendRawLine('<span class="term-comment">&gt; ' + escapeHtml(headerKeys[rh] + ': ' + opts.headers[headerKeys[rh]]) + '</span>');
        }
        self._appendRawLine('<span class="term-comment">&gt;</span>');
      }

      fetch(url, fetchOpts)
        .then(function (response) {
          var status = response.status;
          var statusText = response.statusText;
          var responseHeaders = {};

          // Collect headers
          response.headers.forEach(function (val, name) {
            responseHeaders[name] = val;
          });

          return response.text().then(function (body) {
            return { status: status, statusText: statusText, headers: responseHeaders, body: body };
          });
        })
        .then(function (result) {
          var outputLines = [];

          // Status line
          if (opts.verbose || opts.headersOnly) {
            var statusLine = 'HTTP/1.1 ' + result.status + ' ' + result.statusText;
            self._appendRawLine(highlightResponseLine(statusLine, queryValue));
            outputLines.push(statusLine);
          }

          // Response headers
          if (opts.verbose || opts.headersOnly) {
            var hdrNames = Object.keys(result.headers);
            for (var i = 0; i < hdrNames.length; i++) {
              var hdrLine = hdrNames[i] + ': ' + result.headers[hdrNames[i]];
              self._appendRawLine(highlightResponseLine(hdrLine, queryValue));
              outputLines.push(hdrLine);
            }
            self._appendLine('', 'term-output-text');
            outputLines.push('');
          }

          // Body (unless -I headers-only)
          if (!opts.headersOnly) {
            var bodyLines = result.body.split('\n');
            for (var b = 0; b < bodyLines.length; b++) {
              self._appendRawLine('<span class="term-output-text">' + highlightResponseLine(bodyLines[b], queryValue) + '</span>');
              outputLines.push(bodyLines[b]);
            }
          }

          self._lastOutput = outputLines.join('\n');

          // Fire onAction
          self._onAction({
            type: 'terminal',
            command: 'curl',
            args: args,
            url: url,
            query: queryValue,
            response: {
              status: result.status,
              headers: result.headers,
              body: result.body
            }
          });
        })
        .catch(function (err) {
          self._appendLine('curl: ' + (err.message || 'network error'), 'term-error');
          self._lastOutput = '';

          self._onAction({
            type: 'terminal',
            command: 'curl',
            args: args,
            url: url,
            query: queryValue,
            response: {
              status: 0,
              headers: {},
              body: ''
            }
          });
        });
    },

    /* ════════════════════════════════════════════════════
       nmap — Simulated port scan
       ════════════════════════════════════════════════════ */

    _cmdNmap: function (args, raw) {
      var target = args[0] || this._workerUrl || 'target';

      // Strip protocol for display
      var displayTarget = target.replace(/^https?:\/\//, '').replace(/\/.*/, '');

      var lines = [
        'Starting Nmap 7.94 ( https://nmap.org )',
        'Nmap scan report for ' + displayTarget,
        'Host is up (0.023s latency).',
        '',
        'PORT     STATE   SERVICE',
        '80/tcp   open    http',
        '443/tcp  open    https',
        '8080/tcp closed  http-proxy',
        '',
        'Nmap done: 1 IP address (1 host up) scanned in 2.34 seconds'
      ];

      var self = this;
      for (var i = 0; i < lines.length; i++) {
        self._appendLine(lines[i], 'term-output-text');
      }

      this._lastOutput = lines.join('\n');

      this._onAction({
        type: 'terminal',
        command: 'nmap',
        args: args
      });
    },

    /* ════════════════════════════════════════════════════
       dig — Simulated DNS lookup
       ════════════════════════════════════════════════════ */

    _cmdDig: function (args, raw) {
      var target = args[0] || this._workerUrl || 'target';
      var displayTarget = target.replace(/^https?:\/\//, '').replace(/\/.*/, '');

      var lines = [
        '; <<>> DiG 9.18.18 <<>> ' + displayTarget,
        ';; global options: +cmd',
        ';; Got answer:',
        ';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41352',
        ';; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1',
        '',
        ';; QUESTION SECTION:',
        ';' + displayTarget + '.              IN      A',
        '',
        ';; ANSWER SECTION:',
        displayTarget + '.       300     IN      A       104.21.32.1',
        displayTarget + '.       300     IN      A       172.67.154.8',
        '',
        ';; Query time: 23 msec',
        ';; SERVER: 1.1.1.1#53(1.1.1.1) (UDP)',
        ';; WHEN: ' + new Date().toUTCString(),
        ';; MSG SIZE  rcvd: 78'
      ];

      var self = this;
      for (var i = 0; i < lines.length; i++) {
        self._appendLine(lines[i], 'term-output-text');
      }

      this._lastOutput = lines.join('\n');

      this._onAction({
        type: 'terminal',
        command: 'dig',
        args: args
      });
    },

    /* ════════════════════════════════════════════════════
       whois — Simulated WHOIS
       ════════════════════════════════════════════════════ */

    _cmdWhois: function (args, raw) {
      var target = args[0] || this._workerUrl || 'target';
      var displayTarget = target.replace(/^https?:\/\//, '').replace(/\/.*/, '');

      var lines = [
        '% WHOIS lookup for ' + displayTarget,
        '',
        'Domain Name: ' + displayTarget.toUpperCase(),
        'Registry Domain ID: 2048573921_DOMAIN',
        'Registrar WHOIS Server: whois.cloudflare.com',
        'Registrar URL: https://www.cloudflare.com',
        'Updated Date: 2024-01-15T08:30:00Z',
        'Creation Date: 2023-06-01T12:00:00Z',
        'Registrar Registration Expiration Date: 2025-06-01T12:00:00Z',
        'Registrar: Cloudflare, Inc.',
        'Registrar IANA ID: 1910',
        '',
        'Domain Status: clientTransferProhibited',
        '',
        'Name Server: ns1.cloudflare.com',
        'Name Server: ns2.cloudflare.com',
        '',
        '>>> REDACTED FOR PRIVACY <<<'
      ];

      var self = this;
      for (var i = 0; i < lines.length; i++) {
        self._appendLine(lines[i], 'term-output-text');
      }

      this._lastOutput = lines.join('\n');

      this._onAction({
        type: 'terminal',
        command: 'whois',
        args: args
      });
    },

    /* ════════════════════════════════════════════════════
       base64 — Real encode/decode
       ════════════════════════════════════════════════════ */

    _cmdBase64: function (args, raw) {
      if (args.length === 0) {
        this._appendLine('Usage: base64 <string> | base64 -d <encoded>', 'term-output-text');
        return;
      }

      var decode = false;
      var input = '';

      if (args[0] === '-d') {
        decode = true;
        input = args.slice(1).join(' ');
      } else {
        input = args.join(' ');
      }

      if (input.length === 0) {
        this._appendLine('base64: missing operand', 'term-error');
        return;
      }

      try {
        var result;
        if (decode) {
          result = atob(input);
        } else {
          result = btoa(input);
        }
        this._appendLine(result, 'term-output-text');
        this._lastOutput = result;
      } catch (e) {
        this._appendLine('base64: invalid input', 'term-error');
      }
    },

    /* ════════════════════════════════════════════════════
       urlencode / urldecode
       ════════════════════════════════════════════════════ */

    _cmdUrlencode: function (args, raw) {
      var input = args.join(' ');
      if (input.length === 0) {
        this._appendLine('Usage: urlencode <string>', 'term-output-text');
        return;
      }
      var result = encodeURIComponent(input);
      this._appendLine(result, 'term-output-text');
      this._lastOutput = result;
    },

    _cmdUrldecode: function (args, raw) {
      var input = args.join(' ');
      if (input.length === 0) {
        this._appendLine('Usage: urldecode <string>', 'term-output-text');
        return;
      }
      try {
        var result = decodeURIComponent(input);
        this._appendLine(result, 'term-output-text');
        this._lastOutput = result;
      } catch (e) {
        this._appendLine('urldecode: malformed input', 'term-error');
      }
    },

    /* ════════════════════════════════════════════════════
       grep — Filter last output
       ════════════════════════════════════════════════════ */

    _cmdGrep: function (args, raw) {
      if (args.length === 0) {
        this._appendLine('Usage: grep <pattern>', 'term-output-text');
        return;
      }

      var pattern = args[0];
      var flags = 'i';

      if (this._lastOutput.length === 0) {
        this._appendLine('grep: no previous output to filter', 'term-error');
        return;
      }

      try {
        var re = new RegExp(pattern, flags);
        var lines = this._lastOutput.split('\n');
        var matched = [];

        for (var i = 0; i < lines.length; i++) {
          if (re.test(lines[i])) {
            // Highlight the match
            var highlighted = escapeHtml(lines[i]).replace(
              new RegExp('(' + escapeHtml(pattern).replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi'),
              '<span class="term-highlight">$1</span>'
            );
            this._appendRawLine('<span class="term-output-text">' + highlighted + '</span>');
            matched.push(lines[i]);
          }
        }

        if (matched.length === 0) {
          this._appendLine('(no matches)', 'term-comment');
        }

        this._lastOutput = matched.join('\n');
      } catch (e) {
        this._appendLine('grep: invalid pattern: ' + pattern, 'term-error');
      }
    },

    /* ════════════════════════════════════════════════════
       echo
       ════════════════════════════════════════════════════ */

    _cmdEcho: function (args, raw) {
      var text = args.join(' ');
      this._appendLine(text, 'term-output-text');
      this._lastOutput = text;
    },

    /* ════════════════════════════════════════════════════
       clear
       ════════════════════════════════════════════════════ */

    _cmdClear: function () {
      this._outputEl.innerHTML = '';
      this._lastOutput = '';
    },

    /* ════════════════════════════════════════════════════
       help
       ════════════════════════════════════════════════════ */

    _cmdHelp: function () {
      var cmds = [
        ['curl <url>', 'Make HTTP requests to the target (supports -s, -I, -X, -H, -d, -v)'],
        ['nmap [target]', 'Scan target ports (simulated)'],
        ['dig [target]', 'DNS lookup (simulated)'],
        ['whois [target]', 'WHOIS lookup (simulated)'],
        ['base64 <string>', 'Base64 encode (use -d to decode)'],
        ['urlencode <string>', 'URL-encode a string'],
        ['urldecode <string>', 'URL-decode a string'],
        ['grep <pattern>', 'Filter last command output by regex'],
        ['echo <text>', 'Echo text to terminal'],
        ['clear', 'Clear terminal output'],
        ['help', 'Show this help message']
      ];

      this._appendLine('Available commands:', 'term-success');
      this._appendLine('', 'term-output-text');

      for (var i = 0; i < cmds.length; i++) {
        var padded = cmds[i][0];
        while (padded.length < 26) padded += ' ';
        this._appendRawLine(
          '<span class="term-command">  ' + escapeHtml(padded) + '</span>' +
          '<span class="term-output-text">' + escapeHtml(cmds[i][1]) + '</span>'
        );
      }

      this._appendLine('', 'term-output-text');
      this._lastOutput = '';
    }
  };

  /* ════════════════════════════════════════════════════
     Register on namespace
     ════════════════════════════════════════════════════ */

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.Terminal = Terminal;
})();
