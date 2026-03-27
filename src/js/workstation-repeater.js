/**
 * Penumbra Forge — Workstation Repeater
 *
 * Burp Suite-style HTTP request editor for crafting and sending
 * HTTP requests to the target Worker. Supports method selection,
 * custom headers, body editing, and reflected-input highlighting.
 */

(function () {
  'use strict';

  /* ════════════════════════════════════════════════════
     Helpers
     ════════════════════════════════════════════════════ */

  function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

  function extractQueryValues(url) {
    var values = [];
    try {
      var u = new URL(url);
      u.searchParams.forEach(function (val) {
        if (val && val.length > 0) {
          values.push(val);
        }
      });
    } catch (e) {
      // not a valid URL — ignore
    }
    return values;
  }

  function parseHeaderLines(text) {
    var headers = {};
    var lines = text.split('\n');
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (line.length === 0) continue;
      var colonIdx = line.indexOf(':');
      if (colonIdx > 0) {
        var name = line.substring(0, colonIdx).trim();
        var value = line.substring(colonIdx + 1).trim();
        headers[name] = value;
      }
    }
    return headers;
  }

  /* ════════════════════════════════════════════════════
     Response Highlighting
     ════════════════════════════════════════════════════ */

  function highlightHeaders(headerText) {
    var lines = headerText.split('\n');
    var result = [];
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var colonIdx = line.indexOf(':');
      if (colonIdx > 0) {
        var name = escapeHtml(line.substring(0, colonIdx));
        var value = escapeHtml(line.substring(colonIdx + 1));
        result.push('<span class="rep-header-name">' + name + '</span>:' + value);
      } else {
        result.push(escapeHtml(line));
      }
    }
    return result.join('\n');
  }

  function highlightBody(body, queryValues) {
    var escaped = escapeHtml(body);

    // Highlight HTML tags — mute them
    escaped = escaped.replace(/(&lt;\/?[a-zA-Z][^&]*?&gt;)/g, '<span style="color:#555">$1</span>');

    // Highlight reflected query values
    for (var i = 0; i < queryValues.length; i++) {
      var safeVal = escapeHtml(queryValues[i]).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      if (safeVal.length > 0) {
        var re = new RegExp('(' + safeVal + ')', 'gi');
        escaped = escaped.replace(re, '<span class="rep-vuln-highlight">$1</span>');
      }
    }

    return escaped;
  }

  /* ════════════════════════════════════════════════════
     Repeater
     ════════════════════════════════════════════════════ */

  var Repeater = {
    _container: null,
    _workerUrl: '',
    _onAction: null,
    _methodEl: null,
    _urlEl: null,
    _sendBtn: null,
    _headersEl: null,
    _bodyEl: null,
    _responsePaneBody: null,
    _sending: false,

    /**
     * Initialize the repeater.
     *
     * @param {Object}      opts
     * @param {HTMLElement}  opts.container  - DOM element to render into
     * @param {string}       opts.workerUrl  - Base URL of the target Worker
     * @param {Function}     opts.onAction   - Callback fired after each send
     */
    init: function (opts) {
      this._container = opts.container;
      this._workerUrl = (opts.workerUrl || '').replace(/\/$/, '');
      this._onAction = opts.onAction || function () {};
      this._sending = false;

      this._render();
      this._bindEvents();

      return this;
    },

    /* ── DOM Construction ── */

    _render: function () {
      this._container.innerHTML = '';
      this._container.className = (this._container.className || '').replace(/\brep-container\b/g, '').trim();
      this._container.classList.add('rep-container');

      // Toolbar
      var toolbar = document.createElement('div');
      toolbar.className = 'rep-toolbar';

      this._methodEl = document.createElement('select');
      this._methodEl.className = 'rep-method';
      var methods = ['GET', 'POST', 'PUT', 'DELETE'];
      for (var m = 0; m < methods.length; m++) {
        var opt = document.createElement('option');
        opt.value = methods[m];
        opt.textContent = methods[m];
        this._methodEl.appendChild(opt);
      }

      this._urlEl = document.createElement('input');
      this._urlEl.type = 'text';
      this._urlEl.className = 'rep-url';
      this._urlEl.value = this._workerUrl;
      this._urlEl.setAttribute('placeholder', 'https://target.example.com/path?q=test');
      this._urlEl.setAttribute('autocomplete', 'off');
      this._urlEl.setAttribute('spellcheck', 'false');

      this._sendBtn = document.createElement('button');
      this._sendBtn.className = 'rep-send';
      this._sendBtn.textContent = 'Send';

      toolbar.appendChild(this._methodEl);
      toolbar.appendChild(this._urlEl);
      toolbar.appendChild(this._sendBtn);

      // Panes container
      var panes = document.createElement('div');
      panes.className = 'rep-panes';

      // Request pane
      var reqPane = document.createElement('div');
      reqPane.className = 'rep-pane';

      var reqHeader = document.createElement('div');
      reqHeader.className = 'rep-pane-header';
      reqHeader.textContent = 'Request';

      var reqBody = document.createElement('div');
      reqBody.className = 'rep-pane-body';
      reqBody.style.padding = '8px 12px';
      reqBody.style.display = 'flex';
      reqBody.style.flexDirection = 'column';
      reqBody.style.gap = '8px';
      reqBody.style.overflow = 'auto';

      // Headers sub-section
      var headersLabel = document.createElement('div');
      headersLabel.style.fontSize = '10px';
      headersLabel.style.color = '#6366f1';
      headersLabel.style.textTransform = 'uppercase';
      headersLabel.style.letterSpacing = '0.5px';
      headersLabel.style.marginBottom = '2px';
      headersLabel.textContent = 'Headers';

      this._headersEl = document.createElement('textarea');
      this._headersEl.className = 'rep-textarea';
      this._headersEl.rows = 4;
      this._headersEl.placeholder = 'Content-Type: application/json\nAccept: */*';

      // Body sub-section
      var bodyLabel = document.createElement('div');
      bodyLabel.style.fontSize = '10px';
      bodyLabel.style.color = '#6366f1';
      bodyLabel.style.textTransform = 'uppercase';
      bodyLabel.style.letterSpacing = '0.5px';
      bodyLabel.style.marginBottom = '2px';
      bodyLabel.textContent = 'Body';

      this._bodyEl = document.createElement('textarea');
      this._bodyEl.className = 'rep-textarea';
      this._bodyEl.rows = 4;
      this._bodyEl.placeholder = '{"key": "value"}';

      reqBody.appendChild(headersLabel);
      reqBody.appendChild(this._headersEl);
      reqBody.appendChild(bodyLabel);
      reqBody.appendChild(this._bodyEl);

      reqPane.appendChild(reqHeader);
      reqPane.appendChild(reqBody);

      // Divider
      var divider = document.createElement('div');
      divider.className = 'rep-divider';

      // Response pane
      var resPane = document.createElement('div');
      resPane.className = 'rep-pane';

      var resHeader = document.createElement('div');
      resHeader.className = 'rep-pane-header';
      resHeader.textContent = 'Response';

      this._responsePaneBody = document.createElement('div');
      this._responsePaneBody.className = 'rep-pane-body';
      this._responsePaneBody.innerHTML = '<span class="rep-empty">Send a request to see the response.</span>';

      resPane.appendChild(resHeader);
      resPane.appendChild(this._responsePaneBody);

      // Assemble panes
      panes.appendChild(reqPane);
      panes.appendChild(divider);
      panes.appendChild(resPane);

      // Assemble container
      this._container.appendChild(toolbar);
      this._container.appendChild(panes);
    },

    /* ── Event Binding ── */

    _bindEvents: function () {
      var self = this;

      this._sendBtn.addEventListener('click', function () {
        self._send();
      });

      // Ctrl+Enter shortcut on the container
      this._container.addEventListener('keydown', function (e) {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
          e.preventDefault();
          self._send();
        }
      });
    },

    /* ── Send Request ── */

    _send: function () {
      if (this._sending) return;

      var method = this._methodEl.value;
      var url = this._urlEl.value.trim();

      if (url.length === 0) {
        this._showError('No URL specified.');
        return;
      }

      // Prepend workerUrl if URL doesn't start with http
      if (!/^https?:\/\//i.test(url)) {
        url = this._workerUrl + (url.charAt(0) === '/' ? '' : '/') + url;
      }

      var headerText = this._headersEl.value;
      var bodyText = this._bodyEl.value;
      var headers = parseHeaderLines(headerText);
      var queryValues = extractQueryValues(url);

      var fetchOpts = {
        method: method,
        headers: {}
      };

      var headerKeys = Object.keys(headers);
      for (var h = 0; h < headerKeys.length; h++) {
        fetchOpts.headers[headerKeys[h]] = headers[headerKeys[h]];
      }

      if ((method === 'POST' || method === 'PUT') && bodyText.trim().length > 0) {
        fetchOpts.body = bodyText;
      }

      this._sending = true;
      this._sendBtn.disabled = true;
      this._sendBtn.textContent = 'Sending...';
      this._responsePaneBody.innerHTML = '<span class="rep-empty">Sending...</span>';

      var self = this;

      fetch(url, fetchOpts)
        .then(function (response) {
          var status = response.status;
          var statusText = response.statusText;
          var responseHeaders = {};

          response.headers.forEach(function (val, name) {
            responseHeaders[name] = val;
          });

          return response.text().then(function (body) {
            return { status: status, statusText: statusText, headers: responseHeaders, body: body };
          });
        })
        .then(function (result) {
          self._sending = false;
          self._sendBtn.disabled = false;
          self._sendBtn.textContent = 'Send';

          self._renderResponse(result, queryValues);

          // Build response header string for action
          var respHeaderLines = [];
          var respHeaderKeys = Object.keys(result.headers);
          for (var r = 0; r < respHeaderKeys.length; r++) {
            respHeaderLines.push(respHeaderKeys[r] + ': ' + result.headers[respHeaderKeys[r]]);
          }

          self._onAction({
            type: 'repeater',
            method: method,
            url: url,
            headers: headers,
            body: bodyText,
            query: queryValues.join(','),
            response: {
              status: result.status,
              headers: result.headers,
              body: result.body
            }
          });
        })
        .catch(function (err) {
          self._sending = false;
          self._sendBtn.disabled = false;
          self._sendBtn.textContent = 'Send';
          self._showError('Network error: ' + (err.message || 'request failed'));

          self._onAction({
            type: 'repeater',
            method: method,
            url: url,
            headers: headers,
            body: bodyText,
            query: queryValues.join(','),
            response: {
              status: 0,
              headers: {},
              body: ''
            }
          });
        });
    },

    /* ── Render Response ── */

    _renderResponse: function (result, queryValues) {
      var html = '';

      // Status line
      html += '<div class="rep-status-line">HTTP/2 ' + escapeHtml(String(result.status)) + ' ' + escapeHtml(result.statusText) + '</div>';

      // Response headers
      var headerLines = [];
      var hdrKeys = Object.keys(result.headers);
      for (var i = 0; i < hdrKeys.length; i++) {
        headerLines.push(hdrKeys[i] + ': ' + result.headers[hdrKeys[i]]);
      }
      if (headerLines.length > 0) {
        html += '<div style="margin-bottom:8px">' + highlightHeaders(headerLines.join('\n')) + '</div>';
      }

      // Response body
      if (result.body && result.body.length > 0) {
        html += '<div>' + highlightBody(result.body, queryValues) + '</div>';
      }

      this._responsePaneBody.innerHTML = html;
    },

    /* ── Error Display ── */

    _showError: function (msg) {
      this._responsePaneBody.innerHTML = '<span style="color:#ef4444">' + escapeHtml(msg) + '</span>';
    }
  };

  /* ════════════════════════════════════════════════════
     Register on namespace
     ════════════════════════════════════════════════════ */

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.Repeater = Repeater;
})();
