/**
 * Penumbra Forge — Workstation Decoder
 *
 * Encoding/decoding utility supporting URL, Base64, Hex, and HTML entities.
 * All operations are performed client-side with native browser APIs.
 */

(function () {
  'use strict';

  /* ════════════════════════════════════════════════════
     Operations
     ════════════════════════════════════════════════════ */

  var operations = {
    'URL Encode': function (input) {
      return encodeURIComponent(input);
    },

    'URL Decode': function (input) {
      return decodeURIComponent(input);
    },

    'Base64 Enc': function (input) {
      // Handle multi-byte characters via TextEncoder
      var bytes = new TextEncoder().encode(input);
      var binary = '';
      for (var i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    },

    'Base64 Dec': function (input) {
      var binary = atob(input.trim());
      var bytes = new Uint8Array(binary.length);
      for (var i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return new TextDecoder().decode(bytes);
    },

    'Hex Enc': function (input) {
      var result = '';
      for (var i = 0; i < input.length; i++) {
        var code = input.charCodeAt(i);
        result += ('0' + code.toString(16)).slice(-2);
      }
      return result;
    },

    'Hex Dec': function (input) {
      var hex = input.replace(/\s/g, '');
      var result = '';
      for (var i = 0; i < hex.length; i += 2) {
        result += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
      }
      return result;
    },

    'HTML Entities': function (input) {
      return input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
    },

    'HTML Decode': function (input) {
      return input
        .replace(/&#x27;/g, "'")
        .replace(/&quot;/g, '"')
        .replace(/&gt;/g, '>')
        .replace(/&lt;/g, '<')
        .replace(/&amp;/g, '&');
    }
  };

  /* ════════════════════════════════════════════════════
     Decoder
     ════════════════════════════════════════════════════ */

  var Decoder = {
    _container: null,
    _inputEl: null,
    _outputEl: null,

    /**
     * Initialize the decoder tool.
     *
     * @param {Object}      opts
     * @param {HTMLElement}  opts.container  - DOM element to render into
     */
    init: function (opts) {
      this._container = opts.container;

      this._render();
      this._bindEvents();

      return this;
    },

    /* ── DOM Construction ── */

    _render: function () {
      this._container.innerHTML = '';
      this._container.className = (this._container.className || '').replace(/\bdec-container\b/g, '').trim();
      this._container.classList.add('dec-container');

      // Input textarea
      this._inputEl = document.createElement('textarea');
      this._inputEl.className = 'dec-textarea';
      this._inputEl.placeholder = 'Paste or type input here…';
      this._inputEl.setAttribute('spellcheck', 'false');
      this._inputEl.setAttribute('autocomplete', 'off');

      // Button row
      var btnRow = document.createElement('div');
      btnRow.className = 'dec-buttons';

      var self = this;
      var opNames = Object.keys(operations);
      for (var i = 0; i < opNames.length; i++) {
        (function (name) {
          var btn = document.createElement('button');
          btn.className = 'dec-btn';
          btn.textContent = name;
          btn.addEventListener('click', function () {
            self._runOp(name);
          });
          btnRow.appendChild(btn);
        })(opNames[i]);
      }

      // Output header row
      var outputHeader = document.createElement('div');
      outputHeader.className = 'dec-output-header';

      var outputLabel = document.createElement('span');
      outputLabel.className = 'dec-output-label';
      outputLabel.textContent = 'Output';

      var copyBtn = document.createElement('button');
      copyBtn.className = 'dec-copy';
      copyBtn.textContent = 'Copy';
      copyBtn.addEventListener('click', function () {
        self._copy();
      });

      outputHeader.appendChild(outputLabel);
      outputHeader.appendChild(copyBtn);

      // Output textarea
      this._outputEl = document.createElement('textarea');
      this._outputEl.className = 'dec-textarea';
      this._outputEl.setAttribute('readonly', '');
      this._outputEl.setAttribute('spellcheck', 'false');
      this._outputEl.placeholder = 'Result will appear here…';

      // Assemble
      this._container.appendChild(this._inputEl);
      this._container.appendChild(btnRow);
      this._container.appendChild(outputHeader);
      this._container.appendChild(this._outputEl);
    },

    /* ── Operations ── */

    _runOp: function (name) {
      var input = this._inputEl.value;
      var fn = operations[name];
      if (!fn) return;

      try {
        this._outputEl.value = fn(input);
        this._outputEl.style.color = '';
      } catch (e) {
        this._outputEl.value = 'Error: ' + (e.message || String(e));
        this._outputEl.style.color = '#ef4444';
      }
    },

    _copy: function () {
      var text = this._outputEl.value;
      if (!text) return;

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(function () {
          // silent failure
        });
      } else {
        this._outputEl.select();
        document.execCommand('copy');
      }
    },

    /* ── Event Binding ── */

    _bindEvents: function () {
      // Ctrl+Enter shortcut: re-run last op? Not applicable here since
      // we have discrete op buttons. Nothing to bind beyond what's in render.
    }
  };

  /* ════════════════════════════════════════════════════
     Register on namespace
     ════════════════════════════════════════════════════ */

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.Decoder = Decoder;
})();
