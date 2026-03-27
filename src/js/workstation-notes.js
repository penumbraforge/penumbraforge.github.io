/**
 * Penumbra Forge — Workstation Notes
 *
 * Persistent scratch-pad scoped to a lab. Content is saved automatically
 * to localStorage with a 500ms debounce after the last keystroke.
 */

(function () {
  'use strict';

  /* ════════════════════════════════════════════════════
     Notes
     ════════════════════════════════════════════════════ */

  var Notes = {
    _container: null,
    _labId: '',
    _textareaEl: null,
    _footerEl: null,
    _saveTimer: null,

    /**
     * Initialize the notes tool.
     *
     * @param {Object}      opts
     * @param {HTMLElement}  opts.container  - DOM element to render into
     * @param {string}       opts.labId      - Lab identifier for localStorage key
     */
    init: function (opts) {
      this._container = opts.container;
      this._labId = opts.labId || 'default';
      this._saveTimer = null;

      this._render();
      this._load();
      this._bindEvents();

      return this;
    },

    /* ── DOM Construction ── */

    _render: function () {
      this._container.innerHTML = '';
      this._container.className = (this._container.className || '').replace(/\bnotes-container\b/g, '').trim();
      this._container.classList.add('notes-container');

      // Full-height textarea
      this._textareaEl = document.createElement('textarea');
      this._textareaEl.className = 'notes-textarea';
      this._textareaEl.placeholder = 'Scratch pad — notes auto-save to this browser.';
      this._textareaEl.setAttribute('spellcheck', 'false');
      this._textareaEl.setAttribute('autocomplete', 'off');

      // Footer with character count
      this._footerEl = document.createElement('div');
      this._footerEl.className = 'notes-footer';
      this._footerEl.textContent = '0 chars';

      this._container.appendChild(this._textareaEl);
      this._container.appendChild(this._footerEl);
    },

    /* ── Persistence ── */

    _storageKey: function () {
      return 'pf-notes-' + this._labId;
    },

    _load: function () {
      var saved = '';
      try {
        saved = localStorage.getItem(this._storageKey()) || '';
      } catch (e) {
        // localStorage unavailable — ignore
      }
      this._textareaEl.value = saved;
      this._updateCount();
    },

    _save: function () {
      try {
        localStorage.setItem(this._storageKey(), this._textareaEl.value);
      } catch (e) {
        // localStorage full or unavailable — ignore
      }
    },

    _scheduleSave: function () {
      var self = this;
      if (this._saveTimer !== null) {
        clearTimeout(this._saveTimer);
      }
      this._saveTimer = setTimeout(function () {
        self._saveTimer = null;
        self._save();
      }, 500);
    },

    /* ── Character Count ── */

    _updateCount: function () {
      var len = this._textareaEl.value.length;
      this._footerEl.textContent = len.toLocaleString() + (len === 1 ? ' char' : ' chars');
    },

    /* ── Event Binding ── */

    _bindEvents: function () {
      var self = this;

      this._textareaEl.addEventListener('input', function () {
        self._updateCount();
        self._scheduleSave();
      });
    }
  };

  /* ════════════════════════════════════════════════════
     Register on namespace
     ════════════════════════════════════════════════════ */

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.Notes = Notes;
})();
