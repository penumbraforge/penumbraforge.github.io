/**
 * Penumbra Forge — Timeline Builder
 *
 * Blue team SOC workstation component. Renders a chronological
 * attack timeline built by pinning events from the SIEM. Supports
 * severity-coded nodes, source tags, user-discovered flags, and
 * single-event removal.
 */

(function () {
  'use strict';

  /* ════════════════════════════════════════════════════
     Constants
     ════════════════════════════════════════════════════ */

  var SOURCE_LABEL_MAP = {
    waf:  'WAF',
    web:  'WEB',
    fw:   'FW',
    ids:  'IDS',
    auth: 'AUTH',
    dns:  'DNS'
  };

  /* ════════════════════════════════════════════════════
     Helpers
     ════════════════════════════════════════════════════ */

  function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

  /**
   * Parse a timestamp string into a comparable value.
   * Accepts ISO 8601 or "YYYY-MM-DD HH:MM:SS" format.
   * Returns the numeric epoch milliseconds, or 0 on failure.
   */
  function parseTimestampMs(ts) {
    if (!ts) return 0;
    var normalized = String(ts).replace(' ', 'T');
    var d = new Date(normalized);
    return isNaN(d.getTime()) ? 0 : d.getTime();
  }

  /* ════════════════════════════════════════════════════
     Timeline
     ════════════════════════════════════════════════════ */

  var Timeline = {
    _container: null,
    _onAction: null,
    _events: null,

    /* ════════════════════════════════════════════════════
       Public API
       ════════════════════════════════════════════════════ */

    /**
     * Initialize the timeline builder.
     *
     * @param {Object}      opts
     * @param {HTMLElement}  opts.container  - DOM element to render into
     * @param {Function}     opts.onAction   - Callback fired on timeline actions
     */
    init: function (opts) {
      this._container = opts.container;
      this._onAction = opts.onAction || function () {};
      this._events = [];

      this._render();

      return this;
    },

    /**
     * Add an event to the timeline. Auto-sorts by timestamp.
     * Fires onAction with type 'timeline_add'.
     *
     * @param {Object} evt
     * @param {string}  evt.timestamp      - Timestamp string (ISO or "YYYY-MM-DD HH:MM:SS")
     * @param {string}  evt.title          - Short event title
     * @param {string}  evt.description    - Longer description text
     * @param {string}  evt.severity       - 'critical' | 'high' | 'medium' | 'low' | 'info'
     * @param {Array}   evt.sources        - Array of source keys e.g. ['waf', 'ids']
     * @param {boolean} evt.userDiscovered - Mark as analyst-discovered finding
     */
    addEvent: function (evt) {
      if (!evt || !evt.timestamp) return;

      // Deduplicate by exact timestamp string
      for (var i = 0; i < this._events.length; i++) {
        if (this._events[i].timestamp === evt.timestamp) return;
      }

      this._events.push({
        timestamp:      evt.timestamp,
        title:          evt.title || '',
        description:    evt.description || '',
        severity:       (evt.severity || 'info').toLowerCase(),
        sources:        evt.sources || [],
        userDiscovered: !!evt.userDiscovered
      });

      // Sort chronologically
      this._events.sort(function (a, b) {
        return parseTimestampMs(a.timestamp) - parseTimestampMs(b.timestamp);
      });

      this._redraw();

      this._onAction({ type: 'timeline_add', event: evt });
    },

    /**
     * Remove an event by its exact timestamp string.
     *
     * @param {string} timestamp
     */
    removeEvent: function (timestamp) {
      var next = [];
      for (var i = 0; i < this._events.length; i++) {
        if (this._events[i].timestamp !== timestamp) {
          next.push(this._events[i]);
        }
      }
      this._events = next;
      this._redraw();
    },

    /**
     * Return a sorted copy of all events.
     *
     * @returns {Array}
     */
    getEvents: function () {
      return this._events.slice();
    },

    /**
     * Remove all events and reset to empty state.
     */
    clear: function () {
      this._events = [];
      this._redraw();
    },

    /* ════════════════════════════════════════════════════
       Rendering
       ════════════════════════════════════════════════════ */

    _render: function () {
      this._container.innerHTML = '';
      this._listEl = document.createElement('div');
      this._listEl.className = 'soc-timeline';
      this._container.appendChild(this._listEl);
      this._redraw();
    },

    _redraw: function () {
      this._listEl.innerHTML = '';

      if (this._events.length === 0) {
        var empty = document.createElement('div');
        empty.className = 'soc-tl-empty';
        empty.textContent = 'Pin events from the SIEM to build the attack timeline';
        this._listEl.appendChild(empty);
        return;
      }

      for (var i = 0; i < this._events.length; i++) {
        var node = this._buildNode(this._events[i]);
        this._listEl.appendChild(node);
      }
    },

    _buildNode: function (evt) {
      var self = this;

      var entry = document.createElement('div');
      entry.className = 'soc-tl-entry sev-' + evt.severity;
      entry.setAttribute('data-timestamp', evt.timestamp);

      // Remove button
      var removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'soc-tl-remove';
      removeBtn.title = 'Remove from timeline';
      removeBtn.textContent = '\u00d7'; // ×
      removeBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        self.removeEvent(evt.timestamp);
      });
      entry.appendChild(removeBtn);

      // Timestamp
      var tsEl = document.createElement('div');
      tsEl.className = 'soc-tl-time';
      tsEl.textContent = evt.timestamp;
      entry.appendChild(tsEl);

      // Title
      var titleEl = document.createElement('div');
      titleEl.className = 'soc-tl-title';
      titleEl.textContent = evt.title;
      entry.appendChild(titleEl);

      // Description
      if (evt.description) {
        var descEl = document.createElement('div');
        descEl.className = 'soc-tl-desc';
        descEl.textContent = evt.description;
        entry.appendChild(descEl);
      }

      // Tags row
      var tagsEl = document.createElement('div');
      tagsEl.className = 'soc-tl-tags';

      // Source tags
      for (var s = 0; s < evt.sources.length; s++) {
        var src = evt.sources[s];
        var tag = document.createElement('span');
        tag.className = 'soc-tl-tag src-' + src;
        tag.textContent = SOURCE_LABEL_MAP[src] || src.toUpperCase();
        tagsEl.appendChild(tag);
      }

      // User-discovered badge
      if (evt.userDiscovered) {
        var userTag = document.createElement('span');
        userTag.className = 'soc-tl-tag user-action';
        userTag.textContent = 'Your finding';
        tagsEl.appendChild(userTag);
      }

      if (tagsEl.childNodes.length > 0) {
        entry.appendChild(tagsEl);
      }

      return entry;
    }
  };

  /* ════════════════════════════════════════════════════
     Register on namespace
     ════════════════════════════════════════════════════ */

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.Timeline = Timeline;
})();
