/**
 * Penumbra Forge — IOC Lookup
 *
 * Blue team SOC workstation component. Provides threat intelligence
 * lookups for IPv4 addresses and domains against a known IOC corpus.
 * Displays reputation, score, geo, ASN, associations, tags, and
 * maintains a lookup history (most recent first, max 10).
 */

(function () {
  'use strict';

  /* ════════════════════════════════════════════════════
     Constants
     ════════════════════════════════════════════════════ */

  var HISTORY_MAX = 10;

  var SCORE_BAR_COLORS = {
    malicious: '#ef4444',
    suspicious: '#f59e0b',
    clean:      '#4ade80',
    unknown:    '#6b7280'
  };

  /* ════════════════════════════════════════════════════
     Helpers
     ════════════════════════════════════════════════════ */

  function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
  }

  function repClass(reputation) {
    if (!reputation) return 'unknown';
    return reputation.toLowerCase();
  }

  /* ════════════════════════════════════════════════════
     IOCLookup
     ════════════════════════════════════════════════════ */

  var IOCLookup = {
    _container: null,
    _knownIOCs: null,
    _onAction:  null,
    _history:   null,

    // DOM refs
    _inputEl:      null,
    _resultsEl:    null,
    _historyListEl: null,

    /* ════════════════════════════════════════════════════
       Public API
       ════════════════════════════════════════════════════ */

    /**
     * Initialize the IOC lookup tool.
     *
     * @param {Object}      opts
     * @param {HTMLElement}  opts.container   - DOM element to render into
     * @param {Object}       opts.knownIOCs   - Indicator → result map
     * @param {Function}     opts.onAction    - Callback fired on each lookup
     */
    init: function (opts) {
      this._container = opts.container;
      this._knownIOCs = opts.knownIOCs || {};
      this._onAction  = opts.onAction  || function () {};
      this._history   = [];

      this._render();

      return this;
    },

    /**
     * Perform a lookup and display results.
     *
     * @param {string} indicator - IP address or domain to look up
     */
    lookup: function (indicator) {
      if (!indicator) return;

      var trimmed = indicator.trim();
      if (!trimmed) return;

      var result = this._knownIOCs[trimmed] || null;

      this._displayResult(trimmed, result);
      this._addToHistory(trimmed, result);

      this._onAction({
        type:      'ioc_lookup',
        indicator: trimmed,
        result:    result
      });
    },

    /* ════════════════════════════════════════════════════
       Rendering
       ════════════════════════════════════════════════════ */

    _render: function () {
      this._container.innerHTML = '';

      var wrap = document.createElement('div');
      wrap.className = 'soc-ioc-container';

      // ── Search row ──
      var searchRow = document.createElement('div');
      searchRow.className = 'soc-ioc-search';

      this._inputEl = document.createElement('input');
      this._inputEl.type        = 'text';
      this._inputEl.className   = 'soc-ioc-input';
      this._inputEl.placeholder = 'IP address or domain…';
      this._inputEl.setAttribute('spellcheck', 'false');
      this._inputEl.setAttribute('autocomplete', 'off');

      var btn = document.createElement('button');
      btn.type      = 'button';
      btn.className = 'soc-ioc-btn';
      btn.textContent = 'Lookup';

      searchRow.appendChild(this._inputEl);
      searchRow.appendChild(btn);
      wrap.appendChild(searchRow);

      // ── Results area ──
      this._resultsEl = document.createElement('div');
      this._resultsEl.className = 'soc-ioc-results';
      wrap.appendChild(this._resultsEl);

      // ── History section ──
      var histSection = document.createElement('div');
      histSection.className = 'soc-ioc-history';

      var histTitle = document.createElement('div');
      histTitle.className   = 'soc-ioc-history-title';
      histTitle.textContent = 'Lookup History';

      this._historyListEl = document.createElement('div');
      this._historyListEl.className = 'soc-ioc-history-list';

      histSection.appendChild(histTitle);
      histSection.appendChild(this._historyListEl);
      wrap.appendChild(histSection);

      this._container.appendChild(wrap);

      // ── Events ──
      var self = this;

      btn.addEventListener('click', function () {
        self.lookup(self._inputEl.value);
        self._inputEl.value = '';
        self._inputEl.focus();
      });

      this._inputEl.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          self.lookup(self._inputEl.value);
          self._inputEl.value = '';
        }
      });
    },

    _displayResult: function (indicator, result) {
      this._resultsEl.innerHTML = '';

      var card = document.createElement('div');
      card.className = 'soc-ioc-result';

      if (!result) {
        // Unknown indicator
        var header = document.createElement('div');
        header.className = 'soc-ioc-indicator';
        header.textContent = indicator;
        card.appendChild(header);

        var empty = document.createElement('div');
        empty.className   = 'soc-ioc-empty';
        empty.textContent = 'No threat intelligence available for this indicator.';
        card.appendChild(empty);

        this._resultsEl.appendChild(card);
        return;
      }

      // ── Indicator + badges row ──
      var indicatorRow = document.createElement('div');
      indicatorRow.className = 'soc-ioc-indicator';

      var indicatorText = document.createTextNode(indicator + '\u00a0');
      indicatorRow.appendChild(indicatorText);

      var typeBadge = document.createElement('span');
      typeBadge.className   = 'soc-ioc-type-badge';
      typeBadge.textContent = result.type || 'Unknown';
      indicatorRow.appendChild(typeBadge);

      var repBadge = document.createElement('span');
      repBadge.className   = 'soc-ioc-rep ' + repClass(result.reputation);
      repBadge.textContent = result.reputation || 'Unknown';
      indicatorRow.appendChild(repBadge);

      card.appendChild(indicatorRow);

      // ── Score bar ──
      if (typeof result.score === 'number') {
        var scoreWrap = document.createElement('div');
        scoreWrap.style.cssText = 'margin:6px 0 4px;';

        var scoreLabel = document.createElement('div');
        scoreLabel.style.cssText = 'font-size:9px; color:#555; margin-bottom:3px;';
        scoreLabel.textContent   = 'Threat Score: ' + result.score + ' / 100';
        scoreWrap.appendChild(scoreLabel);

        var scoreTrack = document.createElement('div');
        scoreTrack.style.cssText = 'height:4px; background:#1e1e2e; border-radius:2px; overflow:hidden;';

        var scoreFill = document.createElement('div');
        var color = SCORE_BAR_COLORS[repClass(result.reputation)] || '#6b7280';
        scoreFill.style.cssText = 'height:100%; border-radius:2px; background:' + color + '; width:' + Math.min(100, Math.max(0, result.score)) + '%;';

        scoreTrack.appendChild(scoreFill);
        scoreWrap.appendChild(scoreTrack);
        card.appendChild(scoreWrap);
      }

      // ── Detail grid ──
      var grid = document.createElement('div');
      grid.className = 'soc-ioc-grid';

      var fields = [
        ['Geo',        result.geo       || '—'],
        ['ASN',        result.asn       || '—'],
        ['First Seen', result.firstSeen || '—'],
        ['Last Seen',  result.lastSeen  || '—']
      ];

      for (var f = 0; f < fields.length; f++) {
        var keyEl = document.createElement('div');
        keyEl.className   = 'soc-ioc-key';
        keyEl.textContent = fields[f][0];

        var valEl = document.createElement('div');
        valEl.className   = 'soc-ioc-val';
        valEl.textContent = fields[f][1];

        grid.appendChild(keyEl);
        grid.appendChild(valEl);
      }

      card.appendChild(grid);

      // ── Associations ──
      if (result.associations && result.associations.length) {
        var assocKeyEl = document.createElement('div');
        assocKeyEl.style.cssText  = 'font-size:9px; color:#555; margin-top:8px; margin-bottom:3px; text-transform:uppercase; letter-spacing:0.5px;';
        assocKeyEl.textContent    = 'Associations';
        card.appendChild(assocKeyEl);

        for (var a = 0; a < result.associations.length; a++) {
          var assocItem = document.createElement('div');
          assocItem.style.cssText  = 'font-size:10px; color:#c8ccd4; padding:1px 0; padding-left:8px; border-left:2px solid #1e1e2e;';
          assocItem.textContent    = result.associations[a];
          card.appendChild(assocItem);
        }
      }

      // ── Tags ──
      if (result.tags && result.tags.length) {
        var tagsRow = document.createElement('div');
        tagsRow.className = 'soc-ioc-tags';

        for (var t = 0; t < result.tags.length; t++) {
          var tagEl = document.createElement('span');
          tagEl.className   = 'soc-ioc-tag';
          tagEl.textContent = result.tags[t];
          tagsRow.appendChild(tagEl);
        }

        card.appendChild(tagsRow);
      }

      this._resultsEl.appendChild(card);
    },

    _addToHistory: function (indicator, result) {
      // Prevent duplicates — remove previous entry for same indicator
      var next = [];
      for (var i = 0; i < this._history.length; i++) {
        if (this._history[i].indicator !== indicator) {
          next.push(this._history[i]);
        }
      }
      next.unshift({ indicator: indicator, result: result });

      // Cap at max
      if (next.length > HISTORY_MAX) {
        next = next.slice(0, HISTORY_MAX);
      }

      this._history = next;
      this._redrawHistory();
    },

    _redrawHistory: function () {
      this._historyListEl.innerHTML = '';

      if (this._history.length === 0) {
        return;
      }

      var self = this;

      for (var i = 0; i < this._history.length; i++) {
        (function (entry) {
          var row = document.createElement('div');
          row.style.cssText = 'display:flex; align-items:center; gap:8px; padding:3px 0; cursor:pointer; border-bottom:1px solid #111119;';

          var rep = entry.result ? repClass(entry.result.reputation) : 'unknown';
          var dot = document.createElement('span');
          dot.style.cssText = 'width:6px; height:6px; border-radius:50%; flex-shrink:0; background:' +
            (SCORE_BAR_COLORS[rep] || '#6b7280') + ';';

          var label = document.createElement('span');
          label.style.cssText  = 'font-size:10px; color:#8b8fa3; flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;';
          label.textContent    = entry.indicator;

          var repLabel = document.createElement('span');
          repLabel.style.cssText  = 'font-size:9px; color:' + (SCORE_BAR_COLORS[rep] || '#6b7280') + '; flex-shrink:0;';
          repLabel.textContent    = entry.result ? (entry.result.reputation || 'Unknown') : 'Unknown';

          row.appendChild(dot);
          row.appendChild(label);
          row.appendChild(repLabel);

          row.addEventListener('click', function () {
            self._displayResult(entry.indicator, entry.result);
          });

          self._historyListEl.appendChild(row);
        }(this._history[i]));
      }
    }
  };

  /* ════════════════════════════════════════════════════
     Register on namespace
     ════════════════════════════════════════════════════ */

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.IOCLookup = IOCLookup;
}());
