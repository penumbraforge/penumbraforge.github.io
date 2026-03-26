/**
 * Penumbra Forge — SIEM Log Viewer
 *
 * Blue team SOC workstation component. Renders a searchable,
 * filterable log stream from an evidence corpus. Supports KQL-like
 * search, source/severity/time filters, expandable detail panels,
 * and investigation actions (pivot, evidence, IOC lookup, timeline).
 */

(function () {
  'use strict';

  /* ════════════════════════════════════════════════════
     Constants
     ════════════════════════════════════════════════════ */

  var SOURCES = [
    { key: 'all', label: 'All Sources' },
    { key: 'waf', label: 'WAF' },
    { key: 'web', label: 'Web Server' },
    { key: 'fw',  label: 'Firewall' },
    { key: 'ids', label: 'IDS/IPS' },
    { key: 'auth', label: 'Auth' },
    { key: 'dns', label: 'DNS' }
  ];

  var SEVERITIES = [
    { key: 'critical', label: 'CRIT', cls: 'sev-crit' },
    { key: 'high',     label: 'HIGH', cls: 'sev-high' },
    { key: 'medium',   label: 'MED',  cls: 'sev-med' },
    { key: 'low',      label: 'LOW',  cls: 'sev-low' },
    { key: 'info',     label: 'INFO', cls: 'sev-info' }
  ];

  var TIME_RANGES = [
    { key: '1h',  label: 'Last 1h',  ms: 60 * 60 * 1000 },
    { key: '4h',  label: 'Last 4h',  ms: 4 * 60 * 60 * 1000 },
    { key: '24h', label: 'Last 24h', ms: 24 * 60 * 60 * 1000 },
    { key: 'all', label: 'All',      ms: 0 }
  ];

  var SOURCE_DOT_MAP = {
    waf:  'waf',
    web:  'web',
    fw:   'fw',
    ids:  'ids',
    auth: 'auth',
    dns:  'dns'
  };

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

  function stripHtml(str) {
    var tmp = document.createElement('div');
    tmp.innerHTML = str;
    return tmp.textContent || tmp.innerText || '';
  }

  /**
   * Parse a timestamp string into a Date object.
   * Accepts ISO 8601 or "YYYY-MM-DD HH:MM:SS" format.
   */
  function parseTimestamp(ts) {
    if (!ts) return null;
    // Replace space between date and time with T for reliable parsing
    var normalized = String(ts).replace(' ', 'T');
    var d = new Date(normalized);
    return isNaN(d.getTime()) ? null : d;
  }

  /**
   * Compute the latest timestamp in the corpus to use as
   * the reference point for time-range filtering (simulates
   * "now" within the incident window).
   */
  function computeMaxTimestamp(corpus) {
    var max = 0;
    for (var i = 0; i < corpus.length; i++) {
      var d = parseTimestamp(corpus[i].timestamp);
      if (d && d.getTime() > max) {
        max = d.getTime();
      }
    }
    return max || Date.now();
  }

  /**
   * Simple JSON syntax highlighting for the raw block.
   * Wraps keys in blue, strings in green, numbers in orange,
   * booleans/null in purple.
   */
  function highlightJson(raw) {
    var escaped = escapeHtml(raw);
    // Keys
    escaped = escaped.replace(
      /(&quot;)([\w.$-]+?)(&quot;)\s*:/g,
      '<span style="color:#60a5fa">$1$2$3</span>:'
    );
    // String values (after colon)
    escaped = escaped.replace(
      /:\s*(&quot;)(.*?)(&quot;)/g,
      ': <span style="color:#4ade80">$1$2$3</span>'
    );
    // Numbers
    escaped = escaped.replace(
      /:\s*(\d+\.?\d*)/g,
      ': <span style="color:#f59e0b">$1</span>'
    );
    // Booleans and null
    escaped = escaped.replace(
      /\b(true|false|null)\b/g,
      '<span style="color:#a78bfa">$1</span>'
    );
    return escaped;
  }

  /* ════════════════════════════════════════════════════
     SIEM Log Viewer
     ════════════════════════════════════════════════════ */

  var SIEM = {
    _container: null,
    _corpus: null,
    _onAction: null,
    _maxTs: 0,

    /* ── Filter state ── */
    _searchText: '',
    _sourceFilter: 'all',
    _activeSeverities: null,
    _timeRange: 'all',
    _pivotIp: null,

    /* ── DOM refs ── */
    _toolbarEl: null,
    _searchInput: null,
    _sourceSelect: null,
    _severityBtns: null,
    _timeSelect: null,
    _countEl: null,
    _streamEl: null,
    _expandedId: null,

    /* ════════════════════════════════════════════════════
       init
       ════════════════════════════════════════════════════ */

    /**
     * Initialize the SIEM log viewer.
     *
     * @param {Object}      opts
     * @param {HTMLElement}  opts.container       - DOM element to render into
     * @param {Array}        opts.evidenceCorpus  - Array of log entry objects
     * @param {Function}     opts.onAction        - Callback for investigation actions
     */
    init: function (opts) {
      this._container = opts.container;
      this._corpus = opts.evidenceCorpus || [];
      this._onAction = opts.onAction || function () {};

      this._searchText = '';
      this._sourceFilter = 'all';
      this._timeRange = 'all';
      this._pivotIp = null;
      this._expandedId = null;

      // All severities active by default
      this._activeSeverities = {};
      for (var i = 0; i < SEVERITIES.length; i++) {
        this._activeSeverities[SEVERITIES[i].key] = true;
      }

      this._maxTs = computeMaxTimestamp(this._corpus);

      this._render();
      this._bindEvents();
      this._applyFilters();

      return this;
    },

    /* ════════════════════════════════════════════════════
       DOM Construction
       ════════════════════════════════════════════════════ */

    _render: function () {
      this._container.innerHTML = '';

      // Toolbar
      this._toolbarEl = document.createElement('div');
      this._toolbarEl.className = 'siem-toolbar';

      // Search group: source dropdown + text input + search button
      var searchGroup = document.createElement('div');
      searchGroup.className = 'siem-search';

      this._sourceSelect = document.createElement('select');
      this._sourceSelect.className = 'siem-search-source';
      for (var s = 0; s < SOURCES.length; s++) {
        var opt = document.createElement('option');
        opt.value = SOURCES[s].key;
        opt.textContent = SOURCES[s].label;
        this._sourceSelect.appendChild(opt);
      }

      this._searchInput = document.createElement('input');
      this._searchInput.type = 'text';
      this._searchInput.className = 'siem-search-input';
      this._searchInput.placeholder = 'Search logs (KQL-like: ip, path, keyword...)';
      this._searchInput.setAttribute('autocomplete', 'off');
      this._searchInput.setAttribute('spellcheck', 'false');

      var searchBtn = document.createElement('button');
      searchBtn.className = 'siem-search-btn';
      searchBtn.textContent = 'Search';
      searchBtn.type = 'button';

      searchGroup.appendChild(this._sourceSelect);
      searchGroup.appendChild(this._searchInput);
      searchGroup.appendChild(searchBtn);

      this._toolbarEl.appendChild(searchGroup);

      // Severity filter buttons
      var filtersDiv = document.createElement('div');
      filtersDiv.className = 'siem-filters';
      this._severityBtns = {};

      for (var sv = 0; sv < SEVERITIES.length; sv++) {
        var sev = SEVERITIES[sv];
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'siem-filter-btn ' + sev.cls + ' active';
        btn.textContent = sev.label;
        btn.setAttribute('data-severity', sev.key);
        filtersDiv.appendChild(btn);
        this._severityBtns[sev.key] = btn;
      }

      this._toolbarEl.appendChild(filtersDiv);

      // Time range
      this._timeSelect = document.createElement('select');
      this._timeSelect.className = 'siem-timerange';
      for (var t = 0; t < TIME_RANGES.length; t++) {
        var topt = document.createElement('option');
        topt.value = TIME_RANGES[t].key;
        topt.textContent = TIME_RANGES[t].label;
        this._timeSelect.appendChild(topt);
      }
      this._toolbarEl.appendChild(this._timeSelect);

      // Result count
      this._countEl = document.createElement('span');
      this._countEl.className = 'siem-count';
      this._countEl.textContent = 'showing 0 of 0 entries';
      this._toolbarEl.appendChild(this._countEl);

      this._container.appendChild(this._toolbarEl);

      // Log stream
      this._streamEl = document.createElement('div');
      this._streamEl.className = 'soc-log-stream';
      this._container.appendChild(this._streamEl);
    },

    /* ════════════════════════════════════════════════════
       Event Binding
       ════════════════════════════════════════════════════ */

    _bindEvents: function () {
      var self = this;

      // Search input — filter on Enter
      this._searchInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          self._pivotIp = null;
          self._searchText = self._searchInput.value;
          self._applyFilters();
        }
      });

      // Search button
      var searchBtn = this._toolbarEl.querySelector('.siem-search-btn');
      searchBtn.addEventListener('click', function () {
        self._pivotIp = null;
        self._searchText = self._searchInput.value;
        self._applyFilters();
      });

      // Source dropdown
      this._sourceSelect.addEventListener('change', function () {
        self._sourceFilter = self._sourceSelect.value;
        self._applyFilters();
      });

      // Severity toggles
      var filterBtns = this._toolbarEl.querySelectorAll('.siem-filter-btn[data-severity]');
      for (var i = 0; i < filterBtns.length; i++) {
        filterBtns[i].addEventListener('click', function () {
          var sev = this.getAttribute('data-severity');
          self._activeSeverities[sev] = !self._activeSeverities[sev];
          if (self._activeSeverities[sev]) {
            this.classList.add('active');
          } else {
            this.classList.remove('active');
          }
          self._applyFilters();
        });
      }

      // Time range
      this._timeSelect.addEventListener('change', function () {
        self._timeRange = self._timeSelect.value;
        self._applyFilters();
      });
    },

    /* ════════════════════════════════════════════════════
       Filtering Logic
       ════════════════════════════════════════════════════ */

    _applyFilters: function () {
      var filtered = [];
      var total = this._corpus.length;
      var searchLower = this._searchText.toLowerCase();

      // Determine the time-range cutoff
      var timeCutoff = 0;
      if (this._timeRange !== 'all') {
        for (var t = 0; t < TIME_RANGES.length; t++) {
          if (TIME_RANGES[t].key === this._timeRange) {
            timeCutoff = this._maxTs - TIME_RANGES[t].ms;
            break;
          }
        }
      }

      for (var i = 0; i < total; i++) {
        var entry = this._corpus[i];

        // Source filter
        if (this._sourceFilter !== 'all' && entry.source !== this._sourceFilter) {
          continue;
        }

        // Severity filter (entry.severity must match an active toggle)
        var sevKey = (entry.severity || '').toLowerCase();
        if (!this._activeSeverities[sevKey]) {
          continue;
        }

        // Time range filter
        if (timeCutoff > 0) {
          var entryTs = parseTimestamp(entry.timestamp);
          if (entryTs && entryTs.getTime() < timeCutoff) {
            continue;
          }
        }

        // Pivot IP override
        if (this._pivotIp) {
          var matchesPivot = false;
          var plainSummary = stripHtml(entry.summary || '').toLowerCase();
          if (plainSummary.indexOf(this._pivotIp) !== -1) matchesPivot = true;
          if (entry.detail) {
            if ((entry.detail.srcIp || '').toLowerCase() === this._pivotIp) matchesPivot = true;
            if ((entry.detail.dstIp || '').toLowerCase() === this._pivotIp) matchesPivot = true;
          }
          if (!matchesPivot) continue;
        }

        // Search text filter
        if (searchLower.length > 0 && !this._pivotIp) {
          var haystack = '';
          haystack += stripHtml(entry.summary || '').toLowerCase() + ' ';
          if (entry.detail) {
            haystack += (entry.detail.srcIp || '').toLowerCase() + ' ';
            haystack += (entry.detail.dstIp || '').toLowerCase() + ' ';
            haystack += (entry.detail.path || '').toLowerCase() + ' ';
          }
          if (haystack.indexOf(searchLower) === -1) {
            continue;
          }
        }

        filtered.push(entry);
      }

      this._renderStream(filtered);
      this._countEl.textContent = 'showing ' + filtered.length + ' of ' + total + ' entries';
    },

    /* ════════════════════════════════════════════════════
       Log Stream Rendering
       ════════════════════════════════════════════════════ */

    _renderStream: function (entries) {
      this._streamEl.innerHTML = '';
      this._expandedId = null;

      for (var i = 0; i < entries.length; i++) {
        var entry = entries[i];
        var row = this._buildRow(entry);
        this._streamEl.appendChild(row);
      }
    },

    _buildRow: function (entry) {
      var self = this;
      var wrapper = document.createElement('div');

      // Entry row
      var row = document.createElement('div');
      row.className = 'soc-log-entry';
      if (entry.suspicious) {
        row.classList.add('suspicious');
      }
      row.setAttribute('data-entry-id', entry.id);

      // Timestamp
      var tsEl = document.createElement('span');
      tsEl.className = 'soc-log-ts';
      tsEl.textContent = entry.timestamp || '';

      // Source indicator
      var sourceEl = document.createElement('span');
      sourceEl.className = 'soc-log-source';

      var dot = document.createElement('span');
      var dotClass = SOURCE_DOT_MAP[entry.source] || 'web';
      dot.className = 'soc-source-dot ' + dotClass;

      var sourceName = document.createElement('span');
      sourceName.className = 'soc-source-name';
      sourceName.textContent = SOURCE_LABEL_MAP[entry.source] || entry.source.toUpperCase();

      sourceEl.appendChild(dot);
      sourceEl.appendChild(sourceName);

      // Severity badge
      var sevEl = document.createElement('span');
      sevEl.className = 'soc-log-sev';
      var sevBadge = document.createElement('span');
      var sevNorm = (entry.severity || 'info').toLowerCase();
      sevBadge.className = 'soc-sev-badge soc-sev-' + sevNorm;
      sevBadge.textContent = sevNorm.toUpperCase();
      sevEl.appendChild(sevBadge);

      // Message summary
      var msgEl = document.createElement('span');
      msgEl.className = 'soc-log-msg';
      msgEl.innerHTML = this._highlightSummary(entry.summary || '');

      row.appendChild(tsEl);
      row.appendChild(sourceEl);
      row.appendChild(sevEl);
      row.appendChild(msgEl);

      wrapper.appendChild(row);

      // Click handler for expand/collapse
      row.addEventListener('click', function () {
        var existingDetail = wrapper.querySelector('.soc-log-detail');
        if (existingDetail) {
          wrapper.removeChild(existingDetail);
          row.classList.remove('expanded');
          self._expandedId = null;
        } else {
          // Collapse any previously expanded entry
          self._collapseAll();
          var detail = self._buildDetail(entry);
          wrapper.appendChild(detail);
          row.classList.add('expanded');
          self._expandedId = entry.id;
        }
      });

      return wrapper;
    },

    /**
     * Highlight IPs, paths, and alert keywords in the summary line.
     */
    _highlightSummary: function (summary) {
      var text = escapeHtml(summary);
      // IPs
      text = text.replace(
        /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g,
        '<span class="soc-ip">$1</span>'
      );
      // Paths (anything starting with /)
      text = text.replace(
        /(\/[^\s,;]+)/g,
        '<span class="soc-path">$1</span>'
      );
      // Alert keywords
      text = text.replace(
        /\b(DETECTED|BLOCKED|ALERT|CRITICAL|DENIED|FAILED|ATTACK)\b/gi,
        '<span class="soc-alert">$1</span>'
      );
      return text;
    },

    _collapseAll: function () {
      var expanded = this._streamEl.querySelectorAll('.soc-log-entry.expanded');
      for (var i = 0; i < expanded.length; i++) {
        expanded[i].classList.remove('expanded');
        var detail = expanded[i].parentNode.querySelector('.soc-log-detail');
        if (detail) {
          detail.parentNode.removeChild(detail);
        }
      }
    },

    /* ════════════════════════════════════════════════════
       Expandable Entry Detail
       ════════════════════════════════════════════════════ */

    _buildDetail: function (entry) {
      var self = this;
      var detail = document.createElement('div');
      detail.className = 'soc-log-detail';

      // Detail grid
      var grid = document.createElement('div');
      grid.className = 'soc-detail-grid';

      var fields = [];
      if (entry.detail) {
        if (entry.detail.srcIp)     fields.push(['Source IP', entry.detail.srcIp]);
        if (entry.detail.dstIp)     fields.push(['Destination', entry.detail.dstIp + (entry.detail.dstPort ? ':' + entry.detail.dstPort : '')]);
        if (entry.detail.method)    fields.push(['Method', entry.detail.method]);
        if (entry.detail.path)      fields.push(['Path', entry.detail.path]);
        if (entry.detail.rule)      fields.push(['Rule', entry.detail.rule]);
        if (entry.detail.action)    fields.push(['Action', entry.detail.action]);
        if (entry.detail.userAgent) fields.push(['User Agent', entry.detail.userAgent]);
        if (entry.detail.geo) {
          var geo = entry.detail.geo;
          var geoParts = [];
          if (geo.country) geoParts.push(geo.country);
          if (geo.city) geoParts.push(geo.city);
          if (geo.asn) geoParts.push(geo.asn);
          fields.push(['Geo', geoParts.join(' / ')]);
        }
      }

      for (var f = 0; f < fields.length; f++) {
        var keyEl = document.createElement('span');
        keyEl.className = 'soc-detail-key';
        keyEl.textContent = fields[f][0];

        var valEl = document.createElement('span');
        valEl.className = 'soc-detail-val';
        valEl.textContent = fields[f][1];

        grid.appendChild(keyEl);
        grid.appendChild(valEl);
      }

      detail.appendChild(grid);

      // Raw JSON block
      if (entry.raw) {
        var rawBlock = document.createElement('div');
        rawBlock.className = 'soc-detail-raw';
        rawBlock.innerHTML = highlightJson(entry.raw);
        detail.appendChild(rawBlock);
      }

      // Action buttons
      var actionsRow = document.createElement('div');
      actionsRow.className = 'soc-log-actions';

      var pivotBtn = this._createActionBtn('Pivot on IP', function () {
        var ip = (entry.detail && entry.detail.srcIp) ? entry.detail.srcIp : '';
        if (!ip) return;
        self._pivotIp = ip.toLowerCase();
        self._searchInput.value = 'ip:' + ip;
        self._sourceSelect.value = 'all';
        self._sourceFilter = 'all';
        self._applyFilters();
        self._onAction({
          type: 'siem_action',
          action: 'pivot',
          entry: entry
        });
      });

      var evidenceBtn = this._createActionBtn('Add to Evidence', function () {
        self._onAction({
          type: 'siem_action',
          action: 'evidence',
          entry: entry
        });
      });

      var iocBtn = this._createActionBtn('Lookup in Threat Intel', function () {
        var ip = (entry.detail && entry.detail.srcIp) ? entry.detail.srcIp : '';
        self._onAction({
          type: 'siem_action',
          action: 'ioc_lookup',
          entry: entry,
          ip: ip
        });
      });

      var timelineBtn = this._createActionBtn('Pin to Timeline', function () {
        self._onAction({
          type: 'siem_action',
          action: 'timeline',
          entry: entry,
          summary: entry.timestamp + ' — ' + (entry.summary || '')
        });
      });

      actionsRow.appendChild(pivotBtn);
      actionsRow.appendChild(evidenceBtn);
      actionsRow.appendChild(iocBtn);
      actionsRow.appendChild(timelineBtn);

      detail.appendChild(actionsRow);

      return detail;
    },

    _createActionBtn: function (label, handler) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'soc-action-btn';
      btn.textContent = label;
      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        handler();
      });
      return btn;
    }
  };

  /* ════════════════════════════════════════════════════
     Register on namespace
     ════════════════════════════════════════════════════ */

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.SIEM = SIEM;
})();
