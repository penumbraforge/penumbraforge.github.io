/**
 * Penumbra Forge — SOAR Playbook Builder
 *
 * Visual workflow builder modelled after XSOAR/Tines playbook editors.
 * Left palette panel with draggable task cards, center canvas showing
 * a top-down flowchart with Start → Tasks → End, connected by lines.
 * Click nodes to configure, hover between to insert.
 */

(function () {
  'use strict';

  var DEFAULT_ACTIONS = [
    { category: 'Triggers',    id: 'trigger-alert',      name: 'On Alert',            param: 'Rule name',    paramDefault: 'Port Scan Detected', desc: 'Fires when a matching alert is created' },
    { category: 'Triggers',    id: 'trigger-threshold',   name: 'On Threshold',        param: 'Threshold',    paramDefault: '500 ports / 5 min', desc: 'Fires when metric exceeds threshold' },
    { category: 'Triggers',    id: 'trigger-schedule',    name: 'On Schedule',         param: 'Cron',         paramDefault: '0 3 * * 2', desc: 'Runs on a cron schedule' },
    { category: 'Triggers',    id: 'trigger-webhook',     name: 'On Webhook',          param: 'Endpoint',     paramDefault: '/api/hooks/soc', desc: 'Fires on incoming webhook' },
    { category: 'Conditions',  id: 'cond-ip-rep',         name: 'IP Reputation',       param: 'Source',       paramDefault: 'src_ip', desc: 'Branch based on IP threat score' },
    { category: 'Conditions',  id: 'cond-alert-count',    name: 'Alert Count',         param: 'Threshold',    paramDefault: '> 10 in 1h', desc: 'Branch if alert count exceeds N' },
    { category: 'Conditions',  id: 'cond-source-match',   name: 'Source Match',        param: 'Match list',   paramDefault: 'known_scanner_list', desc: 'Branch if source matches list' },
    { category: 'Conditions',  id: 'cond-severity-gate',  name: 'Severity Gate',       param: 'Min severity', paramDefault: 'high', desc: 'Branch if severity >= threshold' },
    { category: 'Conditions',  id: 'cond-geo-check',      name: 'GeoIP Gate',          param: 'Block list',   paramDefault: 'RU, CN, KP', desc: 'Branch based on geolocation' },
    { category: 'Actions',     id: 'act-block-ip',        name: 'Block IP',            param: 'Target',       paramDefault: 'src_ip', desc: 'Add IP to firewall blocklist' },
    { category: 'Actions',     id: 'act-slack-notify',    name: 'Notify Slack',        param: 'Channel',      paramDefault: '#soc-alerts', desc: 'Send notification to channel' },
    { category: 'Actions',     id: 'act-create-ticket',   name: 'Create Ticket',       param: 'Priority',     paramDefault: 'P2', desc: 'Open incident ticket' },
    { category: 'Actions',     id: 'act-quarantine',      name: 'Quarantine Host',     param: 'Target',       paramDefault: 'src_host', desc: 'Isolate host from network' },
    { category: 'Actions',     id: 'act-enable-waf',      name: 'Enable WAF Rule',     param: 'Rule ID',      paramDefault: 'block-scanner', desc: 'Activate WAF protection rule' },
    { category: 'Actions',     id: 'act-revoke-session',  name: 'Revoke Sessions',     param: 'User',         paramDefault: 'affected_user', desc: 'Terminate all user sessions' },
    { category: 'Actions',     id: 'act-log-close',       name: 'Log and Close',       param: 'Reason',       paramDefault: 'Benign scanner — auto-closed', desc: 'Close alert with reason' },
    { category: 'Enrichment',  id: 'enrich-geoip',        name: 'GeoIP Lookup',        param: 'Target',       paramDefault: 'src_ip', desc: 'Resolve IP to country/city/ASN' },
    { category: 'Enrichment',  id: 'enrich-virustotal',   name: 'VirusTotal',          param: 'Hash/URL',     paramDefault: 'file_hash', desc: 'Check hash/URL reputation' },
    { category: 'Enrichment',  id: 'enrich-whois',        name: 'WHOIS Query',         param: 'Domain',       paramDefault: 'src_domain', desc: 'Domain registration lookup' },
    { category: 'Enrichment',  id: 'enrich-shodan',       name: 'Shodan Lookup',       param: 'IP',           paramDefault: 'src_ip', desc: 'Scan for open ports/services' }
  ];

  var CATS = ['Triggers', 'Conditions', 'Enrichment', 'Actions'];
  var CAT_COLORS = { Triggers: '#f59e0b', Conditions: '#6366f1', Enrichment: '#06b6d4', Actions: '#4ade80' };

  var _container, _actions, _flow, _onSubmit, _uid, _selected, _canvasEl, _svgEl, _countEl, _resultEl;

  function id() { return 'n' + (++_uid); }
  function h(tag, cls, html) { var e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; }
  function esc(s) { return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;'); }
  function findAct(aid) { for (var i = 0; i < _actions.length; i++) { if (_actions[i].id === aid) return _actions[i]; } return null; }

  /* ═══════════════════════════════════════════════════
     Sidebar — task palette
     ═══════════════════════════════════════════════════ */

  function buildSidebar() {
    var sb = h('div', 'xpb-sidebar');

    var search = h('div', 'xpb-search');
    var input = h('input');
    input.type = 'text';
    input.placeholder = 'Search tasks...';
    input.addEventListener('input', function () {
      var q = this.value.toLowerCase();
      sb.querySelectorAll('.xpb-task').forEach(function (t) {
        t.style.display = t.textContent.toLowerCase().indexOf(q) !== -1 ? '' : 'none';
      });
    });
    search.appendChild(input);
    sb.appendChild(search);

    var list = h('div', 'xpb-task-list');
    CATS.forEach(function (cat) {
      var sec = h('div', 'xpb-cat');
      var hdr = h('div', 'xpb-cat-label');
      hdr.style.color = CAT_COLORS[cat];
      hdr.textContent = cat;
      sec.appendChild(hdr);

      _actions.filter(function (a) { return a.category === cat; }).forEach(function (act) {
        var card = h('div', 'xpb-task');
        var dot = h('span', 'xpb-dot');
        dot.style.background = CAT_COLORS[cat];
        card.appendChild(dot);

        var info = h('div', 'xpb-task-info');
        info.innerHTML = '<div class="xpb-task-name">' + esc(act.name) + '</div>' +
                         '<div class="xpb-task-desc">' + esc(act.desc || '') + '</div>';
        card.appendChild(info);

        card.addEventListener('click', function () { addNode(act.id); });
        sec.appendChild(card);
      });
      list.appendChild(sec);
    });
    sb.appendChild(list);
    return sb;
  }

  /* ═══════════════════════════════════════════════════
     Canvas — flowchart
     ═══════════════════════════════════════════════════ */

  function renderCanvas() {
    _canvasEl.innerHTML = '';

    // SVG layer for connection lines
    _svgEl = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    _svgEl.setAttribute('class', 'xpb-svg');
    _svgEl.innerHTML = '<defs><marker id="xpb-arrow" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6" fill="none" stroke="var(--border-active)" stroke-width="1"/></marker></defs>';
    _canvasEl.appendChild(_svgEl);

    // Start node
    var start = h('div', 'xpb-pill xpb-pill-start', 'START');
    _canvasEl.appendChild(start);

    // Task nodes
    _flow.forEach(function (node, idx) {
      // Insert button
      var ins = h('div', 'xpb-insert');
      ins.innerHTML = '<button class="xpb-insert-btn">+</button>';
      ins.querySelector('button').addEventListener('click', function (e) {
        e.stopPropagation();
        showInsertMenu(idx, ins);
      });
      _canvasEl.appendChild(ins);

      // Node
      var act = findAct(node.actionId);
      var cat = act ? act.category : 'Unknown';
      var color = CAT_COLORS[cat] || '#888';
      var isSelected = _selected === node.uid;

      var el = h('div', 'xpb-node' + (isSelected ? ' xpb-node-sel' : ''));
      el.setAttribute('data-uid', node.uid);

      // Accent bar
      var accent = h('div', 'xpb-accent');
      accent.style.background = color;
      el.appendChild(accent);

      // Content
      var content = h('div', 'xpb-node-body');

      // Row 1: badge + name + step # + delete
      var row1 = h('div', 'xpb-row1');
      row1.innerHTML =
        '<span class="xpb-badge" style="color:' + color + ';border-color:' + color + ';">' + cat.substring(0, 4).toUpperCase() + '</span>' +
        '<span class="xpb-name">' + esc(node.name) + '</span>' +
        '<span class="xpb-step">#' + (idx + 1) + '</span>';

      var del = h('button', 'xpb-del', '&times;');
      del.addEventListener('click', function (e) { e.stopPropagation(); removeNode(idx); });
      row1.appendChild(del);
      content.appendChild(row1);

      // Row 2: parameter preview
      var row2 = h('div', 'xpb-preview');
      row2.textContent = node.paramLabel + ': ' + node.paramValue;
      content.appendChild(row2);

      // Config panel (shown when selected)
      if (isSelected) {
        var cfg = h('div', 'xpb-config');

        var paramGroup = h('div', 'xpb-cfg-group');
        paramGroup.innerHTML = '<label>' + esc(node.paramLabel) + '</label>';
        var paramIn = h('input');
        paramIn.type = 'text';
        paramIn.value = node.paramValue;
        paramIn.addEventListener('change', function () { node.paramValue = this.value; renderCanvas(); });
        paramGroup.appendChild(paramIn);
        cfg.appendChild(paramGroup);

        if (act && act.desc) {
          var descEl = h('div', 'xpb-cfg-desc');
          descEl.textContent = act.desc;
          cfg.appendChild(descEl);
        }

        // Move buttons
        var moveRow = h('div', 'xpb-cfg-moves');
        if (idx > 0) {
          var upBtn = h('button', 'xpb-cfg-btn', 'Move Up');
          upBtn.addEventListener('click', function () { moveNode(idx, idx - 1); });
          moveRow.appendChild(upBtn);
        }
        if (idx < _flow.length - 1) {
          var downBtn = h('button', 'xpb-cfg-btn', 'Move Down');
          downBtn.addEventListener('click', function () { moveNode(idx, idx + 1); });
          moveRow.appendChild(downBtn);
        }
        cfg.appendChild(moveRow);
        content.appendChild(cfg);
      }

      el.appendChild(content);

      // Click to select/deselect
      el.addEventListener('click', function () {
        _selected = _selected === node.uid ? null : node.uid;
        renderCanvas();
      });

      _canvasEl.appendChild(el);
    });

    // Final insert button
    var lastIns = h('div', 'xpb-insert');
    lastIns.innerHTML = '<button class="xpb-insert-btn">+</button>';
    lastIns.querySelector('button').addEventListener('click', function (e) {
      e.stopPropagation();
      showInsertMenu(_flow.length, lastIns);
    });
    _canvasEl.appendChild(lastIns);

    // End node
    var end = h('div', 'xpb-pill xpb-pill-end', 'END');
    _canvasEl.appendChild(end);

    updateCount();

    // Draw SVG connections after DOM settles
    requestAnimationFrame(function () { drawConnections(); });
  }

  /* ═══════════════════════════════════════════════════
     SVG connections
     ═══════════════════════════════════════════════════ */

  function drawConnections() {
    if (!_svgEl || !_canvasEl) return;

    // Remove old paths (keep defs)
    var old = _svgEl.querySelectorAll('.xpb-line');
    for (var i = 0; i < old.length; i++) old[i].remove();

    var canvasRect = _canvasEl.getBoundingClientRect();
    var scrollTop = _canvasEl.scrollTop;

    // Collect all connectable elements in order
    var nodes = _canvasEl.querySelectorAll('.xpb-pill, .xpb-node');
    if (nodes.length < 2) return;

    // Size SVG to canvas scroll height
    _svgEl.style.height = _canvasEl.scrollHeight + 'px';

    for (var n = 0; n < nodes.length - 1; n++) {
      var from = nodes[n];
      var to = nodes[n + 1];
      var fRect = from.getBoundingClientRect();
      var tRect = to.getBoundingClientRect();

      var x1 = fRect.left + fRect.width / 2 - canvasRect.left;
      var y1 = fRect.bottom - canvasRect.top + scrollTop;
      var x2 = tRect.left + tRect.width / 2 - canvasRect.left;
      var y2 = tRect.top - canvasRect.top + scrollTop;

      var midY = (y1 + y2) / 2;

      var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('d', 'M' + x1 + ',' + y1 + ' C' + x1 + ',' + midY + ' ' + x2 + ',' + midY + ' ' + x2 + ',' + y2);
      path.setAttribute('class', 'xpb-line');
      path.setAttribute('marker-end', 'url(#xpb-arrow)');
      _svgEl.appendChild(path);
    }
  }

  /* ═══════════════════════════════════════════════════
     Insert menu (dropdown at "+" button)
     ═══════════════════════════════════════════════════ */

  function showInsertMenu(insertIdx, anchor) {
    // Close any existing
    var existing = _canvasEl.querySelector('.xpb-menu');
    if (existing) existing.remove();

    var menu = h('div', 'xpb-menu');

    CATS.forEach(function (cat) {
      var catLabel = h('div', 'xpb-menu-cat');
      catLabel.style.color = CAT_COLORS[cat];
      catLabel.textContent = cat;
      menu.appendChild(catLabel);

      _actions.filter(function (a) { return a.category === cat; }).forEach(function (act) {
        var item = h('div', 'xpb-menu-item');
        var dot = h('span', 'xpb-dot');
        dot.style.background = CAT_COLORS[cat];
        item.appendChild(dot);
        item.appendChild(document.createTextNode(act.name));
        item.addEventListener('click', function (e) {
          e.stopPropagation();
          menu.remove();
          insertNode(act.id, insertIdx);
        });
        menu.appendChild(item);
      });
    });

    anchor.appendChild(menu);

    setTimeout(function () {
      document.addEventListener('click', function closer() {
        menu.remove();
        document.removeEventListener('click', closer);
      });
    }, 0);
  }

  /* ═══════════════════════════════════════════════════
     Flow mutations
     ═══════════════════════════════════════════════════ */

  function addNode(actionId) {
    var act = findAct(actionId);
    if (!act) return;
    _flow.push({
      uid: id(), actionId: act.id, name: act.name,
      paramLabel: act.param, paramValue: act.paramDefault
    });
    _selected = null;
    renderCanvas();
    _canvasEl.scrollTop = _canvasEl.scrollHeight;
  }

  function insertNode(actionId, idx) {
    var act = findAct(actionId);
    if (!act) return;
    _flow.splice(idx, 0, {
      uid: id(), actionId: act.id, name: act.name,
      paramLabel: act.param, paramValue: act.paramDefault
    });
    renderCanvas();
  }

  function removeNode(idx) { _flow.splice(idx, 1); _selected = null; renderCanvas(); }
  function moveNode(from, to) { var item = _flow.splice(from, 1)[0]; _flow.splice(to, 0, item); renderCanvas(); }
  function updateCount() { if (_countEl) _countEl.textContent = _flow.length + ' step' + (_flow.length !== 1 ? 's' : ''); }

  /* ═══════════════════════════════════════════════════
     Test playbook
     ═══════════════════════════════════════════════════ */

  function testPlaybook() {
    if (!_resultEl) return;
    _resultEl.style.display = '';

    if (_flow.length === 0) {
      _resultEl.innerHTML = '<div class="xpb-msg xpb-msg-err">Add steps to test.</div>';
      return;
    }

    var has = { Triggers: false, Conditions: false, Actions: false, Enrichment: false };
    _flow.forEach(function (n) { var a = findAct(n.actionId); if (a) has[a.category] = true; });

    var issues = [];
    if (!has.Triggers)   issues.push('Missing trigger — playbook needs a starting condition');
    if (!has.Enrichment) issues.push('Missing enrichment — add context before decisions');
    if (!has.Conditions) issues.push('Missing condition — all alerts treated identically');
    if (!has.Actions)    issues.push('Missing action — playbook detects but doesn\'t respond');

    var score = (has.Triggers ? 25 : 0) + (has.Conditions ? 25 : 0) + (has.Actions ? 25 : 0) + (has.Enrichment ? 25 : 0);
    var cls = score >= 75 ? 'good' : score >= 50 ? 'mid' : 'low';

    var html = '<div class="xpb-result-hdr">Pipeline Test</div>';
    html += '<div class="xpb-score xpb-score-' + cls + '"><span>Coverage</span><span class="xpb-score-bar"><span style="width:' + score + '%"></span></span><span>' + score + '%</span></div>';
    if (issues.length) {
      issues.forEach(function (s) { html += '<div class="xpb-issue">' + s + '</div>'; });
    } else {
      html += '<div class="xpb-msg xpb-msg-ok">Pipeline covers all categories. Ready to submit.</div>';
    }
    _resultEl.innerHTML = html;
  }

  function getPlaybook() {
    return _flow.map(function (n) {
      var a = findAct(n.actionId);
      return { actionId: n.actionId, category: a ? a.category : 'Unknown', name: n.name, param: n.paramValue };
    });
  }

  /* ═══════════════════════════════════════════════════
     Init
     ═══════════════════════════════════════════════════ */

  function init(opts) {
    _container = opts.container;
    _actions = opts.availableActions || DEFAULT_ACTIONS;
    _onSubmit = opts.onPlaybookSubmit || null;
    _flow = [];
    _uid = 0;
    _selected = null;

    _container.innerHTML = '';

    // Build layout: sidebar | canvas area
    var wrap = h('div', 'xpb-wrap');
    wrap.appendChild(buildSidebar());

    var main = h('div', 'xpb-main');

    // Header
    var hdr = h('div', 'xpb-header');
    hdr.innerHTML = '<span class="xpb-title">Playbook</span>';
    _countEl = h('span', 'xpb-count');
    _countEl.textContent = '0 steps';
    hdr.appendChild(_countEl);
    main.appendChild(hdr);

    // Canvas
    _canvasEl = h('div', 'xpb-canvas');
    _canvasEl.addEventListener('click', function (e) {
      if (e.target === _canvasEl) { _selected = null; renderCanvas(); }
    });
    main.appendChild(_canvasEl);

    // Controls
    var ctrls = h('div', 'xpb-ctrls');
    var testBtn = h('button', 'xpb-btn xpb-btn-sec', 'Test Pipeline');
    testBtn.addEventListener('click', testPlaybook);
    var submitBtn = h('button', 'xpb-btn xpb-btn-pri', 'Submit Playbook');
    submitBtn.addEventListener('click', function () {
      var pb = getPlaybook();
      if (pb.length > 0 && _onSubmit) _onSubmit(pb);
    });
    ctrls.appendChild(testBtn);
    ctrls.appendChild(submitBtn);
    main.appendChild(ctrls);

    // Results
    _resultEl = h('div', 'xpb-results');
    _resultEl.style.display = 'none';
    main.appendChild(_resultEl);

    wrap.appendChild(main);
    _container.appendChild(wrap);

    renderCanvas();
    window.addEventListener('resize', function () { requestAnimationFrame(drawConnections); });
  }

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.PlaybookBuilder = { init: init, getPlaybook: getPlaybook };
})();
