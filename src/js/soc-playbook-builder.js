/**
 * Penumbra Forge — SOAR Playbook Builder
 *
 * Professional playbook designer. Top toolbar with categorised action
 * buttons, scrollable pipeline canvas below. Users click toolbar actions
 * to append steps, configure parameters inline, reorder/remove, test
 * the pipeline logic, and submit.
 */

(function () {
  'use strict';

  var DEFAULT_ACTIONS = [
    { category: 'Triggers',    id: 'trigger-alert',      name: 'On Alert',            param: 'Rule name',    paramDefault: 'Port Scan Detected' },
    { category: 'Triggers',    id: 'trigger-threshold',   name: 'On Threshold',        param: 'Threshold',    paramDefault: '500 ports / 5 min' },
    { category: 'Triggers',    id: 'trigger-schedule',    name: 'On Schedule',         param: 'Cron',         paramDefault: '0 3 * * 2' },
    { category: 'Triggers',    id: 'trigger-webhook',     name: 'On Webhook',          param: 'Endpoint',     paramDefault: '/api/hooks/soc' },
    { category: 'Conditions',  id: 'cond-ip-rep',         name: 'IP Reputation',       param: 'Source',       paramDefault: 'src_ip' },
    { category: 'Conditions',  id: 'cond-alert-count',    name: 'Alert Count > N',     param: 'Threshold',    paramDefault: '> 10 in 1h' },
    { category: 'Conditions',  id: 'cond-source-match',   name: 'Source Match',        param: 'Match list',   paramDefault: 'known_scanner_list' },
    { category: 'Conditions',  id: 'cond-severity-gate',  name: 'Severity Gate',       param: 'Min severity', paramDefault: 'high' },
    { category: 'Conditions',  id: 'cond-geo-check',      name: 'GeoIP Gate',          param: 'Block list',   paramDefault: 'RU, CN, KP' },
    { category: 'Actions',     id: 'act-block-ip',        name: 'Block IP',            param: 'Target',       paramDefault: 'src_ip' },
    { category: 'Actions',     id: 'act-slack-notify',    name: 'Notify Slack',        param: 'Channel',      paramDefault: '#soc-alerts' },
    { category: 'Actions',     id: 'act-create-ticket',   name: 'Create Ticket',       param: 'Priority',     paramDefault: 'P2' },
    { category: 'Actions',     id: 'act-quarantine',      name: 'Quarantine Host',     param: 'Target',       paramDefault: 'src_host' },
    { category: 'Actions',     id: 'act-enable-waf',      name: 'Enable WAF Rule',     param: 'Rule ID',      paramDefault: 'block-scanner' },
    { category: 'Actions',     id: 'act-revoke-session',  name: 'Revoke Sessions',     param: 'User',         paramDefault: 'affected_user' },
    { category: 'Actions',     id: 'act-log-close',       name: 'Log and Close',       param: 'Reason',       paramDefault: 'Benign scanner — auto-closed' },
    { category: 'Enrichment',  id: 'enrich-geoip',        name: 'GeoIP Lookup',        param: 'Target',       paramDefault: 'src_ip' },
    { category: 'Enrichment',  id: 'enrich-virustotal',   name: 'VirusTotal',          param: 'Hash/URL',     paramDefault: 'file_hash' },
    { category: 'Enrichment',  id: 'enrich-whois',        name: 'WHOIS Query',         param: 'Domain',       paramDefault: 'src_domain' },
    { category: 'Enrichment',  id: 'enrich-shodan',       name: 'Shodan Lookup',       param: 'IP',           paramDefault: 'src_ip' }
  ];

  var CATEGORY_ORDER = ['Triggers', 'Conditions', 'Enrichment', 'Actions'];

  var CATEGORY_COLORS = {
    'Triggers':   '#f59e0b',
    'Conditions': '#6366f1',
    'Enrichment': '#06b6d4',
    'Actions':    '#4ade80'
  };

  var _container = null;
  var _actions = [];
  var _flow = [];
  var _onSubmit = null;
  var _uidCounter = 0;
  var _flowEl = null;
  var _countEl = null;

  function uid() { return 'pb-' + (++_uidCounter); }

  function el(tag, cls, html) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html !== undefined) e.innerHTML = html;
    return e;
  }

  function findAction(id) {
    for (var i = 0; i < _actions.length; i++) {
      if (_actions[i].id === id) return _actions[i];
    }
    return null;
  }

  function escAttr(s) { return (s || '').replace(/"/g, '&quot;').replace(/</g, '&lt;'); }

  function updateCount() {
    if (_countEl) _countEl.textContent = _flow.length + ' step' + (_flow.length !== 1 ? 's' : '');
  }

  /* ════════════════════════════════════════════════════
     Render — Toolbar (horizontal, top)
     ════════════════════════════════════════════════════ */

  function buildToolbar() {
    var toolbar = el('div', 'pb-toolbar');

    CATEGORY_ORDER.forEach(function (cat) {
      var group = el('div', 'pb-toolbar-group');

      var label = el('span', 'pb-toolbar-label');
      label.textContent = cat;
      label.style.color = CATEGORY_COLORS[cat] || 'var(--text-3)';
      group.appendChild(label);

      var items = _actions.filter(function (a) { return a.category === cat; });
      items.forEach(function (action) {
        var btn = el('button', 'pb-toolbar-btn');
        btn.textContent = action.name;
        btn.title = action.param + ': ' + action.paramDefault;
        btn.style.borderColor = CATEGORY_COLORS[cat] || 'var(--border)';
        btn.addEventListener('click', function () { addNode(action.id); });
        btn.addEventListener('mouseenter', function () {
          btn.style.color = CATEGORY_COLORS[cat];
          btn.style.borderColor = CATEGORY_COLORS[cat];
        });
        btn.addEventListener('mouseleave', function () {
          btn.style.color = '';
          btn.style.borderColor = CATEGORY_COLORS[cat] || 'var(--border)';
        });
        group.appendChild(btn);
      });

      toolbar.appendChild(group);
    });

    return toolbar;
  }

  /* ════════════════════════════════════════════════════
     Render — Pipeline Flow
     ════════════════════════════════════════════════════ */

  function renderFlow() {
    if (!_flowEl) return;
    _flowEl.innerHTML = '';
    updateCount();

    if (_flow.length === 0) {
      _flowEl.innerHTML =
        '<div class="pb-empty">' +
          '<div class="pb-empty-title">Empty pipeline</div>' +
          '<div class="pb-empty-desc">Click actions in the toolbar above to build your automation playbook.</div>' +
        '</div>';
      return;
    }

    _flow.forEach(function (node, idx) {
      var action = findAction(node.actionId);
      var cat = action ? action.category : 'Unknown';
      var color = CATEGORY_COLORS[cat] || 'var(--text-3)';

      // Connector
      if (idx > 0) {
        var conn = el('div', 'pb-connector');
        conn.innerHTML = '<div class="pb-connector-line"></div>';
        _flowEl.appendChild(conn);
      }

      // Node
      var nodeEl = el('div', 'pb-node');
      nodeEl.style.borderLeftColor = color;

      // Step number
      var num = el('div', 'pb-step-num');
      num.textContent = String(idx + 1);
      num.style.color = color;
      nodeEl.appendChild(num);

      // Body
      var body = el('div', 'pb-node-body');

      // Header row
      var header = el('div', 'pb-node-header');
      var tag = el('span', 'pb-node-tag');
      tag.textContent = cat.toUpperCase();
      tag.style.color = color;
      tag.style.borderColor = color;
      header.appendChild(tag);
      var name = el('span', 'pb-node-name');
      name.textContent = node.name;
      header.appendChild(name);
      body.appendChild(header);

      // Param
      var paramRow = el('div', 'pb-node-param');
      var paramLabel = el('span', 'pb-node-plabel');
      paramLabel.textContent = node.paramLabel + ':';
      paramRow.appendChild(paramLabel);
      var paramInput = el('input', 'pb-node-pinput');
      paramInput.type = 'text';
      paramInput.value = node.paramValue;
      paramInput.setAttribute('data-uid', node.uid);
      paramInput.addEventListener('change', function () {
        var u = this.getAttribute('data-uid');
        for (var i = 0; i < _flow.length; i++) {
          if (_flow[i].uid === u) { _flow[i].paramValue = this.value; break; }
        }
      });
      paramRow.appendChild(paramInput);
      body.appendChild(paramRow);

      nodeEl.appendChild(body);

      // Controls
      var ctrls = el('div', 'pb-node-ctrls');
      if (idx > 0) {
        var up = el('button', 'pb-cbtn', '&#x2191;');
        up.title = 'Move up';
        up.addEventListener('click', function () { moveNode(idx, idx - 1); });
        ctrls.appendChild(up);
      }
      if (idx < _flow.length - 1) {
        var down = el('button', 'pb-cbtn', '&#x2193;');
        down.title = 'Move down';
        down.addEventListener('click', function () { moveNode(idx, idx + 1); });
        ctrls.appendChild(down);
      }
      var rm = el('button', 'pb-cbtn pb-cbtn-rm', '&#x00D7;');
      rm.title = 'Remove';
      rm.addEventListener('click', function () { removeNode(idx); });
      ctrls.appendChild(rm);

      nodeEl.appendChild(ctrls);
      _flowEl.appendChild(nodeEl);
    });
  }

  /* ════════════════════════════════════════════════════
     Mutations
     ════════════════════════════════════════════════════ */

  function addNode(actionId) {
    var action = findAction(actionId);
    if (!action) return;
    _flow.push({
      uid: uid(),
      actionId: action.id,
      name: action.name,
      paramLabel: action.param,
      paramValue: action.paramDefault
    });
    renderFlow();
    // Scroll to bottom
    if (_flowEl) _flowEl.scrollTop = _flowEl.scrollHeight;
  }

  function removeNode(idx) { _flow.splice(idx, 1); renderFlow(); }
  function moveNode(from, to) { var item = _flow.splice(from, 1)[0]; _flow.splice(to, 0, item); renderFlow(); }

  /* ════════════════════════════════════════════════════
     Test
     ════════════════════════════════════════════════════ */

  function testPlaybook(resultEl) {
    resultEl.innerHTML = '';
    if (_flow.length === 0) {
      resultEl.innerHTML = '<div class="pb-rmsg pb-rmsg-err">Add steps to the pipeline first.</div>';
      return;
    }

    var has = { Triggers: false, Conditions: false, Actions: false, Enrichment: false };
    var steps = [];
    _flow.forEach(function (node) {
      var action = findAction(node.actionId);
      if (action) has[action.category] = true;
      steps.push({ cat: action ? action.category : '?', name: node.name, param: node.paramValue });
    });

    var html = '<div class="pb-rhead">Execution Trace</div><div class="pb-rtrace">';
    steps.forEach(function (s, i) {
      html += '<div class="pb-rstep">' +
        '<span class="pb-rnum" style="color:' + (CATEGORY_COLORS[s.cat] || '') + '">' + (i + 1) + '</span>' +
        '<span class="pb-rname">' + s.name + '</span>' +
        '<span class="pb-rparam">' + escAttr(s.param) + '</span>' +
        '<span class="pb-rok">PASS</span></div>';
    });
    html += '</div>';

    var issues = [];
    if (!has.Triggers)   issues.push('No trigger. The playbook needs a starting condition.');
    if (!has.Enrichment) issues.push('No enrichment. Add context before making decisions.');
    if (!has.Conditions) issues.push('No condition gate. All alerts get the same treatment.');
    if (!has.Actions)    issues.push('No response action. The playbook detects but does nothing.');

    if (issues.length) {
      html += '<div class="pb-rhead" style="margin-top:8px">Issues</div>';
      issues.forEach(function (s) { html += '<div class="pb-rissue">' + s + '</div>'; });
    }

    var score = (has.Triggers ? 25 : 0) + (has.Conditions ? 25 : 0) + (has.Actions ? 25 : 0) + (has.Enrichment ? 25 : 0);
    var cls = score >= 75 ? 'good' : score >= 50 ? 'mid' : 'low';
    html += '<div class="pb-rscore pb-rscore-' + cls + '">' +
      '<span class="pb-rscore-lbl">Coverage</span>' +
      '<span class="pb-rscore-bar"><span class="pb-rscore-fill" style="width:' + score + '%"></span></span>' +
      '<span class="pb-rscore-val">' + score + '%</span></div>';

    resultEl.innerHTML = html;
  }

  function getPlaybook() {
    return _flow.map(function (node) {
      var action = findAction(node.actionId);
      return { actionId: node.actionId, category: action ? action.category : 'Unknown', name: node.name, param: node.paramValue };
    });
  }

  /* ════════════════════════════════════════════════════
     Init
     ════════════════════════════════════════════════════ */

  function init(opts) {
    _container = opts.container;
    _actions = opts.availableActions || DEFAULT_ACTIONS;
    _onSubmit = opts.onPlaybookSubmit || null;
    _flow = [];
    _uidCounter = 0;

    _container.innerHTML = '';
    _container.classList.add('pb-container');

    // Toolbar (top, fixed height)
    _container.appendChild(buildToolbar());

    // Pipeline header
    var pipeHeader = el('div', 'pb-pipe-header');
    pipeHeader.innerHTML = '<span class="pb-pipe-title">Pipeline</span>';
    _countEl = el('span', 'pb-pipe-count');
    _countEl.textContent = '0 steps';
    pipeHeader.appendChild(_countEl);
    _container.appendChild(pipeHeader);

    // Flow canvas (scrollable, fills remaining space)
    _flowEl = el('div', 'pb-flow');
    renderFlow();
    _container.appendChild(_flowEl);

    // Bottom bar (fixed)
    var bottom = el('div', 'pb-bottom');
    var resultArea = el('div', 'pb-results');

    var testBtn = el('button', 'pb-btn pb-btn-sec', 'Test Pipeline');
    testBtn.addEventListener('click', function () { testPlaybook(resultArea); });

    var submitBtn = el('button', 'pb-btn pb-btn-pri', 'Submit Playbook');
    submitBtn.addEventListener('click', function () {
      var pb = getPlaybook();
      if (pb.length === 0) return;
      if (_onSubmit) _onSubmit(pb);
    });

    var btnRow = el('div', 'pb-btn-row');
    btnRow.appendChild(testBtn);
    btnRow.appendChild(submitBtn);
    bottom.appendChild(btnRow);
    bottom.appendChild(resultArea);
    _container.appendChild(bottom);
  }

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.PlaybookBuilder = { init: init, getPlaybook: getPlaybook };
})();
