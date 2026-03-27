/**
 * Penumbra Forge — SOAR Playbook Builder
 *
 * Professional playbook designer for building automated incident response
 * workflows. Users construct trigger-condition-action-enrichment pipelines
 * from categorised steps, configure parameters, test execution logic,
 * and submit the final playbook for scoring.
 *
 * Modelled on real SOAR platforms (Splunk SOAR, Palo Alto XSOAR, Tines).
 */

(function () {
  'use strict';

  /* ════════════════════════════════════════════════════
     Action Catalogue
     ════════════════════════════════════════════════════ */

  var DEFAULT_ACTIONS = [
    // Triggers — what starts the playbook
    { category: 'Triggers',    id: 'trigger-alert',      name: 'On Alert',              param: 'Rule name',   paramDefault: 'Port Scan Detected' },
    { category: 'Triggers',    id: 'trigger-threshold',   name: 'On Threshold',          param: 'Threshold',   paramDefault: '500 ports / 5 min' },
    { category: 'Triggers',    id: 'trigger-schedule',    name: 'On Schedule',           param: 'Cron',        paramDefault: '0 3 * * 2' },
    { category: 'Triggers',    id: 'trigger-webhook',     name: 'On Webhook',            param: 'Endpoint',    paramDefault: '/api/hooks/soc' },
    // Conditions — decision gates
    { category: 'Conditions',  id: 'cond-ip-rep',         name: 'IP Reputation Check',   param: 'Source',      paramDefault: 'src_ip' },
    { category: 'Conditions',  id: 'cond-alert-count',    name: 'Alert Count > N',       param: 'Threshold',   paramDefault: '> 10 in 1h' },
    { category: 'Conditions',  id: 'cond-source-match',   name: 'Source Match',          param: 'Match list',  paramDefault: 'known_scanner_list' },
    { category: 'Conditions',  id: 'cond-severity-gate',  name: 'Severity Gate',         param: 'Min severity', paramDefault: 'high' },
    { category: 'Conditions',  id: 'cond-geo-check',      name: 'GeoIP Gate',            param: 'Block list',  paramDefault: 'RU, CN, KP' },
    // Actions — response steps
    { category: 'Actions',     id: 'act-block-ip',        name: 'Block IP at Firewall',  param: 'Target',      paramDefault: 'src_ip' },
    { category: 'Actions',     id: 'act-slack-notify',    name: 'Notify via Slack',      param: 'Channel',     paramDefault: '#soc-alerts' },
    { category: 'Actions',     id: 'act-create-ticket',   name: 'Create Jira Ticket',    param: 'Priority',    paramDefault: 'P2' },
    { category: 'Actions',     id: 'act-quarantine',      name: 'Quarantine Host',       param: 'Target',      paramDefault: 'src_host' },
    { category: 'Actions',     id: 'act-enable-waf',      name: 'Enable WAF Rule',       param: 'Rule ID',     paramDefault: 'block-scanner' },
    { category: 'Actions',     id: 'act-revoke-session',  name: 'Revoke Sessions',       param: 'User',        paramDefault: 'affected_user' },
    { category: 'Actions',     id: 'act-log-close',       name: 'Log and Close',         param: 'Reason',      paramDefault: 'Benign scanner — auto-closed' },
    // Enrichment — context gathering
    { category: 'Enrichment',  id: 'enrich-geoip',        name: 'GeoIP Lookup',          param: 'Target',      paramDefault: 'src_ip' },
    { category: 'Enrichment',  id: 'enrich-virustotal',   name: 'VirusTotal Lookup',     param: 'Hash/URL',    paramDefault: 'file_hash' },
    { category: 'Enrichment',  id: 'enrich-whois',        name: 'WHOIS Query',           param: 'Domain',      paramDefault: 'src_domain' },
    { category: 'Enrichment',  id: 'enrich-shodan',       name: 'Shodan Host Lookup',    param: 'IP',          paramDefault: 'src_ip' }
  ];

  var CATEGORY_ORDER = ['Triggers', 'Conditions', 'Enrichment', 'Actions'];

  var CATEGORY_COLORS = {
    'Triggers':   { text: '#f59e0b', bg: 'rgba(245,158,11,0.08)', border: 'rgba(245,158,11,0.25)' },
    'Conditions': { text: '#6366f1', bg: 'rgba(99,102,241,0.08)', border: 'rgba(99,102,241,0.25)' },
    'Enrichment': { text: '#06b6d4', bg: 'rgba(6,182,212,0.08)', border: 'rgba(6,182,212,0.25)' },
    'Actions':    { text: '#4ade80', bg: 'rgba(74,222,128,0.08)', border: 'rgba(74,222,128,0.25)' }
  };

  /* ════════════════════════════════════════════════════
     State
     ════════════════════════════════════════════════════ */

  var _container = null;
  var _actions = [];
  var _flow = [];
  var _onSubmit = null;
  var _uidCounter = 0;
  var _flowEl = null;

  /* ════════════════════════════════════════════════════
     Helpers
     ════════════════════════════════════════════════════ */

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

  function getCategoryTag(category) {
    var c = CATEGORY_COLORS[category] || { text: '#8b8fa3', bg: 'rgba(139,143,163,0.08)', border: 'rgba(139,143,163,0.25)' };
    return '<span class="pb-cat-tag" style="color:' + c.text + ';background:' + c.bg + ';border:1px solid ' + c.border + ';">' + category.toUpperCase() + '</span>';
  }

  /* ════════════════════════════════════════════════════
     Render — Palette (left sidebar)
     ════════════════════════════════════════════════════ */

  function renderPalette(paletteEl) {
    paletteEl.innerHTML = '';
    var grouped = {};
    _actions.forEach(function (a) {
      if (!grouped[a.category]) grouped[a.category] = [];
      grouped[a.category].push(a);
    });

    CATEGORY_ORDER.forEach(function (cat) {
      if (!grouped[cat]) return;
      var c = CATEGORY_COLORS[cat] || {};
      var section = el('div', 'pb-palette-section');

      var header = el('div', 'pb-palette-header');
      header.style.color = c.text || 'var(--text-2)';
      header.textContent = cat;
      section.appendChild(header);

      grouped[cat].forEach(function (action) {
        var card = el('div', 'pb-action-card');
        card.setAttribute('data-action-id', action.id);
        card.setAttribute('draggable', 'true');

        var catDot = el('span', 'pb-card-dot');
        catDot.style.background = c.text || '#8b8fa3';
        card.appendChild(catDot);

        var nameSpan = el('span', 'pb-card-name');
        nameSpan.textContent = action.name;
        card.appendChild(nameSpan);

        // Click to add
        card.addEventListener('click', function () { addNode(action.id); });

        // Drag support
        card.addEventListener('dragstart', function (e) {
          e.dataTransfer.setData('text/plain', action.id);
          e.dataTransfer.effectAllowed = 'copy';
          card.classList.add('pb-dragging');
        });
        card.addEventListener('dragend', function () {
          card.classList.remove('pb-dragging');
        });

        section.appendChild(card);
      });

      paletteEl.appendChild(section);
    });
  }

  /* ════════════════════════════════════════════════════
     Render — Flow (main canvas)
     ════════════════════════════════════════════════════ */

  function renderFlow() {
    if (!_flowEl) return;
    _flowEl.innerHTML = '';

    if (_flow.length === 0) {
      var emptyState = el('div', 'pb-empty');
      emptyState.innerHTML =
        '<div class="pb-empty-title">No steps defined</div>' +
        '<div class="pb-empty-desc">Click or drag actions from the sidebar to build your automation pipeline.</div>';
      _flowEl.appendChild(emptyState);
      return;
    }

    _flow.forEach(function (node, idx) {
      var action = findAction(node.actionId);
      var cat = action ? action.category : 'Unknown';
      var colors = CATEGORY_COLORS[cat] || {};

      // Connector line between nodes
      if (idx > 0) {
        var connector = el('div', 'pb-connector');
        var connLine = el('div', 'pb-connector-line');
        connector.appendChild(connLine);
        _flowEl.appendChild(connector);
      }

      // Node
      var nodeEl = el('div', 'pb-node');
      nodeEl.setAttribute('data-uid', node.uid);
      nodeEl.style.borderLeftColor = colors.text || 'var(--border-active)';

      // Step number
      var stepNum = el('div', 'pb-step-num');
      stepNum.textContent = String(idx + 1);
      stepNum.style.color = colors.text || 'var(--text-3)';
      nodeEl.appendChild(stepNum);

      // Node body
      var body = el('div', 'pb-node-body');

      // Top row: category tag + name
      var topRow = el('div', 'pb-node-top');
      topRow.innerHTML = getCategoryTag(cat);
      var nameEl = el('span', 'pb-node-name');
      nameEl.textContent = node.name;
      topRow.appendChild(nameEl);
      body.appendChild(topRow);

      // Param row
      var paramRow = el('div', 'pb-node-param');
      var paramLabel = el('span', 'pb-node-param-label');
      paramLabel.textContent = node.paramLabel;
      paramRow.appendChild(paramLabel);

      var paramInput = el('input', 'pb-node-param-input');
      paramInput.type = 'text';
      paramInput.value = node.paramValue;
      paramInput.setAttribute('data-uid', node.uid);
      paramInput.addEventListener('change', function () {
        for (var i = 0; i < _flow.length; i++) {
          if (_flow[i].uid === paramInput.getAttribute('data-uid')) {
            _flow[i].paramValue = paramInput.value;
            break;
          }
        }
      });
      paramRow.appendChild(paramInput);
      body.appendChild(paramRow);

      nodeEl.appendChild(body);

      // Controls (move + remove)
      var controls = el('div', 'pb-node-controls');

      if (idx > 0) {
        var upBtn = el('button', 'pb-ctrl-icon');
        upBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M6 9V3M6 3L3 6M6 3l3 3"/></svg>';
        upBtn.title = 'Move up';
        upBtn.addEventListener('click', function () { moveNode(idx, idx - 1); });
        controls.appendChild(upBtn);
      }
      if (idx < _flow.length - 1) {
        var downBtn = el('button', 'pb-ctrl-icon');
        downBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M6 3v6M6 9l3-3M6 9L3 6"/></svg>';
        downBtn.title = 'Move down';
        downBtn.addEventListener('click', function () { moveNode(idx, idx + 1); });
        controls.appendChild(downBtn);
      }

      var removeBtn = el('button', 'pb-ctrl-icon pb-ctrl-remove');
      removeBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 3l6 6M9 3l-6 6"/></svg>';
      removeBtn.title = 'Remove';
      removeBtn.addEventListener('click', function () { removeNode(idx); });
      controls.appendChild(removeBtn);

      nodeEl.appendChild(controls);
      _flowEl.appendChild(nodeEl);
    });

    // Drop zone at bottom
    var dropZone = el('div', 'pb-drop-zone');
    dropZone.textContent = 'Drop here or click an action to add';
    dropZone.addEventListener('dragover', function (e) { e.preventDefault(); dropZone.classList.add('pb-drop-active'); });
    dropZone.addEventListener('dragleave', function () { dropZone.classList.remove('pb-drop-active'); });
    dropZone.addEventListener('drop', function (e) {
      e.preventDefault();
      dropZone.classList.remove('pb-drop-active');
      var actionId = e.dataTransfer.getData('text/plain');
      if (actionId) addNode(actionId);
    });
    _flowEl.appendChild(dropZone);
  }

  /* ════════════════════════════════════════════════════
     Flow Mutations
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
  }

  function removeNode(idx) {
    _flow.splice(idx, 1);
    renderFlow();
  }

  function moveNode(fromIdx, toIdx) {
    var item = _flow.splice(fromIdx, 1)[0];
    _flow.splice(toIdx, 0, item);
    renderFlow();
  }

  /* ════════════════════════════════════════════════════
     Test Playbook
     ════════════════════════════════════════════════════ */

  function testPlaybook(resultEl) {
    resultEl.innerHTML = '';

    if (_flow.length === 0) {
      resultEl.innerHTML = '<div class="pb-result-msg pb-result-error">Add at least one step to test.</div>';
      return;
    }

    var hasTrigger = false;
    var hasCondition = false;
    var hasAction = false;
    var hasEnrich = false;
    var steps = [];

    _flow.forEach(function (node) {
      var action = findAction(node.actionId);
      if (!action) return;
      if (action.category === 'Triggers')    hasTrigger = true;
      if (action.category === 'Conditions')  hasCondition = true;
      if (action.category === 'Actions')     hasAction = true;
      if (action.category === 'Enrichment')  hasEnrich = true;
      steps.push({ category: action.category, name: node.name, param: node.paramValue });
    });

    // Execution trace
    var html = '<div class="pb-result-header">Execution Trace</div>';
    html += '<div class="pb-result-trace">';
    steps.forEach(function (step, i) {
      var c = CATEGORY_COLORS[step.category] || {};
      html += '<div class="pb-trace-step">' +
        '<span class="pb-trace-num" style="color:' + (c.text || 'var(--text-3)') + ';">' + (i + 1) + '</span>' +
        '<span class="pb-trace-name">' + step.name + '</span>' +
        '<span class="pb-trace-param">' + escAttr(step.param) + '</span>' +
        '<span class="pb-trace-status">PASS</span>' +
      '</div>';
    });
    html += '</div>';

    // Analysis
    var issues = [];
    if (!hasTrigger)   issues.push('No trigger defined. Playbook needs a starting condition to execute automatically.');
    if (!hasEnrich)    issues.push('No enrichment step. Add context (GeoIP, VirusTotal) before making blocking decisions.');
    if (!hasCondition) issues.push('No decision gate. Without conditions, every alert gets the same response.');
    if (!hasAction)    issues.push('No response action. The playbook detects but doesn\'t respond.');

    if (issues.length > 0) {
      html += '<div class="pb-result-header" style="margin-top:12px;">Analysis</div>';
      html += '<div class="pb-result-issues">';
      issues.forEach(function (issue) {
        html += '<div class="pb-result-issue">' + issue + '</div>';
      });
      html += '</div>';
    }

    // Score
    var score = 0;
    if (hasTrigger)   score += 25;
    if (hasCondition) score += 25;
    if (hasAction)    score += 25;
    if (hasEnrich)    score += 25;

    var scoreClass = score >= 75 ? 'pb-score-good' : score >= 50 ? 'pb-score-mid' : 'pb-score-low';
    html += '<div class="pb-result-score ' + scoreClass + '">' +
      '<span class="pb-score-label">Pipeline Coverage</span>' +
      '<span class="pb-score-bar"><span class="pb-score-fill" style="width:' + score + '%;"></span></span>' +
      '<span class="pb-score-value">' + score + '%</span>' +
    '</div>';

    resultEl.innerHTML = html;
  }

  /* ════════════════════════════════════════════════════
     Get Playbook Definition
     ════════════════════════════════════════════════════ */

  function getPlaybook() {
    return _flow.map(function (node) {
      var action = findAction(node.actionId);
      return {
        actionId: node.actionId,
        category: action ? action.category : 'Unknown',
        name: node.name,
        param: node.paramValue
      };
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

    // --- Left: Action palette ---
    var sidebar = el('div', 'pb-sidebar');
    var sidebarHeader = el('div', 'pb-sidebar-header', 'Actions');
    sidebar.appendChild(sidebarHeader);
    renderPalette(sidebar);
    _container.appendChild(sidebar);

    // --- Right: Flow canvas + controls ---
    var main = el('div', 'pb-main');

    // Canvas header
    var canvasHeader = el('div', 'pb-canvas-header');
    canvasHeader.innerHTML =
      '<span class="pb-canvas-title">Playbook Pipeline</span>' +
      '<span class="pb-canvas-count" id="pb-step-count">0 steps</span>';
    main.appendChild(canvasHeader);

    // Flow area
    _flowEl = el('div', 'pb-canvas');

    // Drop support on canvas
    _flowEl.addEventListener('dragover', function (e) { e.preventDefault(); });
    _flowEl.addEventListener('drop', function (e) {
      e.preventDefault();
      var actionId = e.dataTransfer.getData('text/plain');
      if (actionId) addNode(actionId);
    });

    renderFlow();
    main.appendChild(_flowEl);

    // Controls bar
    var controlBar = el('div', 'pb-control-bar');

    var testBtn = el('button', 'pb-btn pb-btn-secondary', 'Test Pipeline');
    var submitBtn = el('button', 'pb-btn pb-btn-primary', 'Submit Playbook');
    var resultArea = el('div', 'pb-result-area');

    testBtn.addEventListener('click', function () { testPlaybook(resultArea); });
    submitBtn.addEventListener('click', function () {
      var pb = getPlaybook();
      if (pb.length === 0) return;
      if (_onSubmit) _onSubmit(pb);
    });

    controlBar.appendChild(testBtn);
    controlBar.appendChild(submitBtn);
    main.appendChild(controlBar);
    main.appendChild(resultArea);

    _container.appendChild(main);

    // Update step count on mutations
    var origRender = renderFlow;
    renderFlow = function () {
      origRender();
      var countEl = document.getElementById('pb-step-count');
      if (countEl) countEl.textContent = _flow.length + ' step' + (_flow.length !== 1 ? 's' : '');
    };
  }

  /* ════════════════════════════════════════════════════
     Public API
     ════════════════════════════════════════════════════ */

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.PlaybookBuilder = {
    init: init,
    getPlaybook: getPlaybook
  };

})();
