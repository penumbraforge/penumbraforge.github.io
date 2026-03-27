/**
 * Penumbra Forge — SOAR Playbook Builder
 *
 * Blue team SOC workstation component. Visual playbook designer for
 * building automated SOAR response workflows. Users add action nodes
 * from a categorised palette into a vertical flow, configure parameters,
 * test the logic against alert data, and submit the final playbook.
 */

(function () {
  'use strict';

  /* ════════════════════════════════════════════════════
     Default Action Catalogue
     ════════════════════════════════════════════════════ */

  var DEFAULT_ACTIONS = [
    { category: 'Triggers',    id: 'trigger-alert',     name: 'Alert Fires',         icon: '\u26A1', param: 'Rule name', paramDefault: 'Port Scan Detected' },
    { category: 'Triggers',    id: 'trigger-threshold',  name: 'Threshold Exceeded',  icon: '\u2191', param: 'Threshold',  paramDefault: '500 ports / 5 min' },
    { category: 'Triggers',    id: 'trigger-cron',       name: 'Schedule (Cron)',     icon: '\u23F0', param: 'Cron expr',  paramDefault: '0 3 * * 2' },
    { category: 'Conditions',  id: 'cond-ip-rep',        name: 'Check IP Reputation', icon: '\u2753', param: 'Source',     paramDefault: 'src_ip' },
    { category: 'Conditions',  id: 'cond-alert-count',   name: 'Check Alert Count',   icon: '#',      param: 'Threshold',  paramDefault: '> 10 in 1h' },
    { category: 'Conditions',  id: 'cond-source',        name: 'Check Source',        icon: '\uD83D\uDD0D', param: 'Match', paramDefault: 'known_scanner_list' },
    { category: 'Conditions',  id: 'cond-severity',      name: 'Check Severity',      icon: '\u25B2', param: 'Min sev',    paramDefault: 'high' },
    { category: 'Actions',     id: 'act-block-ip',       name: 'Block IP',            icon: '\u26D4', param: 'Target',     paramDefault: 'src_ip' },
    { category: 'Actions',     id: 'act-slack',          name: 'Send Slack Alert',    icon: '\uD83D\uDCE8', param: 'Channel', paramDefault: '#soc-alerts' },
    { category: 'Actions',     id: 'act-ticket',         name: 'Create Ticket',       icon: '\uD83C\uDFAB', param: 'Priority', paramDefault: 'P2' },
    { category: 'Actions',     id: 'act-quarantine',     name: 'Quarantine Host',     icon: '\uD83D\uDEE1', param: 'Target', paramDefault: 'src_host' },
    { category: 'Actions',     id: 'act-waf',            name: 'Enable WAF Rule',     icon: '\uD83D\uDEE1', param: 'Rule ID', paramDefault: 'block-scanner' },
    { category: 'Actions',     id: 'act-log-close',      name: 'Log & Close',         icon: '\u2714', param: 'Reason',     paramDefault: 'Auto-closed: benign scanner' },
    { category: 'Enrichment',  id: 'enrich-geoip',       name: 'GeoIP Lookup',        icon: '\uD83C\uDF0D', param: 'Target', paramDefault: 'src_ip' },
    { category: 'Enrichment',  id: 'enrich-vt',          name: 'VirusTotal Check',    icon: '\uD83E\uDDA0', param: 'Hash/URL', paramDefault: 'file_hash' },
    { category: 'Enrichment',  id: 'enrich-whois',       name: 'WHOIS Query',         icon: '\uD83D\uDCC4', param: 'Domain', paramDefault: 'src_domain' }
  ];

  var CATEGORY_ORDER = ['Triggers', 'Conditions', 'Actions', 'Enrichment'];

  /* ════════════════════════════════════════════════════
     State
     ════════════════════════════════════════════════════ */

  var _container = null;
  var _actions = [];
  var _flow = [];       // array of { uid, actionId, name, icon, param, paramLabel, paramValue }
  var _onSubmit = null;
  var _uidCounter = 0;

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

  /* ════════════════════════════════════════════════════
     Render — Palette
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
      var catDiv = el('div', 'pb-palette-category');
      var label = el('div', 'pb-palette-label', cat);
      catDiv.appendChild(label);

      grouped[cat].forEach(function (action) {
        var card = el('div', 'pb-action-card');
        card.setAttribute('data-action-id', action.id);
        card.innerHTML = '<span class="pb-action-icon">' + action.icon + '</span>' +
                         '<span class="pb-action-name">' + action.name + '</span>';
        card.addEventListener('click', function () { addNode(action.id); });
        catDiv.appendChild(card);
      });

      paletteEl.appendChild(catDiv);
    });
  }

  /* ════════════════════════════════════════════════════
     Render — Flow
     ════════════════════════════════════════════════════ */

  function renderFlow(flowEl) {
    flowEl.innerHTML = '';

    if (_flow.length === 0) {
      flowEl.innerHTML = '<div class="pb-empty">Click actions from the palette to build your playbook flow.</div>';
      return;
    }

    _flow.forEach(function (node, idx) {
      // Arrow between nodes
      if (idx > 0) {
        var arrow = el('div', 'pb-node-arrow');
        var insertBtn = el('button', 'pb-add-btn', '+');
        insertBtn.title = 'Insert step here';
        insertBtn.setAttribute('data-insert-idx', idx);
        insertBtn.addEventListener('click', function () { showInsertMenu(idx, arrow); });
        arrow.appendChild(insertBtn);
        flowEl.appendChild(arrow);
      }

      var nodeDiv = el('div', 'pb-node');
      nodeDiv.setAttribute('data-uid', node.uid);

      // Move controls
      var moveDiv = el('div', 'pb-node-move');
      if (idx > 0) {
        var upBtn = el('button', 'pb-move-btn', '\u2191');
        upBtn.title = 'Move up';
        upBtn.addEventListener('click', function () { moveNode(idx, idx - 1); });
        moveDiv.appendChild(upBtn);
      }
      if (idx < _flow.length - 1) {
        var downBtn = el('button', 'pb-move-btn', '\u2193');
        downBtn.title = 'Move down';
        downBtn.addEventListener('click', function () { moveNode(idx, idx + 1); });
        moveDiv.appendChild(downBtn);
      }
      nodeDiv.appendChild(moveDiv);

      // Node content
      var content = el('div', 'pb-node-content');
      content.innerHTML =
        '<span class="pb-node-icon">' + node.icon + '</span>' +
        '<div class="pb-node-info">' +
          '<span class="pb-node-name">' + node.name + '</span>' +
          '<div class="pb-node-param">' +
            '<label class="pb-node-param-label">' + node.paramLabel + ':</label>' +
            '<input class="pb-node-param-input" type="text" value="' + escAttr(node.paramValue) + '" data-uid="' + node.uid + '">' +
          '</div>' +
        '</div>';
      nodeDiv.appendChild(content);

      // Remove button
      var removeBtn = el('button', 'pb-remove-btn', '\u00D7');
      removeBtn.title = 'Remove step';
      removeBtn.addEventListener('click', function () { removeNode(idx); });
      nodeDiv.appendChild(removeBtn);

      flowEl.appendChild(nodeDiv);
    });

    // Add step button at end
    var endArrow = el('div', 'pb-node-arrow pb-node-arrow-end');
    var endBtn = el('button', 'pb-add-btn pb-add-btn-end', '+ Add Step');
    endBtn.addEventListener('click', function () { showInsertMenu(_flow.length, endArrow); });
    endArrow.appendChild(endBtn);
    flowEl.appendChild(endArrow);

    // Attach param input handlers
    flowEl.querySelectorAll('.pb-node-param-input').forEach(function (input) {
      input.addEventListener('change', function () {
        var u = input.getAttribute('data-uid');
        for (var i = 0; i < _flow.length; i++) {
          if (_flow[i].uid === u) { _flow[i].paramValue = input.value; break; }
        }
      });
    });
  }

  function escAttr(s) { return (s || '').replace(/"/g, '&quot;').replace(/</g, '&lt;'); }

  /* ════════════════════════════════════════════════════
     Flow Mutations
     ════════════════════════════════════════════════════ */

  function addNode(actionId, insertIdx) {
    var action = findAction(actionId);
    if (!action) return;

    var node = {
      uid: uid(),
      actionId: action.id,
      name: action.name,
      icon: action.icon,
      paramLabel: action.param,
      paramValue: action.paramDefault
    };

    if (insertIdx !== undefined && insertIdx < _flow.length) {
      _flow.splice(insertIdx, 0, node);
    } else {
      _flow.push(node);
    }

    refresh();
  }

  function removeNode(idx) {
    _flow.splice(idx, 1);
    refresh();
  }

  function moveNode(fromIdx, toIdx) {
    var item = _flow.splice(fromIdx, 1)[0];
    _flow.splice(toIdx, 0, item);
    refresh();
  }

  function showInsertMenu(idx, anchorEl) {
    // Close any existing menu
    var existing = _container.querySelector('.pb-insert-menu');
    if (existing) existing.remove();

    var menu = el('div', 'pb-insert-menu');
    _actions.forEach(function (action) {
      var item = el('div', 'pb-insert-item');
      item.innerHTML = '<span class="pb-action-icon">' + action.icon + '</span> ' + action.name;
      item.addEventListener('click', function () {
        menu.remove();
        addNode(action.id, idx);
      });
      menu.appendChild(item);
    });

    anchorEl.appendChild(menu);

    // Close on outside click
    setTimeout(function () {
      document.addEventListener('click', function closer(e) {
        if (!menu.contains(e.target)) {
          menu.remove();
          document.removeEventListener('click', closer);
        }
      });
    }, 0);
  }

  /* ════════════════════════════════════════════════════
     Test Playbook
     ════════════════════════════════════════════════════ */

  function testPlaybook(resultEl) {
    resultEl.innerHTML = '';

    if (_flow.length === 0) {
      resultEl.innerHTML = '<div class="pb-test-msg pb-test-warn">Add at least one action to test.</div>';
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
      if (action.category === 'Triggers')   hasTrigger = true;
      if (action.category === 'Conditions') hasCondition = true;
      if (action.category === 'Actions')    hasAction = true;
      if (action.category === 'Enrichment') hasEnrich = true;
      steps.push({ category: action.category, name: node.name, param: node.paramValue });
    });

    var html = '<div class="pb-test-header">Playbook Test Results</div>';

    // Simulate execution
    html += '<div class="pb-test-steps">';
    steps.forEach(function (step, i) {
      html += '<div class="pb-test-step">' +
        '<span class="pb-test-step-num">' + (i + 1) + '</span>' +
        '<span class="pb-test-step-cat">' + step.category + '</span>' +
        '<span class="pb-test-step-name">' + step.name + '</span>' +
        '<span class="pb-test-step-status pb-test-ok">OK</span>' +
      '</div>';
    });
    html += '</div>';

    // Scoring
    var issues = [];
    if (!hasTrigger)   issues.push('Missing trigger — playbook needs a starting condition');
    if (!hasEnrich)    issues.push('No enrichment step — add context before deciding');
    if (!hasCondition) issues.push('No condition — all alerts treated the same');
    if (!hasAction)    issues.push('No response action — playbook does nothing');

    if (issues.length > 0) {
      html += '<div class="pb-test-issues">';
      issues.forEach(function (issue) {
        html += '<div class="pb-test-issue">' + issue + '</div>';
      });
      html += '</div>';
    }

    var score = 100 - (issues.length * 20);
    if (score < 0) score = 0;
    var cls = score >= 80 ? 'pb-test-good' : score >= 40 ? 'pb-test-warn' : 'pb-test-bad';
    html += '<div class="pb-test-score ' + cls + '">Playbook score: ' + score + '/100</div>';

    if (score >= 80) {
      html += '<div class="pb-test-msg pb-test-good">Playbook looks solid. Ready to submit.</div>';
    } else if (score >= 40) {
      html += '<div class="pb-test-msg pb-test-warn">Playbook is functional but could be improved.</div>';
    } else {
      html += '<div class="pb-test-msg pb-test-bad">Playbook needs more work before submission.</div>';
    }

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
     Refresh
     ════════════════════════════════════════════════════ */

  function refresh() {
    var flowEl = _container.querySelector('.pb-flow');
    if (flowEl) renderFlow(flowEl);
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

    // Palette
    var palette = el('div', 'pb-palette');
    var paletteTitle = el('div', 'pb-palette-title', 'Available Actions');
    palette.appendChild(paletteTitle);
    renderPalette(palette);

    // Flow
    var flowWrap = el('div', 'pb-flow-wrap');
    var flowTitle = el('div', 'pb-flow-title', 'Playbook Flow');
    var flowEl = el('div', 'pb-flow');
    renderFlow(flowEl);
    flowWrap.appendChild(flowTitle);
    flowWrap.appendChild(flowEl);

    // Controls
    var controls = el('div', 'pb-controls');
    var testResult = el('div', 'pb-test-result');

    var testBtn = el('button', 'pb-ctrl-btn pb-ctrl-test', 'Test Playbook');
    testBtn.addEventListener('click', function () { testPlaybook(testResult); });

    var submitBtn = el('button', 'pb-ctrl-btn pb-ctrl-submit', 'Submit Playbook');
    submitBtn.addEventListener('click', function () {
      var pb = getPlaybook();
      if (pb.length === 0) return;
      if (_onSubmit) _onSubmit(pb);
    });

    controls.appendChild(testBtn);
    controls.appendChild(submitBtn);
    flowWrap.appendChild(controls);
    flowWrap.appendChild(testResult);

    _container.appendChild(palette);
    _container.appendChild(flowWrap);
  }

  /* ════════════════════════════════════════════════════
     Public API
     ════════════════════════════════════════════════════ */

  var PlaybookBuilder = {
    init: init,
    getPlaybook: getPlaybook
  };

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.PlaybookBuilder = PlaybookBuilder;

})();
