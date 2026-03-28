/**
 * Penumbra Forge — SOAR Playbook Builder
 *
 * XSOAR-style visual workflow editor. Left sidebar with categorised task
 * palette, center canvas with SVG-connected flowchart nodes, inline
 * config panels. Vanilla JS, no dependencies.
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
  var _selectedUid = null;

  /* DOM references */
  var _canvasEl = null;
  var _svgEl = null;
  var _countEl = null;
  var _resultEl = null;
  var _sidebarSections = null;

  function uid() { return 'pb-' + (++_uidCounter); }

  function el(tag, cls, html) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html !== undefined) e.innerHTML = html;
    return e;
  }

  function svgEl(tag) {
    return document.createElementNS('http://www.w3.org/2000/svg', tag);
  }

  function findAction(id) {
    for (var i = 0; i < _actions.length; i++) {
      if (_actions[i].id === id) return _actions[i];
    }
    return null;
  }

  function findNode(u) {
    for (var i = 0; i < _flow.length; i++) {
      if (_flow[i].uid === u) return _flow[i];
    }
    return null;
  }

  function findNodeIndex(u) {
    for (var i = 0; i < _flow.length; i++) {
      if (_flow[i].uid === u) return i;
    }
    return -1;
  }

  function escAttr(s) { return (s || '').replace(/"/g, '&quot;').replace(/</g, '&lt;'); }

  function updateCount() {
    if (_countEl) _countEl.textContent = _flow.length + ' step' + (_flow.length !== 1 ? 's' : '');
  }

  /* ════════════════════════════════════════════════════
     Sidebar — categorised task palette with search
     ════════════════════════════════════════════════════ */

  function buildSidebar() {
    var sidebar = el('div', 'pb-sidebar');

    /* Search */
    var searchWrap = el('div', 'pb-sidebar-search');
    var searchInput = el('input');
    searchInput.type = 'text';
    searchInput.placeholder = 'Search tasks...';
    searchInput.addEventListener('input', function () {
      filterSidebar(this.value.toLowerCase());
    });
    searchWrap.appendChild(searchInput);
    sidebar.appendChild(searchWrap);

    /* Categories */
    _sidebarSections = el('div', 'pb-sidebar-sections');

    CATEGORY_ORDER.forEach(function (cat) {
      var catEl = el('div', 'pb-sidebar-cat');
      catEl.setAttribute('data-category', cat);

      var header = el('div', 'pb-sidebar-cat-header');
      header.textContent = cat;
      header.style.color = CATEGORY_COLORS[cat] || 'var(--text-3)';
      catEl.appendChild(header);

      var items = _actions.filter(function (a) { return a.category === cat; });
      items.forEach(function (action) {
        var task = el('div', 'pb-sidebar-task');
        task.setAttribute('data-action-id', action.id);
        task.setAttribute('data-name', action.name.toLowerCase());

        var dot = el('span', 'pb-sidebar-dot');
        dot.style.background = CATEGORY_COLORS[cat];
        task.appendChild(dot);

        var label = el('span');
        label.textContent = action.name;
        task.appendChild(label);

        task.addEventListener('click', function () { addNode(action.id); });
        catEl.appendChild(task);
      });

      _sidebarSections.appendChild(catEl);
    });

    sidebar.appendChild(_sidebarSections);
    return sidebar;
  }

  function filterSidebar(query) {
    if (!_sidebarSections) return;
    var cats = _sidebarSections.querySelectorAll('.pb-sidebar-cat');
    for (var c = 0; c < cats.length; c++) {
      var tasks = cats[c].querySelectorAll('.pb-sidebar-task');
      var anyVisible = false;
      for (var t = 0; t < tasks.length; t++) {
        var name = tasks[t].getAttribute('data-name') || '';
        var show = !query || name.indexOf(query) !== -1;
        tasks[t].style.display = show ? '' : 'none';
        if (show) anyVisible = true;
      }
      cats[c].style.display = anyVisible ? '' : 'none';
    }
  }

  /* ════════════════════════════════════════════════════
     Canvas — visual workflow graph
     ════════════════════════════════════════════════════ */

  function renderCanvas() {
    if (!_canvasEl) return;

    /* Preserve scroll position */
    var scrollTop = _canvasEl.scrollTop;

    _canvasEl.innerHTML = '';
    updateCount();

    /* SVG overlay for connections */
    _svgEl = svgEl('svg');
    _svgEl.setAttribute('class', 'pb-connections');
    _canvasEl.appendChild(_svgEl);

    /* Arrowhead marker */
    var defs = svgEl('defs');
    var marker = svgEl('marker');
    marker.setAttribute('id', 'pb-arrowhead');
    marker.setAttribute('markerWidth', '6');
    marker.setAttribute('markerHeight', '4');
    marker.setAttribute('refX', '6');
    marker.setAttribute('refY', '2');
    marker.setAttribute('orient', 'auto');
    var markerPath = svgEl('polygon');
    markerPath.setAttribute('points', '0 0, 6 2, 0 4');
    markerPath.setAttribute('class', 'pb-arrow-fill');
    marker.appendChild(markerPath);
    defs.appendChild(marker);
    _svgEl.appendChild(defs);

    /* Start node */
    var startNode = el('div', 'pb-start-node');
    startNode.textContent = 'Start';
    _canvasEl.appendChild(startNode);

    /* Task nodes with insert buttons between them */
    _flow.forEach(function (node, idx) {
      /* Insert button before this node */
      var insertBtn = el('button', 'pb-insert-btn');
      insertBtn.textContent = '+';
      insertBtn.title = 'Insert task here';
      insertBtn.setAttribute('data-insert-at', String(idx));
      insertBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        _insertAt = idx;
        highlightSidebar();
      });
      _canvasEl.appendChild(insertBtn);

      /* Node element */
      var action = findAction(node.actionId);
      var cat = action ? action.category : 'Unknown';
      var color = CATEGORY_COLORS[cat] || 'var(--text-3)';
      var isCondition = cat === 'Conditions';
      var isSelected = node.uid === _selectedUid;

      var nodeEl = el('div', 'pb-node' + (isCondition ? ' pb-node-condition' : '') + (isSelected ? ' pb-node-selected' : ''));
      nodeEl.setAttribute('data-uid', node.uid);

      /* Click to select */
      nodeEl.addEventListener('click', function (e) {
        if (e.target.classList.contains('pb-node-delete') || e.target.tagName === 'INPUT') return;
        selectNode(node.uid);
      });

      /* Accent bar */
      var accent = el('div', 'pb-node-accent');
      accent.style.background = color;
      nodeEl.appendChild(accent);

      /* Content area */
      var content = el('div', 'pb-node-content');

      /* Header: badge + title + delete */
      var header = el('div', 'pb-node-header');

      var badge = el('span', 'pb-node-type-badge');
      badge.textContent = cat.toUpperCase();
      badge.style.color = color;
      badge.style.borderColor = color;
      header.appendChild(badge);

      var title = el('span', 'pb-node-title');
      title.textContent = node.name;
      header.appendChild(title);

      var delBtn = el('button', 'pb-node-delete');
      delBtn.innerHTML = '&#x00D7;';
      delBtn.title = 'Remove';
      delBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        removeNode(node.uid);
      });
      header.appendChild(delBtn);

      content.appendChild(header);

      /* Param preview (shown when not selected) */
      if (!isSelected && node.paramValue) {
        var preview = el('div', 'pb-node-param-preview');
        preview.textContent = node.paramLabel + ': ' + node.paramValue;
        content.appendChild(preview);
      }

      /* Condition diamond indicator */
      if (isCondition) {
        var diamond = el('div', 'pb-node-diamond');
        diamond.style.borderColor = color;
        nodeEl.appendChild(diamond);
      }

      /* Config panel (shown when selected) */
      var config = el('div', 'pb-node-config');

      /* Task name row */
      var nameRow = el('div', 'pb-config-row');
      var nameLabel = el('label');
      nameLabel.textContent = 'Task name';
      nameRow.appendChild(nameLabel);
      var nameInput = el('input');
      nameInput.type = 'text';
      nameInput.value = node.name;
      nameInput.setAttribute('data-uid', node.uid);
      nameInput.setAttribute('data-field', 'name');
      nameInput.addEventListener('change', function () {
        var n = findNode(this.getAttribute('data-uid'));
        if (n) { n.name = this.value; renderCanvas(); }
      });
      nameRow.appendChild(nameInput);
      config.appendChild(nameRow);

      /* Param row */
      var paramRow = el('div', 'pb-config-row');
      var paramLabel = el('label');
      paramLabel.textContent = node.paramLabel;
      paramRow.appendChild(paramLabel);
      var paramInput = el('input');
      paramInput.type = 'text';
      paramInput.value = node.paramValue;
      paramInput.setAttribute('data-uid', node.uid);
      paramInput.setAttribute('data-field', 'paramValue');
      paramInput.addEventListener('change', function () {
        var n = findNode(this.getAttribute('data-uid'));
        if (n) { n.paramValue = this.value; }
      });
      paramRow.appendChild(paramInput);
      config.appendChild(paramRow);

      /* Description row */
      var descRow = el('div', 'pb-config-row');
      var descLabel = el('label');
      descLabel.textContent = 'Description';
      descRow.appendChild(descLabel);
      var descInput = el('input');
      descInput.type = 'text';
      descInput.value = node.description || '';
      descInput.placeholder = 'Optional...';
      descInput.setAttribute('data-uid', node.uid);
      descInput.addEventListener('change', function () {
        var n = findNode(this.getAttribute('data-uid'));
        if (n) { n.description = this.value; }
      });
      descRow.appendChild(descInput);
      config.appendChild(descRow);

      content.appendChild(config);
      nodeEl.appendChild(content);
      _canvasEl.appendChild(nodeEl);
    });

    /* Insert button after last node (before End) */
    var lastInsert = el('button', 'pb-insert-btn');
    lastInsert.textContent = '+';
    lastInsert.title = 'Insert task here';
    lastInsert.setAttribute('data-insert-at', String(_flow.length));
    lastInsert.addEventListener('click', function (e) {
      e.stopPropagation();
      _insertAt = _flow.length;
      highlightSidebar();
    });
    _canvasEl.appendChild(lastInsert);

    /* End node */
    var endNode = el('div', 'pb-end-node');
    endNode.textContent = 'End';
    _canvasEl.appendChild(endNode);

    /* Draw SVG connections after layout settles */
    requestAnimationFrame(function () {
      drawConnections();
      _canvasEl.scrollTop = scrollTop;
    });
  }

  var _insertAt = -1;

  function highlightSidebar() {
    /* Brief flash on sidebar to hint user should pick a task */
    if (_sidebarSections) {
      _sidebarSections.classList.add('pb-sidebar-highlight');
      setTimeout(function () {
        _sidebarSections.classList.remove('pb-sidebar-highlight');
      }, 600);
    }
  }

  /* ════════════════════════════════════════════════════
     SVG Connection Drawing
     ════════════════════════════════════════════════════ */

  function drawConnections() {
    if (!_svgEl || !_canvasEl) return;

    _svgEl.querySelectorAll('.pb-connection-path').forEach(function (p) { p.remove(); });

    /* Collect all nodes in visual order (start, tasks, end) */
    var allNodes = _canvasEl.querySelectorAll('.pb-start-node, .pb-node, .pb-end-node');
    if (allNodes.length < 2) return;

    var canvasRect = _canvasEl.getBoundingClientRect();
    var scrollLeft = _canvasEl.scrollLeft;
    var scrollTop = _canvasEl.scrollTop;

    /* Size the SVG to cover entire scrollable area */
    _svgEl.setAttribute('width', _canvasEl.scrollWidth);
    _svgEl.setAttribute('height', _canvasEl.scrollHeight);
    _svgEl.style.width = _canvasEl.scrollWidth + 'px';
    _svgEl.style.height = _canvasEl.scrollHeight + 'px';

    for (var i = 0; i < allNodes.length - 1; i++) {
      var from = allNodes[i];
      var to = allNodes[i + 1];

      /* Skip insert buttons — only connect actual nodes */
      if (from.classList.contains('pb-insert-btn') || to.classList.contains('pb-insert-btn')) continue;

      var fromRect = from.getBoundingClientRect();
      var toRect = to.getBoundingClientRect();

      var x1 = fromRect.left + fromRect.width / 2 - canvasRect.left + scrollLeft;
      var y1 = fromRect.bottom - canvasRect.top + scrollTop;
      var x2 = toRect.left + toRect.width / 2 - canvasRect.left + scrollLeft;
      var y2 = toRect.top - canvasRect.top + scrollTop;

      var path = svgEl('path');
      var midY = (y1 + y2) / 2;
      path.setAttribute('d', 'M' + x1 + ',' + y1 + ' C' + x1 + ',' + midY + ' ' + x2 + ',' + midY + ' ' + x2 + ',' + y2);
      path.setAttribute('class', 'pb-connection-path');
      path.setAttribute('marker-end', 'url(#pb-arrowhead)');
      _svgEl.appendChild(path);
    }
  }

  /* ════════════════════════════════════════════════════
     Selection
     ════════════════════════════════════════════════════ */

  function selectNode(u) {
    if (_selectedUid === u) {
      _selectedUid = null;
    } else {
      _selectedUid = u;
    }
    renderCanvas();
  }

  /* ════════════════════════════════════════════════════
     Mutations
     ════════════════════════════════════════════════════ */

  function addNode(actionId) {
    var action = findAction(actionId);
    if (!action) return;

    var newNode = {
      uid: uid(),
      actionId: action.id,
      name: action.name,
      paramLabel: action.param,
      paramValue: action.paramDefault,
      description: ''
    };

    /* Insert at specific position if set by "+" button, or after selected node, or at end */
    if (_insertAt >= 0) {
      _flow.splice(_insertAt, 0, newNode);
      _insertAt = -1;
    } else if (_selectedUid) {
      var idx = findNodeIndex(_selectedUid);
      if (idx >= 0) {
        _flow.splice(idx + 1, 0, newNode);
      } else {
        _flow.push(newNode);
      }
    } else {
      _flow.push(newNode);
    }

    _selectedUid = newNode.uid;
    renderCanvas();

    /* Scroll the new node into view */
    requestAnimationFrame(function () {
      var nodeEl = _canvasEl.querySelector('[data-uid="' + newNode.uid + '"]');
      if (nodeEl) nodeEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
  }

  function removeNode(u) {
    var idx = findNodeIndex(u);
    if (idx < 0) return;
    _flow.splice(idx, 1);
    if (_selectedUid === u) _selectedUid = null;
    renderCanvas();
  }

  /* ════════════════════════════════════════════════════
     Test
     ════════════════════════════════════════════════════ */

  function testPlaybook() {
    if (!_resultEl) return;
    _resultEl.innerHTML = '';
    _resultEl.style.display = 'block';

    if (_flow.length === 0) {
      _resultEl.innerHTML = '<div class="pb-rmsg pb-rmsg-err">Add steps to the pipeline first.</div>';
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
        '<span class="pb-rname">' + escAttr(s.name) + '</span>' +
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

    _resultEl.innerHTML = html;
  }

  function getPlaybook() {
    return _flow.map(function (node) {
      var action = findAction(node.actionId);
      return {
        actionId: node.actionId,
        category: action ? action.category : 'Unknown',
        name: node.name,
        param: node.paramValue,
        description: node.description || ''
      };
    });
  }

  /* ════════════════════════════════════════════════════
     Init — build the full XSOAR-style editor layout
     ════════════════════════════════════════════════════ */

  function init(opts) {
    _container = opts.container;
    _actions = opts.availableActions || DEFAULT_ACTIONS;
    _onSubmit = opts.onPlaybookSubmit || null;
    _flow = [];
    _uidCounter = 0;
    _selectedUid = null;
    _insertAt = -1;

    _container.innerHTML = '';
    _container.classList.add('pb-editor');

    /* Left sidebar — task palette */
    _container.appendChild(buildSidebar());

    /* Center canvas area */
    var canvasArea = el('div', 'pb-canvas-area');

    /* Canvas header */
    var canvasHeader = el('div', 'pb-canvas-header');
    var headerTitle = el('span', 'pb-canvas-title');
    headerTitle.textContent = 'Pipeline';
    canvasHeader.appendChild(headerTitle);
    _countEl = el('span', 'pb-canvas-count');
    _countEl.textContent = '0 steps';
    canvasHeader.appendChild(_countEl);
    canvasArea.appendChild(canvasHeader);

    /* Scrollable canvas */
    _canvasEl = el('div', 'pb-canvas');
    _canvasEl.addEventListener('click', function (e) {
      /* Deselect when clicking canvas background */
      if (e.target === _canvasEl) {
        _selectedUid = null;
        renderCanvas();
      }
    });
    canvasArea.appendChild(_canvasEl);

    /* Bottom controls */
    var controls = el('div', 'pb-canvas-controls');

    var testBtn = el('button', 'pb-btn pb-btn-sec', 'Test Pipeline');
    testBtn.addEventListener('click', function () { testPlaybook(); });

    var submitBtn = el('button', 'pb-btn pb-btn-pri', 'Submit Playbook');
    submitBtn.addEventListener('click', function () {
      var pb = getPlaybook();
      if (pb.length === 0) return;
      if (_onSubmit) _onSubmit(pb);
    });

    controls.appendChild(testBtn);
    controls.appendChild(submitBtn);
    canvasArea.appendChild(controls);

    /* Results area */
    _resultEl = el('div', 'pb-canvas-results');
    _resultEl.style.display = 'none';
    canvasArea.appendChild(_resultEl);

    _container.appendChild(canvasArea);

    /* Initial render */
    renderCanvas();

    /* Redraw connections on resize */
    var resizeTimer;
    window.addEventListener('resize', function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function () { drawConnections(); }, 100);
    });

    /* Redraw connections on canvas scroll */
    _canvasEl.addEventListener('scroll', function () {
      /* SVG is absolutely positioned so no redraw needed — it scrolls with the content */
    });
  }

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.PlaybookBuilder = { init: init, getPlaybook: getPlaybook };
})();
