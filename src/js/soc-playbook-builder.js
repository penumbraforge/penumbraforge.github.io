/**
 * Penumbra Forge — SOAR Playbook Workflow Editor
 *
 * Canvas-based node graph editor with drag-to-connect ports,
 * condition branching (Yes/No paths), auto-layout, and a
 * slide-in configuration panel.
 */

(function () {
  'use strict';

  /* ═══════════════════════════════════════════════════
     Task definitions
     ═══════════════════════════════════════════════════ */

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

  /* ─── State ─── */
  var _container, _actions, _onSubmit;
  var _nodes, _connections;
  var _uid = 0;
  var _selectedId = null;
  var _isMobile = false;

  /* ─── DOM refs ─── */
  var _wrapEl, _sidebarEl, _canvasEl, _svgEl, _configPanel, _countEl, _resultEl;

  /* ─── Drag-connect state ─── */
  var _dragLine = null;
  var _dragFrom = null; // { nodeId, port }
  var _dragStartPos = null;

  /* ─── Node drag state ─── */
  var _nodeDrag = null; // { nodeId, startX, startY, origX, origY }

  /* ─── Selected connection ─── */
  var _selectedConnId = null;

  /* ═══════════════════════════════════════════════════
     Utilities
     ═══════════════════════════════════════════════════ */

  function uid() { return 'n' + (++_uid); }
  function cid() { return 'c' + (++_uid); }
  function h(tag, cls, html) { var e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; }
  function esc(s) { return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;'); }
  function findAct(aid) { for (var i = 0; i < _actions.length; i++) { if (_actions[i].id === aid) return _actions[i]; } return null; }
  function findNode(id) { for (var i = 0; i < _nodes.length; i++) { if (_nodes[i].id === id) return _nodes[i]; } return null; }

  function checkMobile() { _isMobile = window.innerWidth < 640; }

  /* ═══════════════════════════════════════════════════
     Graph helpers
     ═══════════════════════════════════════════════════ */

  function getChildren(nodeId) {
    var kids = [];
    for (var i = 0; i < _connections.length; i++) {
      if (_connections[i].from === nodeId) kids.push(_connections[i]);
    }
    return kids;
  }

  function getParents(nodeId) {
    var parents = [];
    for (var i = 0; i < _connections.length; i++) {
      if (_connections[i].to === nodeId) parents.push(_connections[i]);
    }
    return parents;
  }

  function hasConnection(fromId, fromPort, toId) {
    for (var i = 0; i < _connections.length; i++) {
      var c = _connections[i];
      if (c.from === fromId && c.fromPort === fromPort && c.to === toId) return true;
    }
    return false;
  }

  function removeConnectionsFor(nodeId) {
    _connections = _connections.filter(function (c) { return c.from !== nodeId && c.to !== nodeId; });
  }

  /* ═══════════════════════════════════════════════════
     Auto-Layout (BFS tree)
     ═══════════════════════════════════════════════════ */

  var LEVEL_GAP = 120;
  var SIBLING_GAP = 280;
  var NODE_W = 220;
  var NODE_H = 70;
  var PILL_W = 80;
  var PILL_H = 32;

  function layout() {
    if (_nodes.length === 0) return;

    // Build adjacency: nodeId -> [child nodeIds in order]
    var adj = {};
    _nodes.forEach(function (n) { adj[n.id] = []; });
    _connections.forEach(function (c) {
      if (adj[c.from]) adj[c.from].push(c.to);
    });

    // BFS from start
    var levels = {};    // nodeId -> level number
    var levelNodes = {}; // level number -> [nodeIds]
    var visited = {};
    var queue = [];

    // Find start node
    var startNode = null;
    for (var i = 0; i < _nodes.length; i++) {
      if (_nodes[i].type === 'start') { startNode = _nodes[i]; break; }
    }
    if (!startNode) return;

    queue.push(startNode.id);
    visited[startNode.id] = true;
    levels[startNode.id] = 0;
    levelNodes[0] = [startNode.id];

    while (queue.length > 0) {
      var cur = queue.shift();
      var children = adj[cur] || [];
      for (var c = 0; c < children.length; c++) {
        var child = children[c];
        if (!visited[child]) {
          visited[child] = true;
          var lvl = levels[cur] + 1;
          levels[child] = lvl;
          if (!levelNodes[lvl]) levelNodes[lvl] = [];
          levelNodes[lvl].push(child);
          queue.push(child);
        }
      }
    }

    // Also place any unvisited nodes (orphans) at the bottom
    var maxLevel = 0;
    for (var k in levels) { if (levels[k] > maxLevel) maxLevel = levels[k]; }

    _nodes.forEach(function (n) {
      if (!visited[n.id]) {
        maxLevel++;
        levels[n.id] = maxLevel;
        if (!levelNodes[maxLevel]) levelNodes[maxLevel] = [];
        levelNodes[maxLevel].push(n.id);
      }
    });

    // Find max width across all levels
    var maxWidth = 0;
    for (var lv in levelNodes) {
      var count = levelNodes[lv].length;
      if (count > maxWidth) maxWidth = count;
    }

    // Position nodes
    var canvasWidth = Math.max(maxWidth * SIBLING_GAP, 600);
    var centerX = canvasWidth / 2;

    for (var lvl2 in levelNodes) {
      var ids = levelNodes[lvl2];
      var totalWidth = (ids.length - 1) * SIBLING_GAP;
      var startX = centerX - totalWidth / 2;

      for (var j = 0; j < ids.length; j++) {
        var node = findNode(ids[j]);
        if (node) {
          var w = (node.type === 'start' || node.type === 'end') ? PILL_W : NODE_W;
          node.x = startX + j * SIBLING_GAP - w / 2;
          node.y = 30 + parseInt(lvl2) * LEVEL_GAP;
        }
      }
    }
  }

  /* ═══════════════════════════════════════════════════
     Port position helpers
     ═══════════════════════════════════════════════════ */

  function getPortPos(node, portName) {
    var w = (node.type === 'start' || node.type === 'end') ? PILL_W : NODE_W;
    var ht = (node.type === 'start' || node.type === 'end') ? PILL_H : NODE_H;

    if (portName === 'in') {
      return { x: node.x + w / 2, y: node.y };
    }
    if (portName === 'out') {
      return { x: node.x + w / 2, y: node.y + ht };
    }
    if (portName === 'yes') {
      return { x: node.x + w * 0.3, y: node.y + ht };
    }
    if (portName === 'no') {
      return { x: node.x + w * 0.7, y: node.y + ht };
    }
    return { x: node.x + w / 2, y: node.y + ht / 2 };
  }

  /* ═══════════════════════════════════════════════════
     Sidebar — task palette
     ═══════════════════════════════════════════════════ */

  function buildSidebar() {
    var sb = h('div', 'pw-sidebar');

    var search = h('div', 'pw-search');
    var input = h('input');
    input.type = 'text';
    input.placeholder = 'Search tasks\u2026';
    input.addEventListener('input', function () {
      var q = this.value.toLowerCase();
      sb.querySelectorAll('.pw-task').forEach(function (t) {
        t.style.display = t.textContent.toLowerCase().indexOf(q) !== -1 ? '' : 'none';
      });
      // Also hide empty category headers
      sb.querySelectorAll('.pw-cat').forEach(function (cat) {
        var tasks = cat.querySelectorAll('.pw-task');
        var visible = false;
        tasks.forEach(function (t) { if (t.style.display !== 'none') visible = true; });
        cat.style.display = visible ? '' : 'none';
      });
    });
    search.appendChild(input);
    sb.appendChild(search);

    var list = h('div', 'pw-task-list');
    CATS.forEach(function (cat) {
      var sec = h('div', 'pw-cat');
      var hdr = h('div', 'pw-cat-label');
      hdr.style.color = CAT_COLORS[cat];
      hdr.textContent = cat;
      sec.appendChild(hdr);

      _actions.filter(function (a) { return a.category === cat; }).forEach(function (act) {
        var card = h('div', 'pw-task');
        var dot = h('span', 'pw-dot');
        dot.style.background = CAT_COLORS[cat];
        card.appendChild(dot);

        var info = h('div', 'pw-task-info');
        info.innerHTML = '<div class="pw-task-name">' + esc(act.name) + '</div>' +
                         '<div class="pw-task-desc">' + esc(act.desc || '') + '</div>';
        card.appendChild(info);

        card.addEventListener('click', function () { addNodeToFlow(act.id); });
        sec.appendChild(card);
      });
      list.appendChild(sec);
    });
    sb.appendChild(list);
    return sb;
  }

  /* ═══════════════════════════════════════════════════
     SVG connection drawing
     ═══════════════════════════════════════════════════ */

  function drawConnections() {
    if (!_svgEl) return;

    // Clear old
    while (_svgEl.lastChild && _svgEl.lastChild.tagName !== 'defs') {
      _svgEl.removeChild(_svgEl.lastChild);
    }

    // Size SVG to canvas content
    var maxY = 0, maxX = 0;
    _nodes.forEach(function (n) {
      var w = (n.type === 'start' || n.type === 'end') ? PILL_W : NODE_W;
      var ht = (n.type === 'start' || n.type === 'end') ? PILL_H : NODE_H;
      if (n.y + ht > maxY) maxY = n.y + ht;
      if (n.x + w > maxX) maxX = n.x + w;
    });
    _svgEl.setAttribute('width', maxX + 100);
    _svgEl.setAttribute('height', maxY + 100);
    _svgEl.style.width = (maxX + 100) + 'px';
    _svgEl.style.height = (maxY + 100) + 'px';

    _connections.forEach(function (conn) {
      var fromNode = findNode(conn.from);
      var toNode = findNode(conn.to);
      if (!fromNode || !toNode) return;

      var p1 = getPortPos(fromNode, conn.fromPort);
      var p2 = getPortPos(toNode, conn.toPort);

      var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      var cy1 = p1.y + 50;
      var cy2 = p2.y - 50;
      path.setAttribute('d', 'M' + p1.x + ',' + p1.y + ' C' + p1.x + ',' + cy1 + ' ' + p2.x + ',' + cy2 + ' ' + p2.x + ',' + p2.y);

      // Color based on port
      var strokeColor = 'var(--border-active)';
      if (conn.fromPort === 'yes') strokeColor = '#4ade80';
      else if (conn.fromPort === 'no') strokeColor = '#ef4444';

      path.setAttribute('class', 'pw-line' + (_selectedConnId === conn.id ? ' pw-line-sel' : ''));
      path.setAttribute('stroke', strokeColor);
      path.setAttribute('marker-end', conn.fromPort === 'yes' ? 'url(#pw-arrow-green)' : conn.fromPort === 'no' ? 'url(#pw-arrow-red)' : 'url(#pw-arrow)');
      path.setAttribute('data-conn-id', conn.id);
      path.style.pointerEvents = 'stroke';
      path.style.cursor = 'pointer';
      path.setAttribute('stroke-width', _selectedConnId === conn.id ? '4' : '2');

      // Click to select/delete connection
      path.addEventListener('click', function (ev) {
        ev.stopPropagation();
        _selectedConnId = _selectedConnId === conn.id ? null : conn.id;
        drawConnections();
      });

      // Invisible wider hit area for easier clicking
      var hitArea = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      hitArea.setAttribute('d', path.getAttribute('d'));
      hitArea.setAttribute('stroke', 'transparent');
      hitArea.setAttribute('stroke-width', '14');
      hitArea.setAttribute('fill', 'none');
      hitArea.style.cursor = 'pointer';
      hitArea.addEventListener('click', function (ev) {
        ev.stopPropagation();
        _selectedConnId = _selectedConnId === conn.id ? null : conn.id;
        drawConnections();
      });

      _svgEl.appendChild(hitArea);
      _svgEl.appendChild(path);

      // If selected, add a delete button at the midpoint
      if (_selectedConnId === conn.id) {
        var mx = (p1.x + p2.x) / 2;
        var my = (p1.y + p2.y) / 2;
        var fo = document.createElementNS('http://www.w3.org/2000/svg', 'foreignObject');
        fo.setAttribute('x', mx - 10);
        fo.setAttribute('y', my - 10);
        fo.setAttribute('width', 20);
        fo.setAttribute('height', 20);
        fo.innerHTML = '<button xmlns="http://www.w3.org/1999/xhtml" style="width:20px;height:20px;border-radius:50%;background:#ef4444;border:none;color:#fff;font-size:12px;cursor:pointer;display:flex;align-items:center;justify-content:center;padding:0;line-height:1;" title="Delete connection">&times;</button>';
        fo.querySelector('button').addEventListener('click', function (ev) {
          ev.stopPropagation();
          _connections = _connections.filter(function (c) { return c.id !== conn.id; });
          _selectedConnId = null;
          render();
        });
        _svgEl.appendChild(fo);
      }
    });
  }

  /* ═══════════════════════════════════════════════════
     Render canvas nodes
     ═══════════════════════════════════════════════════ */

  function render() {
    layout();

    // Clear nodes (keep SVG)
    var toRemove = [];
    for (var i = 0; i < _canvasEl.children.length; i++) {
      var child = _canvasEl.children[i];
      if (child !== _svgEl && !child.classList.contains('pw-config-panel') &&
          !child.classList.contains('pw-ctrls') && !child.classList.contains('pw-results') &&
          !child.classList.contains('pw-add-popup')) {
        toRemove.push(child);
      }
    }
    toRemove.forEach(function (el) { el.remove(); });

    // Compute step numbering for task/condition nodes
    var stepNum = 0;
    var nodeSteps = {};
    // BFS order from start
    var visited = {};
    var queue = [];
    var startNode = null;
    for (var s = 0; s < _nodes.length; s++) {
      if (_nodes[s].type === 'start') { startNode = _nodes[s]; break; }
    }
    if (startNode) {
      queue.push(startNode.id);
      visited[startNode.id] = true;
      while (queue.length > 0) {
        var cur = queue.shift();
        var n = findNode(cur);
        if (n && (n.type === 'task' || n.type === 'condition')) {
          stepNum++;
          nodeSteps[n.id] = stepNum;
        }
        var children = getChildren(cur);
        children.forEach(function (c) {
          if (!visited[c.to]) {
            visited[c.to] = true;
            queue.push(c.to);
          }
        });
      }
    }

    // Render each node
    _nodes.forEach(function (node) {
      var el;

      if (node.type === 'start') {
        el = h('div', 'pw-pill pw-pill-start');
        el.innerHTML = '<span class="pw-port pw-port-out" data-node-id="' + node.id + '" data-port="out"></span>START';
        el.style.left = node.x + 'px';
        el.style.top = node.y + 'px';
        _canvasEl.appendChild(el);
        setupPortListeners(el);
        return;
      }

      if (node.type === 'end') {
        el = h('div', 'pw-pill pw-pill-end');
        el.innerHTML = '<span class="pw-port pw-port-in" data-node-id="' + node.id + '" data-port="in"></span>END';
        el.style.left = node.x + 'px';
        el.style.top = node.y + 'px';
        _canvasEl.appendChild(el);
        setupPortListeners(el);
        return;
      }

      // Task or condition node
      var act = findAct(node.actionId);
      var cat = act ? act.category : node.category || 'Unknown';
      var color = CAT_COLORS[cat] || '#888';
      var isCondition = node.type === 'condition';
      var isSelected = _selectedId === node.id;

      el = h('div', 'pw-node' + (isCondition ? ' pw-node-cond' : '') + (isSelected ? ' pw-node-sel' : ''));
      el.setAttribute('data-node-id', node.id);
      el.style.left = node.x + 'px';
      el.style.top = node.y + 'px';

      // Input port
      var inPort = '<span class="pw-port pw-port-in" data-node-id="' + node.id + '" data-port="in"></span>';

      // Output ports
      var outPorts = '';
      if (isCondition) {
        outPorts = '<span class="pw-port pw-port-yes" data-node-id="' + node.id + '" data-port="yes"></span>' +
                   '<span class="pw-port pw-port-no" data-node-id="' + node.id + '" data-port="no"></span>';
      } else {
        outPorts = '<span class="pw-port pw-port-out" data-node-id="' + node.id + '" data-port="out"></span>';
      }

      var stepLabel = nodeSteps[node.id] ? '#' + nodeSteps[node.id] : '';
      var diamondBadge = isCondition ? ' <span class="pw-diamond">&#9670;</span>' : '';
      var catBadge = cat.substring(0, 4).toUpperCase();
      if (isCondition) catBadge = 'COND';

      el.innerHTML = inPort +
        '<div class="pw-accent" style="background:' + color + '"></div>' +
        '<div class="pw-node-body">' +
          '<div class="pw-row1">' +
            '<span class="pw-step">' + stepLabel + '</span>' +
            '<span class="pw-badge" style="color:' + color + ';border-color:' + color + '">' + catBadge + '</span>' +
            diamondBadge +
            '<span class="pw-name">' + esc(node.name) + '</span>' +
            (node.type !== 'start' && node.type !== 'end' ? '<button class="pw-del" data-del="' + node.id + '">&times;</button>' : '') +
          '</div>' +
          '<div class="pw-preview">' + esc(node.paramLabel || '') + ': ' + esc(node.param || '') + '</div>' +
        '</div>' +
        outPorts;

      // Condition labels
      if (isCondition) {
        var labelRow = h('div', 'pw-cond-labels');
        labelRow.innerHTML = '<span class="pw-cond-yes">Yes</span><span class="pw-cond-no">No</span>';
        el.appendChild(labelRow);
      }

      // Mobile: add "+" buttons below for connecting
      if (_isMobile) {
        var mobileAdd = h('button', 'pw-mobile-add', '+');
        mobileAdd.setAttribute('data-after-node', node.id);
        el.appendChild(mobileAdd);
      }

      _canvasEl.appendChild(el);

      // Click to select + drag to move
      (function (nodeRef, nodeEl) {
        var dragStarted = false;
        var startMX, startMY;

        nodeEl.addEventListener('mousedown', function (e) {
          if (e.target.classList.contains('pw-port') || e.target.classList.contains('pw-del') || e.target.closest('input') || _isMobile) return;
          e.preventDefault();
          dragStarted = false;
          startMX = e.clientX;
          startMY = e.clientY;
          _nodeDrag = { nodeId: nodeRef.id, origX: nodeRef.x, origY: nodeRef.y };

          function onMove(ev) {
            var dx = ev.clientX - startMX;
            var dy = ev.clientY - startMY;
            if (!dragStarted && Math.abs(dx) + Math.abs(dy) > 5) dragStarted = true;
            if (dragStarted) {
              nodeRef.x = Math.max(0, _nodeDrag.origX + dx);
              nodeRef.y = Math.max(0, _nodeDrag.origY + dy);
              nodeEl.style.left = nodeRef.x + 'px';
              nodeEl.style.top = nodeRef.y + 'px';
              drawConnections();
              sizeCanvas();
            }
          }

          function onUp() {
            document.removeEventListener('mousemove', onMove);
            document.removeEventListener('mouseup', onUp);
            _nodeDrag = null;
            if (!dragStarted) {
              selectNode(nodeRef.id);
            }
          }

          document.addEventListener('mousemove', onMove);
          document.addEventListener('mouseup', onUp);
        });
      })(node, el);

      // Delete button
      var delBtn = el.querySelector('[data-del]');
      if (delBtn) {
        delBtn.addEventListener('click', function (e) {
          e.stopPropagation();
          removeNode(node.id);
        });
      }

      // Mobile add button
      var mAdd = el.querySelector('.pw-mobile-add');
      if (mAdd) {
        mAdd.addEventListener('click', function (e) {
          e.stopPropagation();
          showAddPopup(node.x + NODE_W / 2, node.y + NODE_H + 20, node.id, node.type === 'condition' ? 'yes' : 'out');
        });
      }

      setupPortListeners(el);
    });

    drawConnections();
    updateCount();
    updateConfigPanel();
    sizeCanvas();
  }

  /* ═══════════════════════════════════════════════════
     Canvas sizing
     ═══════════════════════════════════════════════════ */

  function sizeCanvas() {
    var maxY = 0, maxX = 0;
    _nodes.forEach(function (n) {
      var w = (n.type === 'start' || n.type === 'end') ? PILL_W : NODE_W;
      var ht = (n.type === 'start' || n.type === 'end') ? PILL_H : NODE_H;
      if (n.y + ht > maxY) maxY = n.y + ht;
      if (n.x + w > maxX) maxX = n.x + w;
    });
    _canvasEl.style.minHeight = (maxY + 80) + 'px';
    _canvasEl.style.minWidth = (maxX + 80) + 'px';
  }

  /* ═══════════════════════════════════════════════════
     Port drag-to-connect
     ═══════════════════════════════════════════════════ */

  function setupPortListeners(el) {
    var ports = el.querySelectorAll('.pw-port');
    ports.forEach(function (port) {
      // Only output ports are draggable (out, yes, no)
      var portType = port.getAttribute('data-port');
      if (portType === 'in') {
        // Input ports are drop targets only — handled in mousemove/mouseup
        return;
      }

      port.addEventListener('mousedown', function (e) {
        if (_isMobile) return;
        e.preventDefault();
        e.stopPropagation();

        var nodeId = port.getAttribute('data-node-id');
        var portName = port.getAttribute('data-port');
        var node = findNode(nodeId);
        if (!node) return;

        var pos = getPortPos(node, portName);
        _dragFrom = { nodeId: nodeId, port: portName };
        _dragStartPos = pos;

        // Create temp SVG line
        _dragLine = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        _dragLine.setAttribute('x1', pos.x);
        _dragLine.setAttribute('y1', pos.y);
        _dragLine.setAttribute('x2', pos.x);
        _dragLine.setAttribute('y2', pos.y);
        _dragLine.setAttribute('class', 'pw-drag-line');
        if (portName === 'yes') _dragLine.setAttribute('stroke', '#4ade80');
        else if (portName === 'no') _dragLine.setAttribute('stroke', '#ef4444');
        _svgEl.appendChild(_dragLine);

        port.classList.add('pw-port-active');

        document.addEventListener('mousemove', onDragMove);
        document.addEventListener('mouseup', onDragEnd);
      });
    });
  }

  function onDragMove(e) {
    if (!_dragLine) return;

    var rect = _canvasEl.getBoundingClientRect();
    var x = e.clientX - rect.left + _canvasEl.scrollLeft;
    var y = e.clientY - rect.top + _canvasEl.scrollTop;

    _dragLine.setAttribute('x2', x);
    _dragLine.setAttribute('y2', y);

    // Highlight nearest input port
    var ports = _canvasEl.querySelectorAll('.pw-port-in');
    ports.forEach(function (p) { p.classList.remove('pw-port-hover'); });

    var closest = findClosestInputPort(x, y);
    if (closest) closest.el.classList.add('pw-port-hover');
  }

  function onDragEnd(e) {
    document.removeEventListener('mousemove', onDragMove);
    document.removeEventListener('mouseup', onDragEnd);

    // Remove active state from source port
    var activePort = _canvasEl.querySelector('.pw-port-active');
    if (activePort) activePort.classList.remove('pw-port-active');

    // Remove hover from all ports
    _canvasEl.querySelectorAll('.pw-port-hover').forEach(function (p) { p.classList.remove('pw-port-hover'); });

    if (!_dragLine || !_dragFrom) {
      cleanupDrag();
      return;
    }

    var rect = _canvasEl.getBoundingClientRect();
    var x = e.clientX - rect.left + _canvasEl.scrollLeft;
    var y = e.clientY - rect.top + _canvasEl.scrollTop;

    var target = findClosestInputPort(x, y);

    if (target && target.nodeId !== _dragFrom.nodeId && !hasConnection(_dragFrom.nodeId, _dragFrom.port, target.nodeId)) {
      // Valid connection
      _connections.push({
        id: cid(),
        from: _dragFrom.nodeId,
        fromPort: _dragFrom.port,
        to: target.nodeId,
        toPort: 'in'
      });
      cleanupDrag();
      render();
    } else {
      // Dropped in empty space — show add popup
      showAddPopup(x, y, _dragFrom.nodeId, _dragFrom.port);
      cleanupDrag();
    }
  }

  function findClosestInputPort(x, y) {
    var best = null;
    var bestDist = 30; // max snap distance

    _nodes.forEach(function (n) {
      if (n.type === 'start') return; // start has no input port
      var pos = getPortPos(n, 'in');
      var dx = pos.x - x;
      var dy = pos.y - y;
      var dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < bestDist) {
        bestDist = dist;
        var portEl = _canvasEl.querySelector('[data-node-id="' + n.id + '"][data-port="in"]');
        if (portEl) best = { nodeId: n.id, el: portEl };
      }
    });

    return best;
  }

  function cleanupDrag() {
    if (_dragLine && _dragLine.parentNode) _dragLine.parentNode.removeChild(_dragLine);
    _dragLine = null;
    _dragFrom = null;
    _dragStartPos = null;
  }

  /* ═══════════════════════════════════════════════════
     Add-node popup (appears on empty-space drop or mobile "+")
     ═══════════════════════════════════════════════════ */

  function showAddPopup(x, y, fromNodeId, fromPort) {
    closeAddPopup();

    var popup = h('div', 'pw-add-popup');
    popup.style.left = x + 'px';
    popup.style.top = y + 'px';

    var title = h('div', 'pw-popup-title', 'Add Node');
    popup.appendChild(title);

    CATS.forEach(function (cat) {
      var catLabel = h('div', 'pw-popup-cat');
      catLabel.style.color = CAT_COLORS[cat];
      catLabel.textContent = cat;
      popup.appendChild(catLabel);

      _actions.filter(function (a) { return a.category === cat; }).forEach(function (act) {
        var item = h('div', 'pw-popup-item');
        var dot = h('span', 'pw-dot');
        dot.style.background = CAT_COLORS[cat];
        item.appendChild(dot);
        item.appendChild(document.createTextNode(act.name));
        item.addEventListener('click', function (e) {
          e.stopPropagation();
          closeAddPopup();
          addNodeConnected(act.id, fromNodeId, fromPort);
        });
        popup.appendChild(item);
      });
    });

    _canvasEl.appendChild(popup);

    setTimeout(function () {
      document.addEventListener('click', function closer(e) {
        if (!popup.contains(e.target)) {
          closeAddPopup();
          document.removeEventListener('click', closer);
        }
      });
    }, 0);
  }

  function closeAddPopup() {
    var existing = _canvasEl.querySelector('.pw-add-popup');
    if (existing) existing.remove();
  }

  /* ═══════════════════════════════════════════════════
     Node mutations
     ═══════════════════════════════════════════════════ */

  function addNodeToFlow(actionId) {
    var act = findAct(actionId);
    if (!act) return;

    var isCondition = act.category === 'Conditions';
    var nodeType = isCondition ? 'condition' : 'task';
    var newId = uid();

    var newNode = {
      id: newId,
      type: nodeType,
      name: act.name,
      x: 0, y: 0,
      category: act.category,
      actionId: act.id,
      param: act.paramDefault,
      paramLabel: act.param
    };

    // Find the end node and the node connected to it
    var endNode = null;
    for (var i = 0; i < _nodes.length; i++) {
      if (_nodes[i].type === 'end') { endNode = _nodes[i]; break; }
    }

    if (endNode) {
      // Find who connects TO end
      var toEnd = null;
      for (var c = 0; c < _connections.length; c++) {
        if (_connections[c].to === endNode.id) { toEnd = _connections[c]; break; }
      }

      if (toEnd) {
        // Remove that connection, insert new node in between
        _connections = _connections.filter(function (cn) { return cn.id !== toEnd.id; });

        // Insert before end
        _nodes.splice(_nodes.length - 1, 0, newNode);

        // Connect previous -> new
        _connections.push({
          id: cid(),
          from: toEnd.from,
          fromPort: toEnd.fromPort,
          to: newId,
          toPort: 'in'
        });

        // Connect new -> end
        _connections.push({
          id: cid(),
          from: newId,
          fromPort: isCondition ? 'yes' : 'out',
          to: endNode.id,
          toPort: 'in'
        });
      } else {
        // No connection to end — just add and connect start to it
        _nodes.splice(_nodes.length - 1, 0, newNode);
        // Find last node that has an unconnected output
        var startId = null;
        for (var s = 0; s < _nodes.length; s++) {
          if (_nodes[s].type === 'start') { startId = _nodes[s].id; break; }
        }
        if (startId && _nodes.length === 3) {
          // start, new, end — connect all
          _connections.push({ id: cid(), from: startId, fromPort: 'out', to: newId, toPort: 'in' });
          _connections.push({ id: cid(), from: newId, fromPort: isCondition ? 'yes' : 'out', to: endNode.id, toPort: 'in' });
        }
      }
    } else {
      _nodes.push(newNode);
    }

    _selectedId = null;
    render();

    // Scroll to bottom
    var scrollParent = _canvasEl.parentNode;
    if (scrollParent && scrollParent.classList.contains('pw-canvas-wrap')) {
      scrollParent.scrollTop = scrollParent.scrollHeight;
    }
  }

  function addNodeConnected(actionId, fromNodeId, fromPort) {
    var act = findAct(actionId);
    if (!act) return;

    var isCondition = act.category === 'Conditions';
    var nodeType = isCondition ? 'condition' : 'task';
    var newId = uid();

    var newNode = {
      id: newId,
      type: nodeType,
      name: act.name,
      x: 0, y: 0,
      category: act.category,
      actionId: act.id,
      param: act.paramDefault,
      paramLabel: act.param
    };

    // Insert before end node
    var endIdx = -1;
    for (var i = 0; i < _nodes.length; i++) {
      if (_nodes[i].type === 'end') { endIdx = i; break; }
    }
    if (endIdx >= 0) {
      _nodes.splice(endIdx, 0, newNode);
    } else {
      _nodes.push(newNode);
    }

    // Connect from source to new node
    _connections.push({
      id: cid(),
      from: fromNodeId,
      fromPort: fromPort,
      to: newId,
      toPort: 'in'
    });

    render();
  }

  function removeNode(nodeId) {
    var node = findNode(nodeId);
    if (!node || node.type === 'start' || node.type === 'end') return;

    // Get parents and children before removing
    var parents = getParents(nodeId);
    var children = getChildren(nodeId);

    // Remove all connections involving this node
    removeConnectionsFor(nodeId);

    // Reconnect: each parent to each child (or first child at least)
    if (parents.length > 0 && children.length > 0) {
      parents.forEach(function (p) {
        _connections.push({
          id: cid(),
          from: p.from,
          fromPort: p.fromPort,
          to: children[0].to,
          toPort: 'in'
        });
      });
    }

    // Remove node
    _nodes = _nodes.filter(function (n) { return n.id !== nodeId; });

    if (_selectedId === nodeId) _selectedId = null;
    render();
  }

  /* ═══════════════════════════════════════════════════
     Node selection & config panel
     ═══════════════════════════════════════════════════ */

  function selectNode(nodeId) {
    if (_selectedId === nodeId) {
      _selectedId = null;
    } else {
      _selectedId = nodeId;
    }
    render();
  }

  function updateConfigPanel() {
    if (!_configPanel) return;

    if (!_selectedId) {
      _configPanel.classList.remove('pw-config-open');
      return;
    }

    var node = findNode(_selectedId);
    if (!node || node.type === 'start' || node.type === 'end') {
      _configPanel.classList.remove('pw-config-open');
      return;
    }

    _configPanel.classList.add('pw-config-open');
    _configPanel.innerHTML = '';

    var act = findAct(node.actionId);
    var cat = act ? act.category : node.category || 'Unknown';
    var color = CAT_COLORS[cat] || '#888';

    // Header
    var hdr = h('div', 'pw-cfg-header');
    hdr.innerHTML = '<span class="pw-cfg-type" style="color:' + color + '">' + esc(cat) + '</span>' +
                    '<button class="pw-cfg-close">&times;</button>';
    _configPanel.appendChild(hdr);

    var closeBtn = hdr.querySelector('.pw-cfg-close');
    closeBtn.addEventListener('click', function () {
      _selectedId = null;
      render();
    });

    // Name field
    var nameGroup = h('div', 'pw-cfg-group');
    nameGroup.innerHTML = '<label>Name</label>';
    var nameInput = h('input');
    nameInput.type = 'text';
    nameInput.value = node.name;
    nameInput.addEventListener('change', function () {
      node.name = this.value;
      render();
    });
    nameGroup.appendChild(nameInput);
    _configPanel.appendChild(nameGroup);

    // Parameter field
    var paramGroup = h('div', 'pw-cfg-group');
    paramGroup.innerHTML = '<label>' + esc(node.paramLabel || 'Parameter') + '</label>';
    var paramInput = h('input');
    paramInput.type = 'text';
    paramInput.value = node.param || '';
    paramInput.addEventListener('change', function () {
      node.param = this.value;
      render();
    });
    paramGroup.appendChild(paramInput);
    _configPanel.appendChild(paramGroup);

    // For condition nodes: operator + value
    if (node.type === 'condition') {
      var opGroup = h('div', 'pw-cfg-group');
      opGroup.innerHTML = '<label>Operator</label>';
      var opSelect = h('select');
      ['equals', 'not equals', 'contains', 'greater than', 'less than', 'matches regex'].forEach(function (op) {
        var opt = h('option');
        opt.value = op;
        opt.textContent = op;
        if (node.operator === op) opt.selected = true;
        opSelect.appendChild(opt);
      });
      opSelect.addEventListener('change', function () { node.operator = this.value; });
      opGroup.appendChild(opSelect);
      _configPanel.appendChild(opGroup);

      var valGroup = h('div', 'pw-cfg-group');
      valGroup.innerHTML = '<label>Value</label>';
      var valInput = h('input');
      valInput.type = 'text';
      valInput.value = node.condValue || '';
      valInput.addEventListener('change', function () { node.condValue = this.value; });
      valGroup.appendChild(valInput);
      _configPanel.appendChild(valGroup);
    }

    // Description
    if (act && act.desc) {
      var descEl = h('div', 'pw-cfg-desc');
      descEl.textContent = act.desc;
      _configPanel.appendChild(descEl);
    }

    // Action ID info
    var idInfo = h('div', 'pw-cfg-id');
    idInfo.textContent = 'ID: ' + node.actionId;
    _configPanel.appendChild(idInfo);
  }

  function updateCount() {
    if (!_countEl) return;
    var count = 0;
    _nodes.forEach(function (n) { if (n.type === 'task' || n.type === 'condition') count++; });
    _countEl.textContent = count + ' step' + (count !== 1 ? 's' : '');
  }

  /* ═══════════════════════════════════════════════════
     Test pipeline
     ═══════════════════════════════════════════════════ */

  function testPlaybook() {
    if (!_resultEl) return;
    _resultEl.style.display = '';

    var taskNodes = _nodes.filter(function (n) { return n.type === 'task' || n.type === 'condition'; });

    if (taskNodes.length === 0) {
      _resultEl.innerHTML = '<div class="pw-msg pw-msg-err">Add steps to test.</div>';
      return;
    }

    var has = { Triggers: false, Conditions: false, Actions: false, Enrichment: false };
    taskNodes.forEach(function (n) {
      var a = findAct(n.actionId);
      if (a) has[a.category] = true;
    });

    var issues = [];
    if (!has.Triggers)   issues.push('Missing trigger \u2014 playbook needs a starting condition');
    if (!has.Enrichment) issues.push('Missing enrichment \u2014 add context before decisions');
    if (!has.Conditions) issues.push('Missing condition \u2014 all alerts treated identically');
    if (!has.Actions)    issues.push('Missing action \u2014 playbook detects but doesn\'t respond');

    var score = (has.Triggers ? 25 : 0) + (has.Conditions ? 25 : 0) + (has.Actions ? 25 : 0) + (has.Enrichment ? 25 : 0);
    var cls = score >= 75 ? 'good' : score >= 50 ? 'mid' : 'low';

    var html = '<div class="pw-result-hdr">Pipeline Test</div>';
    html += '<div class="pw-score pw-score-' + cls + '"><span>Coverage</span><span class="pw-score-bar"><span style="width:' + score + '%"></span></span><span>' + score + '%</span></div>';
    if (issues.length) {
      issues.forEach(function (s) { html += '<div class="pw-issue">' + s + '</div>'; });
    } else {
      html += '<div class="pw-msg pw-msg-ok">Pipeline covers all categories. Ready to submit.</div>';
    }
    _resultEl.innerHTML = html;
  }

  /* ═══════════════════════════════════════════════════
     getPlaybook() — public API, returns same format
     ═══════════════════════════════════════════════════ */

  function getPlaybook() {
    var result = [];
    // Walk BFS order from start, only include task/condition nodes
    var visited = {};
    var queue = [];
    for (var i = 0; i < _nodes.length; i++) {
      if (_nodes[i].type === 'start') { queue.push(_nodes[i].id); visited[_nodes[i].id] = true; break; }
    }

    while (queue.length > 0) {
      var cur = queue.shift();
      var node = findNode(cur);
      if (node && (node.type === 'task' || node.type === 'condition')) {
        var a = findAct(node.actionId);
        result.push({
          actionId: node.actionId,
          category: a ? a.category : node.category || 'Unknown',
          name: node.name,
          param: node.param || ''
        });
      }
      var children = getChildren(cur);
      children.forEach(function (c) {
        if (!visited[c.to]) {
          visited[c.to] = true;
          queue.push(c.to);
        }
      });
    }

    return result;
  }

  /* ═══════════════════════════════════════════════════
     Init
     ═══════════════════════════════════════════════════ */

  function init(opts) {
    _container = opts.container;
    _actions = opts.availableActions || DEFAULT_ACTIONS;
    _onSubmit = opts.onPlaybookSubmit || null;
    _uid = 0;
    _selectedId = null;

    checkMobile();

    // Default flow: Start -> End
    _nodes = [
      { id: 'start', type: 'start', name: 'Start', x: 0, y: 0, config: {} },
      { id: 'end',   type: 'end',   name: 'End',   x: 0, y: 0, config: {} }
    ];
    _connections = [];

    _container.innerHTML = '';

    // Build layout
    _wrapEl = h('div', 'pw-wrap');

    // Sidebar
    _sidebarEl = buildSidebar();
    _wrapEl.appendChild(_sidebarEl);

    // Main area
    var main = h('div', 'pw-main');

    // Header
    var hdr = h('div', 'pw-header');
    hdr.innerHTML = '<span class="pw-title">Playbook</span>';
    _countEl = h('span', 'pw-count');
    _countEl.textContent = '0 steps';
    hdr.appendChild(_countEl);
    main.appendChild(hdr);

    // Canvas scroll container
    var canvasWrap = h('div', 'pw-canvas-wrap');

    _canvasEl = h('div', 'pw-canvas');

    // SVG layer
    _svgEl = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    _svgEl.setAttribute('class', 'pw-svg');
    _svgEl.innerHTML =
      '<defs>' +
        '<marker id="pw-arrow" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6" fill="none" stroke="var(--border-active)" stroke-width="1"/></marker>' +
        '<marker id="pw-arrow-green" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6" fill="none" stroke="#4ade80" stroke-width="1"/></marker>' +
        '<marker id="pw-arrow-red" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6" fill="none" stroke="#ef4444" stroke-width="1"/></marker>' +
      '</defs>';
    _canvasEl.appendChild(_svgEl);

    // Config panel (right side)
    _configPanel = h('div', 'pw-config-panel');
    _canvasEl.appendChild(_configPanel);

    canvasWrap.appendChild(_canvasEl);

    // Click canvas background to deselect nodes and connections
    _canvasEl.addEventListener('click', function (e) {
      if (e.target === _canvasEl) {
        _selectedId = null;
        _selectedConnId = null;
        closeAddPopup();
        render();
      }
    });

    // Keyboard: Delete/Backspace removes selected connection
    document.addEventListener('keydown', function (e) {
      if ((e.key === 'Delete' || e.key === 'Backspace') && _selectedConnId) {
        // Don't intercept if user is typing in an input
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
        e.preventDefault();
        _connections = _connections.filter(function (c) { return c.id !== _selectedConnId; });
        _selectedConnId = null;
        render();
      }
    });

    main.appendChild(canvasWrap);

    // Controls
    var ctrls = h('div', 'pw-ctrls');
    var testBtn = h('button', 'pw-btn pw-btn-sec', 'Test Pipeline');
    testBtn.addEventListener('click', testPlaybook);
    var submitBtn = h('button', 'pw-btn pw-btn-pri', 'Submit Playbook');
    submitBtn.addEventListener('click', function () {
      var pb = getPlaybook();
      if (pb.length > 0 && _onSubmit) _onSubmit(pb);
    });
    ctrls.appendChild(testBtn);
    ctrls.appendChild(submitBtn);
    main.appendChild(ctrls);

    // Results
    _resultEl = h('div', 'pw-results');
    _resultEl.style.display = 'none';
    main.appendChild(_resultEl);

    _wrapEl.appendChild(main);
    _container.appendChild(_wrapEl);

    render();

    window.addEventListener('resize', function () {
      checkMobile();
      render();
    });
  }

  /* ═══════════════════════════════════════════════════
     Export — same API surface
     ═══════════════════════════════════════════════════ */

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.PlaybookBuilder = { init: init, getPlaybook: getPlaybook };
})();
