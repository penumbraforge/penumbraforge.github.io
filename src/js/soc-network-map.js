/**
 * Penumbra Forge — Network Containment Map
 *
 * Blue team SOC workstation component. Renders a visual network topology
 * of hosts grouped by network segment. Each host card shows status
 * (online, compromised, isolated) and provides isolate/restore controls.
 * Designed for the Active Containment lab.
 */

(function () {
  'use strict';

  /* ════════════════════════════════════════════════════
     State
     ════════════════════════════════════════════════════ */

  var _container = null;
  var _hosts = [];
  var _onIsolate = null;

  /* ════════════════════════════════════════════════════
     Helpers
     ════════════════════════════════════════════════════ */

  function el(tag, cls, html) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html !== undefined) e.innerHTML = html;
    return e;
  }

  function esc(s) {
    var d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  }

  function findHost(id) {
    for (var i = 0; i < _hosts.length; i++) {
      if (_hosts[i].id === id) return _hosts[i];
    }
    return null;
  }

  /* ════════════════════════════════════════════════════
     Role Icons (text-based)
     ════════════════════════════════════════════════════ */

  var ROLE_ICONS = {
    'Web Server':        '\uD83C\uDF10',
    'Database':          '\uD83D\uDDC4',
    'Domain Controller': '\uD83C\uDFF0',
    'Workstation':       '\uD83D\uDCBB',
    'File Server':       '\uD83D\uDCC1',
    'Email Server':      '\uD83D\uDCE7',
    'Backup Server':     '\uD83D\uDCBE',
    'Jump Box':          '\uD83D\uDD11'
  };

  function roleIcon(role) {
    return ROLE_ICONS[role] || '\uD83D\uDDA5';
  }

  /* ════════════════════════════════════════════════════
     Segment Grouping
     ════════════════════════════════════════════════════ */

  function groupBySegment(hosts) {
    var segments = {};
    hosts.forEach(function (host) {
      // Derive segment from IP (first 3 octets) or role
      var seg = deriveSegment(host);
      if (!segments[seg]) segments[seg] = [];
      segments[seg].push(host);
    });
    return segments;
  }

  function deriveSegment(host) {
    // Group by subnet — first 3 octets
    if (host.ip) {
      var parts = host.ip.split('.');
      if (parts.length >= 3) {
        var subnet = parts[0] + '.' + parts[1] + '.' + parts[2] + '.0/24';
        return subnet;
      }
    }
    // Fallback: group by role type
    if (/controller|dc/i.test(host.role || '')) return 'Management';
    if (/server/i.test(host.role || ''))         return 'Servers';
    return 'Workstations';
  }

  /* ════════════════════════════════════════════════════
     Render
     ════════════════════════════════════════════════════ */

  function render() {
    _container.innerHTML = '';

    var title = el('div', 'netmap-title', 'Network Topology');
    var subtitle = el('div', 'netmap-subtitle', _hosts.length + ' hosts \u00B7 ' + countByStatus('compromised') + ' compromised \u00B7 ' + countByStatus('isolated') + ' isolated');
    _container.appendChild(title);
    _container.appendChild(subtitle);

    // Legend
    var legend = el('div', 'netmap-legend');
    legend.innerHTML =
      '<span class="netmap-legend-item"><span class="netmap-legend-dot netmap-dot-online"></span>Online</span>' +
      '<span class="netmap-legend-item"><span class="netmap-legend-dot netmap-dot-compromised"></span>Compromised</span>' +
      '<span class="netmap-legend-item"><span class="netmap-legend-dot netmap-dot-isolated"></span>Isolated</span>';
    _container.appendChild(legend);

    // Grouped grid
    var segments = groupBySegment(_hosts);
    var segmentKeys = Object.keys(segments).sort();

    segmentKeys.forEach(function (segKey) {
      var segDiv = el('div', 'netmap-segment');
      var segLabel = el('div', 'netmap-segment-label', segKey);
      segDiv.appendChild(segLabel);

      var grid = el('div', 'netmap-grid');

      segments[segKey].forEach(function (host) {
        var card = el('div', 'netmap-host ' + host.status);
        card.setAttribute('data-host-id', host.id);

        // Connection info
        var connNames = [];
        if (host.connections) {
          host.connections.forEach(function (cid) {
            var ch = findHost(cid);
            if (ch) connNames.push(ch.name);
          });
        }

        card.innerHTML =
          '<div class="netmap-host-header">' +
            '<span class="netmap-host-icon">' + roleIcon(host.role) + '</span>' +
            '<span class="netmap-host-status-dot"></span>' +
          '</div>' +
          '<div class="netmap-host-name">' + esc(host.name) + '</div>' +
          '<div class="netmap-host-ip">' + esc(host.ip) + '</div>' +
          '<div class="netmap-host-role">' + esc(host.role) + '</div>' +
          (connNames.length > 0 ? '<div class="netmap-host-conns">Links: ' + connNames.join(', ') + '</div>' : '') +
          '<div class="netmap-host-actions"></div>';

        // Action buttons
        var actionsDiv = card.querySelector('.netmap-host-actions');

        if (host.status !== 'isolated') {
          var isolateBtn = el('button', 'netmap-isolate-btn', 'Isolate');
          isolateBtn.addEventListener('click', function (e) {
            e.stopPropagation();
            isolateHost(host.id);
          });
          actionsDiv.appendChild(isolateBtn);
        } else {
          var restoreBtn = el('button', 'netmap-restore-btn', 'Restore');
          restoreBtn.addEventListener('click', function (e) {
            e.stopPropagation();
            restoreHost(host.id);
          });
          actionsDiv.appendChild(restoreBtn);
        }

        grid.appendChild(card);
      });

      segDiv.appendChild(grid);
      _container.appendChild(segDiv);
    });
  }

  /* ════════════════════════════════════════════════════
     Actions
     ════════════════════════════════════════════════════ */

  function isolateHost(hostId) {
    var host = findHost(hostId);
    if (!host || host.status === 'isolated') return;
    host._prevStatus = host.status;
    host.status = 'isolated';
    render();
    if (_onIsolate) _onIsolate(hostId);
  }

  function restoreHost(hostId) {
    var host = findHost(hostId);
    if (!host || host.status !== 'isolated') return;
    host.status = host._prevStatus || 'online';
    delete host._prevStatus;
    render();
  }

  function setHostStatus(hostId, status) {
    var host = findHost(hostId);
    if (!host) return;
    host.status = status;
    render();
  }

  function countByStatus(status) {
    var n = 0;
    _hosts.forEach(function (h) { if (h.status === status) n++; });
    return n;
  }

  /* ════════════════════════════════════════════════════
     Init
     ════════════════════════════════════════════════════ */

  function init(opts) {
    _container = opts.container;
    _hosts = (opts.hosts || []).map(function (h) { return Object.assign({}, h); });
    _onIsolate = opts.onIsolate || null;

    _container.innerHTML = '';
    _container.classList.add('netmap-container');
    render();
  }

  /* ════════════════════════════════════════════════════
     Public API
     ════════════════════════════════════════════════════ */

  var NetworkMap = {
    init: init,
    isolateHost: isolateHost,
    restoreHost: restoreHost,
    setHostStatus: setHostStatus
  };

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.NetworkMap = NetworkMap;

})();
