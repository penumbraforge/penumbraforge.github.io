/* Site console — a real command line for the site, summoned with ⌘` / Ctrl+`.
   Everything it does is something you could do with the mouse; the point is
   that a security engineer already lives in a terminal, so navigating this
   site shouldn't require leaving one. Commands resolve against the same
   tool index the ⌘K palette uses, so it can never drift out of sync.

   No dependencies, no network calls, nothing persisted except the pinned
   history in sessionStorage. */
(function () {
  var HISTORY_KEY = 'pf-console-history';
  var root, out, input, hint;
  var history = [];
  var histIndex = -1;
  var cwd = '/';
  var tools = [];
  var booted = false;

  var PAGES = {
    '/': 'Home',
    '/gate/': 'Gate — secret scanner',
    '/vexes/': 'vexes — dependency scanner',
    '/librarian/': 'mcp-librarian — signed skill supply chain',
    '/umbra/': 'Umbra — local-first AI studio',
    '/tools/': 'The console — browser tools',
    '/blog/': 'Blog',
    '/about/': 'About',
    '/playground/': 'Playground — experiments'
  };

  var EXPERIMENTS = {
    breach: '/game/',
    snake: '/snake/',
    terminal: '/terminal/'
  };

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function print(html, cls) {
    var line = document.createElement('div');
    line.className = 'pfc-line' + (cls ? ' pfc-' + cls : '');
    line.innerHTML = html;
    out.appendChild(line);
    out.scrollTop = out.scrollHeight;
  }

  function printCmd(cmd) {
    print('<span class="pfc-prompt">' + esc(cwd) + ' $</span> ' + esc(cmd));
  }

  function loadTools() {
    if (tools.length) return Promise.resolve(tools);
    return fetch('/tools/index.json')
      .then(function (r) { return r.json(); })
      .then(function (data) {
        tools = Array.isArray(data) ? data : (data.tools || []);
        return tools;
      })
      .catch(function () { return []; });
  }

  var COMMANDS = {
    help: function () {
      print('Commands:', 'dim');
      [
        ['ls', 'list pages here, or tools inside /tools/'],
        ['cd &lt;page&gt;', 'change location (cd gate, cd .., cd /)'],
        ['open [page]', 'navigate the browser to a page'],
        ['find &lt;query&gt;', 'search all tools by name and keyword'],
        ['demo &lt;product&gt;', 'jump to a recorded terminal demo'],
        ['breach | snake | terminal', 'launch an experiment'],
        ['whoami', 'about this site'],
        ['clear', 'clear the console'],
        ['exit', 'close the console']
      ].forEach(function (r) {
        print('<span class="pfc-key">' + r[0] + '</span><span class="pfc-desc">' + r[1] + '</span>', 'row');
      });
      print('Tip: Tab completes, ↑/↓ walks history, Esc closes.', 'dim');
    },

    ls: function () {
      if (cwd === '/tools/') {
        return loadTools().then(function (list) {
          if (!list.length) { print('tool index unavailable — try /tools/', 'warn'); return; }
          print(list.length + ' tools. Use "find &lt;query&gt;" to narrow, "open &lt;slug&gt;" to launch.', 'dim');
          var cols = list.slice(0, 40).map(function (t) { return t.slug || t.name; });
          print(cols.map(esc).join('  '), 'wrap');
          if (list.length > 40) print('…and ' + (list.length - 40) + ' more.', 'dim');
        });
      }
      Object.keys(PAGES).forEach(function (p) {
        print('<span class="pfc-key">' + esc(p) + '</span><span class="pfc-desc">' + esc(PAGES[p]) + '</span>', 'row');
      });
    },

    cd: function (arg) {
      if (!arg || arg === '/' || arg === '~') { cwd = '/'; return; }
      if (arg === '..') {
        cwd = '/';
        return;
      }
      var target = resolvePage(arg);
      if (target) { cwd = target; print('now at ' + esc(target), 'dim'); }
      else print('no such page: ' + esc(arg) + ' (try "ls")', 'warn');
    },

    open: function (arg) {
      var target = arg ? resolvePage(arg) : cwd;
      if (!target && arg) {
        // Fall back to treating the argument as a tool slug.
        return loadTools().then(function (list) {
          var hit = list.filter(function (t) { return t.slug === arg; })[0];
          if (hit) { go('/tools/' + hit.slug + '/'); }
          else print('nothing to open for: ' + esc(arg), 'warn');
        });
      }
      go(target);
    },

    find: function (arg) {
      if (!arg) { print('usage: find &lt;query&gt;', 'warn'); return; }
      var q = arg.toLowerCase();
      return loadTools().then(function (list) {
        var hits = list.filter(function (t) {
          var hay = [t.name, t.slug, t.description, (t.keywords || []).join(' ')].join(' ').toLowerCase();
          return hay.indexOf(q) !== -1;
        }).slice(0, 12);
        if (!hits.length) { print('no tools match "' + esc(arg) + '"', 'warn'); return; }
        hits.forEach(function (t) {
          print('<a class="pfc-key pfc-link" href="/tools/' + esc(t.slug) + '/">' + esc(t.slug) +
                '</a><span class="pfc-desc">' + esc(t.description || t.name) + '</span>', 'row');
        });
        print(hits.length + ' shown. "open &lt;slug&gt;" to launch.', 'dim');
      });
    },

    demo: function (arg) {
      var map = { gate: '/gate/#demo', vexes: '/vexes/#recorded-title', librarian: '/librarian/#recorded-title' };
      var key = (arg || '').toLowerCase();
      if (!map[key]) { print('usage: demo gate | vexes | librarian', 'warn'); return; }
      go(map[key]);
    },

    whoami: function () {
      print('Penumbra Forge — security tooling for the AI-agent era.', 'dim');
      print('Deterministic tools you can run everywhere, with AI assistance layered on top', 'dim');
      print('rather than bolted through the middle. Built to fail loud rather than pass quietly.', 'dim');
    },

    clear: function () { out.innerHTML = ''; },
    exit: function () { close(); }
  };

  Object.keys(EXPERIMENTS).forEach(function (name) {
    COMMANDS[name] = function () { go(EXPERIMENTS[name]); };
  });

  function resolvePage(arg) {
    var a = String(arg).replace(/^\/+|\/+$/g, '').toLowerCase();
    if (!a) return '/';
    var direct = '/' + a + '/';
    if (PAGES[direct]) return direct;
    if (a === 'home') return '/';
    var alias = { librarian: '/librarian/', 'mcp-librarian': '/librarian/', docs: '/gate/wiki/', wiki: '/gate/wiki/' };
    return alias[a] || null;
  }

  function go(url) {
    print('→ ' + esc(url), 'dim');
    window.location.href = url;
  }

  function run(raw) {
    var cmd = raw.trim();
    if (!cmd) return;
    printCmd(cmd);
    history.push(cmd);
    histIndex = history.length;
    try { sessionStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(-40))); } catch (e) {}

    var parts = cmd.split(/\s+/);
    var name = parts[0].toLowerCase();
    var arg = parts.slice(1).join(' ');

    if (COMMANDS[name]) {
      var res = COMMANDS[name](arg);
      if (res && typeof res.then === 'function') res.catch(function () { print('command failed', 'warn'); });
    } else {
      print(esc(name) + ': not a command. Type "help".', 'warn');
    }
  }

  function complete() {
    var val = input.value.trim();
    if (!val) return;
    var parts = val.split(/\s+/);
    if (parts.length === 1) {
      var matches = Object.keys(COMMANDS).filter(function (c) { return c.indexOf(parts[0].toLowerCase()) === 0; });
      if (matches.length === 1) input.value = matches[0] + ' ';
      else if (matches.length > 1) print(matches.join('  '), 'dim');
    } else if (parts[0] === 'cd' || parts[0] === 'open') {
      var frag = parts[1].toLowerCase();
      var pages = Object.keys(PAGES).map(function (p) { return p.replace(/\//g, ''); }).filter(Boolean);
      var hit = pages.filter(function (p) { return p.indexOf(frag) === 0; });
      if (hit.length === 1) input.value = parts[0] + ' ' + hit[0];
      else if (hit.length > 1) print(hit.join('  '), 'dim');
    }
  }

  function build() {
    root = document.createElement('div');
    root.className = 'pfc';
    root.setAttribute('role', 'dialog');
    root.setAttribute('aria-modal', 'true');
    root.setAttribute('aria-label', 'Site console');
    root.hidden = true;
    root.innerHTML =
      '<div class="pfc-panel">' +
        '<div class="pfc-bar">' +
          '<span class="pfc-dot"></span><span class="pfc-dot"></span><span class="pfc-dot"></span>' +
          '<span class="pfc-title">penumbraforge — console</span>' +
          '<button type="button" class="pfc-close" aria-label="Close console">esc</button>' +
        '</div>' +
        '<div class="pfc-out" id="pfcOut" tabindex="0" aria-live="polite"></div>' +
        '<label class="pfc-inputrow"><span class="pfc-prompt" id="pfcCwd">/ $</span>' +
        '<input class="pfc-input" id="pfcInput" autocomplete="off" autocapitalize="off" spellcheck="false" aria-label="Console command">' +
        '</label>' +
      '</div>';
    document.body.appendChild(root);

    out = root.querySelector('.pfc-out');
    input = root.querySelector('.pfc-input');

    root.querySelector('.pfc-close').addEventListener('click', close);
    root.addEventListener('mousedown', function (e) { if (e.target === root) close(); });

    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { run(input.value); input.value = ''; syncPrompt(); }
      else if (e.key === 'Tab') { e.preventDefault(); complete(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); if (histIndex > 0) input.value = history[--histIndex] || ''; }
      else if (e.key === 'ArrowDown') { e.preventDefault(); if (histIndex < history.length - 1) input.value = history[++histIndex] || ''; else { histIndex = history.length; input.value = ''; } }
    });

    try { history = JSON.parse(sessionStorage.getItem(HISTORY_KEY) || '[]'); histIndex = history.length; } catch (e) {}
  }

  function syncPrompt() {
    var el = root.querySelector('#pfcCwd');
    if (el) el.textContent = cwd + ' $';
  }

  function open() {
    if (!root) build();
    root.hidden = false;
    document.body.classList.add('pfc-locked');
    syncPrompt();
    if (!booted) {
      booted = true;
      print('penumbraforge console — type <span class="pfc-key">help</span> for commands.', 'dim');
    }
    input.focus();
  }

  function close() {
    if (!root) return;
    root.hidden = true;
    document.body.classList.remove('pfc-locked');
  }

  function toggle() { if (!root || root.hidden) open(); else close(); }

  document.addEventListener('keydown', function (e) {
    // ⌘` / Ctrl+` — next to Esc, and doesn't collide with ⌘K.
    if ((e.metaKey || e.ctrlKey) && e.key === '`') { e.preventDefault(); toggle(); }
    else if (e.key === 'Escape' && root && !root.hidden) { close(); }
  });

  document.addEventListener('click', function (e) {
    var trigger = e.target.closest && e.target.closest('[data-open-console]');
    if (trigger) { e.preventDefault(); open(); }
  });

  window.penumbraConsole = { open: open, close: close, toggle: toggle };
})();
