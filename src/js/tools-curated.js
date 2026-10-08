/* The selected collection is the default. Search and saved pins span the full index. */
(function () {
  var root = document.querySelector('.tool-collection');
  if (!root) return;
  var search = document.getElementById('collectionSearch');
  var curated = document.getElementById('collectionCurated');
  var results = document.getElementById('collectionResults');
  var rows = Array.from(root.querySelectorAll('[data-search-row]'));
  var buttons = Array.from(root.querySelectorAll('[data-view]'));
  var pinButtons = Array.from(root.querySelectorAll('[data-pin]'));
  var count = document.getElementById('collectionCount');
  var defaultCount = count.textContent;
  var resultCount = document.getElementById('searchCount');
  var empty = document.getElementById('collectionEmpty');
  var pinNote = document.getElementById('pinNote');
  var filter = 'selected';
  var hadQuery = false;
  var categories = new Set(rows.map(function (row) { return row.dataset.cat; }));
  var names = { security: 'Security', intelligence: 'Investigation', devops: 'DevOps', web: 'Web & API', encoding: 'Encoding & data', text: 'Text', media: 'Media & creative', ai: 'AI' };
  var collections = {
    ir: ['ir-timeline', 'ioc-workbench', 'log-parser', 'email-header-forensics', 'entropy-xray', 'yara-playground', 'sigma-rule-builder', 'siem-query-translator', 'ai-security-copilot'],
    keys: ['passkey-inspector', 'key-converter', 'jwt-decoder', 'jwt-attack', 'ssh-keygen', 'totp-generator', 'secrets-scanner', 'secret-lock', 'one-time-secret', 'hash-generator', 'password-generator'],
    web: ['cors-debugger', 'curl-converter', 'api-request-builder', 'header-analyzer', 'security-headers', 'site-score', 'jwt-decoder', 'url-encoder']
  };
  var collectionNames = { ir: 'Incident response', keys: 'Keys & auth', web: 'Web & API' };
  var pins = [];
  var temporaryPins = false;
  function readPins() {
    if (temporaryPins) return;
    try {
      var stored = JSON.parse(localStorage.getItem('pf:favs') || '[]');
      pins = Array.isArray(stored) ? Array.from(new Set(stored.filter(function (slug) {
        return typeof slug === 'string' && rows.some(function (row) { return row.dataset.slug === slug; });
      }))) : [];
    } catch (_) { /* Keep this page's pins when browser storage is unavailable. */ }
  }
  function renderPins() {
    document.getElementById('pinCount').textContent = pins.length;
    pinButtons.forEach(function (button) {
      var pinned = pins.includes(button.dataset.pin);
      button.setAttribute('aria-pressed', String(pinned));
      button.setAttribute('aria-label', (pinned ? 'Unpin ' : 'Pin ') + button.dataset.name);
    });
  }
  function filterLabel() {
    if (filter === 'pinned') return 'Pinned';
    if (filter === 'featured') return 'Featured in the full index';
    if (filter === 'new') return 'New in the full index';
    if (filter.startsWith('cat:')) return names[filter.slice(4)] || filter.slice(4);
    if (filter.startsWith('col:')) return collectionNames[filter.slice(4)];
    return 'Full collection';
  }
  function matchesFilter(row) {
    if (filter === 'pinned') return pins.includes(row.dataset.slug);
    if (filter === 'featured') return !!row.dataset.featured;
    if (filter === 'new') return !!row.dataset.new;
    if (filter.startsWith('cat:')) return row.dataset.cat === filter.slice(4);
    if (filter.startsWith('col:')) return collections[filter.slice(4)].includes(row.dataset.slug);
    return true;
  }
  function apply() {
    var query = search.value.trim().toLowerCase();
    var showSelected = filter === 'selected' && !query;
    curated.hidden = !showSelected;
    results.hidden = showSelected;
    buttons.forEach(function (button) {
      var active = button.dataset.view === 'selected' ? showSelected : filter === button.dataset.view;
      button.classList.toggle('active', active);
      button.setAttribute('aria-pressed', String(active));
    });
    var visible = 0;
    rows.forEach(function (row) {
      var text = [row.dataset.name, row.dataset.keywords, row.dataset.cat, row.querySelector('.tool-row-description').textContent].join(' ').toLowerCase();
      row.hidden = !matchesFilter(row) || !query.split(/\s+/).every(function (word) { return text.includes(word); });
      if (!row.hidden) visible++;
    });
    var total = visible + (visible === 1 ? ' tool' : ' tools');
    count.textContent = showSelected ? defaultCount : filterLabel();
    resultCount.textContent = total + (query ? ' matching “' + search.value.trim() + '”' : '') + ' · ' + filterLabel();
    empty.hidden = visible !== 0;
    empty.querySelector('h2').textContent = filter === 'pinned' && !pins.length ? 'Your collection starts here.' : 'No tools found.';
    empty.querySelector('p').textContent = filter === 'pinned' && !pins.length ? 'Use the star beside a tool to keep it handy. Pins are saved in this browser.' : 'Try a broader search, or return to the selected collection.';
  }
  function writeUrl(push) {
    var url = new URL(location.href);
    ['q', 'cat', 'filter'].forEach(function (key) { url.searchParams.delete(key); });
    if (search.value.trim()) url.searchParams.set('q', search.value.trim());
    if (filter.startsWith('cat:')) url.searchParams.set('cat', filter.slice(4));
    else if (filter !== 'selected') url.searchParams.set('filter', filter);
    if (url.href !== location.href) history[push ? 'pushState' : 'replaceState'](null, '', url);
    hadQuery = !!search.value.trim();
  }
  function readUrl() {
    var params = new URLSearchParams(location.search);
    var requested = params.has('cat') ? 'cat:' + params.get('cat') : params.get('filter') || 'selected';
    var valid = ['selected', 'all', 'pinned', 'featured', 'new'].includes(requested) ||
      (requested.startsWith('cat:') && categories.has(requested.slice(4))) ||
      (requested.startsWith('col:') && Object.hasOwn(collections, requested.slice(4)));
    filter = valid ? requested : 'selected';
    search.value = params.get('q') || '';
    hadQuery = !!search.value.trim();
    apply();
  }
  function reset() {
    search.value = '';
    filter = 'selected';
    apply();
    writeUrl(true);
    search.focus();
  }
  buttons.forEach(function (button) {
    button.hidden = false;
    button.addEventListener('click', function () {
      filter = button.dataset.view;
      search.value = '';
      apply();
      writeUrl(true);
    });
  });
  pinButtons.forEach(function (button) {
    button.hidden = false;
    button.addEventListener('click', function () {
      readPins();
      var slug = button.dataset.pin;
      pins = pins.includes(slug) ? pins.filter(function (item) { return item !== slug; }) : pins.concat(slug);
      try {
        localStorage.setItem('pf:favs', JSON.stringify(pins));
        pinNote.textContent = 'Pins stay in this browser.';
      } catch (_) {
        temporaryPins = true;
        pinNote.textContent = 'Browser storage is unavailable. These pins last until you leave this page.';
      }
      renderPins();
      apply();
      // Keep keyboard focus usable when an unpinned result disappears.
      if (filter === 'pinned' && !pins.includes(slug)) search.focus();
    });
  });
  search.form.addEventListener('submit', function (event) { event.preventDefault(); apply(); writeUrl(!hadQuery); });
  search.addEventListener('input', function () { apply(); writeUrl(!hadQuery && !!search.value.trim()); });
  search.addEventListener('keydown', function (event) { if (event.key === 'Escape') { event.preventDefault(); reset(); } });
  document.getElementById('collectionReset').addEventListener('click', reset);
  document.getElementById('collectionEmptyReset').addEventListener('click', reset);
  window.addEventListener('popstate', readUrl);
  window.addEventListener('storage', function (event) { if (event.key === 'pf:favs' || event.key === null) { readPins(); renderPins(); apply(); } });
  pinNote.hidden = false;
  readPins();
  renderPins();
  readUrl();
})();
