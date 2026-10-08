/* Tool-directory navigation. Filters live in the URL; pins stay on this device. */
(function () {
  var search = document.getElementById('hubSearch');
  var rail = document.getElementById('hubRail');
  var main = document.getElementById('hubMain');
  if (!search || !rail || !main) return;

  var cards = Array.from(main.querySelectorAll('.hub-card'));
  var sections = Array.from(main.querySelectorAll('.hub-section'));
  var filters = Array.from(rail.querySelectorAll('[data-filter]'));
  var results = document.getElementById('hubResults');
  var mobileFilter = document.getElementById('hubFilter');
  var reset = document.getElementById('hubReset');
  var empty = document.getElementById('hubEmpty');
  var filter = 'all';
  var collections = {
    ir: ['ir-timeline', 'ioc-workbench', 'log-parser', 'email-header-forensics', 'entropy-xray', 'yara-playground', 'sigma-rule-builder', 'siem-query-translator', 'ai-security-copilot'],
    keys: ['passkey-inspector', 'key-converter', 'jwt-decoder', 'jwt-attack', 'ssh-keygen', 'totp-generator', 'secrets-scanner', 'secret-lock', 'one-time-secret', 'hash-generator', 'password-generator'],
    web: ['cors-debugger', 'curl-converter', 'api-request-builder', 'header-analyzer', 'security-headers', 'site-score', 'jwt-decoder', 'url-encoder']
  };
  var pins = [];
  var temporaryPins = false;
  function readPins() { if (temporaryPins) return; try {
    var stored = JSON.parse(localStorage.getItem('pf:favs') || '[]');
    if (Array.isArray(stored)) pins = stored.filter(function (slug) {
      return cards.some(function (card) { return card.dataset.slug === slug; });
    });
  } catch (_) {} }
  readPins();

  document.getElementById('cntNew').textContent = cards.filter(function (card) { return card.dataset.new; }).length;
  document.getElementById('cntFeat').textContent = cards.filter(function (card) { return card.dataset.featured; }).length;

  function matchesFilter(card) {
    if (filter === 'new') return !!card.dataset.new;
    if (filter === 'featured') return !!card.dataset.featured;
    if (filter === 'pinned') return pins.includes(card.dataset.slug);
    if (filter.startsWith('cat:')) return card.dataset.cat === filter.slice(4);
    if (filter.startsWith('col:')) return (collections[filter.slice(4)] || []).includes(card.dataset.slug);
    return true;
  }

  function highlight(card, query) {
    var heading = card.querySelector('h3');
    var name = card.dataset.name;
    var start = query ? name.toLowerCase().indexOf(query) : -1;
    heading.textContent = '';
    if (start < 0) { heading.textContent = name; return; }
    heading.appendChild(document.createTextNode(name.slice(0, start)));
    var mark = document.createElement('mark');
    mark.textContent = name.slice(start, start + query.length);
    heading.appendChild(mark);
    heading.appendChild(document.createTextNode(name.slice(start + query.length)));
  }

  function apply() {
    var query = search.value.trim().toLowerCase();
    var count = 0;
    cards.forEach(function (card) {
      var haystack = [card.dataset.name, card.dataset.keywords, card.dataset.cat, card.querySelector('p').textContent].join(' ').toLowerCase();
      card.hidden = !matchesFilter(card) || (query && !haystack.includes(query));
      if (!card.hidden) count++;
      highlight(card, query);
    });
    sections.forEach(function (section) {
      var visible = section.querySelectorAll('.hub-card:not([hidden])').length;
      section.hidden = visible === 0;
      section.querySelector('.cnt').textContent = visible;
      section.querySelector('.cnt').setAttribute('aria-label', visible + (visible === 1 ? ' tool' : ' tools'));
    });
    filters.forEach(function (button) {
      var active = button.dataset.filter === filter;
      button.classList.toggle('active', active);
      button.setAttribute('aria-pressed', String(active));
    });
    mobileFilter.value = filter;
    results.textContent = count + (count === 1 ? ' tool' : ' tools') + (query ? ' matching “' + search.value.trim() + '”' : '');
    reset.hidden = filter === 'all' && !query;
    empty.hidden = count !== 0;
  }

  function saveUrl(push) {
    var url = new URL(location.href);
    ['cat', 'filter', 'q'].forEach(function (key) { url.searchParams.delete(key); });
    if (filter.startsWith('cat:')) url.searchParams.set('cat', filter.slice(4));
    else if (filter !== 'all') url.searchParams.set('filter', filter);
    if (search.value.trim()) url.searchParams.set('q', search.value.trim());
    if (url.href !== location.href) history[push ? 'pushState' : 'replaceState'](null, '', url.href);
  }

  function readUrl() {
    var params = new URLSearchParams(location.search);
    var requested = params.has('cat') ? 'cat:' + params.get('cat') : params.get('filter') || 'all';
    search.value = params.get('q') || '';
    setFilter(requested);
  }

  function setFilter(next, push) {
    filter = filters.some(function (button) { return button.dataset.filter === next; }) ? next : 'all';
    apply();
    if (push !== undefined) saveUrl(push);
  }

  function renderPins() {
    document.getElementById('cntPinned').textContent = pins.length;
    mobileFilter.querySelector('option[value="pinned"]').textContent = 'Pinned (' + pins.length + ')';
    cards.forEach(function (card) {
      var button = card.querySelector('.hub-star');
      var pinned = pins.includes(card.dataset.slug);
      var label = (pinned ? 'Unpin ' : 'Pin ') + card.dataset.name;
      button.classList.toggle('on', pinned);
      button.setAttribute('aria-pressed', String(pinned));
      button.setAttribute('aria-label', label);
      button.title = label;
    });
  }

  cards.forEach(function (card) {
    card.querySelector('.hub-star').addEventListener('click', function () {
      readPins();
      var slug = card.dataset.slug;
      if (pins.includes(slug)) pins = pins.filter(function (item) { return item !== slug; });
      else pins.push(slug);
      try { localStorage.setItem('pf:favs', JSON.stringify(pins)); } catch (_) { temporaryPins = true; }
      renderPins();
      apply();
    });
  });
  filters.forEach(function (button) {
    button.addEventListener('click', function () {
      setFilter(button.dataset.filter, true);
    });
  });
  mobileFilter.addEventListener('change', function () { setFilter(mobileFilter.value, true); });
  search.addEventListener('input', function () { apply(); saveUrl(false); });
  search.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') { search.value = ''; apply(); saveUrl(false); }
  });
  function clear() { search.value = ''; setFilter('all', true); search.focus(); }
  reset.addEventListener('click', clear);
  document.getElementById('hubEmptyReset').addEventListener('click', clear);
  window.addEventListener('popstate', readUrl);
  window.addEventListener('storage', function (event) {
    if (event.key === 'pf:favs' || event.key === null) { readPins(); renderPins(); apply(); }
  });
  renderPins();
  readUrl();
})();
