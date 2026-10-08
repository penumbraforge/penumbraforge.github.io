// Run after `npm run build`: node --test scripts/verify-tool-collection.mjs
// Executes the shipped directory scripts against rendered HTML with a small DOM
// adapter. This covers state/navigation behavior; browser layout remains visual QA.
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync, existsSync } from 'node:fs';
import { parseDocument } from 'htmlparser2'; // Already installed by Eleventy's toolchain.

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const catalog = JSON.parse(read('src/_data/tools.json')).filter(tool => tool.status === 'live');
const selection = JSON.parse(read('src/_data/toolCollection.json'));
const selectedSlugs = [...selection.featured, ...selection.lanes.flatMap(lane => lane.tools)];
const html = { curated: read('_site/tools/index.html'), archive: read('_site/tools/all/index.html') };
const scripts = { curated: read('src/js/tools-curated.js'), archive: read('src/js/tools-directory.js') };

class Events {
  handlers = new Map();
  addEventListener(type, callback) {
    const callbacks = this.handlers.get(type) || [];
    callbacks.push(callback);
    this.handlers.set(type, callbacks);
  }
  dispatch(type, fields = {}) {
    const event = { type, target: this, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, ...fields };
    for (const callback of this.handlers.get(type) || []) callback.call(this, event);
    return event;
  }
}
const textOf = node => node.type === 'text' ? node.data : (node.children || []).map(textOf).join('');
function descendants(node) { return (node.children || []).flatMap(child => [child, ...descendants(child)]); }
function matches(node, selector) {
  if (!node.attribs) return false;
  const negative = selector.match(/:not\(([^)]+)\)$/);
  if (negative) {
    if (matches(node, negative[1])) return false;
    selector = selector.slice(0, negative.index);
  }
  const attribute = selector.match(/\[([^=\]]+)(?:="([^"]*)")?\]/);
  if (attribute) {
    if (!Object.hasOwn(node.attribs, attribute[1])) return false;
    if (attribute[2] !== undefined && node.attribs[attribute[1]] !== attribute[2]) return false;
    selector = selector.replace(attribute[0], '');
  }
  if (!selector) return true;
  if (selector.startsWith('.')) return (node.attribs.class || '').split(/\s+/).includes(selector.slice(1));
  if (selector.startsWith('#')) return node.attribs.id === selector.slice(1);
  return node.name === selector;
}

function page(kind = 'curated', { url = `https://example.test/tools/${kind === 'archive' ? 'all/' : ''}`, storage = new Map(), failRead = false, failWrite = false } = {}) {
  const raw = parseDocument(html[kind]);
  const wrappers = new WeakMap();
  const window = new Events();
  const state = { activeElement: null };
  class Element extends Events {
    constructor(node) { super(); this.node = node; this.value = node.attribs?.value || ''; }
    get dataset() { return Object.fromEntries(Object.entries(this.node.attribs || {}).filter(([key]) => key.startsWith('data-')).map(([key, value]) => [key.slice(5).replace(/-([a-z])/g, (_, char) => char.toUpperCase()), value])); }
    get hidden() { return Object.hasOwn(this.node.attribs || {}, 'hidden'); }
    set hidden(value) { if (value) this.setAttribute('hidden', ''); else delete this.node.attribs.hidden; }
    get textContent() { return textOf(this.node); }
    set textContent(value) { this.node.children = [{ type: 'text', data: String(value), parent: this.node }]; }
    get form() { let parent = this.node.parent; while (parent && parent.name !== 'form') parent = parent.parent; return parent ? wrap(parent) : null; }
    get classList() { return { toggle: (name, force) => {
      const classes = new Set((this.node.attribs.class || '').split(/\s+/).filter(Boolean));
      if (force === undefined ? !classes.has(name) : force) classes.add(name); else classes.delete(name);
      this.node.attribs.class = [...classes].join(' ');
    } }; }
    setAttribute(name, value) { this.node.attribs ||= {}; this.node.attribs[name] = String(value); }
    getAttribute(name) { return this.node.attribs?.[name] ?? null; }
    querySelectorAll(selector) { return descendants(this.node).filter(node => matches(node, selector)).map(wrap); }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    appendChild(child) { this.node.children ||= []; this.node.children.push(child.node); child.node.parent = this.node; return child; }
    focus() { state.activeElement = this; }
  }
  function wrap(node) { if (!wrappers.has(node)) wrappers.set(node, new Element(node)); return wrappers.get(node); }
  const document = wrap(raw);
  document.getElementById = id => document.querySelector(`#${id}`);
  document.createTextNode = data => wrap({ type: 'text', data, parent: null });
  document.createElement = name => wrap({ type: 'tag', name, attribs: {}, children: [], parent: null });
  let locationUrl = new URL(url);
  const location = { get href() { return locationUrl.href; }, get search() { return locationUrl.search; } };
  const entries = [locationUrl.href];
  let position = 0;
  const history = {
    pushState(_state, _title, next) { locationUrl = new URL(String(next), locationUrl); entries.splice(position + 1); entries.push(locationUrl.href); position++; },
    replaceState(_state, _title, next) { locationUrl = new URL(String(next), locationUrl); entries[position] = locationUrl.href; },
    back() { if (position > 0) { locationUrl = new URL(entries[--position]); window.dispatch('popstate'); } },
    forward() { if (position < entries.length - 1) { locationUrl = new URL(entries[++position]); window.dispatch('popstate'); } },
  };
  const localStorage = {
    getItem(key) { if (failRead) throw new Error('fixture storage read failure'); return storage.get(key) ?? null; },
    setItem(key, value) { if (failWrite) throw new Error('fixture storage write failure'); storage.set(key, String(value)); },
  };
  vm.runInNewContext(scripts[kind], { document, window, localStorage, location, history, URL, URLSearchParams }, { filename: `${kind}-directory.js` });
  const byId = id => document.getElementById(id);
  return {
    document, raw, state, window, storage, history, location, byId,
    search: byId(kind === 'curated' ? 'collectionSearch' : 'hubSearch'),
    rows: () => document.querySelectorAll(kind === 'curated' ? '[data-search-row]' : '.hub-card'),
    visible: () => document.querySelectorAll(kind === 'curated' ? '[data-search-row]' : '.hub-card').filter(row => !row.hidden).map(row => row.dataset.slug),
    pin(slug) { return document.querySelector(kind === 'curated' ? `[data-pin="${slug}"]` : `.hub-card`).dataset &&
      (kind === 'curated' ? document.querySelector(`[data-pin="${slug}"]`) : document.querySelectorAll('.hub-card').find(row => row.dataset.slug === slug).querySelector('.hub-star')); },
    input(value) { this.search.value = value; this.search.dispatch('input'); },
    clickView(value) { document.querySelector(`[${kind === 'curated' ? 'data-view' : 'data-filter'}="${value}"]`).dispatch('click'); },
  };
}

// Fail meaningfully if generation drops a prior tool, omits a selected tool, or
// creates a second interactive control inside a navigation link.
test('all 77 live tool URLs survive, and the selected composition has 12 distinct real tools', () => {
  assert.equal(catalog.length, 77);
  assert.equal(selectedSlugs.length, 12);
  assert.equal(new Set(selectedSlugs).size, 12);
  for (const tool of catalog) assert.ok(existsSync(new URL(`../_site/tools/${tool.slug}/index.html`, import.meta.url)), tool.slug);
  const landing = page();
  const archive = page('archive');
  assert.deepEqual(landing.rows().map(row => row.dataset.slug).sort(), catalog.map(tool => tool.slug).sort());
  assert.deepEqual(archive.rows().map(row => row.dataset.slug).sort(), catalog.map(tool => tool.slug).sort());
  const curatedLinks = landing.byId('collectionCurated').querySelectorAll('a').map(link => link.getAttribute('href'));
  for (const slug of selectedSlugs) assert.ok(curatedLinks.includes(`/tools/${slug}/`), slug);
  for (const surface of [landing, archive]) {
    for (const anchor of surface.document.querySelectorAll('a')) assert.equal(anchor.querySelectorAll('button').length, 0, 'pins must be sibling buttons');
    const ids = descendants(surface.raw).map(node => node.attribs?.id).filter(Boolean);
    assert.equal(new Set(ids).size, ids.length, 'generated IDs are unique');
  }
});

test('search finds a nonselected tool, preserves literal input, and Escape restores selection', () => {
  const surface = page();
  assert.equal(surface.byId('collectionCurated').hidden, false);
  assert.equal(surface.byId('collectionResults').hidden, true);
  assert.ok(!selectedSlugs.includes('diff-viewer'));
  surface.input('diff');
  assert.ok(surface.visible().includes('diff-viewer'));
  assert.equal(surface.byId('collectionCurated').hidden, true);
  assert.equal(new URL(surface.location.href).searchParams.get('q'), 'diff');
  surface.input('<img src=x onerror=alert(1)>');
  assert.equal(surface.visible().length, 0);
  assert.ok(surface.byId('searchCount').textContent.includes('<img src=x onerror=alert(1)>'));
  assert.equal(surface.byId('searchCount').querySelectorAll('img').length, 0);
  surface.search.dispatch('keydown', { key: 'Escape' });
  assert.equal(surface.byId('collectionCurated').hidden, false);
  assert.equal(surface.search.value, '');
  assert.equal(surface.state.activeElement, surface.search);
});

test('legacy category/task/filter links still work on both directory routes', () => {
  for (const kind of ['curated', 'archive']) {
    const base = `https://example.test/tools/${kind === 'archive' ? 'all/' : ''}`;
    assert.deepEqual(page(kind, { url: `${base}?cat=text&q=diff` }).visible(), ['diff-viewer']);
    const keys = page(kind, { url: `${base}?filter=col:keys` }).visible();
    assert.ok(keys.includes('key-converter'));
    assert.ok(keys.includes('jwt-decoder'));
    assert.ok(!keys.includes('image-converter'));
    const featured = page(kind, { url: `${base}?filter=featured` }).visible();
    assert.deepEqual(featured.sort(), catalog.filter(tool => tool.featured).map(tool => tool.slug).sort());
  }
});

test('Back and Forward restore search and selected view without leaving stale filters', () => {
  const surface = page();
  surface.input('diff');
  surface.byId('collectionReset').dispatch('click');
  assert.equal(surface.byId('collectionCurated').hidden, false);
  surface.history.back();
  assert.equal(surface.search.value, 'diff');
  assert.equal(surface.byId('collectionCurated').hidden, true);
  assert.ok(surface.visible().includes('diff-viewer'));
  surface.history.forward();
  assert.equal(surface.byId('collectionCurated').hidden, false);
  assert.equal(surface.search.value, '');
});

test('saved nonselected pins remain available and survive pinning a featured tool', () => {
  const storage = new Map([['pf:favs', JSON.stringify(['diff-viewer'])]]);
  const surface = page('curated', { storage });
  surface.pin('email-header-forensics').dispatch('click');
  assert.deepEqual(JSON.parse(storage.get('pf:favs')).sort(), ['diff-viewer', 'email-header-forensics'].sort());
  surface.clickView('pinned');
  assert.deepEqual(surface.visible().sort(), ['diff-viewer', 'email-header-forensics'].sort());
  surface.pin('diff-viewer').dispatch('click');
  assert.equal(surface.state.activeElement, surface.search);
  assert.deepEqual(surface.visible(), ['email-header-forensics']);
  const fresh = page('archive', { storage, url: 'https://example.test/tools/all/?filter=pinned' });
  assert.deepEqual(fresh.visible(), ['email-header-forensics']);
});

test('open curated/archive pages observe external pins and do not overwrite newer saved pins', () => {
  const storage = new Map();
  const curated = page('curated', { storage });
  const archive = page('archive', { storage });
  curated.pin('email-header-forensics').dispatch('click');
  // Exercise the re-read before mutation even if the browser storage event has
  // not arrived yet; a stale archive should not clobber the earlier pin.
  archive.pin('diff-viewer').dispatch('click');
  assert.deepEqual(JSON.parse(storage.get('pf:favs')).sort(), ['diff-viewer', 'email-header-forensics'].sort());
  curated.window.dispatch('storage', { key: 'pf:favs' });
  assert.equal(curated.pin('diff-viewer').getAttribute('aria-pressed'), 'true');
  archive.window.dispatch('storage', { key: 'pf:favs' });
  assert.equal(archive.pin('email-header-forensics').getAttribute('aria-pressed'), 'true');
  storage.delete('pf:favs');
  for (const surface of [curated, archive]) surface.window.dispatch('storage', { key: null });
  assert.equal(curated.byId('pinCount').textContent, '0');
  assert.equal(archive.byId('cntPinned').textContent, '0');
});

test('unavailable storage leaves pins usable for the current page and explains persistence limits', () => {
  const surface = page('curated', { failRead: true, failWrite: true });
  surface.pin('key-converter').dispatch('click');
  surface.pin('redos-tester').dispatch('click');
  surface.clickView('pinned');
  assert.deepEqual(surface.visible().sort(), ['key-converter', 'redos-tester'].sort());
  assert.match(surface.byId('pinNote').textContent, /last until you leave/);
});

test('write-only storage failure does not discard earlier temporary pins on the next click', () => {
  const surface = page('curated', { failWrite: true });
  surface.pin('key-converter').dispatch('click');
  surface.pin('redos-tester').dispatch('click');
  surface.clickView('pinned');
  assert.deepEqual(surface.visible().sort(), ['key-converter', 'redos-tester'].sort());
});
