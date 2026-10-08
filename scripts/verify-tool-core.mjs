// Run with: node --test scripts/verify-tool-core.mjs
// Exercises the actual inline functions, with real isolated worker threads for timing.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Worker as NodeWorker } from 'node:worker_threads';
import vm from 'node:vm';
import test from 'node:test';
import yaml from 'js-yaml';

const redosWorkerSource = readFileSync(new URL('../src/js/redos-timing-worker.js', import.meta.url), 'utf8');
const redos = readFileSync(new URL('../src/tools/redos-tester.njk', import.meta.url), 'utf8');
const email = readFileSync(new URL('../src/tools/email-header-forensics.njk', import.meta.url), 'utf8');
const sigma = readFileSync(new URL('../src/tools/sigma-rule-builder.njk', import.meta.url), 'utf8');
function section(source, start, end) {
  const from = source.indexOf(start);
  const to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, 'Source section exists');
  return source.slice(from, to);
}

test('all three complete inline scripts parse', () => {
  for (const source of [redos, sigma, email]) {
    const script = source.slice(source.indexOf('<script>') + '<script>'.length, source.lastIndexOf('</script>'));
    assert.doesNotThrow(() => new vm.Script(script));
  }
});

// Adapt the Web Worker transport; the tool's worker body and deadline logic are unchanged.
class BrowserWorker {
  constructor(url) {
    assert.equal(new URL(url, 'https://penumbraforge.com').pathname, '/js/redos-timing-worker.js');
    this.worker = new NodeWorker(`
      const { parentPort } = require('node:worker_threads');
      global.self = { postMessage: data => parentPort.postMessage(data) };
      parentPort.on('message', data => self.onmessage({ data }));
      ${redosWorkerSource}
    `, { eval: true });
    this.worker.on('message', data => this.onmessage?.({ data }));
    this.worker.on('error', error => this.onerror?.({ message: error.message, preventDefault() {} }));
  }
  postMessage(data) { this.worker.postMessage(data); }
  terminate() { this.worker.terminate(); }
}
function redosApi(worker = BrowserWorker) {
  const context = vm.createContext({ Worker: worker, setTimeout, clearTimeout });
  vm.runInContext(section(redos, '  /* Isolated timing helpers */', '  function esc(s)'), context);
  return context;
}

test('ReDoS uses the same-origin static worker without Blob or inline-source transport', () => {
  assert.doesNotThrow(() => new vm.Script(redosWorkerSource));
  assert.match(redos, /new Worker\('\/js\/redos-timing-worker\.js\?v=\{\{ assetv \}\}'\)/);
  assert.doesNotMatch(redos, /createObjectURL|new Blob|timingWorker\.toString/);
});

test('every increasing stress sample retains the chosen failure suffix', () => {
  const samples = redosApi().buildSamples('1', '!');
  assert.equal(samples.length, 12);
  assert.equal(samples[0].input, 'test');
  let lastLength = 0;
  for (const sample of samples.slice(1)) {
    assert.match(sample.input, /^1+!$/);
    assert.ok(sample.input.length > lastLength);
    lastLength = sample.input.length;
  }
  assert.equal(lastLength, 129);
});

test('safe samples finish and global regex state is reset per sample', async () => {
  const outcome = await redosApi().runSamples('a+', 'g', [
    { label: 'one', input: 'aaa' }, { label: 'two', input: 'aaa' }
  ]).promise;
  assert.equal(outcome.status, 'complete');
  assert.equal(outcome.results.length, 2);
  assert.ok(outcome.results.every(r => r.matched && Number.isFinite(r.duration)));
});

test('catastrophic regex is terminated while the calling thread remains responsive', async () => {
  let ticks = 0;
  const interval = setInterval(() => ticks++, 10);
  const started = performance.now();
  try {
    const outcome = await redosApi().runSamples('(a+)+$', '', [
      { label: 'catastrophic', input: 'a'.repeat(128) + '!' },
      { label: 'must not run', input: 'a' }
    ]).promise;
    assert.equal(outcome.status, 'timeout');
    assert.equal(outcome.results.length, 1);
    assert.equal(outcome.results[0].timeout, true);
    assert.ok(ticks >= 10, `Main thread ticked ${ticks} times during blocked worker`);
    assert.ok(performance.now() - started < 1800, 'Termination respects bounded time');
  } finally { clearInterval(interval); }
});

test('invalid syntax and unsupported flags are errors inside the worker', async () => {
  for (const [pattern, flags] of [['(', ''], ['a', 'z']]) {
    const outcome = await redosApi().runSamples(pattern, flags, [{ label: 'none', input: 'a' }]).promise;
    assert.equal(outcome.status, 'syntax-error');
    assert.equal(outcome.results.length, 0);
    assert.ok(outcome.message);
  }
});

test('missing or blocked Workers never execute a main-thread fallback', async () => {
  for (const Worker of [undefined, class { constructor() { throw new Error('CSP blocks worker'); } }]) {
    const api = redosApi(Worker);
    // Explicitly set undefined; the helper's default parameter supplies a real worker otherwise.
    api.Worker = Worker;
    api.RegExp = class { constructor() { assert.fail('Regex executed on caller'); } };
    const outcome = await api.runSamples('(a+)+$', '', [{ input: 'a'.repeat(128) + '!' }]).promise;
    assert.equal(outcome.status, 'unavailable');
    assert.equal(outcome.results.length, 0);
  }
});

test('cancelling an active run settles and stops it', async () => {
  const run = redosApi().runSamples('(a+)+$', '', [{ input: 'a'.repeat(128) + '!' }]);
  run.cancel();
  assert.equal((await run.promise).status, 'cancelled');
});

function row(key, mod, value) {
  const selectors = { '.srb-kv-key': key, '.srb-kv-modifier': mod, '.srb-kv-val': value };
  return { querySelector: selector => ({ value: selectors[selector] }) };
}
function group(name, logic, rows) {
  return {
    querySelector: selector => ({ value: selector === '.srb-group-name-input' ? name : logic }),
    querySelectorAll: () => rows
  };
}
function sigmaApi(groups = []) {
  const context = vm.createContext({ groupsEl: { querySelectorAll: () => groups } });
  vm.runInContext(section(sigma, '  function indentLines(', '  // ─── Preview / validation'), context);
  return context;
}

test('Sigma AND emits a map requiring both fields; OR emits alternatives', () => {
  const api = sigmaApi();
  const fields = { 'Image|endswith': ['powershell.exe'], 'CommandLine|contains': ['-enc', '-nop'] };
  for (const logic of ['AND', 'OR']) {
    const parsed = yaml.load(api.buildDetectionYaml({ selection: { logic, fields } }, 'selection'));
    assert.equal(parsed.detection.condition, 'selection');
    if (logic === 'AND') assert.deepEqual(parsed.detection.selection, { 'Image|endswith': 'powershell.exe', 'CommandLine|contains': ['-enc', '-nop'] });
    else assert.deepEqual(parsed.detection.selection, [
      { 'Image|endswith': ['powershell.exe'] }, { 'CommandLine|contains': ['-enc', '-nop'] }
    ].map(object => Object.fromEntries(Object.entries(object).map(([key, value]) => [key, value.length === 1 ? value[0] : value]))));
  }
});

test('Sigma preserves condition negation, all modifier, regex pipes and typed-looking strings', () => {
  const api = sigmaApi([
    group('selection', 'AND', [row('CommandLine', 're', '(foo|bar)'), row('Name', '=', 'null')]),
    group('filter', 'AND', [row('CommandLine', 'contains|all', '001'), row('CommandLine', 'contains|all', "it's #literal")])
  ]);
  const parsed = yaml.load(api.buildDetectionYaml(api.collectDetection(), 'selection and not filter'));
  assert.equal(parsed.detection.condition, 'selection and not filter');
  assert.equal(parsed.detection.selection['CommandLine|re'], '(foo|bar)');
  assert.equal(parsed.detection.selection.Name, 'null');
  assert.deepEqual(parsed.detection.filter['CommandLine|contains|all'], ['001', "it's #literal"]);
});

test('Sigma all modifier stays a list even with one value', () => {
  const api = sigmaApi();
  const parsed = yaml.load(api.buildDetectionYaml({ selection: { logic: 'AND', fields: { 'Name|contains|all': ['one'] } } }, 'selection'));
  assert.deepEqual(parsed.detection.selection['Name|contains|all'], ['one']);
});

test('Sigma rejects duplicate groups, missing rows and modifiers entered as field names', () => {
  const valid = group('selection', 'AND', [row('Image', 'contains', 'example')]);
  for (const groups of [[], [valid, valid], [group('selection', 'AND', [])], [group('selection', 'AND', [row('Image|endswith', 'endswith', 'exe')])]]) {
    assert.throws(() => sigmaApi(groups).collectDetection());
  }
});

test('Sigma never offers the inaccurate SIEM translations and actions rebuild the form', () => {
  assert.doesNotMatch(sigma, /function exportTo(?:Splunk|Kql|Esql)|id="srb-export-select"/);
  assert.match(sigma, /SIEM query export is unavailable/);
  for (const button of ['copyYamlBtn', 'downloadBtn']) {
    const handler = section(sigma, `  ${button}.addEventListener('click'`, '\n  });');
    assert.match(handler, /if \(!refreshPreview\(true\)\) return;/);
  }
  assert.doesNotMatch(sigma, /key: '(?:Image\|endswith|CommandLine\|contains)'/);
});


test('complete Sigma draft parses and preserves title/date/condition as strings', () => {
  const api = sigmaApi([group('selection', 'AND', [row('Image', 'endswith', 'example.exe')])]);
  const values = {
    titleEl: 'null', statusEl: 'experimental', levelEl: 'medium', descEl: 'A sample rule.',
    authorEl: 'Test', dateEl: '2026-10-08', tagsEl: 'T1059.001', lsCatEl: 'process_creation',
    lsProdEl: 'windows', lsSvcEl: '', condEl: 'selection', falseposEl: 'A known case'
  };
  for (const [key, value] of Object.entries(values)) api[key] = { value };
  const result = api.buildYaml();
  assert.equal(result.ok, true);
  const parsed = yaml.load(result.yaml);
  assert.equal(parsed.title, 'null');
  assert.equal(parsed.date, '2026-10-08');
  assert.equal(parsed.detection.condition, 'selection');
  assert.equal(parsed.detection.selection['Image|endswith'], 'example.exe');
  api.dateEl.value = '2026/10/08';
  assert.equal(api.buildYaml().ok, false);
});


function emailApi() {
  const context = vm.createContext({ authEl: { innerHTML: '' }, assessEl: { innerHTML: '' } });
  vm.runInContext(section(email, '  function parseHeaders(', '  /* ── Format delay'), context);
  vm.runInContext(section(email, '  function renderOverview(', '  function renderTimeline('), context);
  context.escHtml = value => String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
  return context;
}

test('authentication records preserve each server without cross-record method fallback', () => {
  const api = emailApi();
  const raw = [
    'Authentication-Results: trusted.example; spf=fail smtp.mailfrom=sender.example;',
    '  dkim=pass header.d=sender.example; dmarc=fail header.from=sender.example',
    'Authentication-Results: forwarder.example; spf=pass smtp.mailfrom=list.example',
    'Received-SPF: neutral (a separate record); receiver=legacy.example;',
    '  client-ip=192.0.2.1'
  ].join('\r\n');
  const records = api.parseAuth(api.parseHeaders(raw));
  assert.equal(records.length, 3);
  assert.equal(records[0].source, 'trusted.example');
  assert.equal(records[1].source, 'forwarder.example');
  assert.equal(records[2].source, 'legacy.example');
  assert.deepEqual(Array.from(records[0].claims, c => [c.method, c.result]), [['spf', 'fail'], ['dkim', 'pass'], ['dmarc', 'fail']]);
  assert.deepEqual(Array.from(records[1].claims, c => [c.method, c.result]), [['spf', 'pass']]);
  assert.deepEqual(Array.from(records[2].claims, c => [c.method, c.result]), [['spf', 'neutral']]);
  assert.ok(records[0].raw.includes('header.d=sender.example'));
  assert.equal(records[2].headerIndex, 3);
  assert.equal(records.spf, undefined, 'No synthetic combined result');
});

test('multiple DKIM claims in one record remain distinct; comments and quoted properties do not create methods', () => {
  const api = emailApi();
  const records = api.parseAuth(api.parseHeaders([
    'Authentication-Results: mx.example (comment; spf=fail);',
    ' dkim=pass (nested (comment; dmarc=fail)) header.d=one.example;',
    ' dkim=fail reason="spf=pass; dmarc=pass" header.d=two.example'
  ].join('\n')));
  assert.equal(records.length, 1);
  assert.equal(records[0].source, 'mx.example');
  assert.deepEqual(Array.from(records[0].claims, c => [c.method, c.result]), [['dkim', 'pass'], ['dkim', 'fail']]);
  assert.ok(records[0].claims[0].raw.includes('one.example'));
  assert.ok(records[0].claims[1].raw.includes('two.example'));
});

test('header parser stops before body-injected authentication fields', () => {
  const api = emailApi();
  const headers = api.parseHeaders('From: sender@example.test\r\nAuthentication-Results: mx.example; spf=fail\r\n\r\nAuthentication-Results: forged.example; spf=pass');
  assert.equal(headers.length, 2);
  const records = api.parseAuth(headers);
  assert.equal(records.length, 1);
  assert.equal(records[0].source, 'mx.example');
});

test('malformed, empty and no-result authentication records do not throw or imply a pass', () => {
  const api = emailApi();
  const records = api.parseAuth(api.parseHeaders([
    'Authentication-Results: ""; none',
    'Authentication-Results: mx.example; dkim=pass (unclosed',
    'Authentication-Results: mx.example; spf=pass=fail',
    'Received-SPF: none; receiver=""'
  ].join('\n')));
  assert.equal(records.length, 4);
  assert.equal(records[0].source, '');
  assert.equal(records[0].claims[0].result, 'none');
  assert.equal(records[1].claims.length, 0);
  assert.ok(records[1].warning);
  assert.equal(records[2].claims.length, 0);
  assert.equal(records[2].unparsed.length, 1);
  assert.equal(records[3].source, '');
});

test('authentication UI keeps record identities and raw source, escapes input, and offers no score', () => {
  const api = emailApi();
  const headers = api.parseHeaders('Authentication-Results: "<img src=x>"; spf=pass smtp.mailfrom=sender.example\nAuthentication-Results: second.example; dkim=fail header.d=other.example');
  const records = api.parseAuth(headers);
  api.renderAuth(records);
  assert.equal((api.authEl.innerHTML.match(/<article /g) || []).length, 2);
  assert.ok(api.authEl.innerHTML.includes('&lt;img src=x&gt;'));
  assert.ok(!api.authEl.innerHTML.includes('<img src=x>'));
  assert.ok(api.authEl.innerHTML.includes('second.example'));
  assert.ok(api.authEl.innerHTML.includes('Original header field'));
  assert.ok(api.authEl.innerHTML.includes('can be forged'));
  api.renderOverview(headers, [], records);
  assert.ok(api.assessEl.innerHTML.includes('2 authentication fields'));
  assert.doesNotMatch(email, /Rule score:|HEURISTIC SCORE|function assessPhishing/);
});


test('email indicators exclude auth assignment keys while retaining actual domain values', () => {
  const api = emailApi();
  const indicators = api.extractIOCs([
    'Authentication-Results: mx.recipient.example; spf=fail smtp.mailfrom=sender@billing.example;',
    ' dmarc=fail header.from = billing.example; dkim=pass header.d=signer.example;',
    ' iprev=pass policy.iprev=reverse.example;',
    ' smtp.auth=identity.example body.hash=hash.example',
    'X-Example-Domain: header.from',
    'X-Other-Domain: smtp.mailfrom'
  ].join('\n'));
  assert.deepEqual(Array.from(indicators.domains), [
    'mx.recipient.example', 'billing.example', 'signer.example', 'reverse.example',
    'identity.example', 'hash.example', 'header.from', 'smtp.mailfrom'
  ]);
  const assignedOnly = api.extractIOCs('smtp.mailfrom=sender@billing.example header.from=billing.example smtp.auth=identity.example policy.iprev=reverse.example body.hash=hash.example');
  for (const key of ['smtp.mailfrom', 'header.from', 'smtp.auth', 'policy.iprev', 'body.hash']) assert.ok(!assignedOnly.domains.includes(key));
  assert.deepEqual(Array.from(assignedOnly.emails), ['sender@billing.example']);
});

test('email IPv4 indicators reject invalid octets and retain valid boundary values', () => {
  const indicators = emailApi().extractIOCs('192.0.2.1 198.51.100.25 203.0.113.156 999.2.3.4 192.256.2.1 1.2.3.999 0.0.0.0 255.255.255.255 192.0.2.1');
  assert.deepEqual(Array.from(indicators.ips), ['192.0.2.1', '198.51.100.25', '203.0.113.156', '0.0.0.0', '255.255.255.255']);
});

test('synthetic email example uses only reserved domains and documentation IPv4 ranges', () => {
  const api = emailApi();
  vm.runInContext(section(email, '  var EXAMPLE_HEADERS =', '  /* ── Header parser'), api);
  const indicators = api.extractIOCs(api.EXAMPLE_HEADERS);
  assert.ok(indicators.domains.length > 0);
  assert.ok(indicators.domains.every(domain => domain.endsWith('.example')));
  assert.ok(indicators.emails.every(address => address.endsWith('.example')));
  assert.ok(indicators.ips.every(ip => /^(192\.0\.2|198\.51\.100|203\.0\.113)\./.test(ip)));
  assert.ok(api.EXAMPLE_HEADERS.includes('security@billing.example'));
  assert.ok(api.EXAMPLE_HEADERS.includes('verify-account-now@billing-update.example'));
  assert.ok(api.EXAMPLE_HEADERS.includes('dkim=fail'));
  assert.match(email, /example is synthetic/);
});
