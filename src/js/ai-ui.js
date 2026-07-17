/* ============================================================
   Penumbra Forge — shared AI UI (depends on window.PenumbraAI)
   Reusable pieces so every AI tool is consistent + safe:
     PenumbraAIUI.mountBar(el)            → trust + engine + settings bar
     PenumbraAIUI.openSettings()          → engine settings modal
     PenumbraAIUI.stream(outEl, opts)     → run chat, stream TEXT into outEl,
                                            with cancel + model-download progress.
                                            opts: {messages, system, temperature,
                                                   onToken, onDone, statusEl, cancelBtn}
     PenumbraAIUI.chat(container, opts)   → full chat widget (Local Chat)
   All model output is inserted with textContent — never HTML.
   ============================================================ */
window.PenumbraAIUI = (function () {
  var AI = window.PenumbraAI;
  var MODELS = [
    { id: 'Llama-3.2-1B-Instruct-q4f16_1-MLC', label: 'Llama 3.2 1B — fast (~0.9 GB)' },
    { id: 'Llama-3.2-3B-Instruct-q4f16_1-MLC', label: 'Llama 3.2 3B — balanced (~2.0 GB)' },
    { id: 'Qwen2.5-1.5B-Instruct-q4f16_1-MLC', label: 'Qwen 2.5 1.5B (~1.2 GB)' },
    { id: 'Phi-3.5-mini-instruct-q4f16_1-MLC', label: 'Phi 3.5 mini (~2.2 GB)' }
  ];

  function el(tag, cls, txt) { var e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }
  function engineLabel(c) { return c.engine === 'webgpu' ? 'In-browser (WebGPU)' : c.engine === 'local' ? 'Your local server' : 'API key'; }

  // ---- safe, dependency-free markdown renderer (for premium AI output) ----
  function mdEsc(s) { return s.replace(/[&<>]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]; }); }
  function mdInline(s) {
    s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/(^|[\s(])\*([^*\n]+)\*/g, '$1<em>$2</em>');
    s = s.replace(/(^|[\s(])_([^_\n]+)_/g, '$1<em>$2</em>');
    s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
    return s;
  }
  function mdToHtml(src) {
    var lines = String(src).split('\n'), html = '', inCode = false, lang = '', code = [], lt = null, lb = [];
    function flush() { if (lt) { html += '<' + lt + '>' + lb.map(function (x) { return '<li>' + mdInline(mdEsc(x)) + '</li>'; }).join('') + '</' + lt + '>'; lt = null; lb = []; } }
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i], f = line.match(/^```(\w*)/);
      if (f) { if (!inCode) { flush(); inCode = true; lang = f[1]; code = []; } else { html += '<pre class="ai-code"' + (lang ? ' data-lang="' + mdEsc(lang) + '"' : '') + '><code>' + mdEsc(code.join('\n')) + '</code></pre>'; inCode = false; } continue; }
      if (inCode) { code.push(line); continue; }
      var h = line.match(/^(#{1,4})\s+(.*)/);
      if (h) { flush(); var lv = Math.min(h[1].length + 2, 5); html += '<h' + lv + '>' + mdInline(mdEsc(h[2])) + '</h' + lv + '>'; continue; }
      var ul = line.match(/^\s*[-*+]\s+(.*)/), ol = line.match(/^\s*\d+\.\s+(.*)/);
      if (ul) { if (lt !== 'ul') { flush(); lt = 'ul'; } lb.push(ul[1]); continue; }
      if (ol) { if (lt !== 'ol') { flush(); lt = 'ol'; } lb.push(ol[1]); continue; }
      if (/^\s*>\s?/.test(line)) { flush(); html += '<blockquote>' + mdInline(mdEsc(line.replace(/^\s*>\s?/, ''))) + '</blockquote>'; continue; }
      if (line.trim() === '') { flush(); continue; }
      flush(); html += '<p>' + mdInline(mdEsc(line)) + '</p>';
    }
    if (inCode) html += '<pre class="ai-code"><code>' + mdEsc(code.join('\n')) + '</code></pre>';
    flush(); return html;
  }

  // ---- Settings modal ----
  var modal = null;
  function openSettings(onSaved) {
    var c = AI.cfg();
    if (modal) modal.remove();
    modal = el('div', 'ai-modal-bd');
    var box = el('div', 'ai-modal');
    box.innerHTML =
      '<div class="ai-modal-h"><span>AI engine</span><button class="ai-x" aria-label="Close">&times;</button></div>' +
      '<div class="ai-seg" role="tablist">' +
        '<button data-eng="webgpu">In-browser</button>' +
        '<button data-eng="local">Local server</button>' +
        '<button data-eng="cloud">API key</button>' +
      '</div>' +
      '<div class="ai-fields"></div>' +
      '<div class="ai-modal-f"><button class="ai-test">Test connection</button><span class="ai-test-out"></span><button class="ai-save">Save</button></div>';
    modal.appendChild(box);
    document.body.appendChild(modal);

    var fields = box.querySelector('.ai-fields');
    var seg = box.querySelectorAll('.ai-seg button');
    var cur = c.engine;
    function paintSeg() { seg.forEach(function (b) { b.classList.toggle('on', b.dataset.eng === cur); }); }
    function renderFields() {
      if (cur === 'webgpu') {
        fields.innerHTML =
          '<label>Model</label><select class="f-webgpuModel">' + MODELS.map(function (m) { return '<option value="' + m.id + '"' + (m.id === c.webgpuModel ? ' selected' : '') + '>' + m.label + '</option>'; }).join('') + '</select>' +
          '<p class="ai-hint">Runs a real LLM <b>inside your browser</b> on your GPU. The model downloads once (from Hugging Face) and is cached; after that it works offline. Nothing you type is ever uploaded. Requires a WebGPU browser (Chrome/Edge/Safari 2024+).' + (AI.hasWebGPU() ? '' : ' <b style="color:#e8a87c">WebGPU not detected in this browser.</b>') + '</p>';
      } else if (cur === 'local') {
        fields.innerHTML =
          '<label>Server URL</label><input class="f-localUrl" value="' + c.localUrl + '" spellcheck="false">' +
          '<label>Model name</label><input class="f-localModel" value="' + c.localModel + '" spellcheck="false">' +
          '<p class="ai-hint">Talks to <b>your own</b> Ollama / LM Studio / llama.cpp server. The model runs on <b>your</b> hardware; this page only sends requests to your machine. For Ollama, allow this site once: <code>OLLAMA_ORIGINS=https://penumbraforge.com ollama serve</code>.</p>';
      } else {
        fields.innerHTML =
          '<label>API base URL</label><input class="f-cloudBase" value="' + c.cloudBase + '" spellcheck="false">' +
          '<label>API key</label><input type="password" class="f-cloudKey" value="' + c.cloudKey + '" placeholder="sk-…" spellcheck="false">' +
          '<label>Model</label><input class="f-cloudModel" value="' + c.cloudModel + '" spellcheck="false">' +
          '<p class="ai-hint">Any OpenAI-compatible endpoint. Your key is stored <b>only in this browser</b> (localStorage) and sent only to the URL above — never to us.</p>';
      }
    }
    paintSeg(); renderFields();
    seg.forEach(function (b) { b.addEventListener('click', function () { cur = b.dataset.eng; paintSeg(); renderFields(); }); });

    function collect() {
      var n = Object.assign({}, c, { engine: cur });
      box.querySelectorAll('[class^="f-"]').forEach(function (inp) { var key = inp.className.replace(/^f-/, ''); n[key] = inp.value.trim(); });
      return n;
    }
    box.querySelector('.ai-test').addEventListener('click', function () {
      var out = box.querySelector('.ai-test-out'); out.textContent = 'Testing…'; out.className = 'ai-test-out';
      AI.save(collect());
      AI.probe().then(function (r) { out.textContent = r.detail; out.className = 'ai-test-out ' + (r.ok ? 'ok' : 'bad'); });
    });
    box.querySelector('.ai-save').addEventListener('click', function () { AI.save(collect()); close(); onSaved && onSaved(AI.cfg()); });
    box.querySelector('.ai-x').addEventListener('click', close);
    modal.addEventListener('click', function (e) { if (e.target === modal) close(); });
    function close() { if (modal) { modal.remove(); modal = null; } }
  }

  // ---- Trust + engine bar ----
  function mountBar(host) {
    var c = AI.cfg();
    var bar = el('div', 'ai-bar');
    bar.innerHTML =
      '<span class="ai-shield">✦</span>' +
      '<span class="ai-bar-txt"><b>Local AI.</b> Runs on your machine — 0 servers, 0 signup, nothing uploaded.</span>' +
      '<span class="ai-bar-engine"></span>' +
      '<button class="ai-bar-cog">Engine ▾</button>';
    host.appendChild(bar);
    function paint() { bar.querySelector('.ai-bar-engine').textContent = engineLabel(AI.cfg()); }
    paint();
    bar.querySelector('.ai-bar-cog').addEventListener('click', function () { openSettings(paint); });
    return { refresh: paint };
  }

  // ---- Stream helper ----
  function stream(outEl, opts) {
    opts = opts || {};
    var msgs = opts.messages || [];
    if (opts.system) msgs = [{ role: 'system', content: opts.system }].concat(msgs);
    var ac = new AbortController();
    var status = opts.statusEl;
    var acc = '', lastRender = 0;
    outEl.innerHTML = '';
    outEl.classList.add('ai-md', 'ai-streaming');
    function render() { outEl.innerHTML = mdToHtml(acc); }
    if (status) { status.textContent = 'Thinking…'; status.className = 'ai-status working'; }
    if (opts.cancelBtn) { opts.cancelBtn.hidden = false; opts.cancelBtn.onclick = function () { ac.abort(); }; }
    var p = AI.chat({
      messages: msgs, temperature: opts.temperature, signal: ac.signal,
      onToken: function (t) { acc += t; var now = Date.now(); if (now - lastRender > 80) { lastRender = now; render(); } opts.onToken && opts.onToken(t, acc); },
      onProgress: function (pr) { if (status) status.textContent = pr.text + (pr.progress ? ' ' + Math.round(pr.progress * 100) + '%' : ''); }
    }).then(function (full) {
      render(); outEl.classList.remove('ai-streaming');
      if (status) { status.textContent = ''; status.className = 'ai-status'; }
      if (opts.cancelBtn) opts.cancelBtn.hidden = true;
      opts.onDone && opts.onDone(full);
      return full;
    }).catch(function (e) {
      if (opts.cancelBtn) opts.cancelBtn.hidden = true;
      if (e.name === 'AbortError') { if (status) { status.textContent = 'Stopped.'; status.className = 'ai-status'; } return acc; }
      if (status) { status.textContent = ''; status.className = 'ai-status'; }
      var err = el('div', 'tool-error'); err.textContent = e.message + '  —  Check AI settings (Engine ▾).';
      outEl.textContent = ''; outEl.appendChild(err);
      throw e;
    });
    return { promise: p, abort: function () { ac.abort(); } };
  }

  // ---- Full chat widget ----
  function chat(container, opts) {
    opts = opts || {};
    container.classList.add('ai-chat');
    var log = el('div', 'ai-log');
    var form = el('form', 'ai-inputrow');
    form.innerHTML = '<textarea class="ai-in" rows="1" placeholder="' + (opts.placeholder || 'Message your local model…') + '" spellcheck="false"></textarea><button class="ai-send" type="submit">Send</button><button class="ai-stop" type="button" hidden>Stop</button>';
    container.appendChild(log); container.appendChild(form);
    var input = form.querySelector('.ai-in'), sendBtn = form.querySelector('.ai-send'), stopBtn = form.querySelector('.ai-stop');
    var history = [];
    if (opts.system) history.push({ role: 'system', content: opts.system });

    input.addEventListener('input', function () { input.style.height = 'auto'; input.style.height = Math.min(input.scrollHeight, 200) + 'px'; });
    input.addEventListener('keydown', function (e) { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); form.requestSubmit(); } });

    function bubble(role) { var b = el('div', 'ai-msg ai-' + role); var body = el('div', 'ai-msg-body'); b.appendChild(body); log.appendChild(b); log.scrollTop = log.scrollHeight; return body; }

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var text = input.value.trim(); if (!text) return;
      input.value = ''; input.style.height = 'auto';
      bubble('user').textContent = text;
      history.push({ role: 'user', content: text });
      var out = bubble('assistant'); var status = el('span', 'ai-status'); out.parentNode.appendChild(status);
      sendBtn.disabled = true;
      stream(out, {
        messages: history.filter(function (m) { return m.role !== 'system'; }),
        system: opts.system, temperature: opts.temperature, statusEl: status, cancelBtn: stopBtn,
        onToken: function () { log.scrollTop = log.scrollHeight; },
        onDone: function (full) { history.push({ role: 'assistant', content: full }); sendBtn.disabled = false; input.focus(); }
      }).promise.catch(function () { sendBtn.disabled = false; });
    });
    if (opts.starter) { var out = bubble('assistant'); out.textContent = opts.starter; }
    return { history: history };
  }

  return { openSettings: openSettings, mountBar: mountBar, stream: stream, chat: chat, MODELS: MODELS };
})();
