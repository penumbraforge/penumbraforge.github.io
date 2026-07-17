/* ============================================================
   Penumbra Forge — Local AI Engine
   One abstraction, three engines, all private:
     • webgpu — runs a real LLM in your browser (WebLLM). Nothing uploaded.
     • local  — talks to YOUR local server (Ollama / LM Studio / any
                OpenAI-compatible endpoint). Model runs on your hardware.
     • cloud  — bring-your-own key; sent only to the endpoint you choose.
   Config persists in localStorage ('pf:ai'). Output is always TEXT —
   callers must never eval/inject it. Streaming + cancel via AbortSignal.
   API (window.PenumbraAI):
     cfg() -> config object          save(cfg)
     hasWebGPU() -> bool             defaults
     chat({messages, onToken, signal, temperature, model, onProgress}) -> Promise<string>
     embed(texts[], {onProgress}) -> Promise<number[][]>
     probe() -> Promise<{ok, detail}>   // test the active engine
   ============================================================ */
window.PenumbraAI = (function () {
  var LS = 'pf:ai';
  var defaults = {
    engine: 'webgpu',
    webgpuModel: 'Llama-3.2-1B-Instruct-q4f16_1-MLC',
    webgpuEmbedModel: 'snowflake-arctic-embed-m-q0f32-MLC-b4',
    localUrl: 'http://localhost:11434',
    localModel: 'llama3.2',
    localEmbedModel: 'nomic-embed-text',
    cloudBase: 'https://api.openai.com/v1',
    cloudKey: '',
    cloudModel: 'gpt-4o-mini',
    cloudEmbedModel: 'text-embedding-3-small'
  };

  function cfg() {
    try { return Object.assign({}, defaults, JSON.parse(localStorage.getItem(LS) || '{}')); }
    catch (e) { return Object.assign({}, defaults); }
  }
  function save(c) { try { localStorage.setItem(LS, JSON.stringify(c)); } catch (e) {} return c; }
  function hasWebGPU() { return typeof navigator !== 'undefined' && 'gpu' in navigator; }

  // ---- WebGPU (in-browser) via vendored WebLLM ----
  var _webllm = null, _engine = null, _engineModel = null, _embedEngine = null, _embedModel = null;
  function loadWebLLM() {
    if (_webllm) return Promise.resolve(_webllm);
    return import('/js/vendor/web-llm.js').then(function (m) { _webllm = m; return m; });
  }
  function ensureEngine(model, onProgress) {
    if (!hasWebGPU()) return Promise.reject(new Error('WebGPU is not available in this browser. Switch to a local server or an API key in AI settings.'));
    if (_engine && _engineModel === model) return Promise.resolve(_engine);
    return loadWebLLM().then(function (webllm) {
      var opts = { initProgressCallback: function (p) { onProgress && onProgress({ stage: 'load', text: p.text || 'Loading model…', progress: p.progress || 0 }); } };
      return webllm.CreateMLCEngine(model, opts).then(function (eng) { _engine = eng; _engineModel = model; return eng; });
    });
  }
  function ensureEmbed(model, onProgress) {
    if (!hasWebGPU()) return Promise.reject(new Error('WebGPU not available.'));
    if (_embedEngine && _embedModel === model) return Promise.resolve(_embedEngine);
    return loadWebLLM().then(function (webllm) {
      var opts = { initProgressCallback: function (p) { onProgress && onProgress({ stage: 'load', text: p.text || 'Loading embeddings…', progress: p.progress || 0 }); } };
      return webllm.CreateMLCEngine(model, opts).then(function (eng) { _embedEngine = eng; _embedModel = model; return eng; });
    });
  }

  // ---- OpenAI-compatible (local + cloud) ----
  function endpoint(c) {
    if (c.engine === 'local') return c.localUrl.replace(/\/+$/, '') + '/v1';
    return c.cloudBase.replace(/\/+$/, '');
  }
  function headers(c) {
    var h = { 'Content-Type': 'application/json' };
    if (c.engine === 'cloud' && c.cloudKey) h['Authorization'] = 'Bearer ' + c.cloudKey;
    return h;
  }

  async function chat(opts) {
    opts = opts || {};
    var c = cfg();
    var messages = opts.messages || [];
    var onToken = opts.onToken || function () {};
    var signal = opts.signal;
    var temperature = (opts.temperature != null) ? opts.temperature : 0.7;

    if (c.engine === 'webgpu') {
      var eng = await ensureEngine(opts.model || c.webgpuModel, opts.onProgress);
      var stream = await eng.chat.completions.create({ messages: messages, temperature: temperature, stream: true });
      var full = '';
      for await (var chunk of stream) {
        if (signal && signal.aborted) { try { await eng.interruptGenerate(); } catch (e) {} break; }
        var t = (chunk.choices && chunk.choices[0] && chunk.choices[0].delta && chunk.choices[0].delta.content) || '';
        if (t) { full += t; onToken(t); }
      }
      return full;
    }

    var model = opts.model || (c.engine === 'local' ? c.localModel : c.cloudModel);
    var res = await fetch(endpoint(c) + '/chat/completions', {
      method: 'POST', headers: headers(c), signal: signal,
      body: JSON.stringify({ model: model, messages: messages, temperature: temperature, stream: true })
    });
    if (!res.ok) {
      var errtxt = await res.text().catch(function () { return res.statusText; });
      throw new Error('Engine error ' + res.status + ': ' + errtxt.slice(0, 240));
    }
    var reader = res.body.getReader(), dec = new TextDecoder(), buf = '', out = '';
    while (true) {
      var r = await reader.read(); if (r.done) break;
      buf += dec.decode(r.value, { stream: true });
      var idx;
      while ((idx = buf.indexOf('\n')) >= 0) {
        var line = buf.slice(0, idx).trim(); buf = buf.slice(idx + 1);
        if (line.slice(0, 5) !== 'data:') continue;
        var data = line.slice(5).trim();
        if (data === '[DONE]') { return out; }
        try { var j = JSON.parse(data); var tt = j.choices && j.choices[0] && j.choices[0].delta && j.choices[0].delta.content; if (tt) { out += tt; onToken(tt); } } catch (e) {}
      }
    }
    return out;
  }

  async function embed(texts, opts) {
    opts = opts || {};
    var c = cfg();
    if (c.engine === 'webgpu') {
      var eng = await ensureEmbed(c.webgpuEmbedModel, opts.onProgress);
      var resp = await eng.embeddings.create({ input: texts });
      return resp.data.map(function (d) { return d.embedding; });
    }
    var model = c.engine === 'local' ? c.localEmbedModel : c.cloudEmbedModel;
    var res = await fetch(endpoint(c) + '/embeddings', {
      method: 'POST', headers: headers(c),
      body: JSON.stringify({ model: model, input: texts })
    });
    if (!res.ok) { var e = await res.text().catch(function () { return res.statusText; }); throw new Error('Embed error ' + res.status + ': ' + e.slice(0, 200)); }
    var j = await res.json();
    return j.data.map(function (d) { return d.embedding; });
  }

  async function probe() {
    var c = cfg();
    try {
      if (c.engine === 'webgpu') {
        if (!hasWebGPU()) return { ok: false, detail: 'WebGPU not supported by this browser.' };
        return { ok: true, detail: 'WebGPU available. Model downloads on first use.' };
      }
      if (c.engine === 'local') {
        var res = await fetch(c.localUrl.replace(/\/+$/, '') + '/v1/models', { headers: headers(c) });
        if (res.ok) { var j = await res.json().catch(function () { return {}; }); var n = (j.data && j.data.length) || 0; return { ok: true, detail: 'Connected to local server' + (n ? ' · ' + n + ' models' : '') + '.' }; }
        return { ok: false, detail: 'Local server responded ' + res.status + '. Is it running with CORS enabled?' };
      }
      if (!c.cloudKey) return { ok: false, detail: 'Add an API key.' };
      var r2 = await fetch(c.cloudBase.replace(/\/+$/, '') + '/models', { headers: headers(c) });
      return r2.ok ? { ok: true, detail: 'API key accepted.' } : { ok: false, detail: 'API responded ' + r2.status + '.' };
    } catch (e) {
      return { ok: false, detail: (c.engine === 'local'
        ? 'Could not reach ' + c.localUrl + '. Start Ollama/LM Studio and allow this origin (OLLAMA_ORIGINS).'
        : 'Request failed: ' + e.message) };
    }
  }

  function cosine(a, b) { var d = 0, na = 0, nb = 0; for (var i = 0; i < a.length; i++) { d += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; } return d / (Math.sqrt(na) * Math.sqrt(nb) + 1e-9); }

  return { cfg: cfg, save: save, chat: chat, embed: embed, probe: probe, hasWebGPU: hasWebGPU, ensureEngine: ensureEngine, cosine: cosine, defaults: defaults };
})();
