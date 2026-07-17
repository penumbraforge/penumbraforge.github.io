/* ============================================================
   Penumbra Forge — Tool I/O contract (agent + human)
   Makes every tool URL-invocable and machine-readable so an AI
   agent can navigate to a tool URL and read a structured result,
   and humans get shareable "here's the exact result" links.

   Agent contract:
     1. GET /tools/<slug>/?in=<input>&<param>=<value>   (params also accepted in the #hash)
        Large/binary-safe input may be passed as ?inb64=<base64url>.
     2. The tool auto-runs and, when finished, sets:
          <html data-pf-ready="1" data-pf-status="ok|error">
          window.PF_RESULT           -> { tool, ok, output, data?, error? }
          <script type="application/json" id="pf-result">…</script>
        and fires document event 'pf:result'.
     3. Read #pf-result (JSON) or window.PF_RESULT.

   API (window.PF):
     input()            -> merged {param: value} from query + hash (inb64 decoded to .in)
     ready(obj)         -> publish a machine-readable result (see shape above)
     fail(msg)          -> publish an error result
     shareUrl(params)   -> absolute URL to this tool with params applied
     slug               -> current tool slug
   ============================================================ */
(function () {
  var root = document.documentElement;
  var slug = (document.querySelector('[data-slug]') || {}).getAttribute ? document.querySelector('[data-slug]').getAttribute('data-slug') : (location.pathname.match(/\/tools\/([^/]+)/) || [])[1] || '';

  function b64urlDecode(s) {
    try {
      s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '=';
      return decodeURIComponent(Array.prototype.map.call(atob(s), function (c) { return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2); }).join(''));
    } catch (e) { return ''; }
  }

  function input() {
    var out = {};
    try {
      var u = new URL(location.href);
      u.searchParams.forEach(function (v, k) { out[k] = v; });
      if (location.hash.length > 1) {
        new URLSearchParams(location.hash.slice(1)).forEach(function (v, k) { if (!(k in out)) out[k] = v; });
      }
      if (out.inb64 != null) out.in = b64urlDecode(out.inb64);
    } catch (e) {}
    return out;
  }

  function publish(obj, status) {
    obj.tool = obj.tool || slug;
    window.PF_RESULT = obj;
    var s = document.getElementById('pf-result');
    if (!s) { s = document.createElement('script'); s.type = 'application/json'; s.id = 'pf-result'; document.body.appendChild(s); }
    s.textContent = JSON.stringify(obj);
    document.querySelectorAll('[data-pf-result]').forEach(function (el) {
      el.textContent = (obj.output != null && typeof obj.output === 'string') ? obj.output : JSON.stringify(obj.data != null ? obj.data : obj, null, 2);
    });
    root.setAttribute('data-pf-ready', '1');
    root.setAttribute('data-pf-status', status);
    try { document.dispatchEvent(new CustomEvent('pf:result', { detail: obj })); } catch (e) {}
  }

  function shareUrl(params) {
    var u = new URL(location.href.split('#')[0]);
    u.search = '';
    Object.keys(params || {}).forEach(function (k) { if (params[k] != null && params[k] !== '') u.searchParams.set(k, params[k]); });
    return u.toString();
  }

  window.PF = {
    slug: slug,
    input: input,
    ready: function (obj) { publish(Object.assign({ ok: true }, obj), 'ok'); },
    fail: function (msg) { publish({ ok: false, error: String(msg) }, 'error'); },
    shareUrl: shareUrl
  };
})();
