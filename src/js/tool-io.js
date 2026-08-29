/* ============================================================
   Penumbra Forge — Tool I/O contract (agent + human)
   Provides a shared URL-input and result contract for tools that
   explicitly opt in. Other tool pages still expose their descriptor,
   but do not promise automatic execution or a structured result.

   Agent contract:
     1. Navigate to /tools/<slug>/#in=<input>&<param>=<value>.
        Large/binary-safe input may be passed as #inb64=<base64url>.
        Legacy query parameters remain readable, but are sent to the
        hosting/CDN layer before this browser script can process them.
     2. The tool auto-runs and, when finished, sets:
          <html data-pf-ready="1" data-pf-status="ok|error">
          window.PF_RESULT           -> { tool, ok, output, data?, error? }
          <script type="application/json" id="pf-result">…</script>
        and fires document event 'pf:result'.
     3. Read #pf-result (JSON) or window.PF_RESULT.

   API (window.PF):
     input()            -> merged {param: value} from legacy query + hash;
                           hash values win (inb64 decoded to .in)
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
    var query = {}, fragment = {}, out = {};
    try {
      var u = new URL(location.href);
      u.searchParams.forEach(function (v, k) { query[k] = v; out[k] = v; });
      if (location.hash.length > 1) {
        new URLSearchParams(location.hash.slice(1)).forEach(function (v, k) { fragment[k] = v; out[k] = v; });
      }
      var fragmentHasInput = Object.prototype.hasOwnProperty.call(fragment, 'in') || Object.prototype.hasOwnProperty.call(fragment, 'inb64');
      if (fragmentHasInput) {
        out.in = fragment.in != null ? fragment.in : b64urlDecode(fragment.inb64);
      } else if (query.in != null || query.inb64 != null) {
        out.in = query.in != null ? query.in : b64urlDecode(query.inb64);
      }
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
    var u = new URL(location.href);
    u.search = '';
    u.hash = '';
    var fragment = new URLSearchParams();
    Object.keys(params || {}).forEach(function (k) { if (params[k] != null && params[k] !== '') fragment.set(k, params[k]); });
    u.hash = fragment.toString();
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
