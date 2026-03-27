/**
 * Penumbra Forge — Phishing Email Viewer
 *
 * Blue team SOC workstation component. Renders an inbox-style email list
 * with a detail pane showing headers, body, links, and attachments.
 * Analysts can mark emails as phishing/legitimate and extract IOCs.
 */

(function () {
  'use strict';

  /* ════════════════════════════════════════════════════
     State
     ════════════════════════════════════════════════════ */

  var _container = null;
  var _emails = [];
  var _selectedId = null;
  var _onAnalysis = null;
  var _classifications = {};   // emailId -> 'phishing' | 'legitimate'

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

  function findEmail(id) {
    for (var i = 0; i < _emails.length; i++) {
      if (_emails[i].id === id) return _emails[i];
    }
    return null;
  }

  /* ════════════════════════════════════════════════════
     Render — Email List
     ════════════════════════════════════════════════════ */

  function renderList(listEl) {
    listEl.innerHTML = '';
    var title = el('div', 'phish-list-title', 'Reported Emails');
    listEl.appendChild(title);

    _emails.forEach(function (email) {
      var item = el('div', 'phish-email' + (email.id === _selectedId ? ' selected' : ''));
      item.setAttribute('data-email-id', email.id);

      var badge = '';
      if (_classifications[email.id] === 'phishing') {
        badge = '<span class="phish-badge phish-badge-phishing">Phishing</span>';
      } else if (_classifications[email.id] === 'legitimate') {
        badge = '<span class="phish-badge phish-badge-legit">Legit</span>';
      }

      item.innerHTML =
        '<div class="phish-email-from">' + esc(email.fromDisplay || email.from) + '</div>' +
        '<div class="phish-email-subject">' + esc(email.subject) + badge + '</div>' +
        '<div class="phish-email-meta">' +
          '<span>' + esc(email.date) + '</span>' +
          '<span>Reported by: ' + esc(email.reportedBy) + '</span>' +
        '</div>';

      item.addEventListener('click', function () {
        _selectedId = email.id;
        refresh();
      });

      listEl.appendChild(item);
    });
  }

  /* ════════════════════════════════════════════════════
     Render — Email Detail
     ════════════════════════════════════════════════════ */

  function renderDetail(detailEl) {
    detailEl.innerHTML = '';

    if (!_selectedId) {
      detailEl.innerHTML = '<div class="phish-detail-empty">Select an email to view its contents.</div>';
      return;
    }

    var email = findEmail(_selectedId);
    if (!email) return;

    // Subject bar
    var subjectBar = el('div', 'phish-detail-subject');
    subjectBar.innerHTML = '<strong>' + esc(email.subject) + '</strong>' +
      '<span class="phish-detail-date">' + esc(email.date) + '</span>';
    detailEl.appendChild(subjectBar);

    // From / To
    var fromTo = el('div', 'phish-detail-fromto');
    fromTo.innerHTML =
      '<div><span class="phish-field-label">From:</span> <span class="phish-field-val">' + esc(email.fromDisplay || email.from) + '</span></div>' +
      '<div><span class="phish-field-label">To:</span> <span class="phish-field-val">' + esc(email.to) + '</span></div>';
    if (email.from !== (email.fromDisplay || '').replace(/.*</, '').replace(/>.*/, '')) {
      fromTo.innerHTML += '<div class="phish-mismatch-warn">Display name does not match sender address</div>';
    }
    detailEl.appendChild(fromTo);

    // Headers (expandable)
    var headersWrap = el('div', 'phish-headers');
    var headersToggle = el('button', 'phish-headers-toggle', 'Email Headers \u25BC');
    var headersContent = el('div', 'phish-headers-content');
    headersContent.style.display = 'none';

    if (email.headers) {
      var grid = '<div class="phish-headers-grid">';
      Object.keys(email.headers).forEach(function (key) {
        var val = email.headers[key];
        var isFail = /fail/i.test(val) || /none/i.test(val);
        grid += '<div class="phish-header-key">' + esc(key) + '</div>' +
                '<div class="phish-header-val' + (isFail ? ' phish-header-fail' : '') + '">' + esc(val) + '</div>';
      });
      grid += '</div>';
      headersContent.innerHTML = grid;
    }

    headersToggle.addEventListener('click', function () {
      var open = headersContent.style.display !== 'none';
      headersContent.style.display = open ? 'none' : 'block';
      headersToggle.innerHTML = 'Email Headers ' + (open ? '\u25BC' : '\u25B2');
    });

    headersWrap.appendChild(headersToggle);
    headersWrap.appendChild(headersContent);
    detailEl.appendChild(headersWrap);

    // Body
    var bodyPanel = el('div', 'phish-body');
    var bodyTitle = el('div', 'phish-section-title', 'Email Body');
    var bodyContent = el('div', 'phish-body-content');
    // Render body safely — replace actual links with highlighted versions
    var safeBody = sanitizeBody(email.body, email.links || []);
    bodyContent.innerHTML = safeBody;
    bodyPanel.appendChild(bodyTitle);
    bodyPanel.appendChild(bodyContent);
    detailEl.appendChild(bodyPanel);

    // Links
    if (email.links && email.links.length > 0) {
      var linksPanel = el('div', 'phish-links');
      var linksTitle = el('div', 'phish-section-title', 'Extracted URLs');
      linksPanel.appendChild(linksTitle);

      email.links.forEach(function (link) {
        var linkDiv = el('div', 'phish-link' + (link.suspicious ? ' suspicious' : ''));
        linkDiv.innerHTML =
          '<div class="phish-link-text">"' + esc(link.text) + '"</div>' +
          '<div class="phish-link-url">' + esc(link.url) + '</div>' +
          (link.suspicious ? '<span class="phish-link-warn">Suspicious URL</span>' : '');
        linksPanel.appendChild(linkDiv);
      });

      detailEl.appendChild(linksPanel);
    }

    // Attachments
    if (email.attachments && email.attachments.length > 0) {
      var attachPanel = el('div', 'phish-attachments');
      var attachTitle = el('div', 'phish-section-title', 'Attachments');
      attachPanel.appendChild(attachTitle);

      email.attachments.forEach(function (att) {
        var attDiv = el('div', 'phish-attachment');
        attDiv.innerHTML =
          '<span class="phish-att-icon">\uD83D\uDCCE</span>' +
          '<span class="phish-att-name">' + esc(att.name) + '</span>' +
          '<span class="phish-att-meta">' + esc(att.type) + ' \u00B7 ' + esc(att.size) + '</span>' +
          (att.hash ? '<div class="phish-att-hash">SHA256: ' + esc(att.hash) + '</div>' : '');
        attachPanel.appendChild(attDiv);
      });

      detailEl.appendChild(attachPanel);
    }

    // Analysis actions
    var actionsBar = el('div', 'phish-actions');

    var phishBtn = el('button', 'phish-action-btn phish-btn-phishing', 'Mark as Phishing');
    phishBtn.addEventListener('click', function () {
      _classifications[email.id] = 'phishing';
      if (_onAnalysis) _onAnalysis({ type: 'classify', emailId: email.id, classification: 'phishing', isCorrect: email.isPhishing === true });
      refresh();
    });

    var legitBtn = el('button', 'phish-action-btn phish-btn-legit', 'Mark as Legitimate');
    legitBtn.addEventListener('click', function () {
      _classifications[email.id] = 'legitimate';
      if (_onAnalysis) _onAnalysis({ type: 'classify', emailId: email.id, classification: 'legitimate', isCorrect: email.isPhishing === false });
      refresh();
    });

    var iocBtn = el('button', 'phish-action-btn phish-btn-ioc', 'Extract IOCs');
    iocBtn.addEventListener('click', function () {
      var iocs = (email.iocs || []).slice();
      // Also pull from headers
      if (email.headers && email.headers['Return-Path']) {
        var rpDomain = email.headers['Return-Path'].replace(/.*@/, '');
        if (rpDomain && iocs.indexOf(rpDomain) === -1) iocs.push(rpDomain);
      }
      if (_onAnalysis) _onAnalysis({ type: 'extract_iocs', emailId: email.id, iocs: iocs });
    });

    actionsBar.appendChild(phishBtn);
    actionsBar.appendChild(legitBtn);
    actionsBar.appendChild(iocBtn);
    detailEl.appendChild(actionsBar);
  }

  /* ════════════════════════════════════════════════════
     Body Sanitizer
     ════════════════════════════════════════════════════ */

  function sanitizeBody(body, links) {
    if (!body) return '<em>No body content</em>';

    // Create a temporary element to parse the HTML safely
    var tmp = document.createElement('div');
    tmp.innerHTML = body;

    // Find all <a> tags and replace with styled spans
    var anchors = tmp.querySelectorAll('a');
    anchors.forEach(function (a) {
      var href = a.getAttribute('href') || '';
      var text = a.textContent;
      var suspicious = false;
      for (var i = 0; i < links.length; i++) {
        if (links[i].url === href && links[i].suspicious) {
          suspicious = true;
          break;
        }
      }
      var span = document.createElement('span');
      span.className = 'phish-body-link' + (suspicious ? ' phish-body-link-suspicious' : '');
      span.textContent = text;
      span.title = 'URL: ' + href;
      a.parentNode.replaceChild(span, a);
    });

    return tmp.innerHTML;
  }

  /* ════════════════════════════════════════════════════
     Refresh
     ════════════════════════════════════════════════════ */

  function refresh() {
    var listEl = _container.querySelector('.phish-list');
    var detailEl = _container.querySelector('.phish-detail');
    if (listEl) renderList(listEl);
    if (detailEl) renderDetail(detailEl);
  }

  /* ════════════════════════════════════════════════════
     Init
     ════════════════════════════════════════════════════ */

  function init(opts) {
    _container = opts.container;
    _emails = opts.emails || [];
    _onAnalysis = opts.onAnalysis || null;
    _selectedId = _emails.length > 0 ? _emails[0].id : null;
    _classifications = {};

    _container.innerHTML = '';
    _container.classList.add('phish-container');

    var listEl = el('div', 'phish-list');
    var detailEl = el('div', 'phish-detail');

    _container.appendChild(listEl);
    _container.appendChild(detailEl);

    renderList(listEl);
    renderDetail(detailEl);
  }

  /* ════════════════════════════════════════════════════
     Public API
     ════════════════════════════════════════════════════ */

  var PhishingViewer = {
    init: init,
    getClassifications: function () { return Object.assign({}, _classifications); }
  };

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.PhishingViewer = PhishingViewer;

})();
