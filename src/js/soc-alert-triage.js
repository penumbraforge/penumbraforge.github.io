/**
 * Penumbra Forge — Alert Triage Classifier
 *
 * Blue team SOC workstation component. Renders a scrollable alert queue
 * with classification buttons (True Positive, False Positive, Misconfigured
 * Rule). Tracks classification progress and scores analyst accuracy on submit.
 */

(function () {
  'use strict';

  /* ════════════════════════════════════════════════════
     Constants
     ════════════════════════════════════════════════════ */

  var CLASSIFICATIONS = [
    { key: 'tp', label: 'True Positive',      cls: 'triage-btn-tp', badgeCls: 'tp' },
    { key: 'fp', label: 'False Positive',      cls: 'triage-btn-fp', badgeCls: 'fp' },
    { key: 'misconfig', label: 'Misconfigured Rule', cls: 'triage-btn-mc', badgeCls: 'mc' }
  ];

  var SEV_COLORS = {
    critical: 'var(--soc-sev-crit)',
    high:     'var(--soc-sev-high)',
    medium:   'var(--soc-sev-med)',
    low:      'var(--soc-sev-low)',
    info:     'var(--soc-sev-info)'
  };

  /* ════════════════════════════════════════════════════
     State
     ════════════════════════════════════════════════════ */

  var _container = null;
  var _alerts = [];
  var _classifications = {};   // { alertId: 'tp'|'fp'|'misconfig' }
  var _onClassify = null;
  var _onSubmit = null;
  var _submitted = false;

  /* ════════════════════════════════════════════════════
     Helpers
     ════════════════════════════════════════════════════ */

  function esc(str) {
    var d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  function classifiedCount() {
    return Object.keys(_classifications).length;
  }

  /* ════════════════════════════════════════════════════
     Render
     ════════════════════════════════════════════════════ */

  function render() {
    if (!_container) return;

    var unclassified = _alerts.length - classifiedCount();

    var html = '<div class="triage-container">';

    // ── Header ──
    html += '<div class="triage-header">';
    html += '<span class="triage-header-title">Alert Queue</span>';
    html += '<span class="triage-badge" id="triage-unclassified">' + unclassified + ' unclassified</span>';
    html += '</div>';

    // ── Queue ──
    html += '<div class="triage-queue" id="triage-queue">';

    for (var i = 0; i < _alerts.length; i++) {
      var a = _alerts[i];
      var sevColor = SEV_COLORS[a.severity] || SEV_COLORS.info;
      var classified = _classifications[a.id];

      html += '<div class="triage-alert" data-alert-id="' + esc(a.id) + '">';

      // Top row: severity + title + meta
      html += '<div class="triage-alert-top" data-toggle="' + esc(a.id) + '">';
      html += '<span class="triage-alert-sev" style="background:' + sevColor + ';color:#fff;">' + esc(a.severity) + '</span>';
      html += '<span class="triage-alert-title">' + esc(a.title) + '</span>';
      html += '<span class="triage-alert-meta">' + esc(a.source) + ' &middot; ' + esc(a.timestamp) + '</span>';
      html += '</div>';

      // Detail (collapsed by default)
      html += '<div class="triage-alert-detail" id="detail-' + esc(a.id) + '">';
      html += '<p>' + esc(a.description) + '</p>';
      if (a.indicators && a.indicators.length > 0) {
        html += '<p><strong>Indicators:</strong> ' + a.indicators.map(function(ind) { return '<code>' + esc(ind) + '</code>'; }).join(', ') + '</p>';
      }
      html += '<div class="triage-alert-raw">' + esc(a.raw || '{}') + '</div>';
      html += '</div>';

      // Actions row
      html += '<div class="triage-actions" id="actions-' + esc(a.id) + '">';
      if (classified && !_submitted) {
        // Show classified badge (clickable to reclassify)
        var match = CLASSIFICATIONS.filter(function(c) { return c.key === classified; })[0];
        html += '<span class="triage-classified ' + match.badgeCls + '" data-reclassify="' + esc(a.id) + '">' + esc(match.label) + '</span>';
      } else if (classified && _submitted) {
        // After submit: show result
        var isCorrect = classified === a.correctAnswer;
        var matchPost = CLASSIFICATIONS.filter(function(c) { return c.key === classified; })[0];
        html += '<span class="triage-classified ' + matchPost.badgeCls + '">' + esc(matchPost.label) + '</span>';
        if (isCorrect) {
          html += ' <span class="triage-result-correct">&#x2713; Correct</span>';
        } else {
          var correctLabel = CLASSIFICATIONS.filter(function(c) { return c.key === a.correctAnswer; })[0];
          html += ' <span class="triage-result-wrong">&#x2717; Was: ' + esc(correctLabel.label) + '</span>';
        }
        if (a.explanation) {
          html += '<div class="triage-result" style="margin-top:6px;">' + esc(a.explanation) + '</div>';
        }
      } else {
        // Show classification buttons
        for (var j = 0; j < CLASSIFICATIONS.length; j++) {
          var c = CLASSIFICATIONS[j];
          html += '<button class="triage-btn ' + c.cls + '" data-classify="' + esc(a.id) + '" data-value="' + c.key + '">' + esc(c.label) + '</button>';
        }
      }
      html += '</div>';

      html += '</div>'; // .triage-alert
    }

    html += '</div>'; // .triage-queue

    // ── Bottom bar ──
    html += '<div class="triage-bottom">';
    html += '<span class="triage-progress" id="triage-progress">' + classifiedCount() + ' of ' + _alerts.length + ' classified</span>';
    if (!_submitted) {
      var allDone = classifiedCount() === _alerts.length;
      html += '<button class="triage-submit" id="triage-submit-btn"' + (allDone ? '' : ' disabled') + '>Submit Classifications</button>';
    } else {
      var score = computeScore();
      html += '<span class="triage-progress" style="font-weight:600;color:var(--soc-accent);">Score: ' + score + '%</span>';
    }
    html += '</div>';

    html += '</div>'; // .triage-container

    _container.innerHTML = html;
    bindEvents();
  }

  /* ════════════════════════════════════════════════════
     Scoring
     ════════════════════════════════════════════════════ */

  function computeScore() {
    var correct = 0;
    for (var i = 0; i < _alerts.length; i++) {
      if (_classifications[_alerts[i].id] === _alerts[i].correctAnswer) {
        correct++;
      }
    }
    return Math.round((correct / _alerts.length) * 100);
  }

  /* ════════════════════════════════════════════════════
     Event Binding
     ════════════════════════════════════════════════════ */

  function bindEvents() {
    if (!_container) return;

    // Toggle detail expansion
    _container.addEventListener('click', function(e) {
      var toggle = e.target.closest('[data-toggle]');
      if (toggle) {
        var id = toggle.getAttribute('data-toggle');
        var detail = document.getElementById('detail-' + id);
        if (detail) detail.classList.toggle('open');
        return;
      }

      // Classify button
      var classifyBtn = e.target.closest('[data-classify]');
      if (classifyBtn) {
        var alertId = classifyBtn.getAttribute('data-classify');
        var value = classifyBtn.getAttribute('data-value');
        classify(alertId, value);
        return;
      }

      // Reclassify (click on badge to go back to buttons)
      var reclassify = e.target.closest('[data-reclassify]');
      if (reclassify && !_submitted) {
        var rid = reclassify.getAttribute('data-reclassify');
        delete _classifications[rid];
        render();
        return;
      }
    });

    // Submit button
    var submitBtn = document.getElementById('triage-submit-btn');
    if (submitBtn) {
      submitBtn.addEventListener('click', function() {
        if (classifiedCount() < _alerts.length) return;
        _submitted = true;
        var score = computeScore();
        if (_onSubmit) {
          _onSubmit({ classifications: Object.assign({}, _classifications), score: score });
        }
        render();
      });
    }
  }

  /* ════════════════════════════════════════════════════
     Classify
     ════════════════════════════════════════════════════ */

  function classify(alertId, value) {
    _classifications[alertId] = value;

    if (_onClassify) {
      _onClassify(alertId, value);
    }

    // Partial re-render: update just the actions row and counters
    updateActionsRow(alertId);
    updateCounters();
  }

  function updateActionsRow(alertId) {
    var actionsEl = document.getElementById('actions-' + alertId);
    if (!actionsEl) return;

    var classified = _classifications[alertId];
    if (classified) {
      var match = CLASSIFICATIONS.filter(function(c) { return c.key === classified; })[0];
      actionsEl.innerHTML = '<span class="triage-classified ' + match.badgeCls + '" data-reclassify="' + esc(alertId) + '">' + esc(match.label) + '</span>';
    } else {
      var html = '';
      for (var j = 0; j < CLASSIFICATIONS.length; j++) {
        var c = CLASSIFICATIONS[j];
        html += '<button class="triage-btn ' + c.cls + '" data-classify="' + esc(alertId) + '" data-value="' + c.key + '">' + esc(c.label) + '</button>';
      }
      actionsEl.innerHTML = html;
    }
  }

  function updateCounters() {
    var count = classifiedCount();
    var unclassified = _alerts.length - count;

    var badgeEl = document.getElementById('triage-unclassified');
    if (badgeEl) badgeEl.textContent = unclassified + ' unclassified';

    var progressEl = document.getElementById('triage-progress');
    if (progressEl) progressEl.textContent = count + ' of ' + _alerts.length + ' classified';

    var submitBtn = document.getElementById('triage-submit-btn');
    if (submitBtn) {
      submitBtn.disabled = count < _alerts.length;
    }
  }

  /* ════════════════════════════════════════════════════
     Public API
     ════════════════════════════════════════════════════ */

  var AlertTriage = {
    /**
     * Initialize the Alert Triage component.
     * @param {Object} opts
     * @param {HTMLElement} opts.container  Target element
     * @param {Array}       opts.alerts     Alert objects (see spec)
     * @param {Function}    opts.onClassify Called on each classification (alertId, value)
     * @param {Function}    opts.onSubmit   Called on final submit ({ classifications, score })
     */
    init: function(opts) {
      _container = opts.container;
      _alerts = opts.alerts || [];
      _onClassify = opts.onClassify || null;
      _onSubmit = opts.onSubmit || null;
      _classifications = {};
      _submitted = false;

      render();
    },

    /** Get current classifications map */
    getClassifications: function() {
      return Object.assign({}, _classifications);
    },

    /** Check if all alerts have been classified */
    isComplete: function() {
      return classifiedCount() === _alerts.length;
    },

    /** Get current score (0-100) */
    getScore: function() {
      return computeScore();
    }
  };

  /* ════════════════════════════════════════════════════
     Register on namespace
     ════════════════════════════════════════════════════ */

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.AlertTriage = AlertTriage;

})();
