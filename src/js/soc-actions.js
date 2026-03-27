/**
 * Penumbra Forge — Containment Actions Panel
 *
 * Blue team SOC workstation component. Presents a checklist of
 * containment recommendations for the active scenario. On submit,
 * scores the analyst's selections against the expected action set,
 * highlights missed critical actions and unnecessary selections.
 */

(function () {
  'use strict';

  /* ════════════════════════════════════════════════════
     Constants
     ════════════════════════════════════════════════════ */

  var ALL_ACTIONS = [
    { id: 'revoke-sessions',  label: 'Revoke all compromised sessions' },
    { id: 'block-ip',         label: 'Block attacker IP at firewall' },
    { id: 'enable-waf',       label: 'Enable WAF blocking mode' },
    { id: 'reset-passwords',  label: 'Force password reset for affected accounts' },
    { id: 'isolate-server',   label: 'Isolate affected web server' },
    { id: 'notify-customers', label: 'Notify affected customers' },
    { id: 'preserve-evidence',label: 'Preserve forensic evidence' },
    { id: 'law-enforcement',  label: 'Engage law enforcement' }
  ];

  /* ════════════════════════════════════════════════════
     SOCActions
     ════════════════════════════════════════════════════ */

  var SOCActions = {
    _container:      null,
    _expectedActions: null,
    _onAction:       null,

    // DOM refs
    _checkboxEls: null,
    _notesEl:     null,
    _submitBtn:   null,
    _scoreEl:     null,

    /* ════════════════════════════════════════════════════
       Public API
       ════════════════════════════════════════════════════ */

    /**
     * Initialize the containment actions panel.
     *
     * @param {Object}      opts
     * @param {HTMLElement}  opts.container        - DOM element to render into
     * @param {Array}        opts.expectedActions  - Array of correct action IDs
     * @param {Function}     opts.onAction         - Callback fired on submit
     */
    init: function (opts) {
      this._container       = opts.container;
      this._expectedActions = opts.expectedActions || [];
      this._onAction        = opts.onAction || function () {};
      this._checkboxEls     = {};

      this._render();

      return this;
    },

    /* ════════════════════════════════════════════════════
       Rendering
       ════════════════════════════════════════════════════ */

    _render: function () {
      var self = this;
      this._container.innerHTML = '';

      var wrap = document.createElement('div');
      wrap.className = 'soc-actions-container';

      // ── Section title ──
      var title = document.createElement('div');
      title.className   = 'soc-actions-title';
      title.textContent = 'Containment Recommendations';
      wrap.appendChild(title);

      // ── Checkbox list ──
      for (var i = 0; i < ALL_ACTIONS.length; i++) {
        var action = ALL_ACTIONS[i];

        var row = document.createElement('div');
        row.className              = 'soc-action-check';
        row.setAttribute('data-id', action.id);

        var checkbox = document.createElement('input');
        checkbox.type      = 'checkbox';
        checkbox.id        = 'soc-action-' + action.id;
        checkbox.name      = action.id;
        checkbox.value     = action.id;

        var label = document.createElement('label');
        label.htmlFor     = 'soc-action-' + action.id;
        label.textContent = action.label;

        row.appendChild(checkbox);
        row.appendChild(label);
        wrap.appendChild(row);

        this._checkboxEls[action.id] = { row: row, checkbox: checkbox };
      }

      // ── Notes textarea ──
      this._notesEl = document.createElement('textarea');
      this._notesEl.className   = 'soc-actions-notes';
      this._notesEl.placeholder = 'Additional recommendations…';
      this._notesEl.setAttribute('spellcheck', 'false');
      wrap.appendChild(this._notesEl);

      // ── Submit button ──
      this._submitBtn = document.createElement('button');
      this._submitBtn.type      = 'button';
      this._submitBtn.className = 'soc-actions-submit';
      this._submitBtn.textContent = 'Submit Containment Plan';
      wrap.appendChild(this._submitBtn);

      // ── Score area (hidden until submit) ──
      this._scoreEl = document.createElement('div');
      this._scoreEl.className = 'soc-actions-score';
      this._scoreEl.style.display = 'none';
      wrap.appendChild(this._scoreEl);

      this._container.appendChild(wrap);

      // ── Events ──
      this._submitBtn.addEventListener('click', function () {
        self._submit();
      });
    },

    _submit: function () {
      var selected = [];
      for (var i = 0; i < ALL_ACTIONS.length; i++) {
        var id = ALL_ACTIONS[i].id;
        if (this._checkboxEls[id] && this._checkboxEls[id].checkbox.checked) {
          selected.push(id);
        }
      }

      var expected = this._expectedActions;
      var notes    = this._notesEl.value.trim();

      // Calculate correct selections (expected ∩ selected)
      var correct = [];
      for (var s = 0; s < selected.length; s++) {
        if (this._inArray(selected[s], expected)) {
          correct.push(selected[s]);
        }
      }

      var score = expected.length > 0
        ? Math.round((correct.length / expected.length) * 100)
        : 100;

      // ── Apply visual feedback ──
      this._clearFeedback();

      for (var a = 0; a < ALL_ACTIONS.length; a++) {
        var actionId = ALL_ACTIONS[a].id;
        var isExpected = this._inArray(actionId, expected);
        var isSelected = this._inArray(actionId, selected);
        var row = this._checkboxEls[actionId].row;

        if (isExpected && !isSelected) {
          // Missed critical action
          row.classList.add('missed');
        } else if (!isExpected && isSelected) {
          // Unnecessary action
          row.classList.add('unnecessary');
        }
      }

      // ── Render score card ──
      this._renderScore(correct.length, expected.length, score, selected, expected);

      // ── Fire callback ──
      this._onAction({
        type:     'containment_submit',
        selected: selected,
        expected: expected,
        score:    score,
        notes:    notes
      });
    },

    _renderScore: function (correct, total, score, selected, expected) {
      var self = this;
      this._scoreEl.innerHTML = '';
      this._scoreEl.style.display = 'block';

      // Headline
      var headline = document.createElement('div');
      headline.style.cssText = 'font-weight:600; color:#e2e4ea; margin-bottom:6px;';
      headline.textContent   = correct + ' of ' + total + ' critical actions selected';
      this._scoreEl.appendChild(headline);

      // Score percentage
      var scoreLine = document.createElement('div');
      var scoreColor = score >= 80 ? '#4ade80' : score >= 50 ? '#f59e0b' : '#ef4444';
      scoreLine.style.cssText  = 'font-size:20px; font-weight:700; color:' + scoreColor + '; margin-bottom:8px;';
      scoreLine.textContent    = score + '%';
      this._scoreEl.appendChild(scoreLine);

      // Legend for feedback
      var missed = [];
      var unnecessary = [];
      for (var i = 0; i < ALL_ACTIONS.length; i++) {
        var id = ALL_ACTIONS[i].id;
        var isExpected = this._inArray(id, expected);
        var isSelected = this._inArray(id, selected);
        if (isExpected && !isSelected) missed.push(ALL_ACTIONS[i].label);
        if (!isExpected && isSelected) unnecessary.push(ALL_ACTIONS[i].label);
      }

      if (missed.length) {
        var missedTitle = document.createElement('div');
        missedTitle.style.cssText = 'font-size:9px; color:#ef4444; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:3px;';
        missedTitle.textContent   = 'Missed critical actions';
        this._scoreEl.appendChild(missedTitle);

        for (var m = 0; m < missed.length; m++) {
          var missedItem = document.createElement('div');
          missedItem.style.cssText = 'font-size:10px; color:#ef4444; padding-left:8px; border-left:2px solid #ef4444; margin-bottom:2px;';
          missedItem.textContent   = missed[m];
          this._scoreEl.appendChild(missedItem);
        }
      }

      if (unnecessary.length) {
        var unnecTitle = document.createElement('div');
        unnecTitle.style.cssText = 'font-size:9px; color:#f59e0b; text-transform:uppercase; letter-spacing:0.5px; margin-top:6px; margin-bottom:3px;';
        unnecTitle.textContent   = 'Unnecessary actions selected';
        this._scoreEl.appendChild(unnecTitle);

        for (var u = 0; u < unnecessary.length; u++) {
          var unnecItem = document.createElement('div');
          unnecItem.style.cssText = 'font-size:10px; color:#f59e0b; padding-left:8px; border-left:2px solid #f59e0b; margin-bottom:2px;';
          unnecItem.textContent   = unnecessary[u];
          this._scoreEl.appendChild(unnecItem);
        }
      }

      // Reset button
      var resetBtn = document.createElement('button');
      resetBtn.type      = 'button';
      resetBtn.style.cssText = 'margin-top:10px; background:none; border:1px solid #1e1e2e; color:#555; padding:4px 10px; font-size:10px; border-radius:3px; cursor:pointer; font-family:inherit;';
      resetBtn.textContent   = 'Reset';
      resetBtn.addEventListener('click', function () {
        self._resetForm();
      });
      this._scoreEl.appendChild(resetBtn);
    },

    _clearFeedback: function () {
      for (var i = 0; i < ALL_ACTIONS.length; i++) {
        var row = this._checkboxEls[ALL_ACTIONS[i].id].row;
        row.classList.remove('missed', 'unnecessary');
      }
    },

    _resetForm: function () {
      for (var i = 0; i < ALL_ACTIONS.length; i++) {
        var id = ALL_ACTIONS[i].id;
        this._checkboxEls[id].checkbox.checked = false;
        this._checkboxEls[id].row.classList.remove('missed', 'unnecessary');
      }
      this._notesEl.value     = '';
      this._scoreEl.innerHTML = '';
      this._scoreEl.style.display = 'none';
    },

    /* ════════════════════════════════════════════════════
       Utility
       ════════════════════════════════════════════════════ */

    _inArray: function (val, arr) {
      for (var i = 0; i < arr.length; i++) {
        if (arr[i] === val) return true;
      }
      return false;
    }
  };

  /* ════════════════════════════════════════════════════
     Register on namespace
     ════════════════════════════════════════════════════ */

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.SOCActions = SOCActions;
}());
