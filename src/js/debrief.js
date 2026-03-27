(function () {
  'use strict';

  /* ── helpers ─────────────────────────────────────────────────── */

  function scoreClass(val) {
    if (val >= 70) return 'high';
    if (val >= 40) return 'mid';
    return 'low';
  }

  function formatTime(seconds) {
    var m = Math.floor(seconds / 60);
    var s = seconds % 60;
    return m + 'm ' + (s < 10 ? '0' : '') + s + 's';
  }

  function el(tag, cls, html) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (html !== undefined) node.innerHTML = html;
    return node;
  }

  /* ── section builders ────────────────────────────────────────── */

  function buildPerformanceSummary(scoring, elapsed) {
    var section = el('div', 'debrief-section');
    var title   = el('div', 'debrief-section-title', 'Performance Summary');
    var perf    = el('div', 'debrief-perf');

    /* time stat */
    var timeStat   = el('div', 'debrief-perf-stat');
    var timeLabel  = el('div', 'debrief-perf-label', 'Time');
    var timeValue  = el('div', 'debrief-perf-value');
    timeValue.style.color = '#c8ccd4';
    timeValue.textContent = formatTime(elapsed || 0);
    timeStat.appendChild(timeLabel);
    timeStat.appendChild(timeValue);
    perf.appendChild(timeStat);

    /* XP stat */
    var xpStat   = el('div', 'debrief-perf-stat');
    var xpLabel  = el('div', 'debrief-perf-label', 'XP Earned');
    var xpValue  = el('div', 'debrief-perf-value', '+' + (scoring.xp || 0));
    xpStat.appendChild(xpLabel);
    xpStat.appendChild(xpValue);
    perf.appendChild(xpStat);

    /* composite stat */
    var compStat   = el('div', 'debrief-perf-stat');
    var compLabel  = el('div', 'debrief-perf-label', 'Score');
    var compValue  = el('div', 'debrief-perf-value', (scoring.composite || 0) + '%');
    compValue.style.color = scoring.composite >= 70 ? '#4ade80' : scoring.composite >= 40 ? '#f59e0b' : '#ef4444';
    compStat.appendChild(compLabel);
    compStat.appendChild(compValue);
    perf.appendChild(compStat);

    /* bonus badges */
    var bonuses = scoring.bonuses || [];
    if (bonuses.length > 0) {
      var bonusStat  = el('div', 'debrief-perf-stat');
      var bonusLabel = el('div', 'debrief-perf-label', 'Bonuses');
      var bonusRow   = el('div');
      bonusRow.style.marginTop = '4px';
      for (var i = 0; i < bonuses.length; i++) {
        var badge = el('span', 'debrief-bonus', bonuses[i]);
        bonusRow.appendChild(badge);
      }
      bonusStat.appendChild(bonusLabel);
      bonusStat.appendChild(bonusRow);
      perf.appendChild(bonusStat);
    }

    section.appendChild(title);
    section.appendChild(perf);
    return section;
  }

  function buildScoreAxes(scoring) {
    var section = el('div', 'debrief-section');
    var title   = el('div', 'debrief-section-title', 'Score Breakdown');
    var grid    = el('div', 'debrief-scores');

    var axes = [
      { key: 'technique',    label: 'Technique'     },
      { key: 'efficiency',   label: 'Efficiency'    },
      { key: 'thoroughness', label: 'Thoroughness'  },
      { key: 'independence', label: 'Independence'  }
    ];

    for (var i = 0; i < axes.length; i++) {
      var axis  = axes[i];
      var val   = scoring[axis.key] || 0;
      var cls   = scoreClass(val);

      var row       = el('div', 'debrief-score-row');
      var labelEl   = el('div', 'debrief-score-label', axis.label);
      var barWrap   = el('div', 'debrief-score-bar');
      var fill      = el('div', 'debrief-score-fill ' + cls);
      fill.style.width = '0%';
      /* animate after paint */
      (function (fillEl, pct) {
        requestAnimationFrame(function () {
          requestAnimationFrame(function () {
            fillEl.style.width = pct + '%';
          });
        });
      })(fill, val);

      var valEl = el('div', 'debrief-score-value', val + '%');

      barWrap.appendChild(fill);
      row.appendChild(labelEl);
      row.appendChild(barWrap);
      row.appendChild(valEl);
      grid.appendChild(row);
    }

    section.appendChild(title);
    section.appendChild(grid);
    return section;
  }

  function buildAnalysis(content) {
    var section = el('div', 'debrief-section');
    var title   = el('div', 'debrief-section-title', 'Vulnerability Analysis');
    var card    = el('div', 'debrief-card');
    card.innerHTML = content;
    section.appendChild(title);
    section.appendChild(card);
    return section;
  }

  function buildFramework(content) {
    var section = el('div', 'debrief-section');
    var title   = el('div', 'debrief-section-title', 'Framework Mapping');
    var card    = el('div', 'debrief-card');
    card.innerHTML = content;
    section.appendChild(title);
    section.appendChild(card);
    return section;
  }

  function buildCode(content) {
    var section = el('div', 'debrief-section');
    var title   = el('div', 'debrief-section-title', 'Vulnerable Code &amp; Fix');
    var wrap    = el('div', 'debrief-code');
    wrap.innerHTML = content;
    section.appendChild(title);
    section.appendChild(wrap);
    return section;
  }

  function buildEvidenceSummary(items) {
    var section = el('div', 'debrief-section');
    var title   = el('div', 'debrief-section-title', 'Evidence Summary');
    var grid    = el('div', 'debrief-evidence');

    for (var i = 0; i < items.length; i++) {
      var item    = items[i];
      var cls     = item.found ? 'debrief-evidence-item found' : 'debrief-evidence-item missed';
      var prefix  = item.found ? '+ ' : '- ';
      var itemEl  = el('div', cls, prefix + item.label);
      grid.appendChild(itemEl);
    }

    section.appendChild(title);
    section.appendChild(grid);
    return section;
  }

  function buildInvestigationPath(steps) {
    var section = el('div', 'debrief-section');
    var title   = el('div', 'debrief-section-title', 'Investigation Path');
    var card    = el('div', 'debrief-card');

    for (var i = 0; i < steps.length; i++) {
      var step  = steps[i];
      var row   = el('div');
      row.style.cssText = 'display:flex;gap:12px;margin-bottom:6px;align-items:flex-start;';

      var ts    = el('span');
      ts.style.cssText = 'font-size:10px;color:#555;white-space:nowrap;padding-top:1px;min-width:50px;';
      ts.textContent = step.timestamp || '';

      var act   = el('span');
      act.style.cssText = 'font-size:11px;color:#c8ccd4;line-height:1.5;';
      act.textContent = step.action || '';

      row.appendChild(ts);
      row.appendChild(act);
      card.appendChild(row);
    }

    section.appendChild(title);
    section.appendChild(card);
    return section;
  }

  function buildCrossPerspective(cross) {
    var section = el('div', 'debrief-section');
    var title   = el('div', 'debrief-section-title', 'Cross-Perspective');
    var card    = el('div', 'debrief-cross');

    var crossTitle = el('div', 'debrief-cross-title', cross.title || '');
    var desc       = el('div', 'debrief-cross-desc', cross.description || '');

    card.appendChild(crossTitle);
    card.appendChild(desc);

    if (cross.linkHref && cross.linkText) {
      var link       = el('a', 'debrief-cross-link', cross.linkText);
      link.href      = cross.linkHref;
      card.appendChild(link);
    }

    section.appendChild(title);
    section.appendChild(card);
    return section;
  }

  /* ── main render ─────────────────────────────────────────────── */

  var Debrief = {
    render: function (opts) {
      var container      = opts.container;
      var scoring        = opts.scoring        || {};
      var elapsed        = opts.elapsed        || 0;
      var debriefContent = opts.debriefContent || {};

      if (!container) return;

      var wrap = el('div', 'debrief-container');

      /* 1 — performance summary */
      wrap.appendChild(buildPerformanceSummary(scoring, elapsed));

      /* 2 — score axes */
      wrap.appendChild(buildScoreAxes(scoring));

      /* 3 — analysis */
      if (debriefContent.analysis) {
        wrap.appendChild(buildAnalysis(debriefContent.analysis));
      }

      /* 4 — framework mapping */
      if (debriefContent.framework) {
        wrap.appendChild(buildFramework(debriefContent.framework));
      }

      /* 5 — code section (red team) */
      if (debriefContent.code) {
        wrap.appendChild(buildCode(debriefContent.code));
      }

      /* 6 — evidence summary (blue team) */
      if (debriefContent.evidenceSummary && debriefContent.evidenceSummary.length > 0) {
        wrap.appendChild(buildEvidenceSummary(debriefContent.evidenceSummary));
      }

      /* 6b — investigation path (blue team, optional) */
      if (debriefContent.investigationPath && debriefContent.investigationPath.length > 0) {
        wrap.appendChild(buildInvestigationPath(debriefContent.investigationPath));
      }

      /* 7 — cross-perspective preview */
      if (debriefContent.crossPerspective) {
        wrap.appendChild(buildCrossPerspective(debriefContent.crossPerspective));
      }

      /* clear and mount */
      container.innerHTML = '';
      container.appendChild(wrap);
    }
  };

  /* ── namespace registration ──────────────────────────────────── */

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.Debrief = Debrief;

}());
