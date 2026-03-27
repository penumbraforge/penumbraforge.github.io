(function () {
  'use strict';

  var Scoring = {
    calculate: function (opts) {
      var actionsLog      = opts.actionsLog      || [];
      var scenario        = opts.scenario        || {};
      var elapsed         = opts.elapsed         || 0;
      var nudgesShown     = opts.nudgesShown     || 0;
      var nudgesDismissed = opts.nudgesDismissed || 0;
      var evidenceFound   = opts.evidenceFound   || 0;
      var totalEvidence   = opts.totalEvidence   || 1;

      /* ── Technique ───────────────────────────────────────── */
      var technique = 0;
      var checks = scenario.techniqueChecks || [];
      for (var i = 0; i < checks.length; i++) {
        if (checks[i].check && checks[i].check(actionsLog)) {
          technique += checks[i].points || 0;
        }
      }
      technique = Math.min(100, technique);

      /* ── Efficiency ──────────────────────────────────────── */
      var optimal = scenario.optimalActions || 10;
      var actual = actionsLog.length;
      var ratio = optimal / Math.max(actual, 1);
      var efficiency = Math.min(100, Math.round(ratio * 100));

      /* ── Thoroughness ────────────────────────────────────── */
      var thoroughness = Math.round((evidenceFound / Math.max(totalEvidence, 1)) * 100);
      if (evidenceFound >= totalEvidence) {
        thoroughness = Math.min(thoroughness + 10, 100);
      }

      /* ── Independence ────────────────────────────────────── */
      var independence = 100;
      independence -= nudgesShown * 15;
      var slowNudges = nudgesShown - nudgesDismissed;
      independence -= slowNudges * 10;
      independence = Math.max(0, independence);

      /* ── Composite ───────────────────────────────────────── */
      var composite = Math.round(
        (technique   * 0.30) +
        (efficiency  * 0.25) +
        (thoroughness * 0.25) +
        (independence * 0.20)
      );

      /* ── XP ──────────────────────────────────────────────── */
      var baseXp = scenario.xpReward || 100;
      var xp = Math.round(baseXp * (composite / 100));
      var bonuses = {};

      if (nudgesShown === 0) {
        xp = Math.round(xp * 1.25);
        bonuses.noScaffolding = true;
      }
      if (scenario.estimatedTime && elapsed < scenario.estimatedTime * 60) {
        xp = Math.round(xp * 1.15);
        bonuses.underTime = true;
      }
      if (evidenceFound >= totalEvidence) {
        xp = Math.round(xp * 1.10);
        bonuses.allEvidence = true;
      }
      xp = Math.max(xp, Math.round(baseXp * 0.25));

      return {
        technique:    technique,
        efficiency:   efficiency,
        thoroughness: thoroughness,
        independence: independence,
        composite:    composite,
        xp:           xp,
        bonuses:      bonuses
      };
    }
  };

  window.PenumbraLabs = window.PenumbraLabs || {};
  window.PenumbraLabs.Scoring = Scoring;
})();
