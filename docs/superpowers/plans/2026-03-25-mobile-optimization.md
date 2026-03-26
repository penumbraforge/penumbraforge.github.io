# Mobile Optimization Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make penumbraforge.com feel premium on all phones (360-430px), fixing overlapping layouts, endless scrolling, missing hamburger nav, sticky hovers, and performance issues.

**Architecture:** Surgical CSS additions to existing breakpoints (640px, 768px) plus a new 480px breakpoint. Small JS additions for hamburger toggle and mobile particle reduction. No desktop changes. No new dependencies.

**Tech Stack:** CSS media queries, vanilla JS, Nunjucks templates (Eleventy 3.0.0)

**Spec:** `docs/superpowers/specs/2026-03-25-mobile-optimization-design.md`

**Testing:** This is a static site with no test suite. Each task is verified by running `npm run dev` and checking in a phone-sized browser viewport (390px wide). Use Chrome DevTools device toolbar or equivalent.

---

## File Structure

| File | Responsibility |
|------|---------------|
| `src/css/style.css` | Main site styles — bulk of mobile CSS changes |
| `src/css/labs.css` | Red team lab styles — gate screen, hover guards |
| `src/css/labs-blue.css` | Blue team lab styles — gate screen, hover guards |
| `src/css/blog.css` | Blog styles — hover guards |
| `src/css/docs.css` | Docs styles — hover guards |
| `src/_includes/base.njk` | Base template — viewport-fit, particle/star JS mobile detection |
| `src/index.njk` | Homepage — hamburger button markup, tools-more-link |
| `src/_includes/lab-workspace.njk` | Red team layout — gate screen HTML |
| `src/_includes/lab-workspace-blue.njk` | Blue team layout — gate screen HTML |

---

### Task 1: Global CSS Foundation — Font Smoothing, Overflow, Smooth Scroll

Small global additions that benefit all pages. Low risk, high impact baseline.

**Files:**
- Modify: `src/css/style.css:33-43` (Reset & Base section)
- Modify: `src/css/style.css:957-961` (existing `prefers-reduced-motion` block)

- [ ] **Step 1: Add font smoothing and html overflow-x**

In `src/css/style.css`, after the `* { margin: 0; ... }` reset (line 33), add to the body rule and add an html rule:

```css
html {
  overflow-x: hidden;
}

body {
  /* existing properties stay unchanged */
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
```

Add the `-webkit-font-smoothing: antialiased` and `-moz-osx-font-smoothing: grayscale` properties to the existing `body` rule at line 35. Add a new `html` rule with `overflow-x: hidden` before the `body` rule.

- [ ] **Step 2: Add smooth scrolling**

In `src/css/style.css`, after the existing `@media (prefers-reduced-motion: reduce)` block (around line 957), add:

```css
@media (prefers-reduced-motion: no-preference) {
  html {
    scroll-behavior: smooth;
  }
}
```

- [ ] **Step 3: Verify**

Run: `npm run dev`

Open Chrome DevTools → mobile viewport (390px). Scroll the homepage — scrolling should feel smooth. Text should render crisply (anti-aliased, not subpixel).

- [ ] **Step 4: Commit**

```bash
git add src/css/style.css
git commit -m "Add font smoothing, html overflow-x, and smooth scrolling"
```

---

### Task 2: Hamburger Navigation for Homepage

The homepage `.home-nav` has no mobile collapse. Add a hamburger button + slide-down overlay.

**Files:**
- Modify: `src/index.njk:4-11` (home-nav section)
- Modify: `src/css/style.css` (add hamburger styles after `.home-nav a:hover` around line 376)

- [ ] **Step 1: Add hamburger button HTML**

In `src/index.njk`, modify the `<nav class="home-nav reveal">` block to add a hamburger button before the links:

```html
<nav class="home-nav reveal">
  <button class="home-nav-toggle" aria-label="Toggle menu" aria-expanded="false">
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5">
      <line x1="3" y1="5" x2="17" y2="5" class="hamburger-top"/>
      <line x1="3" y1="10" x2="17" y2="10" class="hamburger-mid"/>
      <line x1="3" y1="15" x2="17" y2="15" class="hamburger-bot"/>
    </svg>
  </button>
  <div class="home-nav-links">
    <a href="/tools/">Tools</a>
    <a href="/labs/">Labs</a>
    <a href="/blog/">Blog</a>
    <a href="/gate/">Gate</a>
    <a href="/librarian/">Librarian</a>
    <a href="https://github.com/penumbraforge" target="_blank" rel="noopener">GitHub</a>
  </div>
</nav>
```

- [ ] **Step 2: Add hamburger CSS**

In `src/css/style.css`, after the `.home-nav a:hover` rule (around line 376), add:

```css
/* Hamburger toggle — hidden on desktop */
.home-nav-toggle {
  display: none;
  background: none;
  border: none;
  color: var(--accent);
  cursor: pointer;
  padding: 8px;
  z-index: 101;
}

/* Desktop: links display as before */
.home-nav-links {
  display: flex;
  gap: 28px;
}

.home-nav-links a {
  color: rgba(232, 228, 239, 0.25);
  text-decoration: none;
  transition: color 300ms;
}

.home-nav-links a:hover {
  color: var(--text-1);
}

@media (max-width: 640px) {
  .home-nav {
    justify-content: space-between;
  }

  .home-nav-toggle {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 44px;
    min-width: 44px;
  }

  .home-nav-links {
    display: none;
    position: fixed;
    inset: 0;
    top: 0;
    z-index: 100;
    background: rgba(10, 10, 20, 0.97);
    backdrop-filter: blur(12px);
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: env(safe-area-inset-top, 20px) 24px env(safe-area-inset-bottom, 20px);
  }

  .home-nav-links a {
    color: var(--text-1);
    font-size: 18px;
    font-family: var(--font-display);
    padding: 14px 24px;
    min-height: 48px;
    display: flex;
    align-items: center;
    width: 100%;
    max-width: 280px;
    justify-content: center;
    border-radius: 8px;
    transition: background 200ms;
  }

  .home-nav-links a:hover,
  .home-nav-links a:active {
    background: rgba(184, 165, 214, 0.08);
  }

  body.nav-open .home-nav-links {
    display: flex;
    animation: navSlideDown 250ms ease;
  }

  body.nav-open .home-nav-toggle svg .hamburger-top {
    transform: rotate(45deg) translate(3.5px, -3.5px);
    transform-origin: center;
  }
  body.nav-open .home-nav-toggle svg .hamburger-mid {
    opacity: 0;
  }
  body.nav-open .home-nav-toggle svg .hamburger-bot {
    transform: rotate(-45deg) translate(3.5px, 3.5px);
    transform-origin: center;
  }

  .home-nav-toggle svg line {
    transition: transform 200ms ease, opacity 200ms ease;
  }
}

@media (max-width: 768px) and (orientation: landscape) {
  .home-nav-toggle {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 44px;
    min-width: 44px;
  }

  .home-nav-links {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 100;
    background: rgba(10, 10, 20, 0.97);
    backdrop-filter: blur(12px);
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 20px 24px;
  }

  .home-nav-links a {
    color: var(--text-1);
    font-size: 16px;
    font-family: var(--font-display);
    padding: 10px 24px;
    min-height: 44px;
    display: flex;
    align-items: center;
  }

  body.nav-open .home-nav-links {
    display: flex;
  }
}

@keyframes navSlideDown {
  from { opacity: 0; transform: translateY(-20px); }
  to { opacity: 1; transform: translateY(0); }
}
```

- [ ] **Step 3: Remove the now-duplicate styles from `.home-nav a`**

The existing `.home-nav a` and `.home-nav a:hover` rules (lines 368-376) are now handled by `.home-nav-links a`. Remove these exact rules:

```css
/* REMOVE this block */
.home-nav a {
  color: rgba(232, 228, 239, 0.25);
  text-decoration: none;
  transition: color 300ms;
}

.home-nav a:hover {
  color: var(--text-1);
}
```

- [ ] **Step 4: Add hamburger toggle JS**

In `src/index.njk`, at the end of the existing `<script>` block (after the demo carousel code, around line 413), add:

```javascript
// Hamburger menu toggle
(function() {
  const toggle = document.querySelector('.home-nav-toggle');
  if (!toggle) return;

  toggle.addEventListener('click', function() {
    const open = document.body.classList.toggle('nav-open');
    toggle.setAttribute('aria-expanded', open);
  });

  // Close on link click
  document.querySelectorAll('.home-nav-links a').forEach(function(link) {
    link.addEventListener('click', function() {
      document.body.classList.remove('nav-open');
      toggle.setAttribute('aria-expanded', 'false');
    });
  });

  // Close on Escape key
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && document.body.classList.contains('nav-open')) {
      document.body.classList.remove('nav-open');
      toggle.setAttribute('aria-expanded', 'false');
    }
  });
})();
```

- [ ] **Step 5: Verify**

Run: `npm run dev`

At 390px viewport: hamburger icon visible, tapping opens full-screen overlay with nav links, links are tappable (48px tall), Escape closes menu.

At 1024px viewport: regular nav links display inline, no hamburger visible.

- [ ] **Step 6: Commit**

```bash
git add src/index.njk src/css/style.css
git commit -m "Add hamburger menu for homepage mobile navigation"
```

---

### Task 3: Layout Spacing Fixes (hero-split, about, station)

Fix spacing that's still too generous on phones.

**Files:**
- Modify: `src/css/style.css` — existing 640px media query block (around line 2058) and new 480px block

- [ ] **Step 1: Add spacing overrides to existing 640px block**

In `src/css/style.css`, inside the `@media (max-width: 640px)` block at line 2058 (the one containing `.hero { padding:` and `.tools-grid { grid-template-columns: 1fr }`), add:

```css
  .hero-split {
    gap: 24px;
    padding-bottom: 40px;
  }

  .about-layout {
    gap: 20px;
  }
```

- [ ] **Step 2: Create new 480px breakpoint**

After the 640px block that ends around line 2108, add a new block:

```css
@media (max-width: 480px) {
  .hero {
    padding: 20px 12px 0;
  }

  .section {
    padding: 32px 12px;
  }

  .hero h1 {
    font-size: 22px;
  }

  .station h2.station-title,
  .station h3 {
    font-size: 19px;
  }

  .station {
    padding: 16px;
  }

  .container {
    padding: 0 12px;
  }
}
```

- [ ] **Step 3: Verify**

Run: `npm run dev`

At 390px: hero section should feel tighter. Padding is 16px on each side.

At 360px (iPhone SE): 12px padding, smaller h1 (22px). Sections shouldn't feel cramped but should fit.

At 768px: unchanged from current.

- [ ] **Step 4: Commit**

```bash
git add src/css/style.css
git commit -m "Tighten spacing for phones: hero-split, about, station, new 480px breakpoint"
```

---

### Task 4: Card Compaction & Scroll Reduction

Make tool cards compact on mobile and limit the homepage to 4 visible cards.

**Files:**
- Modify: `src/css/style.css` — existing 640px block (line 4358+, the big mobile block)
- Modify: `src/index.njk` — add `.tools-more-link` element (only for the tools section, not labs)

- [ ] **Step 1: Add compact card layout**

In `src/css/style.css`, inside the large `@media (max-width: 640px)` block starting at line 4358 (the one beginning with `/* == 1. MOBILE NAVIGATION == */`), add after the existing `.t-card` rules (around line 4450):

```css
  /* Compact horizontal card layout */
  .tools-grid .t-card {
    display: flex;
    gap: 12px;
    align-items: center;
    padding: 16px;
  }

  .tools-grid .t-card .t-icon {
    margin-bottom: 0;
    flex-shrink: 0;
  }

  .tools-grid .t-card h4 {
    font-size: 13px;
    margin-bottom: 2px;
  }

  .tools-grid .t-card p {
    font-size: 11px;
  }

  .tools-grid .t-card .local-badge {
    margin-top: 4px;
    font-size: 8px;
  }
```

- [ ] **Step 2: Add a scoping class to the homepage tools grid**

In `src/index.njk`, the "Developer & Security Tools" section (around line 215) has `<div class="tools-grid">`. Add a scoping class so we can target just this grid without affecting the labs grid (which also uses `.tools-grid`):

```html
<!-- Before -->
<div class="tools-grid">

<!-- After -->
<div class="tools-grid tools-grid--home">
```

- [ ] **Step 3: Hide tools 5+ and show "View all" link on homepage**

In `src/css/style.css`, inside the same 640px block, add:

```css
  /* Homepage tools section: limit to 4 cards */
  .tools-grid--home .t-card:nth-child(n+5) {
    display: none;
  }

  /* Show "View all" link on mobile */
  .tools-more-link {
    display: block;
  }
```

Add a desktop-level rule (outside any media query, after the `.tools-grid` section around line 813):

```css
.tools-more-link {
  display: none;
  text-align: center;
  margin-top: 16px;
}

.tools-more-link a {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--accent);
  padding: 12px 24px;
  border: 1px solid rgba(184, 165, 214, 0.1);
  border-radius: 8px;
  display: inline-block;
  min-height: 44px;
  line-height: 20px;
}
```

- [ ] **Step 4: Add tools-more-link HTML to homepage**

In `src/index.njk`, after the tools section `.tools-grid` closing `</div>` (the one around line 224, in the "Developer & Security Tools" section), add before the existing `.tools-cta-row`:

```html
  <div class="tools-more-link">
    <a href="/tools/">View all 63 tools &rarr;</a>
  </div>
```

Note: The labs section (line 190-199) only shows 4 cards already and has its own CTA. No change needed there.

- [ ] **Step 5: Hide station terminals on mobile**

In `src/css/style.css`, inside the same 640px block, add:

```css
  /* Hide station decorative terminals on mobile */
  .station-terminal,
  .station-visual {
    display: none;
  }
```

- [ ] **Step 6: Verify**

Run: `npm run dev`

At 390px:
- Tool cards should be horizontal (icon left, text right), compact
- Only 4 tool cards visible in the "Developer & Security Tools" section
- "View all 63 tools" link visible below the grid
- Labs section still shows all 4 cards (unaffected — uses `.tools-grid` without `--home`)
- Station cards show only text, no terminal demos

At 1024px: everything unchanged, all cards visible, terminals visible.

- [ ] **Step 7: Commit**

```bash
git add src/css/style.css src/index.njk
git commit -m "Compact cards on mobile, limit homepage tools to 4, hide station terminals"
```

---

### Task 5: Tap Targets & Hero Stats Styling

Improve tap target sizing and make the vertical hero stats list feel intentional.

**Files:**
- Modify: `src/css/style.css` — existing 640px blocks

- [ ] **Step 1: Add tap target and hero stats styling**

In `src/css/style.css`, inside the `@media (max-width: 640px)` block at line 2058, add:

```css
  .tool-btn {
    padding: 10px 20px;
  }

  .tech-chip {
    padding: 8px 16px;
  }

  .hero-stats > div {
    border-left: 2px solid rgba(184, 165, 214, 0.15);
    padding-left: 12px;
  }
```

- [ ] **Step 2: Verify**

Run: `npm run dev`

At 390px: tool buttons should be easier to tap. Tech chips in about section should be tappable. Hero stats should have a subtle left accent bar.

- [ ] **Step 3: Commit**

```bash
git add src/css/style.css
git commit -m "Improve tap targets and hero stats vertical styling on mobile"
```

---

### Task 6: Particle & Star Performance on Mobile

Reduce rendering cost on phones.

**Files:**
- Modify: `src/_includes/base.njk:84-151` (particle and star scripts)
- Modify: `src/css/style.css` (orb hiding, star animation, eclipse resize)

- [ ] **Step 1: Add mobile detection to particle script**

In `src/_includes/base.njk`, modify the particle system script (starting at line 84). Replace the `PARTICLE_COUNT` and loop section:

```javascript
(function() {
    const canvas = document.getElementById('particle-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let w, h;
    const particles = [];
    const isMobile = window.innerWidth < 768;
    const PARTICLE_COUNT = isMobile ? 18 : 50;

    function resize() {
      w = canvas.width = window.innerWidth;
      h = canvas.height = window.innerHeight;
    }

    window.addEventListener('resize', resize);
    resize();

    for (let i = 0; i < PARTICLE_COUNT; i++) {
      particles.push({
        x: Math.random() * w,
        y: Math.random() * h,
        size: 0.5 + Math.random() * 1.5,
        speedY: -(0.08 + Math.random() * 0.2),
        speedX: (Math.random() - 0.5) * 0.15,
        wobbleAmp: 0.3 + Math.random() * 0.5,
        wobbleSpeed: 0.002 + Math.random() * 0.004,
        phase: Math.random() * Math.PI * 2,
        opacity: 0.08 + Math.random() * 0.2,
        hue: Math.random() > 0.85 ? 150 : 270,
        saturation: 30 + Math.random() * 40,
      });
    }

    let scrollY = 0;
    window.addEventListener('scroll', () => { scrollY = window.scrollY; }, { passive: true });

    let frame = 0;
    function animate(time) {
      frame++;
      // On mobile, skip every other frame (~30fps)
      if (isMobile && frame % 2 !== 0) {
        requestAnimationFrame(animate);
        return;
      }

      ctx.clearRect(0, 0, w, h);

      for (const p of particles) {
        p.phase += p.wobbleSpeed;
        p.x += p.speedX + Math.sin(p.phase) * p.wobbleAmp * 0.1;
        p.y += p.speedY;

        if (p.y < -10) {
          p.y = h + 10;
          p.x = Math.random() * w;
        }
        if (p.x < -10) p.x = w + 10;
        if (p.x > w + 10) p.x = -10;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = `hsla(${p.hue}, ${p.saturation}%, 70%, ${p.opacity})`;
        ctx.fill();

        // Glow effect — skip on mobile
        if (!isMobile && p.size > 1.2) {
          ctx.beginPath();
          ctx.arc(p.x, p.y, p.size * 3, 0, Math.PI * 2);
          ctx.fillStyle = `hsla(${p.hue}, ${p.saturation}%, 70%, ${p.opacity * 0.15})`;
          ctx.fill();
        }
      }

      requestAnimationFrame(animate);
    }

    requestAnimationFrame(animate);
  })();
```

- [ ] **Step 2: Add mobile detection to star field script**

In `src/_includes/base.njk`, modify the star field script (starting around line 156). Change the star count:

```javascript
(function() {
    const container = document.getElementById('stars');
    if (!container) return;
    const isMobile = window.innerWidth < 768;
    const STAR_COUNT = isMobile ? 25 : 70;
    for (let i = 0; i < STAR_COUNT; i++) {
      const star = document.createElement('div');
      star.className = Math.random() > 0.87 ? 'star star--bright' : 'star';
      star.style.left = Math.random() * 100 + '%';
      star.style.top = Math.random() * 100 + '%';
      star.style.opacity = 0.08 + Math.random() * 0.25;
      if (star.classList.contains('star--bright')) {
        star.style.animationDelay = (Math.random() * 6) + 's';
        star.style.animationDuration = (3 + Math.random() * 5) + 's';
      }
      container.appendChild(star);
    }
  })();
```

- [ ] **Step 3: Add CSS for orb hiding, star animation, eclipse resize**

In `src/css/style.css`, add a new `@media (max-width: 768px)` block near the existing orb/particle CSS (after the `.page-glow` rule, around line 172):

```css
@media (max-width: 768px) {
  .orb-3, .orb-4, .orb-5, .orb-6 {
    display: none;
  }

  .orb-1, .orb-2 {
    filter: blur(40px);
  }

  .star--bright {
    animation: none;
  }

  #eclipse-particles {
    width: 300px;
    height: 300px;
  }
}
```

- [ ] **Step 4: Verify**

Run: `npm run dev`

At 390px: particles should be visibly fewer and without glow halos. Only 2 orbs visible. Stars should be fewer and not twinkling. Eclipse corona still animates but smaller. Page should scroll smoothly without jank.

At 1024px: full particle count, all orbs, twinkling stars — unchanged.

- [ ] **Step 5: Commit**

```bash
git add src/_includes/base.njk src/css/style.css
git commit -m "Reduce particles, stars, and orbs on mobile for performance"
```

---

### Task 7: Labs Gate on Mobile

Show a branded gate screen instead of the workspace on phones.

**Files:**
- Modify: `src/_includes/lab-workspace.njk:25-47` (add gate before workspace)
- Modify: `src/_includes/lab-workspace-blue.njk:26-46` (add gate before workspace)
- Modify: `src/css/labs.css` (gate styles + workspace hide)

- [ ] **Step 1: Add gate HTML to red team workspace**

In `src/_includes/lab-workspace.njk`, after the `<script src="/js/lab-engine.js"></script>` line (line 43) and before `<!-- Workspace -->` (line 44), add:

```html
<!-- Mobile gate — shown below 900px, workspace hidden -->
<div class="lab-mobile-gate">
  <div class="lab-mobile-gate-inner">
    <svg class="lab-mobile-gate-icon" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
      <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
    </svg>
    <h2 class="lab-mobile-gate-title">{{ labTitle }}</h2>
    <span class="lab-mobile-gate-diff diff-{{ labDifficulty }}">{{ labDifficulty }}</span>
    <p class="lab-mobile-gate-desc">{{ labDescription }}</p>
    <p class="lab-mobile-gate-msg">This lab requires a desktop browser for the full interactive experience.</p>
    <div class="lab-mobile-gate-actions">
      <button class="lab-mobile-gate-copy" onclick="navigator.clipboard.writeText(window.location.href).then(function(){this.textContent='Copied!'}.bind(this))">Copy link</button>
      <a href="/labs/" class="lab-mobile-gate-back">View all labs</a>
    </div>
  </div>
</div>
```

- [ ] **Step 2: Add gate HTML to blue team workspace**

In `src/_includes/lab-workspace-blue.njk`, after the `<script src="/js/lab-engine.js"></script>` line (line 43) and before `{{ content | safe }}` (line 46), add the same gate HTML as Step 1 (identical markup).

- [ ] **Step 3: Add gate CSS**

In `src/css/labs.css`, at the end of the file, add:

```css
/* ============================================================
   Mobile Gate — shown below 900px instead of workspace
   ============================================================ */
.lab-mobile-gate {
  display: none;
}

@media (max-width: 900px) {
  .lab-workspace,
  .blue-workspace {
    display: none;
  }

  .lab-mobile-gate {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: calc(100vh - 48px);
    padding: 40px 24px;
    background: var(--surface-0);
  }

  .lab-mobile-gate-inner {
    text-align: center;
    max-width: 360px;
  }

  .lab-mobile-gate-icon {
    color: var(--accent);
    opacity: 0.5;
    margin-bottom: 24px;
  }

  .lab-mobile-gate-title {
    font-family: var(--font-display);
    font-size: 24px;
    color: var(--text-1);
    font-weight: 400;
    margin-bottom: 8px;
  }

  .lab-mobile-gate-diff {
    display: inline-block;
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 1px;
    text-transform: uppercase;
    padding: 4px 10px;
    border-radius: 4px;
    border: 1px solid var(--border);
    margin-bottom: 20px;
  }

  .lab-mobile-gate-desc {
    font-size: 14px;
    color: var(--text-2);
    line-height: 1.7;
    margin-bottom: 24px;
  }

  .lab-mobile-gate-msg {
    font-size: 13px;
    color: var(--text-3);
    margin-bottom: 28px;
    font-style: italic;
  }

  .lab-mobile-gate-actions {
    display: flex;
    flex-direction: column;
    gap: 12px;
    align-items: center;
  }

  .lab-mobile-gate-copy {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--accent);
    background: rgba(184, 165, 214, 0.06);
    border: 1px solid rgba(184, 165, 214, 0.12);
    border-radius: 8px;
    padding: 12px 28px;
    cursor: pointer;
    min-height: 44px;
    transition: background 200ms;
  }

  .lab-mobile-gate-copy:active {
    background: rgba(184, 165, 214, 0.12);
  }

  .lab-mobile-gate-back {
    font-size: 13px;
    color: var(--text-3);
    min-height: 44px;
    display: flex;
    align-items: center;
  }

  /* Also need to unlock body scroll on mobile since workspace sets overflow:hidden */
  body {
    overflow: auto !important;
    height: auto !important;
  }
}
```

- [ ] **Step 4: Verify**

Run: `npm run dev`

Navigate to any lab (e.g., `/labs/red/xss-shopstack/`).

At 390px: should see the gate screen with title, difficulty, description, copy link button, and "View all labs" link. No workspace visible. Body should scroll normally.

At 1024px: workspace visible, no gate visible.

- [ ] **Step 5: Commit**

```bash
git add src/_includes/lab-workspace.njk src/_includes/lab-workspace-blue.njk src/css/labs.css
git commit -m "Add mobile gate screen for labs — workspace gated below 900px"
```

---

### Task 8: Hover Guards & Active States

Wrap transform/box-shadow hovers in `@media (hover: hover)` to fix iOS sticky hover. Add `:active` feedback for touch.

**Files:**
- Modify: `src/css/style.css` — multiple `:hover` rules
- Modify: `src/css/labs.css` — lab-card hover
- Modify: `src/css/labs-blue.css` — classify-btn hover
- Modify: `src/css/blog.css` — blog-post-card hover
- Modify: `src/css/docs.css` — docs-feature hover

- [ ] **Step 1: Guard style.css hover transforms**

In `src/css/style.css`, wrap these hover rules inside `@media (hover: hover) { }`:

1. `.t-card:hover` (line 824) — has `transform: translateY(-3px)` and `box-shadow`
2. `.station-terminal:hover` (line 685) — has `box-shadow`

Only these two have transform/box-shadow effects. Other hover rules (`.station:hover`, `.wiki-card:hover`, `.featured-card:hover`, `.lib-feature-card:hover`) only change `border-color` or `background` — leave those unwrapped per the spec's rule of thumb.

For each, wrap:

```css
/* Before */
.t-card:hover {
  border-color: rgba(184, 165, 214, 0.1);
  transform: translateY(-3px);
  box-shadow: 0 20px 50px rgba(0, 0, 0, 0.35);
}

/* After */
@media (hover: hover) {
  .t-card:hover {
    border-color: rgba(184, 165, 214, 0.1);
    transform: translateY(-3px);
    box-shadow: 0 20px 50px rgba(0, 0, 0, 0.35);
  }
}
```

Leave simple color-only hovers (like `a:hover { color: ... }`) unwrapped.

- [ ] **Step 2: Guard labs-blue.css hover transform**

In `src/css/labs-blue.css`, wrap `.siem-classify-btn:hover` (line 255) in `@media (hover: hover) { }`.

- [ ] **Step 3: Guard labs.css hover transforms**

In `src/css/labs.css`, wrap `.lab-card:hover` (line 990) in `@media (hover: hover) { }` if it has transform or box-shadow.

- [ ] **Step 4: Verify blog.css and docs.css — no guards needed**

`.blog-post-card:hover` (blog.css line 54) only changes `color` — no guard needed.
`.docs-feature:hover` (docs.css line 287) only changes `border-color` and `background` — no guard needed.

No changes to these files for hover guards. The `:active` states added in Step 5 still apply.

- [ ] **Step 5: Add global active state**

In `src/css/style.css`, add near the global styles (after the `a:hover` rule, around line 52):

```css
/* Touch feedback */
.t-card:active,
.station:active,
.station-terminal:active,
.wiki-card:active,
.featured-card:active,
.lab-card:active,
.blog-post-card:active {
  opacity: 0.85;
  transition: opacity 100ms;
}
```

- [ ] **Step 6: Verify**

Run: `npm run dev`

At 390px (with touch simulation in DevTools): tap a card — should see brief opacity dip. No hover state should stick after tap.

At 1024px with mouse: hover effects (transform, shadow) should still work normally.

- [ ] **Step 7: Commit**

```bash
git add src/css/style.css src/css/labs.css src/css/labs-blue.css src/css/blog.css src/css/docs.css
git commit -m "Add hover guards for touch devices and active state feedback"
```

---

### Task 9: Viewport Fit & Mobile Overflow Safety

Final polish: safe areas for notched phones, overflow protection on sections.

**Files:**
- Modify: `src/_includes/base.njk:5` (viewport meta tag)
- Modify: `src/css/style.css` — footer safe area, section overflow
- Modify: `src/_includes/lab-workspace.njk:6` (viewport meta tag)
- Modify: `src/_includes/lab-workspace-blue.njk:6` (viewport meta tag)

- [ ] **Step 1: Add viewport-fit=cover to base template**

In `src/_includes/base.njk`, change line 5:

```html
<!-- Before -->
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<!-- After -->
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
```

Do the same in `src/_includes/lab-workspace.njk` (line 6) and `src/_includes/lab-workspace-blue.njk` (line 6).

- [ ] **Step 2: Add safe area padding to footer**

In `src/css/style.css`, inside the `@media (max-width: 640px)` footer block (around line 947), add:

```css
  .footer {
    /* existing rules stay */
    padding-bottom: calc(24px + env(safe-area-inset-bottom, 0px));
  }
```

- [ ] **Step 3: Add section/container overflow safety**

In `src/css/style.css`, inside the large `@media (max-width: 640px)` block (line 4358), add:

```css
  .section,
  .container {
    max-width: 100vw;
  }
```

- [ ] **Step 4: Verify**

Run: `npm run dev`

At 390px: check that the footer has extra bottom padding on notched phones (visible in DevTools with "Show device frame" for iPhone 14/15). No horizontal scroll on any page.

- [ ] **Step 5: Commit**

```bash
git add src/_includes/base.njk src/_includes/lab-workspace.njk src/_includes/lab-workspace-blue.njk src/css/style.css
git commit -m "Add viewport-fit cover, safe areas, and overflow protection"
```

---

### Task 10: Final Visual Verification

Run through all major pages at phone viewport to catch anything missed.

**Files:** None — verification only.

- [ ] **Step 1: Start dev server**

Run: `npm run dev`

- [ ] **Step 2: Check each page at 390px width**

Open Chrome DevTools → Device toolbar → iPhone 14 (390px).

Verify each page:
- `/` (homepage): hamburger works, cards compact, stations text-only, stats vertical with accent, particles reduced
- `/tools/` (tools hub): cards compact, filters tappable, search works
- `/tools/json-formatter/` (sample tool): inputs full-width, buttons tappable, output scrollable
- `/labs/` (labs index): cards display correctly, browseable
- `/labs/red/xss-shopstack/` (sample lab): gate screen shows, workspace hidden
- `/labs/blue/alert-triage/` (sample blue lab): gate screen shows
- `/blog/` (blog index): readable, no overflow
- `/gate/` (product page): layout okay, code blocks scroll
- `/librarian/` (product page): layout okay

- [ ] **Step 3: Check at 360px width (small phones)**

Switch to 360px viewport and re-check homepage and tools hub for any overflow or text truncation.

- [ ] **Step 4: Check landscape mode**

Rotate to landscape (640x360). Hamburger should appear. Nav should not be cramped.

- [ ] **Step 5: Document any issues found**

If issues are found, create follow-up tasks. Otherwise, this task is complete.
