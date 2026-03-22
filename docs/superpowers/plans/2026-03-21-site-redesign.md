# Penumbra Forge Site Redesign — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign penumbraforge.com to match the approved mockup-g direction — centered eclipse with breathing corona, split hero with live tool demo, project stations, particle/parallax background system, new typography and spacing.

**Architecture:** The site is an Eleventy 3.0 static site with Nunjucks templates. Three templates control all pages: `base.njk` (root), `tool-layout.njk` (60 tool pages), `index.njk` (homepage), plus `tools/index.njk` (hub). The redesign rewrites `style.css` and all four templates. Tool `.njk` files are NOT modified — they inherit the new design through `tool-layout.njk` and CSS changes. All JS is vanilla, no dependencies.

**Tech Stack:** Eleventy 3.0, Nunjucks, vanilla CSS (custom properties), vanilla JS (canvas particles, IntersectionObserver, requestAnimationFrame), Google Fonts (Bricolage Grotesque, Plus Jakarta Sans, JetBrains Mono)

**Design reference:** `/Users/penumbra/penumbraforge/public/mockup-g.html` contains the approved design — use it as the source of truth for all visual decisions.

---

## File Map

| Action | File | Responsibility |
|--------|------|---------------|
| Rewrite | `src/css/style.css` | Complete design system + all component styles |
| Rewrite | `src/_includes/base.njk` | Root HTML — fonts, particle canvas, stars, orbs, z-layering |
| Rewrite | `src/_includes/footer.njk` | Updated footer matching new design |
| Rewrite | `src/index.njk` | Homepage — eclipse hero, split layout, stations, tools grid, about |
| Rewrite | `src/tools/index.njk` | Tools hub — search, filters, card grid in new style |
| Rewrite | `src/_includes/tool-layout.njk` | Tool page wrapper — nav, breadcrumbs, content area, related tools |
| No change | `src/tools/*.njk` (60 files) | Tool pages inherit new design via template + CSS |
| No change | `src/_data/*.json` | Data files unchanged |
| No change | `eleventy.config.js` | Config unchanged |
| Delete | `public/mockup-*.html` | Clean up mockup files after implementation |

---

### Task 1: Design Tokens & Base CSS Reset

**Files:**
- Rewrite: `src/css/style.css` (lines 1–77, design tokens + reset + layout)

This task establishes the new design system foundation. Everything else builds on these tokens.

- [ ] **Step 1: Read the current design tokens and the mockup-g CSS**

Read: `src/css/style.css` lines 1–77
Read: `public/mockup-g.html` — extract all CSS custom properties, base styles, font declarations

- [ ] **Step 2: Rewrite design tokens section**

Replace lines 1–77 of `style.css` with new tokens from mockup-g:
- New color palette (`--surface-0: #050509`, updated borders, accents)
- New font stacks (Bricolage Grotesque, Plus Jakarta Sans, JetBrains Mono)
- New base font size (14px), line-height (1.6), font-weight (300)
- `@property --penumbra-hue` declaration
- Reset styles
- Updated `.container` max-width (1400px) and section padding (80px)

Key values from mockup-g:
```css
:root {
  --surface-0: #050509;
  --surface-1: #0a0a14;
  --surface-2: #0d0d1e;
  --border: rgba(184, 165, 214, 0.045);
  --border-hover: rgba(184, 165, 214, 0.09);
  --accent: #b8a5d6;
  --accent-dim: rgba(184, 165, 214, 0.45);
  --text-1: #e8e4ef;
  --text-2: #999;
  --text-3: #666;
  --text-4: #444;
  --sage: #6bcf8f;
  --warn: #e8a87c;
  --font-display: 'Bricolage Grotesque', sans-serif;
  --font-body: 'Plus Jakarta Sans', sans-serif;
  --font-mono: 'JetBrains Mono', monospace;
}
```

- [ ] **Step 3: Verify dev server renders with new tokens**

Run: `npm run dev` (should already be running)
Check: Homepage loads without CSS errors, colors shifted to new palette

- [ ] **Step 4: Commit**

```bash
git add src/css/style.css
git commit -m "redesign: replace design tokens with new palette, typography, and spacing"
```

---

### Task 2: Base Layout Template

**Files:**
- Rewrite: `src/_includes/base.njk`

Add the background layer system (particle canvas, star field, parallax orbs, page glow), Google Fonts link tags, and z-index layering structure. This is the foundation all pages inherit.

- [ ] **Step 1: Read current base.njk**

Read: `src/_includes/base.njk`

- [ ] **Step 2: Rewrite base.njk**

New structure:
```
<head>
  - Keep all existing meta, OG, JSON-LD blocks
  - Add Google Fonts preconnect + stylesheet links
  - Keep existing CSS link
  - Add headExtra block
</head>
<body>
  <!-- Background layers (z-index: 0) -->
  <canvas id="particle-canvas"></canvas>
  <div class="stars" id="stars"></div>
  <div class="page-glow"></div>
  <div class="orb-layer">
    <div class="orb orb-1" data-parallax="0.15"></div>
    ... (6 orbs from mockup-g)
  </div>

  <!-- Content layer (z-index: 1) -->
  <div class="content">
    {{ content | safe }}
    {% include "footer.njk" %}
  </div>

  <!-- Scripts: particles, stars, parallax, scroll-reveal -->
  <script> ... (from mockup-g) </script>
</body>
```

Key details:
- Google Fonts: `Bricolage+Grotesque`, `Plus+Jakarta+Sans`, `JetBrains+Mono`
- Remove the old grain overlay div
- JS includes: particle canvas system (50 particles), star field (70 stars), parallax orbs, IntersectionObserver scroll-reveal
- Add `prefers-reduced-motion` handling in JS

- [ ] **Step 3: Verify pages still render**

Open: `http://localhost:8080/`
Check: Page loads, particle canvas visible in background, fonts loaded

- [ ] **Step 4: Commit**

```bash
git add src/_includes/base.njk
git commit -m "redesign: add background particle system, fonts, and z-layered base layout"
```

---

### Task 3: Background Layer CSS

**Files:**
- Modify: `src/css/style.css` — add background layer styles after the base reset section

All the CSS for the particle canvas, star field, parallax orbs, page glow, scroll-reveal animations, and section gap spacers. These are shared across every page.

- [ ] **Step 1: Add background layer CSS from mockup-g**

After the reset/base section, add all of:
- `#particle-canvas` (fixed, z-index 0)
- `.stars`, `.star`, `.star--bright` + `@keyframes twinkle`
- `.orb-layer`, `.orb`, `.orb-1` through `.orb-6` (positions, sizes, gradients, blur)
- `.page-glow` (fixed radial gradient)
- `.content` (z-index 1)
- `.section` (solid `#050509` background to mask particles)
- `.section-gap`, `.section-gap-lg` (transparent spacers)
- `.reveal`, `.reveal.visible`, `.reveal-delay-1` through `.reveal-delay-7`
- `@media (prefers-reduced-motion: reduce)` block

- [ ] **Step 2: Verify particles render behind content**

Open: `http://localhost:8080/`
Scroll: Particles should be visible between sections, hidden behind section backgrounds

- [ ] **Step 3: Commit**

```bash
git add src/css/style.css
git commit -m "redesign: add background particle system, orbs, star field, and scroll-reveal CSS"
```

---

### Task 4: Footer

**Files:**
- Rewrite: `src/_includes/footer.njk`
- Modify: `src/css/style.css` — replace footer section (lines ~480–518)

- [ ] **Step 1: Rewrite footer.njk**

Match mockup-g footer structure:
```html
<footer class="footer">
  <span>&copy; 2026 Penumbra Forge</span>
  <div class="footer-links">
    <a href="https://github.com/penumbraforge">GitHub</a>
    <a href="/privacy.html">Privacy</a>
    <a href="/terms.html">Terms</a>
  </div>
</footer>
```

- [ ] **Step 2: Replace footer CSS**

From mockup-g: max-width 1400px, padding 32px 80px, flex between, 11px text, #333 color, solid background for particle masking.

- [ ] **Step 3: Verify footer renders**

Check: Footer visible at bottom of homepage with correct links

- [ ] **Step 4: Commit**

```bash
git add src/_includes/footer.njk src/css/style.css
git commit -m "redesign: update footer to match new design system"
```

---

### Task 5: Homepage — Eclipse Hero

**Files:**
- Rewrite: `src/index.njk` (hero section only, first pass)
- Modify: `src/css/style.css` — replace hero CSS (lines ~78–116)

Build the hero section: centered eclipse with breathing corona + backlight, split layout with text left and live tool demo right, stats row.

- [ ] **Step 1: Write the eclipse hero HTML in index.njk**

Structure from mockup-g:
```
<section class="hero">
  <div class="eclipse-row reveal">
    <div class="penumbra-mark">
      <div class="penumbra-backlight"></div>
      <div class="penumbra-corona"></div>
      <div class="penumbra-light"></div>
      <div class="penumbra-edge"></div>
      <div class="penumbra-shadow"></div>
      <canvas id="eclipse-particles" width="500" height="500"></canvas>
    </div>
  </div>

  <div class="hero-split">
    <!-- Left: label, h1, subtitle, stats -->
    <!-- Right: live tool demo (secrets-scanner) -->
  </div>
</section>
```

Include the full live-tool card with syntax-highlighted secrets-scanner output.

- [ ] **Step 2: Add hero CSS**

From mockup-g — all `.hero`, `.eclipse-row`, `.penumbra-mark`, `.penumbra-shadow`, `.penumbra-light`, `.penumbra-edge`, `.penumbra-corona`, `.penumbra-backlight`, `@keyframes` (penumbra-shift, penumbra-rotate, corona-breathe, backlight-breathe), `.hero-split`, `.hero-label`, `.hero h1`, `.hero-subtitle`, `.hero-stats`, `.stat-num`, `.stat-label`, `.live-tool`, `.tool-titlebar`, `.tool-dot`, `.tool-name`, `.tool-body pre`, `.hl-*` syntax classes, `.tool-footer`, `.tool-badge`, `.tool-btn`

- [ ] **Step 3: Add eclipse corona JS to base.njk**

Add the eclipse corona wisp canvas script from mockup-g (the breathing light version with 12 wisps at 1.5-3% opacity).

- [ ] **Step 4: Verify hero renders correctly**

Open: `http://localhost:8080/`
Check: Eclipse centered with breathing backlight, split layout below, tool demo on right, stats row, particles visible in background

- [ ] **Step 5: Commit**

```bash
git add src/index.njk src/css/style.css src/_includes/base.njk
git commit -m "redesign: add eclipse hero with corona wisps, split layout, and live tool demo"
```

---

### Task 6: Homepage — Project Stations

**Files:**
- Modify: `src/index.njk` — replace principles, librarian, umbra, and products sections
- Modify: `src/css/style.css` — replace those section styles with station CSS

Replace the old sections with the station card layout from mockup-g: section dividers, Gate station, mcp-librarian station, Umbra station (with in-development status).

- [ ] **Step 1: Write station HTML**

Structure from mockup-g:
```
<div class="section-gap section-gap-lg"></div>
<div class="section">
  <div class="section-divider reveal"><span>From the Forge</span></div>
  <!-- Gate station -->
  <!-- mcp-librarian station -->
  <!-- Umbra station (station-umbra variant) -->
</div>
```

Each station has: `.station-tag`, `h3`, description `p`, `.station-features` list, `.station-visual` placeholder.

- [ ] **Step 2: Add station CSS**

From mockup-g — all `.section-divider`, `.station`, `.station::before`, `.station-content`, `.station-tag`, `.station h3`, `.station p`, `.station-features`, `.station-feature`, `.station-visual`, `.station-umbra`, `.umbra-status`, `.status-dot`, `.status-text`, `@keyframes pulse`

- [ ] **Step 3: Remove old section CSS**

Delete CSS for: `.principles-grid`, `.librarian`, `.librarian-grid`, `.librarian-card`, `.umbra`, `.umbra-header`, `.umbra-orb`, `.umbra-name`, `.umbra-status` (old version), `.product-card`, `.product-card-content`, `.product-name`, `.product-card-actions`, `.product-source`, `.product-arrow`

- [ ] **Step 4: Verify stations render**

Scroll: Three station cards visible with correct layout, divider line, hover effects

- [ ] **Step 5: Commit**

```bash
git add src/index.njk src/css/style.css
git commit -m "redesign: replace homepage sections with project station cards"
```

---

### Task 7: Homepage — Tools Grid & About

**Files:**
- Modify: `src/index.njk` — replace tools showcase and about sections
- Modify: `src/css/style.css` — replace those section styles

- [ ] **Step 1: Write tools grid HTML**

From mockup-g: section divider, section head with h2 + description + "53 tools & counting" count, 4-column grid of 8 featured tool cards with icons, names, descriptions, and "runs in your browser" badges.

- [ ] **Step 2: Write about section HTML**

From mockup-g: section divider, two-column layout (240px left: name, role, location / right: two paragraphs + tech chips).

- [ ] **Step 3: Add tools grid and about CSS**

From mockup-g — `.section-head`, `.section-desc`, `.section-count`, `.tools-grid`, `.t-card`, `.t-icon`, `.t-card h4`, `.local-badge`, `.about-layout`, `.about-name`, `.about-role`, `.about-location`, `.about-body`, `.tech-row`, `.tech-chip`

- [ ] **Step 4: Remove old section CSS**

Delete CSS for: `.tools-showcase*`, `.about` (old version), `.tech-tags`, `.tech-tag`

- [ ] **Step 5: Verify full homepage**

Scroll through entire homepage: eclipse → stations → tools grid → about → footer. All sections render, particles visible between sections.

- [ ] **Step 6: Commit**

```bash
git add src/index.njk src/css/style.css
git commit -m "redesign: add tools grid and structured about section"
```

---

### Task 8: Tools Hub Page

**Files:**
- Rewrite: `src/tools/index.njk`
- Modify: `src/css/style.css` — replace tools hub section (lines ~945–1233)

The tools hub is the `/tools/` page with search, category filters, and the full grid of 53+ tools.

- [ ] **Step 1: Read current tools hub page and CSS**

Read: `src/tools/index.njk`
Read: `src/css/style.css` lines 945–1233

- [ ] **Step 2: Rewrite tools hub HTML**

New structure matching mockup-g design language:
- Site header/nav (styled to match new design)
- Hero section with search input (styled with new tokens)
- Filter buttons (restyled with new button aesthetics)
- Tool card grid (4-column, using `.t-card` style from homepage)
- All data attributes preserved for JS filtering
- Keep existing search/filter JS logic, update class names if needed

- [ ] **Step 3: Replace tools hub CSS**

Rewrite `.tools-hub*` styles using new design tokens. Match card style to the homepage `.t-card` pattern for consistency. Update search input, filter buttons, empty state.

- [ ] **Step 4: Verify tools hub**

Open: `http://localhost:8080/tools/`
Check: Search works, category filters work, cards render in new style, responsive layout

- [ ] **Step 5: Commit**

```bash
git add src/tools/index.njk src/css/style.css
git commit -m "redesign: rewrite tools hub with new card grid and filter styling"
```

---

### Task 9: Tool Page Layout Template

**Files:**
- Rewrite: `src/_includes/tool-layout.njk`
- Modify: `src/css/style.css` — replace tool page sections (lines ~567–944)

This template controls all 60 individual tool pages. Update the nav, breadcrumbs, content area, and related tools section to match the new design.

- [ ] **Step 1: Read current tool-layout.njk and tool page CSS**

Read: `src/_includes/tool-layout.njk`
Read: `src/css/style.css` lines 567–944

- [ ] **Step 2: Rewrite tool-layout.njk**

Update structure:
- Site header: restyled nav with new font/color tokens
- Breadcrumbs: restyled with new separator and typography
- Tool content area: updated header, badge, description styling
- Keep all `{% block %}` structures so tool pages work unchanged
- Related tools: use new card style consistent with homepage
- Tool CTA section: restyled
- Remove grain overlay div (now in base.njk particle system)

Critical: All block names and tool data references must stay the same so the 60 tool `.njk` files continue to work without modification.

- [ ] **Step 3: Replace tool page CSS**

Rewrite all tool page styles using new design tokens:
- `.site-header` — new font, spacing, colors
- `.tool-nav` — updated breadcrumbs
- `.tool-page`, `.tool-main` — max-width updated, backgrounds
- `.tool-header`, `.tool-badge` — new typography
- `.tool-group`, `.tool-row`, `.tool-options` — updated form styling
- `.btn` — new button style matching `.tool-btn` from mockup
- `input`, `textarea`, `select` — dark inputs with new border colors
- `.output-area` — updated code output styling
- `.tool-related` — card grid matching homepage style
- `.tool-cta` — updated call-to-action

- [ ] **Step 4: Verify tool pages render**

Open: `http://localhost:8080/tools/json-formatter/`
Open: `http://localhost:8080/tools/secrets-scanner/`
Open: `http://localhost:8080/tools/subnet-calculator/`
Check: Nav, breadcrumbs, inputs, outputs, related tools all render. Tool functionality still works (format JSON, run scanner, calculate subnets).

- [ ] **Step 5: Check for tool pages with inline styles**

Some tool pages (e.g., jwt-decoder.njk) have inline `<style>` blocks. Verify these don't conflict with the new design by spot-checking:
- JWT Decoder: `http://localhost:8080/tools/jwt-decoder/`
- Diff Viewer: `http://localhost:8080/tools/diff-viewer/`
- Git Branch Visualizer: `http://localhost:8080/tools/git-branch-visualizer/`

- [ ] **Step 6: Commit**

```bash
git add src/_includes/tool-layout.njk src/css/style.css
git commit -m "redesign: rewrite tool page layout with new nav, forms, and related tools"
```

---

### Task 10: Responsive Design

**Files:**
- Modify: `src/css/style.css` — add/replace all media queries

- [ ] **Step 1: Add responsive breakpoints for new layout**

Breakpoints: 1200px, 1024px, 768px, 640px

Key responsive behaviors:
- Hero split → stacked at 1024px (eclipse stays centered, tool demo below text)
- Station cards → stacked at 768px
- Tools grid → 3-col at 1024px, 2-col at 768px, 1-col at 640px
- About layout → stacked at 768px
- Section padding → reduced at smaller screens (80px → 40px → 24px)
- Hero h1 → scale down at smaller screens
- Stats row → wraps or reduces gap
- Live tool demo → full width at mobile

- [ ] **Step 2: Remove old responsive CSS**

Delete all old media queries from the previous design (lines ~140–150, ~267–282, ~318–322, ~1151–1233).

- [ ] **Step 3: Test at all breakpoints**

Resize browser to: 1400px, 1200px, 1024px, 768px, 640px, 375px
Check: Homepage, tools hub, and individual tool pages at each breakpoint

- [ ] **Step 4: Commit**

```bash
git add src/css/style.css
git commit -m "redesign: add responsive breakpoints for all new layout components"
```

---

### Task 11: Cleanup & Polish

**Files:**
- Delete: `public/mockup-a.html`, `public/mockup-b.html`, `public/mockup-c.html`, `public/mockup-d.html`, `public/mockup-e.html`, `public/mockup-f.html`, `public/mockup-g.html`
- Modify: `src/css/style.css` — remove any orphaned CSS from old design
- Modify: `src/css/style.css` — clean up scrollbar, grain overlay sections

- [ ] **Step 1: Delete all mockup files**

```bash
rm public/mockup-*.html
```

- [ ] **Step 2: Remove orphaned CSS**

Search `style.css` for any classes no longer referenced in any template:
- Old grain overlay (`.grain`)
- Old hero orb (`.hero-orb`)
- Old principles grid
- Old product cards
- Any other dead selectors

- [ ] **Step 3: Verify the full site**

Test every major path:
- Homepage: `http://localhost:8080/`
- Tools hub: `http://localhost:8080/tools/`
- 3+ tool pages: json-formatter, secrets-scanner, subnet-calculator
- Gate docs: `http://localhost:8080/gate/`
- Librarian: `http://localhost:8080/librarian/`

Check: All pages render, no broken styles, particles work, scroll reveals fire, tool functionality preserved.

- [ ] **Step 4: Run build**

```bash
npm run build
```

Verify: Clean build with no errors.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "redesign: cleanup mockup files and remove orphaned CSS"
```

---

## Execution Notes

- **Order matters:** Tasks 1–4 establish the foundation. Task 5–7 build the homepage. Task 8–9 update secondary pages. Task 10–11 polish.
- **Tool pages are fragile:** 60 tool `.njk` files have inline JS that selects elements by class name. When rewriting `tool-layout.njk` CSS, preserve class names on interactive elements (inputs, buttons, output areas) or update selectors in all 60 files.
- **CSS is a single file:** All styles live in one `style.css`. Work section by section to avoid merge conflicts.
- **Test frequently:** After each task, visually verify in the browser. The dev server hot-reloads.
- **Preserve functionality:** Every tool must still work after the redesign. The visual treatment changes; the behavior doesn't.
