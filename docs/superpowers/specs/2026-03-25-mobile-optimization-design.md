# Mobile Optimization Design

**Date:** 2026-03-25
**Scope:** Whole-site mobile optimization for penumbraforge.com
**Target devices:** All phones, 360px-430px core range, graceful handling to 320px
**Approach:** Surgical fixes to existing CSS — no architecture rewrite

## Existing Mobile Work

The site already has substantial mobile CSS (style.css lines 4358-4745) covering:
- `.site-header-nav` wrapping with 44px tap targets at 640px
- Hero section centering and text alignment
- Station terminal font/padding reduction
- `.t-card` padding reduced to 20px, icon sizing
- About section text centering
- Tool page inputs sized to 16px (prevents iOS zoom), buttons with 44px min-height
- Tools hub search/filter tap targets
- Gate/wiki/librarian page mobile adjustments
- Global: all `button`/`[role="button"]` get `min-height: 44px`, all `pre` blocks get `overflow-x: auto`

Additionally, at 1024px:
- `.hero-split` collapses to single column (gap 40px)
- `.station` collapses to single column (gap 28px)
- `.about-layout` collapses to single column (gap 32px)
- `.tools-grid` goes to 2 columns
- `.brand-preview-hero` collapses to single column

At 768px:
- `.site-header` gets `flex-wrap: wrap` with 44px tap targets on nav links
- Padding reductions on hero, sections
- Font size reductions on hero h1 (32px), section h2 (26px), station h3 (22px)

At 640px:
- `.tools-grid` goes to single column
- `.hero-stats` goes `flex-direction: column`
- Further padding/gap reductions

**This spec covers what's still missing or broken despite the above work.**

## Constraints

- Desktop layout is untouched
- Tablet experience above 900px is untouched (already mostly functional)
- No functionality removed — everything adapts to viewport
- Visual identity preserved — same colors, fonts, atmosphere
- No CSS framework or build tool additions

## 1. Mobile Navigation (Hamburger Menu)

### Problem
The homepage uses `.home-nav` — a fixed `flex` row of links with `gap: 28px` and no mobile collapse. Unlike `.site-header-nav` (used on inner pages, which wraps at 640px), `.home-nav` has no mobile override and will overflow or wrap awkwardly on phones.

### Design
- Add a hamburger button (three-line SVG icon) visible only below 640px
- On tap, opens a slide-down overlay from the top — full-width, semi-transparent dark background using `--surface-1`
- Nav links stack vertically with 48px minimum tap-target height
- Close animation: slide up + fade
- Hamburger icon uses `--accent` purple
- Desktop (>640px): existing `.home-nav` unchanged
- Inner pages: `.site-header-nav` already wraps at 640px — no change needed

### Implementation
- Small JS toggle: add/remove `.nav-open` class on `<body>`
- CSS handles visibility, transitions, and layout
- Hamburger button hidden on desktop via `display: none` above 640px
- Overlay uses `position: fixed; inset: 0` with `z-index: 100` (avoids conflict with existing z-index: 60 floating button at line 3848)

### Affected files
- Homepage template (likely `src/index.njk` or equivalent) — add hamburger button markup
- `src/css/style.css` — hamburger + overlay styles, media query

## 2. Remaining Layout Issues

### Problem
Most grid layouts already collapse at 1024px, but several elements still have spacing or sizing issues at phone widths that the existing 640px block doesn't address.

### Fixes

**`.hero-split`** (collapses at 1024px with gap: 40px, padding-bottom: 80px — both too large for phones):
- Below 640px: gap to 24px, padding-bottom to 40px

**`.about-layout`** (collapses at 1024px with gap: 32px — adequate, but the 240px-wide side column content needs attention):
- No grid change needed (already 1fr at 1024px)
- Below 640px: gap to 20px to tighten vertical rhythm

**`.station`** (collapses at 1024px with gap: 28px, padding: 40px):
- Padding already reduced to 24px at 640px
- Below 480px: padding to 16px for smallest phones

**`.brand-preview-hero`** (already collapses at 1024px):
- No change needed — already handled

### Affected files
- `src/css/style.css` — additions to existing 640px block, new 480px block

## 3. Card Sizing & Scroll Reduction

### Problem
Cards go single-column on mobile but the page is extremely tall because every card renders at full height. The homepage shows all tool cards (16+) in a vertical stack.

### Fixes

**`.t-card` (homepage tools grid):**
- Below 640px: padding already reduced to 20px — further reduce to 16px
- Switch to compact horizontal layout: `display: flex; gap: 12px; align-items: center` — icon left, title + description right
- `.t-icon` margin-bottom: 0 (no longer stacked)
- Cuts vertical space per card roughly in half

**`.station` cards:**
- Below 640px: hide `.station-terminal` and `.station-visual` via `display: none`
- Show only text content (title, description, features)
- Each station already contains a link in its content — the station-terminal is a decorative demo preview, and the actual product link is in `.station-content`. Hiding the terminal removes visual weight without removing navigation.

**`.tools-hub-card` (tools hub page):**
- `.tools-hub-card` inherits from `.t-card` styles — the `.t-card` padding reduction to 16px at 640px covers this automatically
- If `.tools-hub-card` has additional internal spacing overrides, tighten those to match

**Homepage tools section:**
- Below 640px: show only first 4 `.t-card` elements via CSS `:nth-child(n+5) { display: none }`
- Add a `.tools-more-link` element after the grid, hidden on desktop, shown on mobile — links to `/tools/`

### Affected files
- `src/css/style.css` — card layout overrides, nth-child rule
- Homepage template — add `.tools-more-link` element

## 4. Typography & Spacing (New 480px Breakpoint)

### Problem
The smallest breakpoint is 640px. Phones at 360-390px still get 640px styles, which can be too generous with spacing and font sizes for the available width.

### Existing state
At 640px, `.section h2` is already 22px, `.hero h1` is 26px, `.section` padding is 40px 16px, `.hero` padding is 24px 16px.

### Fixes

**New 480px breakpoint for smallest phones:**
- `.hero h1`: 22px (from 26px at 640px)
- `.station h3`: 19px (from 22px at 768px)
- `.section` padding: 32px 12px (from 40px 16px at 640px)
- `.hero` padding: 20px 12px 0 (from 24px 16px 0 at 640px)

**Tap target improvements (640px block):**
- `.tool-btn` padding: `10px 20px` (up from `7px 18px` — min-height 44px already applied globally but padding is still visually cramped)
- `.tech-chip` padding: `8px 16px` (easier to tap in the about section)

**Hero stats vertical styling:**
- Already goes `flex-direction: column` at 640px
- Add subtle left border accent on each stat (`border-left: 2px solid rgba(184, 165, 214, 0.15); padding-left: 12px`) so the vertical list feels intentional

### Affected files
- `src/css/style.css` — new 480px media query block, additions to 640px block

## 5. Particle Effects & Performance

### Problem
50 particles at full framerate via `requestAnimationFrame`, 70 star DOM elements, 6 parallax orbs with `filter: blur(80px)` — all running on mobile GPUs.

### Fixes

**Particle canvas (inline script in `base.njk`):**
- Detect mobile: `window.innerWidth < 768` at init
- Mobile particle count: 18 (down from 50)
- Remove glow effect (secondary arc for `size > 1.2`) on mobile — halves draw calls
- Implementation of framerate reduction left to implementer's discretion (RAF skip, setTimeout, or other approach)

**Star field (inline script in `base.njk`):**
- Mobile: 25 stars (down from 70)
- Below 768px CSS: disable `.star--bright` `twinkle` animation

**Parallax orbs:**
- Below 768px CSS: hide `.orb-3` through `.orb-6` via `display: none`
- Keep `.orb-1` and `.orb-2` for subtle atmosphere
- Reduce `filter: blur(80px)` to `blur(40px)` on mobile

**Eclipse particles (`#eclipse-particles`):**
- Below 768px CSS: reduce width/height from 500px to 300px
- Already hidden by `prefers-reduced-motion`

### Net result
Atmosphere stays alive at roughly 1/3 the rendering cost.

### Affected files
- `src/_includes/base.njk` — particle + star script mobile detection
- `src/css/style.css` — orb hiding, star animation disable, eclipse resize

## 6. Labs Gate on Mobile

### Problem
Lab workspace pages have multi-panel layouts with fixed-width sidebars (320-380px) that cannot fit on phone screens.

### Design
- Below 900px, instead of the workspace, show a gate screen:
  - Lab title and difficulty badge
  - Brief description of the lab
  - Desktop/laptop SVG icon
  - Message: "This lab requires a desktop browser for the full interactive experience"
  - "Copy link" button (small JS: `navigator.clipboard.writeText`)
  - "View all labs" link back to `/labs/`
- Gate uses the same dark theme, typography, and spacing — feels intentional
- Labs index page (`/labs/`) works fully on mobile — browsing, descriptions, difficulty ratings all functional
- Only the workspace view is gated

### Breakpoint
900px — tablets in portrait can still use the workspace

### Implementation
- Gate HTML always present in lab templates, hidden on desktop via `display: none` above 900px
- Workspace container hidden below 900px via `display: none`
- No JS detection needed — pure CSS visibility toggle
- Copy-link button uses inline JS: `navigator.clipboard.writeText(window.location.href)`

### Affected files
- `src/_includes/lab-workspace.njk` (or equivalent red team template) — add gate markup
- `src/_includes/lab-workspace-blue.njk` (or equivalent blue team template) — add gate markup
- `src/css/labs.css` — gate styles, workspace hide below 900px
- `src/css/labs-blue.css` — same gate treatment for blue team

## 7. Touch Interactions & Polish

### Problem
No touch-specific states across the site. Hover effects (like `.t-card:hover { transform: translateY(-3px) }`) feel sticky on iOS Safari, which keeps `:hover` styles applied after tap.

### Fixes

**Hover guard:**
- Wrap hover transforms/effects in `@media (hover: hover) { }` across all CSS files
- Rule of thumb: guard `transform`, `box-shadow`, and `opacity` hover changes. Leave simple `color` hover changes alone (they're harmless on touch and useful as `:active` fallback)
- This is a meaningful refactor — there are dozens of `:hover` rules across `style.css`, `labs.css`, `blog.css`, and `docs.css`
- Touch devices skip guarded hovers, solving the iOS sticky-hover issue

**Active states:**
- On touch devices, interactive elements (cards, buttons, links) get `:active` feedback — subtle opacity dip (`opacity: 0.85`)

**Horizontal overflow protection:**
- Add `overflow-x: hidden` on `html` element (body already has it; some iOS edge cases need it on html too)
- `max-width: 100vw` on `.section` and `.container` within the 640px media query

**Smooth scrolling:**
- `scroll-behavior: smooth` inside `@media (prefers-reduced-motion: no-preference)`

**Font rendering:**
- `-webkit-font-smoothing: antialiased` on body for crisp thin weights on iOS

**Safe area for notched phones:**
- Add `viewport-fit=cover` to the existing viewport meta tag
- Apply `padding: env(safe-area-inset-top) env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left)` on the hamburger overlay
- Apply `padding-bottom: env(safe-area-inset-bottom)` on the footer

**Landscape consideration:**
- The hamburger breakpoint at 640px means landscape phones (e.g., 640x360) would show desktop nav in a cramped space
- Use `@media (max-width: 768px) and (orientation: landscape)` to also show the hamburger in landscape mode on phones

### Affected files
- `src/css/style.css` — hover guards, active states, overflow, font smoothing, safe areas, landscape query
- `src/css/labs.css`, `src/css/blog.css`, `src/css/docs.css` — extend hover guards to page-specific interactive elements
- `src/_includes/base.njk` — add `viewport-fit=cover` to meta tag

## Files Changed Summary

| File | Changes |
|------|---------|
| `src/css/style.css` | New 480px breakpoint, hero-split/station spacing, card compaction, hover guards, active states, particle/orb CSS, hamburger styles, safe areas, landscape, smooth scroll, font smoothing |
| `src/css/labs.css` | Labs gate styles, workspace hide, hover guards |
| `src/css/labs-blue.css` | Blue team gate styles, workspace hide, hover guards |
| `src/css/blog.css` | Hover guards for blog cards |
| `src/css/docs.css` | Hover guards for doc links |
| `src/_includes/base.njk` | Hamburger button markup (homepage), particle/star script mobile detection, `viewport-fit=cover` |
| Homepage template | `.tools-more-link` element, hamburger button |
| Lab workspace templates | Gate screen markup, copy-link button script |

## What Is NOT Changing

- Desktop layout and styles
- Tablet experience above 900px
- `.site-header-nav` mobile behavior (already wraps correctly at 640px)
- `.about-layout` grid collapse (already 1fr at 1024px)
- `.station` grid collapse (already 1fr at 1024px)
- `.brand-preview-hero` grid collapse (already 1fr at 1024px)
- Global 44px tap-target minimums (already applied at 640px)
- `pre`/`code` overflow handling (already applied at 640px)
- iOS zoom prevention on inputs (already `font-size: 16px` at 640px)
- Site functionality (all tools, pages, content remain accessible)
- Visual identity (colors, fonts, brand atmosphere)
- Build system or dependencies
