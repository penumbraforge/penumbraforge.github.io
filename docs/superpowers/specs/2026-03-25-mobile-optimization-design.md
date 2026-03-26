# Mobile Optimization Design

**Date:** 2026-03-25
**Scope:** Whole-site mobile optimization for penumbraforge.com
**Target devices:** All phones, 360px-430px core range, graceful handling to 320px
**Approach:** Surgical fixes to existing CSS — no architecture rewrite

## Constraints

- Desktop layout is untouched
- Tablet experience above 900px is untouched (already mostly functional)
- No functionality removed — everything adapts to viewport
- Visual identity preserved — same colors, fonts, atmosphere
- No CSS framework or build tool additions

## 1. Mobile Navigation (Hamburger Menu)

### Problem
`.home-nav` is a fixed `flex` row of links with `gap: 28px`. On phones, links wrap awkwardly or overflow horizontally.

### Design
- Add a hamburger button (three-line SVG icon) visible only below 640px
- On tap, opens a slide-down overlay from the top — full-width, semi-transparent dark background using `--surface-1`
- Nav links stack vertically with 48px minimum tap-target height
- Close animation: slide up + fade
- Hamburger icon uses `--accent` purple
- Desktop (>640px): existing nav unchanged

### Implementation
- Small JS toggle: add/remove `.nav-open` class on `<body>`
- CSS handles visibility, transitions, and layout
- Hamburger button hidden on desktop via `display: none` above 640px
- Overlay uses `position: fixed; inset: 0` with `z-index: 60` (above existing nav at z-50)

### Affected files
- `src/_includes/base.njk` (or homepage template) — add hamburger button markup
- `src/css/style.css` — hamburger + overlay styles, media query
- Inline `<script>` or new small JS block — toggle handler

## 2. Fix Overlapping Layouts

### Problem
Several grid layouts use fixed or ratio-based columns that never collapse on phones, causing content to overlap or overflow.

### Fixes

**`.about-layout`** (`grid-template-columns: 240px 1fr`, gap 64px, no mobile override):
- Below 768px: `grid-template-columns: 1fr` (single column)
- Gap reduced to 28px

**`.station`** (`grid-template-columns: 5fr 4fr`, collapses only at 1024px):
- Below 768px: `grid-template-columns: 1fr` (single column)
- Padding: 24px at 768px, 20px at 480px

**`.hero-split`** (collapses at 1024px but gap/padding stay desktop-sized):
- Below 640px: gap to 24px, padding-bottom to 40px

**`.brand-preview-hero`** (`minmax(320px, 0.85fr)` forces 320px min):
- Below 768px: `grid-template-columns: 1fr`, remove minmax constraint

### Affected files
- `src/css/style.css` — media query additions in existing 768px and 640px blocks

## 3. Card Sizing & Scroll Reduction

### Problem
Cards go single-column on mobile but keep full desktop padding and content, creating endlessly tall pages.

### Fixes

**`.t-card` (homepage tools grid):**
- Below 640px: padding from 24px to 16px
- Compact horizontal layout: icon left, title + description right (list-item style instead of stacked card)
- Cuts vertical space per card roughly in half

**`.station` cards:**
- Below 640px: hide `.station-terminal` and `.station-visual` entirely
- Show only text content (title, description, features) with a link/button

**`.tools-hub-card` (tools hub page):**
- Below 640px: padding from 24px to 16px, tighter internal spacing

**Homepage tools section:**
- Below 640px: show only first 4 `.t-card` elements, hide the rest
- Add a "View all tools" link at the bottom
- Implementation: CSS `:nth-child(n+5) { display: none }` inside the media query, plus a `.tools-more-link` element that's `display: none` on desktop and visible on mobile

### Affected files
- `src/css/style.css` — card overrides, nth-child rule
- Homepage template — add `.tools-more-link` element

## 4. Typography & Spacing

### Problem
Font sizes drop at 640px but there's no intermediate scaling. No 480px breakpoint exists for the smallest phones.

### Fixes

**New 480px breakpoint:**
- `.hero h1`: 22px
- `.section h2`: 22px
- `.station h3`: 19px
- `.section` padding: 32px 12px
- `.hero` padding: 20px 12px

**Tap targets (all mobile breakpoints):**
- All interactive elements: `min-height: 44px`
- `.tool-btn` padding: `10px 20px` (up from `7px 18px`)
- `.tech-chip` padding: `8px 16px`

**Hero stats vertical layout:**
- Already goes `flex-direction: column` at 640px
- Add a subtle left border accent on each `.hero-stats > *` to feel intentional as a vertical list

### Affected files
- `src/css/style.css` — new 480px media query block, tap target overrides

## 5. Particle Effects & Performance

### Problem
50 particles at full framerate, 70 star DOM elements, 6 parallax orbs with 80px blur filters — all running on mobile GPUs.

### Fixes

**Particle canvas (inline script in `base.njk`):**
- Detect mobile: `window.innerWidth < 768` at init
- Mobile particle count: 18 (down from 50)
- Remove glow effect (secondary arc for `size > 1.2`) on mobile — halves draw calls
- Throttle to ~30fps on mobile: skip every other `requestAnimationFrame` tick

**Star field (inline script in `base.njk`):**
- Mobile: 25 stars (down from 70)
- Below 768px: disable `.star--bright` `twinkle` animation via CSS

**Parallax orbs:**
- Below 768px: hide `.orb-3` through `.orb-6` via `display: none`
- Keep `.orb-1` and `.orb-2` for subtle atmosphere
- Reduce `filter: blur(80px)` to `blur(40px)` on mobile

**Eclipse particles (`#eclipse-particles`):**
- Reduce canvas size from 500px to 300px on mobile
- Already hidden by `prefers-reduced-motion`

### Net result
Atmosphere stays alive at roughly 1/3 the rendering cost.

### Affected files
- `src/_includes/base.njk` — particle + star script modifications
- `src/css/style.css` — orb hiding, star animation disable, eclipse resize

## 6. Labs Gate on Mobile

### Problem
Lab workspace pages have multi-panel layouts with fixed-width sidebars (320-380px) that cannot fit on phone screens.

### Design
- Below 900px, instead of the workspace, show a gate screen:
  - Lab title and difficulty badge
  - Brief description of the lab
  - Desktop/laptop icon or illustration
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
- Workspace container hidden below 900px
- No JS detection needed — pure CSS visibility toggle

### Affected files
- `src/_includes/lab-workspace.njk` (or equivalent) — add gate markup
- `src/css/labs.css` — gate styles, workspace hide below 900px
- `src/css/labs-blue.css` — same gate treatment for blue team

## 7. Touch Interactions & Polish

### Problem
No touch-specific states. Hover effects (like `transform: translateY(-3px)`) feel sticky on iOS.

### Fixes

**Hover guard:**
- Wrap all hover transforms/effects in `@media (hover: hover) { }`
- Touch devices skip hover entirely, solving the iOS sticky-hover issue

**Active states:**
- On touch devices, interactive elements get `:active` feedback — subtle opacity dip (`opacity: 0.85`) or border-color flash

**Horizontal overflow protection:**
- Add `overflow-x: hidden` on `<html>` element (body already has it; iOS needs it on html too)
- `max-width: 100vw` on `.section` and `.container` on mobile
- All `pre`/`code` blocks: `overflow-x: auto` with `-webkit-overflow-scrolling: touch`

**Smooth scrolling:**
- `scroll-behavior: smooth` inside `@media (prefers-reduced-motion: no-preference)`

**Font rendering:**
- `-webkit-font-smoothing: antialiased` on body for crisp thin weights on iOS

### Affected files
- `src/css/style.css` — hover guards, active states, overflow, font smoothing
- `src/css/labs.css`, `src/css/blog.css`, `src/css/docs.css` — extend hover guards to page-specific interactive elements

## Files Changed Summary

| File | Changes |
|------|---------|
| `src/css/style.css` | Bulk of changes: new 480px breakpoint, layout collapses, card compaction, hover guards, touch states, particle/orb CSS, hamburger styles |
| `src/css/labs.css` | Labs gate styles, workspace hide, hover guards |
| `src/css/labs-blue.css` | Blue team gate styles, workspace hide |
| `src/css/blog.css` | Hover guards for blog cards |
| `src/css/docs.css` | Hover guards for doc links |
| `src/_includes/base.njk` | Hamburger button markup, particle/star script mobile detection |
| Homepage template | `.tools-more-link` element |
| Lab workspace templates | Gate screen markup, copy-link button script |

## What Is NOT Changing

- Desktop layout and styles
- Tablet experience above 900px
- Site functionality (all tools, pages, content remain accessible)
- Visual identity (colors, fonts, brand atmosphere)
- Build system or dependencies
- No CSS framework or library additions
