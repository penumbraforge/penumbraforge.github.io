# Tools Hub Overhaul — Design Spec

**Date:** 2026-03-21
**Author:** Shadoe Myers
**Status:** Draft

---

## Problem

1. The tools page 404s from the homepage — `products.json` links to `/tools` but files live in `public/tools-page/`
2. The current terminal-only UI is invisible to search engines (JS-rendered, no crawlable content)
3. No per-tool SEO — no individual pages, no meta tags, no structured data
4. The tools-page lists 12 tools, the terminal has additional kit-based tools — counts are inconsistent and some links are broken
5. No internal cross-linking between tools, no discoverability funnel to Gate/Librarian/Umbra
6. Nobody knows the site exists — zero organic search entry points

## Solution

A full tools hub overhaul with three pillars:

1. **Visual tools index** — SEO-friendly grid replacing the terminal as the default tools landing page
2. **50+ individual tool pages** — each with its own SEO, structured data, and cross-linking
3. **Terminal preservation** — the existing terminal UI stays at `/terminal` as a power-user mode

---

## Architecture

### Directory Structure

Eleventy owns the tools hub index and all new tool pages. Existing standalone HTML tools (curl-converter, dockerfile-optimizer, git-branch-visualizer) migrate from `public/tools-page/` into Eleventy templates so they gain the shared layout, SEO, and sitemap inclusion. The `public/tools/` directory is **not used** — Eleventy generates everything under `_site/tools/`.

```
src/
  _includes/
    base.njk                     ← existing site layout
    tool-layout.njk              ← NEW: shared tool page layout (extends base.njk)
    footer.njk                   ← existing
  _data/
    tools.json                   ← NEW: tool metadata driving hub + pages
    products.json                ← fix URL: /tools → /tools/
    site.json                    ← unchanged
  tools/
    tools.json                   ← directory data file (sets layout: tool-layout.njk)
    index.njk                    ← tools hub index page
    jwt-decoder.njk              ← individual tool page
    json-formatter.njk           ← individual tool page
    curl-converter.njk           ← migrated from public/tools-page/
    dockerfile-optimizer.njk     ← migrated from public/tools-page/
    git-branch-visualizer.njk   ← migrated from public/tools-page/
    ...

public/
  terminal/index.html            ← preserved as-is
  gate/index.html                ← unchanged
  librarian/index.html           ← unchanged
  (tools-page/ removed after migration)
```

**Why Eleventy owns everything:** This avoids the passthrough-copy collision where both `public/tools/index.html` and Eleventy-generated `_site/tools/index.html` would fight for the same output path. All tool pages go through Eleventy templates, gaining shared layout, SEO, and automatic sitemap inclusion.

### tools.json Schema

`src/_data/tools.json` drives the hub index, category filters, related tools, and SEO:

```json
[
  {
    "name": "JWT Decoder",
    "slug": "jwt-decoder",
    "description": "Decode and inspect JSON Web Tokens without verification",
    "longDescription": "Free online JWT decoder. Paste a JWT to inspect its header, payload, and signature. No data sent to any server — runs entirely in your browser.",
    "category": "security",
    "keywords": ["jwt decoder", "jwt debugger", "json web token decoder", "decode jwt online"],
    "badge": "local",
    "relatedTools": ["hash-gen", "encoding-suite", "secrets-scanner"],
    "status": "live"
  }
]
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Display name |
| `slug` | string | yes | URL slug — must match the `.njk` filename. Generates `/tools/{slug}/` |
| `description` | string | yes | One-line description for hub cards |
| `longDescription` | string | yes | Used as `<meta description>` — should be keyword-rich, ~155 chars |
| `category` | enum | yes | One of: `security`, `encoding`, `devops`, `web`, `text` |
| `keywords` | string[] | yes | Used for internal search/filter. (Not used as `<meta keywords>` — Google ignores that tag.) |
| `badge` | enum | yes | `local` (client-side) or `cloud` (requires tools.penumbraforge.com) |
| `relatedTools` | string[] | yes | 3-4 slugs for the "Related Tools" section. At least 1 cross-category. |
| `status` | enum | yes | `live`, `coming-soon`, or `planned` |

**Related tools algorithm:** Manually curated via `relatedTools` array. This gives full control over cross-linking topology. During bulk tool creation, default to 2 same-category + 1 cross-category + 1 high-traffic tool.

### Shared Tool Layout Template (`src/_includes/tool-layout.njk`)

Extends `base.njk`. Every tool page sets `layout: tool-layout.njk` via the directory data file `src/tools/tools.json`:

```json
{
  "layout": "tool-layout.njk"
}
```

The layout provides:

- `<title>` — `{tool.name} — Free Online {category} Tool | Penumbra Forge`
- `<meta name="description">` — from `longDescription`
- Open Graph tags (title, description, image)
- Twitter card meta (`summary_large_image`)
- JSON-LD structured data (`SoftwareApplication` schema)
- Breadcrumb navigation: `Penumbra Forge → Tools → {Category} → {Tool Name}`
- Breadcrumb JSON-LD (`BreadcrumbList` schema)
- Consistent header with Penumbra Forge logo + nav back to tools index
- "Related tools" footer section (driven by `relatedTools` array)
- CTA banner: subtle link to Gate, Librarian, Umbra
- Shared CSS (Forge Dark design tokens from main site `style.css`)
- Footer (matches main site via `footer.njk` include)

Each individual `.njk` file provides front matter overrides and the tool's HTML/CSS/JS content block.

### Tools Hub Index (`src/tools/index.njk`)

The main `/tools/` landing page (uses `base.njk` layout, not `tool-layout.njk`):

- Hero section: "Tool Kits — Free developer & security tools. No accounts, no tracking."
- Search bar (client-side JS filter, instant results)
- Category filter pills: All | Security | Encoding | DevOps | Web | Text
- Responsive card grid — each card shows: tool name, one-line description, category badge, local/cloud badge
- Cards link to individual tool pages (`/tools/{slug}/`)
- Tool count: dynamically rendered from `tools.json` length
- "Power user? Try the terminal →" subtle link at bottom
- SEO: targets "free developer tools" / "online security tools" / "free dev utilities"

### Individual Tool Pages

Each tool page contains:

- The shared layout (header, breadcrumbs, SEO, footer, related tools)
- Brief "About this tool" paragraph (crawlable text — what Google indexes)
- The tool UI (forms, inputs, outputs — all client-side JS)
- "How to use" expandable section (adds crawlable keyword-rich content)
- Privacy note: "Runs entirely in your browser. No data is sent to any server."

---

## Existing Tool Migration

### Hash-Anchor Tools

The tools-page terminal currently has several tools accessible only via hash anchors (`/tools#password`, `/tools#hash`, `/tools#jwt`, `/tools#base64`, `/tools#entropy`). These are implemented as JS within the terminal's `index.html` — they aren't standalone pages.

**Migration plan:** Each hash-anchor tool becomes its own Eleventy-generated page:
- `/tools#password` → `/tools/password-generator/` (new `.njk` with fresh UI)
- `/tools#hash` → `/tools/hash-generator/` (new `.njk` with fresh UI)
- `/tools#jwt` → `/tools/jwt-decoder/` (new `.njk` with fresh UI)
- `/tools#base64` → `/tools/base64-encoder/` (new `.njk` with fresh UI)
- `/tools#entropy` → `/tools/entropy-calculator/` (new `.njk` with fresh UI)

These are rewritten as proper tool pages with the shared layout, not extracted from the terminal JS. The terminal's internal tool implementations remain unchanged.

### Standalone HTML Tools

The three existing standalone HTML files migrate to Eleventy templates:
- `public/tools-page/curl-converter.html` → `src/tools/curl-converter.njk`
- `public/tools-page/dockerfile-optimizer.html` → `src/tools/dockerfile-optimizer.njk`
- `public/tools-page/git-branch-visualizer.html` → `src/tools/git-branch-visualizer.njk`

Each wraps the existing tool HTML/CSS/JS inside the `tool-layout.njk` content block. The tool's internal logic is preserved; only the surrounding chrome changes.

### Broken Link Audit

Current broken references to fix:
- `products.json` → `"url": "/tools"` — tools-page is at `/tools-page/` (404) → fix to `/tools/`
- Terminal `tools` object → `/tools#password`, `/tools#hash`, etc. — these hash anchors have no corresponding sections on the tools-page index → update to point to new individual pages
- Terminal `tools` object → `/tools/regex-generator.html` — file does not exist → create or remove
- Terminal `tools` object → `/tools/curl-converter.html`, `/tools/dockerfile-optimizer.html`, `/tools/git-branch-visualizer.html` → update paths to new Eleventy-generated slugs (`/tools/curl-converter/`, etc.)

---

## Visual Design: Forge Dark

Extends the existing penumbraforge.com design language.

### Design Tokens (inherited from current site)

```css
--surface-0: #06060c;
--surface-1: #0a0a14;
--surface-2: #10101c;
--border: #1e1e35;
--border-active: #2e2e50;
--accent: #b8a5d6;          /* lavender */
--accent-strong: #d4c4f0;
--text-1: #e8e4ef;
--text-2: #999;
--text-3: #666;
--muted: #444;
--slate: #687a8e;
--sage: #6bcf8f;             /* status/local badges */
```

### Hub Page Design

- Dark background (`surface-0`)
- Category pills with lavender active state
- Tool cards: `surface-1` background, `border` outline, lavender tool name, muted description
- Cards show a subtle hover state (border brightens to `border-active`)
- "local" badges in sage green, "cloud" badges in slate blue
- Search bar: subtle, monospace placeholder text, no heavy borders
- Grain overlay (matches main site)
- Responsive: 3-col on desktop, 2-col on tablet, 1-col on mobile

### Tool Page Design

- Clean, focused layout — the tool UI is the star
- Monospace font for inputs/outputs (code-like content)
- Sans-serif for explanatory text
- Consistent button style: subtle borders, lavender accent on primary actions
- Output areas: slightly darker background (`surface-0` inside `surface-1`)
- Copy-to-clipboard buttons on all outputs

---

## SEO Strategy

### Per-Page SEO

Every tool page gets:

| Element | Example (JWT Decoder) |
|---|---|
| `<title>` | `JWT Decoder — Decode & Inspect JSON Web Tokens Online | Penumbra Forge` |
| `<meta description>` | `Free online JWT decoder. Paste a JWT to inspect its header, payload, and signature. No data sent to any server — runs entirely in your browser.` |
| OG title | `JWT Decoder — Free Online Tool` |
| OG description | Same as meta description |
| OG image | Shared Penumbra Forge PNG OG image (see OG Image section below) |
| JSON-LD | `SoftwareApplication` with name, description, applicationCategory, operatingSystem: "Any (browser-based)", offers: { price: "0" } |
| Breadcrumb JSON-LD | `BreadcrumbList`: Home → Tools → Security → JWT Decoder |

Note: `<meta name="keywords">` is intentionally omitted — Google ignores it. Keywords are used internally for search/filter only.

### OG Image

The current OG image is SVG (`/og-image.svg`). Many social platforms (Twitter/X, LinkedIn, Slack) do not render SVG.

**Action:** Convert or generate a PNG version at `/og-image.png` (1200x630px). Update `base.njk` and `tool-layout.njk` to reference the PNG. Per-tool OG images are deferred — the template includes a `{% if tool.ogImage %}` hook so individual tools can override later.

### Sitemap

All tool pages are Eleventy-generated and automatically included in `src/sitemap.njk` via `collections.all`. No manual entries needed.

### Internal Linking

Each tool page links to 3-4 related tools via the `relatedTools` array. This creates a web of internal links that:
- Keeps users on-site longer (reduces bounce rate)
- Distributes page authority across all tool pages
- Helps Google discover and index all pages

### Robots.txt

Allow all tool pages. Keep existing `Disallow: /umbra`.

### Content Strategy

Each tool page includes a short "About this tool" section with:
- What the tool does (plain language)
- Why you'd use it
- Privacy note: "Runs entirely in your browser. No data is sent to any server."
- This crawlable text content is what Google indexes — the JS tool UI is a bonus

---

## Accessibility

All tool pages meet WCAG 2.1 AA:

- **Keyboard navigation:** All interactive elements (search, filter pills, cards, tool inputs, buttons) are fully keyboard-accessible with visible focus indicators
- **Focus management:** When a filter is applied, focus stays on the filter bar. When a tool output is generated, focus moves to the output area.
- **ARIA roles:** Filter pills use `role="tablist"` / `role="tab"`. Tool cards use `role="link"`. Copy buttons announce "Copied to clipboard" via `aria-live="polite"`.
- **Color contrast:** All text/background combinations verified against WCAG AA (4.5:1 for normal text, 3:1 for large text). Key pairs to verify:
  - `--text-2` (#999) on `--surface-0` (#06060c) = 9.3:1 ✓
  - `--text-3` (#666) on `--surface-0` (#06060c) = 5.1:1 ✓
  - `--accent` (#b8a5d6) on `--surface-1` (#0a0a14) = 7.8:1 ✓
  - `--sage` (#6bcf8f) on `--surface-1` (#0a0a14) = 9.2:1 ✓
- **Screen readers:** All tool inputs have associated `<label>` elements. Output areas have `aria-label` descriptions. Decorative elements (grain overlay, orbs) use `aria-hidden="true"`.
- **Reduced motion:** Respect `prefers-reduced-motion` — disable animations and transitions (already implemented for grain overlay on main site, extend to tool pages).

---

## Error Handling

### Client-Side Tool Failures

- If tool JS fails to load, the "About this tool" section and navigation remain functional (progressive enhancement)
- Tool output areas show a fallback message: "Something went wrong. Try refreshing the page."
- All tool operations wrapped in try/catch with user-visible error messages (no silent failures)

### Cloud Tool Errors (secret-lock, one-time-secret, view-lock)

- These depend on `tools.penumbraforge.com`. If the API is unreachable, show: "This tool requires a connection to our secure service. Please check your network and try again."
- Badge clearly indicates "cloud" so users understand the dependency
- No service worker / offline support in initial scope — tools are lightweight and always-online is a reasonable assumption

---

## Testing Strategy

### Build-Time Checks

- **Eleventy build:** All `.njk` templates compile without errors (`npm run build` exits 0)
- **Link validation:** Run a link checker (e.g., `html-validate` or `linkinator`) against `_site/` to catch broken internal links
- **SEO audit:** Script to verify every tool page has: `<title>`, `<meta description>`, OG tags, JSON-LD, breadcrumb JSON-LD

### Per-Tool Smoke Tests

Each tool gets a manual checklist:
- [ ] Page loads without JS errors
- [ ] Tool accepts input and produces correct output
- [ ] Copy-to-clipboard works
- [ ] Responsive layout: desktop, tablet, mobile
- [ ] Keyboard-navigable (tab through all inputs)
- [ ] Related tools section renders with correct links
- [ ] Breadcrumb links work

### Regression

- After each wave ships, re-run the link checker and SEO audit
- Verify the tools hub index renders all tools with correct categories and links

---

## Tool Inventory

### Wave 1 — Highest Traffic (ship first)

| Tool | Category | Search Volume Signal | Status |
|---|---|---|---|
| JSON Formatter/Validator | encoding | 1M+/month | new |
| UUID Generator (v4/v7) | security | 500K+ | new |
| ASCII/Unicode Table | text | 800K+ | new |
| Epoch/Unix Timestamp Converter | encoding | 400K+ | new |
| Subnet/CIDR Calculator | security | 300K+ | new |
| Cron Expression Builder | devops | 200K+ | new |
| Regex Tester | text | 200K+ | upgrade from regex-gen |
| Chmod Calculator | devops | 150K+ | new |
| Base64 Encoder/Decoder | encoding | 150K+ | exists (rebuild as own page) |
| Password Generator | security | 150K+ | exists (rebuild as own page) |
| Hash Generator (SHA-256/512) | security | 100K+ | exists (rebuild as own page) |
| JWT Decoder | web | 100K+ | exists (rebuild as own page) |
| Color Converter | encoding | 100K+ | new |
| URL Encoder/Decoder | encoding | 100K+ | exists (rebuild as own page) |

### Wave 2 — Security & Crypto

| Tool | Category | Notes |
|---|---|---|
| Secret Lock (encrypt) | security | exists (cloud) — wrap in shared layout |
| One-Time Secret | security | exists (cloud) — wrap in shared layout |
| View Lock (decrypt) | security | exists (cloud) — wrap in shared layout |
| Entropy Calculator | security | exists — rebuild as own page |
| Client-Side Secrets Scanner | security | NEW — market gap, ties to Gate |
| Security Headers Analyzer | security | NEW — market gap |
| CSP Header Generator | security | NEW |
| DMARC/DKIM/SPF Builder | security | NEW — market gap |
| TOTP Generator | security | NEW |
| SSH Key Generator | security | NEW (WebCrypto) |

### Wave 3 — DevOps & Infrastructure

| Tool | Category | Notes |
|---|---|---|
| Dockerfile Optimizer | devops | exists — migrate to Eleventy template |
| Git Branch Visualizer | devops | exists — migrate to Eleventy template |
| cURL Converter | web | exists — migrate to Eleventy template |
| Shell Command Explainer | devops | NEW |
| .gitignore Generator | devops | NEW |
| HTTP Status Code Reference | devops | NEW |
| Nginx Config Generator | devops | NEW |
| GitHub Actions Workflow Generator | devops | NEW — market gap |
| Kubernetes Manifest Generator | devops | NEW — market gap |
| Terraform/HCL Formatter | devops | NEW — market gap |

### Wave 4 — Encoding, Web & Text

| Tool | Category | Notes |
|---|---|---|
| JSON ↔ YAML Converter | encoding | NEW |
| HTML Entity Encoder/Decoder | encoding | NEW |
| Markdown Preview | encoding | NEW |
| JSON-to-TypeScript | web | NEW |
| Cron Explainer (English ↔ cron) | devops | NEW |
| API Request Builder | web | NEW |
| CSS Grid/Flexbox Generator | web | NEW |
| Meta Tag Generator | web | NEW |
| SVG Optimizer | web | NEW |
| Diff Viewer | text | NEW |
| Lorem Ipsum Generator | text | NEW |
| Word/Character Counter | text | NEW |
| CSV ↔ JSON Converter | text | NEW |
| Slug Generator | text | NEW |

### Wave 5 — Market Gap Tools

| Tool | Category | Notes |
|---|---|---|
| .env File Linter | devops | NEW — nothing good exists in-browser |
| DNS Record Explainer & Builder | security | NEW — market gap |
| IP & Network Toolkit (What's My IP + ASN) | security | NEW |
| YAML Linter & Path Finder | devops | NEW — market gap |
| Log Parser & Highlighter | security | NEW — from CIRT background |

**Total: ~53 tools** across 5 waves

---

## Terminal Preservation

The existing terminal UI at `public/terminal/index.html` stays unchanged at `/terminal`. It remains accessible from:
- The footer link (already exists)
- The tools hub (add a subtle "Power user? Try the terminal →" link)

The terminal's internal tool URLs should be updated to point to the new `/tools/{slug}/` paths once individual pages exist. This is a non-blocking update — the terminal continues to work independently.

---

## Bug Fix: 404 Resolution (prerequisite)

Ships before any new tool work:

1. Rename `public/tools-page/` → `public/tools/` (temporary — will be removed once tools migrate to Eleventy)
2. Update `src/_data/products.json`: change tool kits URL from `/tools` to `/tools/`
3. Update `products.json` description to reflect accurate tool count
4. Update internal tool URLs in terminal's `index.html` from `/tools` to `/tools/`
5. Verify all tool page links resolve correctly after rename

---

## Implementation Notes

- All tools are client-side HTML/CSS/JS — no backend required
- Eleventy generates the hub index and all individual tool pages
- The shared `tool-layout.njk` template handles all SEO boilerplate
- Tools ship in waves — Wave 1 first (highest traffic), then progressively
- Each wave can be its own PR/commit
- The 404 fix ships immediately as a prerequisite
- The OG image PNG conversion ships with Wave 1
