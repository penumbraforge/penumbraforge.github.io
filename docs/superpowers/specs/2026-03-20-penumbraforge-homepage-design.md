# Penumbra Forge Homepage Rebuild — Design Spec

**Date:** 2026-03-20
**Author:** Shadoe Myers + Claude
**Status:** Approved

---

## Overview

Rebuild penumbraforge.com as a professional, single-scroll homepage for Penumbra Forge LLC — an independent software studio focused on security tooling, local AI, and automation. The site should convey quiet confidence, technical credibility, and the handcrafted ethos of a solo engineer who takes the work seriously.

### Goals

1. **Credibility** — Visitors should immediately understand this is a serious, professional operation.
2. **Showcase** — Display shipped products and active work without filler or self-promotion.
3. **SEO foundation** — Proper meta tags, semantic HTML, sitemap, Open Graph, structured data.
4. **Umbra launch readiness** — Teaser now, full reveal later, controlled by a single config flag.
5. **Blog-ready architecture** — Even if no posts exist yet, the structure supports markdown posts from day one.

### Non-Goals

- No user accounts, newsletter signups, or interactive features on the homepage.
- No migration of existing pages (terminal, gate, librarian, tools) — they stay as-is.
- No client-side JavaScript on the homepage.

---

## Stack

| Component | Technology |
|-----------|-----------|
| Static site generator | Eleventy (11ty) |
| Templating | Nunjucks (.njk) |
| Styling | Vanilla CSS, single file, Umbra design tokens |
| Hosting | GitHub Pages (under penumbraforge GitHub account) |
| Build | GitHub Actions (npm run build → deploy _site/) |
| CDN / DNS | Cloudflare (existing setup, CNAME update to new account) |
| Domain | penumbraforge.com |

---

## Design Language

The homepage uses Umbra's spectral design system adapted for a static marketing page.

### Color Palette (Spectral Dark)

| Token | Value | Usage |
|-------|-------|-------|
| surface-0 | `#06060c` | Page background |
| surface-1 | `#0a0a14` | Card backgrounds |
| surface-2 | `#10101c` | Hover states |
| border | `#1e1e35` | Borders, dividers |
| border-active | `#2e2e50` | Hover borders |
| accent | `#b8a5d6` | Spectral violet — headings, links, interactive |
| accent-strong | `#d4c4f0` | Hover emphasis |
| text-1 | `#e8e4ef` | Primary text |
| text-2 | `#999` | Secondary text |
| text-3 | `#666` | Tertiary text |
| muted | `#444` | Labels, timestamps |
| slate | `#687a8e` | Studio name label, subdued blue-gray |
| sage | `#6bcf8f` | Success, "In Development" indicator |

### Typography

- **Sans-serif:** `-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif` — all UI text
- **Monospace:** `'SF Mono', 'Fira Code', 'Cascadia Code', monospace` — tech stack tags only
- **Base size:** 13px body, 26px h1, 11px labels

### Visual Effects

- **Spectral glow:** Radial gradient behind hero orb (`rgba(184, 165, 214, 0.06)`)
- **Grain overlay:** Optional SVG fractal noise at `opacity: 0.03` (matches Umbra's grain toggle)
- **Pulse animation:** Single green dot on Umbra's "In Development" status — the only animation on the page
- **Reduced motion:** All animations wrapped in `@media (prefers-reduced-motion: no-preference)`

---

## Page Structure

### 1. Hero

- **Spectral orb:** 52px circle with radial gradient (`#c4a8d8` → `#6a5a8e`), box-shadow glow
- **Spectral orb** is a CSS-only decorative element (empty `<div>` with `aria-hidden="true"` and `role="presentation"`)
- **Studio name:** "PENUMBRA FORGE" in 11px tracked uppercase, color `slate` (`#687a8e`)
- **Tagline (h1):** "Software, forged by Shadoe."
- **Subtitle:** "One engineer. Security tools. Local AI. No compromises."
- No navigation bar — the page is the nav (single scroll)
- Radial gradient glow behind the orb for atmosphere

### 2. Principles Row

Three columns on desktop (> 768px), two columns on tablet (641–768px), single column on mobile (≤ 640px):

| Principle | Description |
|-----------|------------|
| Privacy-first | No telemetry. No cloud dependency. Your machine, your data. |
| Built to last | No shortcuts. No compat shims. Quality over speed, always. |
| Open by design | AGPL-3.0 core. Extensible. Community-driven ecosystems. |

Accent-colored headings, muted descriptions. No icons.

### 3. Flagship Product — Umbra

**Two modes controlled by `site.json` → `umbra.launched` flag:**

#### Pre-launch (current):
- Spectral orb (28px) + "umbra" in accent color
- Green pulse dot + "In Development" label (sage color)
- One-liner: "A local-first AI creation studio for Apple Silicon. Run large language models on your hardware. No cloud. No subscriptions. More details soon."
- No feature cards, no links, no download CTA
- Subtle violet gradient background to differentiate from other sections

#### Post-launch (future):
- Full description paragraph
- 4 feature cards: MLX-native inference, Knowledge packs, Plugin ecosystem, Full workspace
- Download/CTA button
- Link to `/umbra` landing page
- Feature cards laid out in 2×2 grid

### 4. Other Work — "Also from the forge"

Section label: "ALSO FROM THE FORGE" in 10px tracked uppercase, color `#444`.

Product cards in a single-column stack at all breakpoints, driven by `src/_data/products.json`. Each card contains:
- Product name (14px, text-1)
- Description (12px, text-3, 1-2 lines)
- Arrow indicator (→) for clickable cards
- "source" link (10px, text-3) — only on products with `repo` field in JSON
- Hover state: border transitions to `border-active`

**Products (initial):**

| Product | Description | Link | Repo |
|---------|------------|------|------|
| gate | Pre-commit secret defense. Catches API keys, tokens, and credentials before they reach your repo. | /gate | Yes |
| librarian | Intelligent MCP skills server. Serves contextual knowledge to AI agents through the Model Context Protocol. | /librarian | Yes |
| tool kits | 16 client-side security and developer utilities. Hashing, encryption, JWT decoding, CIDR calculation, and more. Zero telemetry. | /tools | No |

### 5. About

Section label: "ABOUT" in 10px tracked uppercase.

**Copy:**
> Penumbra Forge is a one-person software studio run by Shadoe Myers out of Arizona. By day, I'm a senior information security engineer on a CIRT team, building automations with SOAR platforms. By night, I build the tools I wish existed — things that respect your privacy, run on your hardware, and don't need a cloud account to function. I've spent years in datacenters, NOCs, and incident response. That background shapes everything I ship: secure by default, minimal attack surface, no unnecessary dependencies.

**Tech stack tags** below the paragraph — quiet pill-shaped badges with 1px border:
- Python
- Swift
- TypeScript
- MLX
- Cloudflare Workers

Subtle violet tint background (`rgba(184, 165, 214, 0.02)`) to differentiate from product sections.

### 6. Footer

- **Left:** © 2026 Penumbra Forge LLC
- **Right:** GitHub · shadoe@penumbraforge.com · Terminal · Privacy · Terms
- "Terminal" is accent-colored (`#b8a5d6`) as an easter egg — links to existing terminal site at `/terminal`
- GitHub links to `github.com/penumbraforge`
- Privacy and Terms link to existing `/privacy.html` and `/terms.html`

---

## Project Structure

```
penumbraforge.com/
├── src/
│   ├── _includes/
│   │   ├── base.njk              ← HTML shell (head, meta, OG tags, CSS)
│   │   └── footer.njk            ← Shared footer
│   ├── _data/
│   │   ├── site.json             ← Site metadata (see Data Schemas below)
│   │   └── products.json         ← Product card data (see Data Schemas below)
│   ├── css/
│   │   └── style.css             ← Single stylesheet, Umbra design tokens
│   ├── blog/                     ← Directory structure only; no listing page,
│   │   │                            post template, or feed until first post
│   │   └── blog.json             ← Collection defaults (layout, tags)
│   ├── index.njk                 ← Homepage (single scroll)
│   ├── robots.txt.njk            ← Generated robots.txt
│   ├── sitemap.njk               ← Generated sitemap.xml
│   └── feed.njk                  ← RSS/Atom feed (future, for blog)
├── public/
│   ├── favicon.svg               ← Spectral orb favicon (from Umbra)
│   └── og-image.png              ← Open Graph preview card
├── .eleventy.js                  ← 11ty config
├── package.json
└── .github/workflows/
    └── deploy.yml                ← Build 11ty → deploy to GitHub Pages
```

---

## Data Schemas

### site.json

```json
{
  "name": "Penumbra Forge",
  "url": "https://penumbraforge.com",
  "title": "Penumbra Forge — Security Tools, Local AI, Automation",
  "description": "Independent software studio by Shadoe Myers. Building privacy-first security tools, local AI applications, and developer utilities.",
  "author": {
    "name": "Shadoe Myers",
    "email": "shadoe@penumbraforge.com",
    "jobTitle": "Senior Information Security Engineer"
  },
  "umbra": {
    "launched": false
  }
}
```

### products.json

```json
[
  {
    "name": "gate",
    "description": "Pre-commit secret defense. Catches API keys, tokens, and credentials before they reach your repo.",
    "url": "/gate",
    "repo": null
  },
  {
    "name": "librarian",
    "description": "Intelligent MCP skills server. Serves contextual knowledge to AI agents through the Model Context Protocol.",
    "url": "/librarian",
    "repo": null
  },
  {
    "name": "tool kits",
    "description": "16 client-side security and developer utilities. Hashing, encryption, JWT decoding, CIDR calculation, and more. Zero telemetry.",
    "url": "/tools",
    "repo": null
  }
]
```

Products with `"repo": null` do not render the "source" link.

---

## SEO & Meta

### HTML Meta (per page)

```html
<title>Penumbra Forge — Security Tools, Local AI, Automation</title>
<meta name="description" content="Independent software studio by Shadoe Myers. Building privacy-first security tools, local AI applications, and developer utilities.">
<link rel="canonical" href="https://penumbraforge.com/">
```

### Open Graph / Twitter Cards

```html
<meta property="og:title" content="Penumbra Forge — Security Tools, Local AI, Automation">
<meta property="og:description" content="Independent software studio by Shadoe Myers. Privacy-first tools that run on your hardware.">
<meta property="og:image" content="https://penumbraforge.com/og-image.png">
<meta property="og:url" content="https://penumbraforge.com/">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
```

### Structured Data (JSON-LD)

```json
{
  "@context": "https://schema.org",
  "@type": "Organization",
  "name": "Penumbra Forge",
  "url": "https://penumbraforge.com",
  "founder": {
    "@type": "Person",
    "name": "Shadoe Myers",
    "jobTitle": "Senior Information Security Engineer"
  },
  "description": "Independent software studio focused on security tooling, local AI, and automation.",
  "address": {
    "@type": "PostalAddress",
    "addressRegion": "AZ",
    "addressCountry": "US"
  }
}
```

### Technical SEO

- `sitemap.xml` generated by 11ty at build time
- `robots.txt` allowing all crawlers, disallowing `/umbra` pre-launch
- Canonical URLs on every page
- Semantic HTML: `<header>`, `<main>`, `<section>`, `<article>`, `<footer>`, proper heading hierarchy

### Performance Targets

- Zero client-side JavaScript
- Single CSS file (inline in `<head>` if under 14KB)
- System font stack (no web font downloads)
- Lighthouse target: 95+ across all four categories

### Security Headers (Cloudflare dashboard or `_headers` file in build output)

```
Content-Security-Policy: default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self'; font-src 'self'; base-uri 'self'; form-action 'none'
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

`'unsafe-inline'` for style-src only because CSS may be inlined in `<head>` for performance. No scripts on the page, so `script-src` is omitted (inherits `default-src 'none'`). Configure via `public/_headers` file (GitHub Pages serves it automatically).

---

## Hosting & Deployment

### Migration Steps

1. Create new repo under `penumbraforge` GitHub account
2. Set up GitHub Pages with custom domain `penumbraforge.com`
3. Update Cloudflare DNS CNAME to point to new GitHub Pages endpoint
4. Existing pages (terminal, gate, librarian, tools) either migrate to the new repo's `public/` directory as passthrough copies, or are served via Cloudflare Workers redirects
5. GitHub Actions workflow: on push to main → `npm run build` → deploy `_site/` to Pages

### Existing Pages Coexistence

The existing terminal site, `/gate`, `/librarian`, and `/tools` are standalone static HTML. Options:
- **Option A (recommended):** Copy them into the 11ty project's `public/` directory as passthrough files. They deploy alongside the new pages with zero changes.
- **Option B:** Keep them in a separate repo and use Cloudflare Workers to route traffic. More complex, harder to maintain.

---

## Responsive Behavior

- **Desktop (> 768px):** Full layout as designed — three-column principles, single-column product cards
- **Tablet (641–768px):** Principles stack to two columns, product cards full-width
- **Mobile (≤ 640px):** Single column throughout. Hero padding reduces. Footer stacks vertically. Tech stack tags wrap.
- **Max content width:** 560px (centered) — maintains readability on ultrawide displays

---

## Future Additions (Not in Scope)

- `/umbra` — Dedicated Umbra landing page (specced separately before launch). Will be added as `src/umbra.njk` with `noindex` meta until ready to go public.
- `/blog` — Markdown posts with frontmatter, 11ty collections, RSS feed. SEO engine for long-tail traffic.
- `/about` — Extended about page. Future home for TBI story when ready.
- Umbra homepage section full reveal — feature cards, download CTA. Controlled by `site.json` → `umbra.launched` flag.
- GBA Studio teaser card — added to products.json when closer to ready.
- Newsletter signup — only when there's something to send.
