# Tools Hub — Wave 0 (Infrastructure) + Wave 1 (High-Traffic Tools) Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the tools 404, build the shared tool page infrastructure (layout template, data file, hub index), and ship the 14 highest-traffic tools as individual SEO-optimized pages.

**Architecture:** Eleventy 3.x generates all tool pages from `.njk` templates using a shared `tool-layout.njk` that provides SEO, breadcrumbs, related tools, and consistent Forge Dark styling. A `tools.json` data file drives the hub index's card grid and category filters. Existing standalone HTML tools are migrated into Eleventy templates. The terminal is preserved at `/terminal`.

**Tech Stack:** Eleventy 3.x, Nunjucks templates, vanilla HTML/CSS/JS (no framework), client-side tools only

**Spec:** `docs/superpowers/specs/2026-03-21-tools-hub-overhaul-design.md`

---

## File Structure

### New Files

| File | Responsibility |
|---|---|
| `src/_includes/tool-layout.njk` | Shared layout for all tool pages — SEO meta, JSON-LD, breadcrumbs, header, related tools, footer |
| `src/_includes/tool-header.njk` | Tool page header partial — logo, nav back to hub, breadcrumb trail |
| `src/_includes/tool-related.njk` | Related tools section partial — renders 3-4 related tool cards |
| `src/_data/tools.json` | Tool metadata array driving the hub index and tool pages |
| `src/tools/tools.json` | Eleventy directory data file — sets `layout: tool-layout.njk` for all pages in `src/tools/` |
| `src/tools/index.njk` | Tools hub landing page — search, category filters, card grid |
| `src/tools/json-formatter.njk` | JSON Formatter tool page |
| `src/tools/uuid-generator.njk` | UUID Generator tool page |
| `src/tools/ascii-unicode-table.njk` | ASCII/Unicode Table tool page |
| `src/tools/epoch-converter.njk` | Epoch/Unix Timestamp Converter tool page |
| `src/tools/subnet-calculator.njk` | Subnet/CIDR Calculator tool page |
| `src/tools/cron-builder.njk` | Cron Expression Builder tool page |
| `src/tools/regex-tester.njk` | Regex Tester tool page |
| `src/tools/chmod-calculator.njk` | Chmod Calculator tool page |
| `src/tools/base64-encoder.njk` | Base64 Encoder/Decoder tool page |
| `src/tools/password-generator.njk` | Password Generator tool page |
| `src/tools/hash-generator.njk` | Hash Generator tool page |
| `src/tools/jwt-decoder.njk` | JWT Decoder tool page |
| `src/tools/color-converter.njk` | Color Converter tool page |
| `src/tools/url-encoder.njk` | URL Encoder/Decoder tool page |
| `src/tools/curl-converter.njk` | Migrated from `public/tools-page/curl-converter.html` |
| `src/tools/dockerfile-optimizer.njk` | Migrated from `public/tools-page/dockerfile-optimizer.html` |
| `src/tools/git-branch-visualizer.njk` | Migrated from `public/tools-page/git-branch-visualizer.html` |
| `public/og-image.png` | PNG OG image (1200x630) replacing SVG for social platform compatibility |

### Modified Files

| File | Changes |
|---|---|
| `src/_data/products.json` | Fix tool kits URL from `/tools` to `/tools/` and update description |
| `src/_includes/base.njk` | Update OG image ref from `.svg` to `.png`, add block tags for child layout overrides |
| `src/css/style.css` | Add tool hub and tool page styles (cards, search, filters, tool chrome) |
| `eleventy.config.js` | Add custom `find` filter for tool data lookup in templates |
| `public/terminal/index.html` | Update tool URLs to new `/tools/{slug}/` paths |
| `src/sitemap.njk` | Already auto-includes Eleventy pages — no changes needed |

### Removed Files

| File | Reason |
|---|---|
| `public/tools-page/index.html` | Replaced by Eleventy-generated `src/tools/index.njk` |
| `public/tools-page/curl-converter.html` | Migrated to `src/tools/curl-converter.njk` |
| `public/tools-page/dockerfile-optimizer.html` | Migrated to `src/tools/dockerfile-optimizer.njk` |
| `public/tools-page/git-branch-visualizer.html` | Migrated to `src/tools/git-branch-visualizer.njk` |

---

## Task 1: Fix the 404, Update products.json, and Add Eleventy Config

**Files:**
- Modify: `src/_data/products.json`
- Modify: `eleventy.config.js`
- Delete: `public/tools-page/` (replaced by Eleventy-generated pages in later tasks)

The 404 fix AND Eleventy config happen together. We delete `public/tools-page/` now to avoid a passthrough-copy collision (Eleventy's `addPassthroughCopy({ "public": "." })` would copy `public/tools/index.html` to `_site/tools/index.html`, colliding with the Eleventy-generated hub page). The brief gap is acceptable since all new pages ship in the same branch.

- [ ] **Step 1: Delete the old tools-page directory**

```bash
rm -rf public/tools-page
```

We're deleting, not renaming. The existing tools will be rebuilt as Eleventy templates in Task 9.

- [ ] **Step 2: Update products.json**

In `src/_data/products.json`, change the tool kits entry:
```json
{
  "name": "tool kits",
  "description": "Free client-side security and developer utilities. Hashing, encryption, JWT decoding, CIDR calculation, and more. Zero telemetry.",
  "url": "/tools/",
  "repo": null
}
```

- [ ] **Step 3: Add custom `find` filter to eleventy.config.js**

The tool layout template needs to look up a tool's data by slug. Nunjucks `{% set %}` inside `{% for %}` is block-scoped (the variable is null outside the loop), so we need a custom filter:

```js
export default function (eleventyConfig) {
  eleventyConfig.addPassthroughCopy({ "public": "." });
  eleventyConfig.addPassthroughCopy("src/css");

  eleventyConfig.addFilter("toISOString", (date) => {
    return new Date(date).toISOString().split("T")[0];
  });

  eleventyConfig.addFilter("find", (arr, key, val) => {
    if (!Array.isArray(arr)) return null;
    return arr.find(item => item[key] === val) || null;
  });

  eleventyConfig.addFilter("capitalize", (str) => {
    if (!str) return "";
    return str.charAt(0).toUpperCase() + str.slice(1);
  });

  return {
    dir: {
      input: "src",
      output: "_site",
      includes: "_includes",
      data: "_data",
    },
  };
}
```

- [ ] **Step 4: Build and verify**

```bash
npm run build
```
Verify: build succeeds, `_site/tools-page/` no longer exists.

- [ ] **Step 5: Commit**

```bash
git add eleventy.config.js src/_data/products.json && git rm -r public/tools-page && git commit -m "fix: remove old tools-page, add Eleventy find filter, update products.json URL"
```

---

## Task 2: Add Block Tags to base.njk for Layout Inheritance

**Files:**
- Modify: `src/_includes/base.njk`

The tool layout needs to override `<title>`, `<meta description>`, and inject additional `<head>` content. Add Nunjucks block tags to `base.njk` so child layouts can override these.

- [ ] **Step 1: Add block tags to base.njk**

Replace the current `<head>` section with block-wrapped versions:

```njk
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{% block title %}{{ site.title }}{% endblock %}</title>
  <meta name="description" content="{% block description %}{{ site.description }}{% endblock %}">
  <link rel="canonical" href="{{ site.url }}{{ page.url }}">

  {% block head %}
  <!-- Open Graph -->
  <meta property="og:title" content="{{ site.title }}">
  <meta property="og:description" content="Independent software studio by Shadoe Myers. Privacy-first tools that run on your hardware.">
  <meta property="og:image" content="{{ site.url }}/og-image.png">
  <meta property="og:url" content="{{ site.url }}{{ page.url }}">
  <meta property="og:type" content="website">
  <meta name="twitter:card" content="summary_large_image">
  {% endblock %}

  <!-- Favicon -->
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">

  <!-- Stylesheet -->
  <link rel="stylesheet" href="/css/style.css">

  {% block headExtra %}{% endblock %}

  <!-- JSON-LD Structured Data -->
  {% block jsonld %}
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@type": "Organization",
    "name": "{{ site.name }}",
    "url": "{{ site.url }}",
    "founder": {
      "@type": "Person",
      "name": "{{ site.author.name }}",
      "jobTitle": "{{ site.author.jobTitle }}"
    },
    "description": "{{ site.description }}",
    "address": {
      "@type": "PostalAddress",
      "addressRegion": "AZ",
      "addressCountry": "US"
    }
  }
  </script>
  {% endblock %}
</head>
<body>
  {% block body %}
  {{ content | safe }}
  {% include "footer.njk" %}
  <div class="grain" aria-hidden="true"></div>
  {% endblock %}
</body>
</html>
```

Also update the OG image reference from `/og-image.svg` to `/og-image.png`.

**Important:** Update the block defaults to use front matter data so child pages can override via front matter:
```njk
<title>{% block title %}{{ title or site.title }}{% endblock %}</title>
<meta name="description" content="{% block description %}{{ description or site.description }}{% endblock %}">
```

- [ ] **Step 2: Build and verify homepage still renders correctly**

```bash
npm run build
```
Verify `_site/index.html` renders the same as before — block tags with defaults should be transparent.

- [ ] **Step 3: Commit**

```bash
git add src/_includes/base.njk && git commit -m "feat: add block tags to base.njk for layout inheritance"
```

---

## Task 3: Create tools.json Data File

**Files:**
- Create: `src/_data/tools.json`

This data file drives the hub index and provides metadata for all tool pages. Start with Wave 1 tools + existing tools being migrated.

- [ ] **Step 1: Create tools.json with Wave 1 + existing tool entries**

Create `src/_data/tools.json` with the full tool registry. Each entry follows this schema:

```json
[
  {
    "name": "JSON Formatter",
    "slug": "json-formatter",
    "description": "Pretty-print, minify, and validate JSON with syntax highlighting",
    "longDescription": "Free online JSON formatter and validator. Pretty-print, minify, and validate JSON data with syntax highlighting. Runs entirely in your browser — no data sent to any server.",
    "category": "encoding",
    "keywords": ["json formatter", "json validator", "json beautifier", "json pretty print", "json minify"],
    "badge": "local",
    "relatedTools": ["jwt-decoder", "base64-encoder", "url-encoder"],
    "status": "live"
  },
  {
    "name": "UUID Generator",
    "slug": "uuid-generator",
    "description": "Generate UUID v4 and v7 with bulk generation",
    "longDescription": "Free online UUID generator. Create UUID v4 (random) and v7 (time-ordered) identifiers with bulk generation. Runs entirely in your browser — no data sent to any server.",
    "category": "security",
    "keywords": ["uuid generator", "uuid v4", "uuid v7", "guid generator", "unique id generator"],
    "badge": "local",
    "relatedTools": ["password-generator", "hash-generator", "base64-encoder"],
    "status": "live"
  },
  {
    "name": "ASCII / Unicode Table",
    "slug": "ascii-unicode-table",
    "description": "Searchable ASCII and Unicode character reference with code points",
    "longDescription": "Free online ASCII and Unicode table. Search characters by name, code point, or symbol. Click to copy. Includes hex, decimal, binary, and HTML entity for every character.",
    "category": "text",
    "keywords": ["ascii table", "unicode table", "character map", "ascii chart", "unicode lookup"],
    "badge": "local",
    "relatedTools": ["url-encoder", "base64-encoder", "color-converter"],
    "status": "live"
  },
  {
    "name": "Epoch Converter",
    "slug": "epoch-converter",
    "description": "Convert between Unix timestamps and human-readable dates",
    "longDescription": "Free online epoch and Unix timestamp converter. Convert between Unix timestamps and human-readable dates instantly. Supports seconds and milliseconds. Runs entirely in your browser.",
    "category": "encoding",
    "keywords": ["epoch converter", "unix timestamp converter", "timestamp to date", "date to timestamp", "epoch time"],
    "badge": "local",
    "relatedTools": ["cron-builder", "json-formatter", "base64-encoder"],
    "status": "live"
  },
  {
    "name": "Subnet Calculator",
    "slug": "subnet-calculator",
    "description": "Visual CIDR and subnet calculator with IP range display",
    "longDescription": "Free online subnet and CIDR calculator. Calculate network address, broadcast address, usable host range, and wildcard mask. Visual IP range display. Runs entirely in your browser.",
    "category": "security",
    "keywords": ["subnet calculator", "cidr calculator", "ip calculator", "network calculator", "subnet mask calculator"],
    "badge": "local",
    "relatedTools": ["password-generator", "hash-generator", "chmod-calculator"],
    "status": "live"
  },
  {
    "name": "Cron Builder",
    "slug": "cron-builder",
    "description": "Visual cron expression editor with plain-English output",
    "longDescription": "Free online cron expression builder and explainer. Build cron schedules visually with real-time plain-English descriptions. Supports standard and extended cron syntax. Runs entirely in your browser.",
    "category": "devops",
    "keywords": ["cron expression generator", "cron builder", "crontab generator", "cron schedule builder", "cron expression explained"],
    "badge": "local",
    "relatedTools": ["chmod-calculator", "epoch-converter", "regex-tester"],
    "status": "live"
  },
  {
    "name": "Regex Tester",
    "slug": "regex-tester",
    "description": "Test, debug, and build regular expressions with live matching",
    "longDescription": "Free online regex tester and debugger. Test regular expressions with live matching, capture group highlighting, and match explanations. Supports JavaScript regex syntax. Runs entirely in your browser.",
    "category": "text",
    "keywords": ["regex tester", "regex debugger", "regular expression tester", "regex validator", "regex builder"],
    "badge": "local",
    "relatedTools": ["json-formatter", "curl-converter", "ascii-unicode-table"],
    "status": "live"
  },
  {
    "name": "Chmod Calculator",
    "slug": "chmod-calculator",
    "description": "Visual file permission calculator for Unix/Linux",
    "longDescription": "Free online chmod calculator. Set Unix/Linux file permissions visually with checkboxes and see the numeric, symbolic, and command output. Runs entirely in your browser.",
    "category": "devops",
    "keywords": ["chmod calculator", "file permissions calculator", "linux permissions", "chmod command generator", "unix permissions"],
    "badge": "local",
    "relatedTools": ["cron-builder", "subnet-calculator", "regex-tester"],
    "status": "live"
  },
  {
    "name": "Base64 Encoder / Decoder",
    "slug": "base64-encoder",
    "description": "Encode and decode Base64 strings and files",
    "longDescription": "Free online Base64 encoder and decoder. Encode text or files to Base64, decode Base64 strings back to text. Supports UTF-8 and binary data. Runs entirely in your browser — no data sent to any server.",
    "category": "encoding",
    "keywords": ["base64 encoder", "base64 decoder", "base64 encode", "base64 decode", "base64 converter"],
    "badge": "local",
    "relatedTools": ["url-encoder", "hash-generator", "json-formatter"],
    "status": "live"
  },
  {
    "name": "Password Generator",
    "slug": "password-generator",
    "description": "Cryptographically secure password generator with strength meter",
    "longDescription": "Free online password generator. Create cryptographically secure passwords with customizable length, character sets, and real-time strength analysis. Uses Web Crypto API. Runs entirely in your browser.",
    "category": "security",
    "keywords": ["password generator", "random password", "secure password generator", "strong password generator", "password maker"],
    "badge": "local",
    "relatedTools": ["hash-generator", "uuid-generator", "base64-encoder"],
    "status": "live"
  },
  {
    "name": "Hash Generator",
    "slug": "hash-generator",
    "description": "Generate SHA-256, SHA-512, and other cryptographic hashes",
    "longDescription": "Free online hash generator. Generate SHA-256, SHA-512, SHA-1, and MD5 hashes from text or files. Compare hashes to verify file integrity. Uses Web Crypto API. Runs entirely in your browser.",
    "category": "security",
    "keywords": ["hash generator", "sha256 hash", "sha512 hash", "md5 hash", "hash calculator", "checksum generator"],
    "badge": "local",
    "relatedTools": ["password-generator", "base64-encoder", "uuid-generator"],
    "status": "live"
  },
  {
    "name": "JWT Decoder",
    "slug": "jwt-decoder",
    "description": "Decode and inspect JSON Web Tokens without verification",
    "longDescription": "Free online JWT decoder. Paste a JSON Web Token to inspect its header, payload, and signature. See claims, expiration, and issuer. No data sent to any server — runs entirely in your browser.",
    "category": "web",
    "keywords": ["jwt decoder", "jwt debugger", "json web token decoder", "decode jwt online", "jwt inspector"],
    "badge": "local",
    "relatedTools": ["base64-encoder", "json-formatter", "hash-generator"],
    "status": "live"
  },
  {
    "name": "Color Converter",
    "slug": "color-converter",
    "description": "Convert between HEX, RGB, HSL color formats with visual picker",
    "longDescription": "Free online color converter. Convert between HEX, RGB, HSL, and HSB color formats. Includes a visual color picker and palette generator. Runs entirely in your browser.",
    "category": "encoding",
    "keywords": ["color converter", "hex to rgb", "rgb to hex", "hsl converter", "color picker", "color code converter"],
    "badge": "local",
    "relatedTools": ["base64-encoder", "json-formatter", "url-encoder"],
    "status": "live"
  },
  {
    "name": "URL Encoder / Decoder",
    "slug": "url-encoder",
    "description": "Encode and decode URLs and query parameters",
    "longDescription": "Free online URL encoder and decoder. Encode special characters for URLs or decode percent-encoded strings. Handles full URLs and individual components. Runs entirely in your browser.",
    "category": "encoding",
    "keywords": ["url encoder", "url decoder", "percent encoding", "url encode online", "urlencode"],
    "badge": "local",
    "relatedTools": ["base64-encoder", "json-formatter", "ascii-unicode-table"],
    "status": "live"
  },
  {
    "name": "cURL Converter",
    "slug": "curl-converter",
    "description": "Convert cURL commands to Python, JavaScript, Go, and Bash",
    "longDescription": "Free online cURL converter. Paste a cURL command and get equivalent code in Python (requests), JavaScript (fetch), Go (net/http), and Bash. Runs entirely in your browser.",
    "category": "web",
    "keywords": ["curl to python", "curl to javascript", "curl converter", "curl to code", "convert curl command"],
    "badge": "local",
    "relatedTools": ["json-formatter", "jwt-decoder", "dockerfile-optimizer"],
    "status": "live"
  },
  {
    "name": "Dockerfile Optimizer",
    "slug": "dockerfile-optimizer",
    "description": "Analyze and optimize Dockerfiles for smaller, faster builds",
    "longDescription": "Free online Dockerfile optimizer. Paste a Dockerfile to get optimization suggestions for layer caching, image size, security, and build speed. Runs entirely in your browser.",
    "category": "devops",
    "keywords": ["dockerfile optimizer", "dockerfile linter", "docker best practices", "optimize dockerfile", "dockerfile analyzer"],
    "badge": "local",
    "relatedTools": ["git-branch-visualizer", "curl-converter", "cron-builder"],
    "status": "live"
  },
  {
    "name": "Git Branch Visualizer",
    "slug": "git-branch-visualizer",
    "description": "Visualize and clean up Git branch structures",
    "longDescription": "Free online Git branch visualizer. Paste git branch output to visualize branch relationships and identify branches safe to clean up. Runs entirely in your browser.",
    "category": "devops",
    "keywords": ["git branch visualizer", "git branch graph", "git branch cleanup", "visualize git branches", "git tree viewer"],
    "badge": "local",
    "relatedTools": ["dockerfile-optimizer", "curl-converter", "chmod-calculator"],
    "status": "live"
  }
]
```

Note: `relatedTools` entries that reference future tools (from Waves 2-5) are fine — the template will only render links for tools that exist in `tools.json`. Missing slugs are silently skipped.

- [ ] **Step 2: Build and verify data loads**

```bash
npm run build
```
No errors means the data file is valid JSON and accessible to templates.

- [ ] **Step 3: Commit**

```bash
git add src/_data/tools.json && git commit -m "feat: add tools.json data file with Wave 1 tool metadata"
```

---

## Task 4: Create the Shared Tool Layout Template

**Files:**
- Create: `src/_includes/tool-layout.njk`
- Create: `src/tools/tools.json` (directory data file)

This is the core infrastructure — every tool page uses this layout.

- [ ] **Step 1: Create the directory data file**

Create `src/tools/tools.json` (this is Eleventy's directory data file, NOT the global `src/_data/tools.json`):

```json
{
  "layout": "tool-layout.njk"
}
```

This automatically sets the layout for all `.njk` files in `src/tools/` (except `index.njk` which will override it).

- [ ] **Step 2: Create tool-layout.njk**

Create `src/_includes/tool-layout.njk`. This extends `base.njk` and overrides the blocks:

```njk
{% extends "base.njk" %}

{# Look up this tool's data using the custom find filter (avoids Nunjucks for-loop scoping bug) #}
{% set toolData = tools | find("slug", toolSlug) %}

{% block title %}{{ toolData.name }} — Free Online Tool | Penumbra Forge{% endblock %}

{% block description %}{{ toolData.longDescription }}{% endblock %}

{% block head %}
<meta property="og:title" content="{{ toolData.name }} — Free Online Tool | Penumbra Forge">
<meta property="og:description" content="{{ toolData.longDescription }}">
<meta property="og:image" content="{{ site.url }}/og-image.png">
<meta property="og:url" content="{{ site.url }}/tools/{{ toolData.slug }}/">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{{ toolData.name }} — Free Online Tool">
<meta name="twitter:description" content="{{ toolData.longDescription }}">
{% endblock %}

{% block jsonld %}
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  "name": "{{ toolData.name }}",
  "description": "{{ toolData.longDescription }}",
  "url": "{{ site.url }}/tools/{{ toolData.slug }}/",
  "applicationCategory": "DeveloperApplication",
  "operatingSystem": "Any (browser-based)",
  "offers": {
    "@type": "Offer",
    "price": "0",
    "priceCurrency": "USD"
  },
  "author": {
    "@type": "Organization",
    "name": "Penumbra Forge",
    "url": "{{ site.url }}"
  }
}
</script>
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "BreadcrumbList",
  "itemListElement": [
    { "@type": "ListItem", "position": 1, "name": "Home", "item": "{{ site.url }}/" },
    { "@type": "ListItem", "position": 2, "name": "Tools", "item": "{{ site.url }}/tools/" },
    { "@type": "ListItem", "position": 3, "name": "{{ toolData.category | capitalize }}", "item": "{{ site.url }}/tools/?cat={{ toolData.category }}" },
    { "@type": "ListItem", "position": 4, "name": "{{ toolData.name }}", "item": "{{ site.url }}/tools/{{ toolData.slug }}/" }
  ]
}
</script>
{% endblock %}

{% block body %}
<div class="tool-page">
  <nav class="tool-nav" aria-label="Breadcrumb">
    <div class="container">
      <a href="/" class="tool-nav-logo">Penumbra Forge</a>
      <span class="tool-nav-sep" aria-hidden="true">/</span>
      <a href="/tools/">Tools</a>
      <span class="tool-nav-sep" aria-hidden="true">/</span>
      <a href="/tools/?cat={{ toolData.category }}">{{ toolData.category | capitalize }}</a>
      <span class="tool-nav-sep" aria-hidden="true">/</span>
      <span class="tool-nav-current" aria-current="page">{{ toolData.name }}</span>
    </div>
  </nav>

  <main class="tool-main">
    <div class="container">
      <div class="tool-header">
        <h1>{{ toolData.name }}</h1>
        <span class="tool-badge tool-badge--{{ toolData.badge }}">{{ toolData.badge }}</span>
      </div>
      <p class="tool-about">{{ toolData.longDescription }}</p>

      <div class="tool-content">
        {{ content | safe }}
      </div>
    </div>
  </main>

  <section class="tool-related">
    <div class="container">
      <p class="section-label">Related tools</p>
      <div class="tool-related-grid">
        {% for relSlug in toolData.relatedTools %}
          {% for t in tools %}
            {% if t.slug == relSlug and t.status == "live" %}
              <a href="/tools/{{ t.slug }}/" class="tool-related-card">
                <h3>{{ t.name }}</h3>
                <p>{{ t.description }}</p>
                <span class="tool-badge tool-badge--{{ t.badge }}">{{ t.badge }}</span>
              </a>
            {% endif %}
          {% endfor %}
        {% endfor %}
      </div>
    </div>
  </section>

  <section class="tool-cta">
    <div class="container">
      <p>Built by <a href="/">Penumbra Forge</a> — also check out <a href="/gate/">Gate</a> and <a href="/librarian/">Librarian</a></p>
    </div>
  </section>

  {% include "footer.njk" %}
  <div class="grain" aria-hidden="true"></div>
</div>
{% endblock %}
```

- [ ] **Step 3: Build and verify**

```bash
npm run build
```
No errors. The layout exists but no tool pages use it yet — that's fine.

- [ ] **Step 4: Commit**

```bash
git add src/_includes/tool-layout.njk src/tools/tools.json && git commit -m "feat: add shared tool layout template with SEO, breadcrumbs, related tools"
```

---

## Task 5: Add Tool Hub and Tool Page CSS

**Files:**
- Modify: `src/css/style.css`

Add all styles needed for the tools hub index and individual tool pages. Uses the existing Forge Dark design tokens.

- [ ] **Step 1: Append tool styles to style.css**

Add the following sections to the end of `src/css/style.css`:

```css
/* ============================================================
   Tool Navigation / Breadcrumbs
   ============================================================ */
.tool-nav {
  padding: 16px 40px;
  font-size: 12px;
  display: flex;
  align-items: center;
  border-bottom: 1px solid var(--border);
}

.tool-nav .container {
  display: flex;
  align-items: center;
  gap: 8px;
  max-width: 900px;
}

.tool-nav a {
  color: var(--text-3);
  text-decoration: none;
}

.tool-nav a:hover {
  color: var(--accent);
}

.tool-nav-logo {
  font-weight: 500;
  color: var(--accent) !important;
}

.tool-nav-sep {
  color: var(--muted);
}

.tool-nav-current {
  color: var(--text-2);
}

/* ============================================================
   Tool Page Layout
   ============================================================ */
.tool-page {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

.tool-main {
  flex: 1;
  padding: 40px;
}

.tool-main .container {
  max-width: 900px;
}

.tool-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 8px;
}

.tool-header h1 {
  font-size: 22px;
  font-weight: 400;
  color: var(--text-1);
  margin: 0;
}

.tool-about {
  font-size: 13px;
  color: var(--text-3);
  line-height: 1.6;
  margin: 0 0 32px;
}

.tool-badge {
  font-size: 10px;
  padding: 2px 8px;
  border-radius: 3px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  flex-shrink: 0;
}

.tool-badge--local {
  border: 1px solid rgba(107, 207, 143, 0.25);
  color: var(--sage);
}

.tool-badge--cloud {
  border: 1px solid rgba(104, 122, 142, 0.25);
  color: var(--slate);
}

/* ============================================================
   Tool Content Area (where each tool lives)
   ============================================================ */
.tool-content {
  background: var(--surface-1);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 24px;
  margin-bottom: 40px;
}

.tool-content label {
  display: block;
  font-size: 11px;
  color: var(--text-3);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 6px;
}

.tool-content textarea,
.tool-content input[type="text"],
.tool-content input[type="number"],
.tool-content select {
  width: 100%;
  background: var(--surface-0);
  border: 1px solid var(--border);
  border-radius: 4px;
  color: var(--text-1);
  font-family: var(--font-mono);
  font-size: 13px;
  padding: 10px 12px;
  outline: none;
  transition: border-color 150ms ease;
}

.tool-content textarea:focus,
.tool-content input:focus,
.tool-content select:focus {
  border-color: var(--border-active);
}

.tool-content textarea {
  min-height: 120px;
  resize: vertical;
}

.tool-content .output-area {
  background: var(--surface-0);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 12px;
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--text-1);
  white-space: pre-wrap;
  word-break: break-all;
  min-height: 60px;
  position: relative;
}

.tool-content .btn {
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-2);
  padding: 8px 16px;
  border-radius: 4px;
  font-size: 12px;
  cursor: pointer;
  transition: all 150ms ease;
}

.tool-content .btn:hover {
  border-color: var(--border-active);
  color: var(--text-1);
}

.tool-content .btn--primary {
  border-color: rgba(184, 165, 214, 0.3);
  color: var(--accent);
}

.tool-content .btn--primary:hover {
  border-color: var(--accent);
  color: var(--accent-strong);
}

.tool-content .btn--copy {
  font-size: 11px;
  padding: 4px 10px;
  position: absolute;
  top: 8px;
  right: 8px;
}

.tool-content .btn--copy.copied {
  color: var(--sage);
  border-color: rgba(107, 207, 143, 0.3);
}

.tool-content .tool-row {
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
  align-items: flex-end;
}

.tool-content .tool-group {
  flex: 1;
  margin-bottom: 16px;
}

.tool-content .tool-options {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 16px;
}

.tool-content .tool-option {
  padding: 6px 12px;
  border: 1px solid var(--border);
  border-radius: 4px;
  font-size: 12px;
  color: var(--text-3);
  cursor: pointer;
  transition: all 150ms ease;
  background: transparent;
}

.tool-content .tool-option:hover {
  border-color: var(--border-active);
  color: var(--text-2);
}

.tool-content .tool-option.active {
  border-color: rgba(184, 165, 214, 0.3);
  color: var(--accent);
  background: rgba(184, 165, 214, 0.05);
}

/* ============================================================
   Related Tools Grid
   ============================================================ */
.tool-related {
  padding: 40px;
  border-top: 1px solid var(--border);
}

.tool-related .container {
  max-width: 900px;
}

.tool-related-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 12px;
}

.tool-related-card {
  padding: 16px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface-1);
  text-decoration: none;
  transition: border-color 150ms ease;
}

.tool-related-card:hover {
  border-color: var(--border-active);
}

.tool-related-card h3 {
  font-size: 13px;
  color: var(--text-1);
  margin: 0 0 4px;
  font-weight: 500;
}

.tool-related-card p {
  font-size: 11px;
  color: var(--text-3);
  margin: 0 0 8px;
  line-height: 1.4;
}

/* ============================================================
   Tool CTA
   ============================================================ */
.tool-cta {
  padding: 24px 40px;
  text-align: center;
  font-size: 12px;
  color: var(--text-3);
}

.tool-cta a {
  color: var(--accent);
}

/* ============================================================
   Tools Hub Index
   ============================================================ */
.tools-hub {
  padding: 60px 40px 40px;
}

.tools-hub .container {
  max-width: 900px;
}

.tools-hub-hero {
  text-align: center;
  margin-bottom: 40px;
}

.tools-hub-hero h1 {
  font-size: 24px;
  font-weight: 300;
  color: var(--text-1);
  margin: 0 0 8px;
}

.tools-hub-hero p {
  font-size: 13px;
  color: var(--text-3);
  margin: 0;
}

.tools-hub-search {
  width: 100%;
  max-width: 480px;
  margin: 24px auto 0;
  display: block;
  background: var(--surface-1);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px 16px;
  color: var(--text-1);
  font-size: 13px;
  font-family: var(--font-mono);
  outline: none;
  transition: border-color 150ms ease;
}

.tools-hub-search:focus {
  border-color: var(--border-active);
}

.tools-hub-search::placeholder {
  color: var(--muted);
}

.tools-hub-filters {
  display: flex;
  gap: 6px;
  justify-content: center;
  flex-wrap: wrap;
  margin-bottom: 32px;
}

.tools-hub-filter {
  padding: 6px 14px;
  border: 1px solid var(--border);
  border-radius: 4px;
  font-size: 12px;
  color: var(--text-3);
  cursor: pointer;
  transition: all 150ms ease;
  background: transparent;
}

.tools-hub-filter:hover {
  border-color: var(--border-active);
  color: var(--text-2);
}

.tools-hub-filter.active {
  border-color: rgba(184, 165, 214, 0.3);
  color: var(--accent);
  background: rgba(184, 165, 214, 0.05);
}

.tools-hub-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
  margin-bottom: 32px;
}

.tools-hub-card {
  display: block;
  padding: 18px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--surface-1);
  text-decoration: none;
  transition: border-color 150ms ease;
}

.tools-hub-card:hover {
  border-color: var(--border-active);
}

.tools-hub-card h3 {
  font-size: 13px;
  color: var(--text-1);
  margin: 0 0 4px;
  font-weight: 500;
}

.tools-hub-card p {
  font-size: 11px;
  color: var(--text-3);
  margin: 0 0 10px;
  line-height: 1.4;
}

.tools-hub-count {
  text-align: center;
  font-size: 11px;
  color: var(--muted);
  margin-bottom: 16px;
}

.tools-hub-terminal-link {
  text-align: center;
  font-size: 11px;
  color: var(--text-3);
  margin-bottom: 32px;
}

.tools-hub-terminal-link a {
  color: var(--accent);
}

.tools-hub-empty {
  text-align: center;
  padding: 40px;
  color: var(--text-3);
  font-size: 13px;
  display: none;
}

@media (max-width: 768px) {
  .tools-hub-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 640px) {
  .tools-hub-grid {
    grid-template-columns: 1fr;
  }

  .tool-main {
    padding: 24px 16px;
  }

  .tool-content {
    padding: 16px;
  }

  .tool-related {
    padding: 24px 16px;
  }

  .tool-related-grid {
    grid-template-columns: 1fr;
  }

  .tool-nav {
    padding: 12px 16px;
  }
}
```

- [ ] **Step 2: Build and verify**

```bash
npm run build
```
No build errors.

- [ ] **Step 3: Commit**

```bash
git add src/css/style.css && git commit -m "feat: add tool hub and tool page CSS in Forge Dark theme"
```

---

## Task 6: Create the Tools Hub Index Page

**Files:**
- Create: `src/tools/index.njk`
- Modify: `eleventy.config.js` (if needed for permalink handling)

The hub index page renders the card grid from `tools.json`, with client-side search and category filters.

- [ ] **Step 1: Create the hub index page**

Create `src/tools/index.njk`:

```njk
---
layout: base.njk
title: "Free Developer & Security Tools — No Tracking, No Accounts | Penumbra Forge"
description: "50+ free online developer and security tools. JSON formatter, JWT decoder, hash generator, subnet calculator, and more. All client-side — your data never leaves your browser."
permalink: /tools/
---

<section class="tools-hub">
  <div class="container">
    <div class="tools-hub-hero">
      <h1>Tool Kits</h1>
      <p>Free developer &amp; security tools. No accounts, no tracking, your data stays in your browser.</p>
      <input
        type="text"
        class="tools-hub-search"
        id="toolSearch"
        placeholder="Search tools..."
        aria-label="Search tools"
        autocomplete="off"
      >
    </div>

    <div class="tools-hub-filters" role="tablist" aria-label="Filter by category">
      <button class="tools-hub-filter active" data-category="all" role="tab" aria-selected="true">All</button>
      <button class="tools-hub-filter" data-category="security" role="tab" aria-selected="false">Security</button>
      <button class="tools-hub-filter" data-category="encoding" role="tab" aria-selected="false">Encoding</button>
      <button class="tools-hub-filter" data-category="devops" role="tab" aria-selected="false">DevOps</button>
      <button class="tools-hub-filter" data-category="web" role="tab" aria-selected="false">Web</button>
      <button class="tools-hub-filter" data-category="text" role="tab" aria-selected="false">Text</button>
    </div>

    <div class="tools-hub-count" id="toolCount" aria-live="polite">
      {{ tools | length }} tools available
    </div>

    <div class="tools-hub-grid" id="toolGrid">
      {% for tool in tools %}
        {% if tool.status == "live" %}
        <a href="/tools/{{ tool.slug }}/" class="tools-hub-card" data-category="{{ tool.category }}" data-keywords="{{ tool.keywords | join(' ') }} {{ tool.name | lower }}">
          <h3>{{ tool.name }}</h3>
          <p>{{ tool.description }}</p>
          <span class="tool-badge tool-badge--{{ tool.badge }}">{{ tool.badge }}</span>
        </a>
        {% endif %}
      {% endfor %}
    </div>

    <div class="tools-hub-empty" id="toolEmpty">
      No tools match your search.
    </div>

    <div class="tools-hub-terminal-link">
      <a href="/terminal/">Power user? Try the terminal →</a>
    </div>
  </div>
</section>

<script>
(function() {
  const search = document.getElementById('toolSearch');
  const grid = document.getElementById('toolGrid');
  const cards = Array.from(grid.querySelectorAll('.tools-hub-card'));
  const filters = document.querySelectorAll('.tools-hub-filter');
  const countEl = document.getElementById('toolCount');
  const emptyEl = document.getElementById('toolEmpty');
  let activeCategory = 'all';

  function filterCards() {
    const query = search.value.toLowerCase().trim();
    let visible = 0;

    cards.forEach(card => {
      const category = card.dataset.category;
      const keywords = card.dataset.keywords;
      const matchesCategory = activeCategory === 'all' || category === activeCategory;
      const matchesSearch = !query || keywords.includes(query);
      const show = matchesCategory && matchesSearch;
      card.style.display = show ? '' : 'none';
      if (show) visible++;
    });

    countEl.textContent = visible + ' tool' + (visible !== 1 ? 's' : '') + (query || activeCategory !== 'all' ? ' found' : ' available');
    emptyEl.style.display = visible === 0 ? 'block' : 'none';
  }

  search.addEventListener('input', filterCards);

  filters.forEach(btn => {
    btn.addEventListener('click', () => {
      filters.forEach(b => { b.classList.remove('active'); b.setAttribute('aria-selected', 'false'); });
      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      activeCategory = btn.dataset.category;
      filterCards();
    });
  });
})();
</script>
```

- [ ] **Step 2: Build and verify**

```bash
npm run build
```
Verify: `_site/tools/index.html` exists and contains the card grid. Open in browser — search and filter should work.

- [ ] **Step 3: Commit**

```bash
git add src/tools/index.njk && git commit -m "feat: add tools hub index page with search, filters, and card grid"
```

---

## Task 7: Create First Tool Page — JSON Formatter (template validation)

**Files:**
- Create: `src/tools/json-formatter.njk`

This is the first real tool page. It validates the entire infrastructure chain: `tools.json` data → `tool-layout.njk` → tool content → build output.

- [ ] **Step 1: Create json-formatter.njk**

Create `src/tools/json-formatter.njk`:

```njk
---
toolSlug: json-formatter
permalink: /tools/json-formatter/
---

<div class="tool-group">
  <label for="jsonInput">Paste JSON</label>
  <textarea id="jsonInput" placeholder='{"name": "example", "items": [1, 2, 3]}'></textarea>
</div>

<div class="tool-options">
  <button class="tool-option active" data-indent="2">2 spaces</button>
  <button class="tool-option" data-indent="4">4 spaces</button>
  <button class="tool-option" data-indent="tab">Tab</button>
  <button class="tool-option" data-action="minify">Minify</button>
</div>

<div class="tool-group">
  <label>Output</label>
  <div class="output-area" id="jsonOutput" role="region" aria-label="Formatted JSON output">
    <button class="btn btn--copy" id="copyBtn" aria-label="Copy output">Copy</button>
    <pre id="jsonResult" style="margin:0;white-space:pre-wrap;word-break:break-word;"></pre>
  </div>
</div>

<div id="jsonError" style="color: var(--accent); font-size: 12px; margin-top: 8px; display: none;" role="alert"></div>

<script>
(function() {
  const input = document.getElementById('jsonInput');
  const result = document.getElementById('jsonResult');
  const error = document.getElementById('jsonError');
  const copyBtn = document.getElementById('copyBtn');
  const options = document.querySelectorAll('.tool-option');
  let indent = 2;
  let minify = false;

  function format() {
    const raw = input.value.trim();
    if (!raw) {
      result.textContent = '';
      error.style.display = 'none';
      return;
    }
    try {
      const parsed = JSON.parse(raw);
      if (minify) {
        result.textContent = JSON.stringify(parsed);
      } else {
        result.textContent = JSON.stringify(parsed, null, indent);
      }
      error.style.display = 'none';
    } catch (e) {
      error.textContent = 'Invalid JSON: ' + e.message;
      error.style.display = 'block';
      result.textContent = raw;
    }
  }

  input.addEventListener('input', format);

  options.forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.dataset.action === 'minify') {
        minify = true;
        options.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
      } else {
        minify = false;
        options.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const val = btn.dataset.indent;
        indent = val === 'tab' ? '\t' : parseInt(val);
      }
      format();
    });
  });

  copyBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(result.textContent);
      copyBtn.textContent = 'Copied!';
      copyBtn.classList.add('copied');
      setTimeout(() => { copyBtn.textContent = 'Copy'; copyBtn.classList.remove('copied'); }, 1500);
    } catch (e) {
      copyBtn.textContent = 'Failed';
      setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
    }
  });
})();
</script>
```

- [ ] **Step 2: Build and verify the full chain**

```bash
npm run build
```
Verify:
1. `_site/tools/json-formatter/index.html` exists
2. Page has correct `<title>`: "JSON Formatter — Free Online Tool | Penumbra Forge"
3. Page has `<meta name="description">` with the longDescription from tools.json
4. Page has JSON-LD `SoftwareApplication` block
5. Page has breadcrumb navigation: Penumbra Forge / Tools / JSON Formatter
6. Page has related tools section
7. The JSON formatter tool actually works (paste JSON, get formatted output)

```bash
grep -c "SoftwareApplication" _site/tools/json-formatter/index.html
# Expected: 1
grep -c "BreadcrumbList" _site/tools/json-formatter/index.html
# Expected: 1
```

- [ ] **Step 3: Commit**

```bash
git add src/tools/json-formatter.njk && git commit -m "feat: add JSON Formatter tool page — validates full infrastructure chain"
```

---

## Task 8: Create Remaining Wave 1 Tool Pages

**Files:**
- Create: 13 more `.njk` files in `src/tools/`

Each tool follows the same pattern as JSON Formatter: front matter with `toolSlug` and `permalink`, then tool-specific HTML/CSS/JS in the content block.

Tools to create (each is a sub-step — commit after every 3-4 tools):

- [ ] **Step 1: UUID Generator** (`src/tools/uuid-generator.njk`)

UUID v4 (random via `crypto.getRandomValues()`) and v7 (time-ordered). Bulk generation (1-100). Click-to-copy. Format toggle (with/without hyphens, uppercase/lowercase).

- [ ] **Step 2: Epoch Converter** (`src/tools/epoch-converter.njk`)

Two-way conversion: epoch ↔ human date. Support seconds and milliseconds. "Now" button showing current timestamp live. Timezone selector. Relative time display ("3 hours ago").

- [ ] **Step 3: Password Generator** (`src/tools/password-generator.njk`)

Sliders for length (8-128). Checkboxes for character sets (uppercase, lowercase, numbers, symbols). Entropy display in bits. Strength meter. Bulk generation. Uses `crypto.getRandomValues()`.

- [ ] **Step 4: Commit batch 1**

```bash
git add src/tools/uuid-generator.njk src/tools/epoch-converter.njk src/tools/password-generator.njk
git commit -m "feat: add UUID generator, epoch converter, password generator tool pages"
```

- [ ] **Step 5: Hash Generator** (`src/tools/hash-generator.njk`)

Input: text or file upload. Algorithms: SHA-256, SHA-512, SHA-1, MD5 (with deprecation note). Uses Web Crypto API (`crypto.subtle.digest()`). Hash comparison mode. Output: hex string with copy button.

- [ ] **Step 6: Base64 Encoder** (`src/tools/base64-encoder.njk`)

Encode/decode toggle. Text input with character count. File drag-and-drop for binary encoding. UTF-8 support. URL-safe Base64 variant toggle.

- [ ] **Step 7: URL Encoder** (`src/tools/url-encoder.njk`)

Encode/decode toggle. Full URL mode vs. component mode. Shows encoded characters highlighted. Handles full URLs and individual query parameters.

- [ ] **Step 8: JWT Decoder** (`src/tools/jwt-decoder.njk`)

Paste JWT → split into header, payload, signature. Color-coded sections. Show decoded JSON with formatting. Expiration check (expired/valid). Claim explanations (iss, sub, aud, exp, iat). No verification (client-side only).

- [ ] **Step 9: Commit batch 2**

```bash
git add src/tools/hash-generator.njk src/tools/base64-encoder.njk src/tools/url-encoder.njk src/tools/jwt-decoder.njk
git commit -m "feat: add hash generator, base64, URL encoder, JWT decoder tool pages"
```

- [ ] **Step 10: Subnet Calculator** (`src/tools/subnet-calculator.njk`)

Input: IP/CIDR notation (e.g., `192.168.1.0/24`). Output: network address, broadcast, first/last usable host, total hosts, wildcard mask, binary representation. Visual subnet map. Common subnet reference table.

- [ ] **Step 11: Cron Builder** (`src/tools/cron-builder.njk`)

Five fields (minute, hour, day-of-month, month, day-of-week) with dropdowns and text input. Real-time plain-English description. Next 5 execution times. Common presets (hourly, daily, weekly, monthly). Bidirectional: edit cron string or use the visual builder.

- [ ] **Step 12: Regex Tester** (`src/tools/regex-tester.njk`)

Pattern input with flag toggles (g, i, m, s). Test string textarea. Live highlighting of matches. Capture group display. Match count. Common pattern library (email, URL, IP, phone). Explanation of what the pattern does.

- [ ] **Step 13: Chmod Calculator** (`src/tools/chmod-calculator.njk`)

3x3 checkbox grid (owner/group/other × read/write/execute). Live numeric output (e.g., 755). Symbolic output (e.g., rwxr-xr-x). Command output (e.g., `chmod 755 file`). Bidirectional: edit checkboxes or type numeric.

- [ ] **Step 14: Commit batch 3**

```bash
git add src/tools/subnet-calculator.njk src/tools/cron-builder.njk src/tools/regex-tester.njk src/tools/chmod-calculator.njk
git commit -m "feat: add subnet calc, cron builder, regex tester, chmod calculator tool pages"
```

- [ ] **Step 15: ASCII/Unicode Table** (`src/tools/ascii-unicode-table.njk`)

Searchable table of ASCII 0-127 with columns: decimal, hex, binary, character, HTML entity, description. Unicode extension: search by name or code point. Click any character to copy. Filter: printable, control, extended.

- [ ] **Step 16: Color Converter** (`src/tools/color-converter.njk`)

Input any format (HEX, RGB, HSL). Live conversion to all formats. Visual color swatch preview. Color picker (`<input type="color">`). Contrast ratio checker (input two colors, get WCAG ratio). Copy buttons for each format.

- [ ] **Step 17: Commit batch 4**

```bash
git add src/tools/ascii-unicode-table.njk src/tools/color-converter.njk
git commit -m "feat: add ASCII/Unicode table and color converter tool pages"
```

---

## Task 9: Rebuild Existing Tools (Quality Overhaul)

**Files:**
- Create: `src/tools/curl-converter.njk`
- Create: `src/tools/dockerfile-optimizer.njk`
- Create: `src/tools/git-branch-visualizer.njk`

The existing tools have quality issues: GitHub-dark theme mismatch, input sanitization gaps (possible XSS via unsanitized innerHTML), fragile regex parsers, and missing error handling. **Rebuild each tool from scratch** using the shared layout and Forge Dark CSS classes. Reference the old code for feature parity but rewrite the implementation with:

- All user input sanitized via `textContent` (never `innerHTML` with unsanitized data)
- Proper error handling with user-visible messages
- Forge Dark design tokens (no inline color overrides)
- Accessible markup (labels, ARIA, keyboard nav)
- Copy-to-clipboard on all outputs

- [ ] **Step 1: Rebuild curl-converter**

Create `src/tools/curl-converter.njk`. Features to preserve:
- Paste curl → get Python/JavaScript/Go/Bash code
- Language tabs, example buttons, parsed info display, copy button

Improvements over current implementation:
- Escape all parsed values before display (current code uses raw `innerHTML` for method/URL/headers)
- Better curl parser that handles multi-line commands, escaped quotes, and `--data-raw`
- Tab switching via `.tool-option` class (shared CSS)
- Proper error message if curl command can't be parsed

- [ ] **Step 2: Rebuild dockerfile-optimizer**

Create `src/tools/dockerfile-optimizer.njk`. Rewrite with proper HTML escaping, Forge Dark theme, and accessible markup. Ensure all Dockerfile analysis output is escaped.

- [ ] **Step 3: Rebuild git-branch-visualizer**

Create `src/tools/git-branch-visualizer.njk`. Rewrite with proper HTML escaping, Forge Dark theme, and accessible markup. Ensure all git branch output is escaped.

- [ ] **Step 4: Build and verify all three rebuilt tools work**

```bash
npm run build
```
Verify each generates at its new permalink and the tool functionality works.

**Security smoke test for each tool:**
- Paste `<script>alert('xss')</script>` as input — verify it renders as text, not executed
- Paste extremely long input (10KB+) — verify no browser hang
- Paste empty input — verify graceful handling (no errors)

- [ ] **Step 5: Commit**

```bash
git add src/tools/curl-converter.njk src/tools/dockerfile-optimizer.njk src/tools/git-branch-visualizer.njk
git commit -m "feat: rebuild existing tools with Forge Dark theme, input sanitization, and accessibility"
```

---

## Task 10: Update Terminal Tool URLs

**Files:**
- Modify: `public/terminal/index.html`

Update the terminal's tool registry to point to the new `/tools/{slug}/` URLs.

- [ ] **Step 1: Update the tools object in terminal index.html**

In the `tools` object (around line 240), update all URLs:

```javascript
const tools = {
  'secret-lock':     { url: 'https://tools.penumbraforge.com/lock',          desc: 'encrypt secrets with a password',          cat: 'security',  badge: 'cloud' },
  'one-time-secret': { url: 'https://tools.penumbraforge.com/secret',        desc: 'share passwords, burns after reading',     cat: 'security',  badge: 'cloud' },
  'view-lock':       { url: 'https://tools.penumbraforge.com/view-lock',     desc: 'decrypt a locked secret',                  cat: 'security',  badge: 'cloud' },
  'password-gen':    { url: '/tools/password-generator/',                     desc: 'cryptographically secure passwords',       cat: 'security',  badge: 'client' },
  'hash-gen':        { url: '/tools/hash-generator/',                        desc: 'sha-256, sha-512 hashing',                 cat: 'security',  badge: 'client' },
  'entropy-calc':    { url: '#',                                              desc: 'detect encrypted/compressed data (coming soon)', cat: 'security',  badge: 'client' },
  'curl-converter':  { url: '/tools/curl-converter/',                        desc: 'curl → python/js/go/bash',                 cat: 'developer', badge: 'client' },
  'dockerfile-opt':  { url: '/tools/dockerfile-optimizer/',                  desc: 'analyze & optimize dockerfiles',           cat: 'developer', badge: 'client' },
  'git-branches':    { url: '/tools/git-branch-visualizer/',                 desc: 'visualize & cleanup branches',             cat: 'developer', badge: 'client' },
  'regex-gen':       { url: '/tools/regex-tester/',                          desc: 'test, generate, build patterns',           cat: 'developer', badge: 'client' },
  'jwt-decoder':     { url: '/tools/jwt-decoder/',                           desc: 'inspect tokens without verification',      cat: 'developer', badge: 'client' },
  'encoding-suite':  { url: '/tools/base64-encoder/',                        desc: 'base64, hex, url, html, unicode',          cat: 'developer', badge: 'client' },
};
```

Note: `entropy-calc` points to a future page (Wave 2) — it will 404 until then. This is acceptable since the terminal is a power-user feature, not the primary entry point.

- [ ] **Step 2: Build and verify**

```bash
npm run build
```

- [ ] **Step 3: Commit**

```bash
git add public/terminal/index.html && git commit -m "feat: update terminal tool URLs to new /tools/{slug}/ paths"
```

---

## Task 11: Generate OG Image PNG

**Files:**
- Create: `public/og-image.png`

Social platforms don't render SVG OG images. Generate a PNG version.

- [ ] **Step 1: Convert SVG to PNG**

Use the existing `public/og-image.svg` to create a 1200x630 PNG:

```bash
# Install librsvg if not present
brew install librsvg 2>/dev/null

# Convert SVG to PNG at OG image dimensions
rsvg-convert -w 1200 -h 630 public/og-image.svg > public/og-image.png
```

If `rsvg-convert` fails or the SVG doesn't convert well, use a Node.js approach:

```bash
npx --yes sharp-cli -i public/og-image.svg -o public/og-image.png --resize 1200 630
```

- [ ] **Step 2: Commit**

```bash
git add public/og-image.png && git commit -m "feat: add PNG OG image for social platform compatibility"
```

---

## Task 12: Final Verification

- [ ] **Step 1: Full build**

```bash
npm run build
```
Exit code 0 — no errors.

- [ ] **Step 2: Verify all tool pages exist**

```bash
ls _site/tools/*/index.html | wc -l
# Expected: 17 (14 Wave 1 + 3 migrated)
```

- [ ] **Step 3: Verify SEO tags on a sample tool page**

```bash
grep '<title>' _site/tools/json-formatter/index.html
# Expected: JSON Formatter — Free Online Tool | Penumbra Forge

grep 'SoftwareApplication' _site/tools/json-formatter/index.html
# Expected: 1 match

grep 'BreadcrumbList' _site/tools/json-formatter/index.html
# Expected: 1 match

grep 'og:title' _site/tools/json-formatter/index.html
# Expected: 1 match
```

- [ ] **Step 4: Verify hub index links**

```bash
grep -c 'tools-hub-card' _site/tools/index.html
# Expected: 17 (one per live tool)
```

- [ ] **Step 5: Verify no broken internal links**

```bash
# Check that all href="/tools/..." paths in the hub resolve to actual files
grep -oP 'href="/tools/[^"]+/"' _site/tools/index.html | sort -u | while read href; do
  path=$(echo $href | sed 's/href="//;s/"$//')
  if [ ! -f "_site${path}index.html" ]; then
    echo "BROKEN: $path"
  fi
done
# Expected: no output (no broken links)
```

- [ ] **Step 6: Security smoke test all tools**

For each tool page, verify:
- Paste `<img src=x onerror=alert(1)>` as input — must render as text, never execute
- Paste `{{7*7}}` as input — must not evaluate (no template injection)
- Paste 50KB of random text — no browser hang or memory spike
- Verify no `innerHTML` with unsanitized user input in any tool's JS (use `textContent` or proper escaping)

```bash
# Quick check: no innerHTML with user-controlled data in tool pages
grep -r 'innerHTML' _site/tools/*/index.html | grep -v 'aria-live' | head -20
# Review each match to ensure input is sanitized
```

- [ ] **Step 7: Test locally**

```bash
npm run dev
```
Visit `http://localhost:8080/tools/` — hub should render with all cards. Click each tool — should load with shared layout. Test search and category filters. Verify each tool produces correct output for at least one real-world input.

- [ ] **Step 8: Commit any final fixes**

If any verification step found issues, fix and commit.

---

## Summary

| Task | What it does |
|---|---|
| 1 | Fix 404 — rename directory, update products.json |
| 2 | Add block tags to base.njk for layout inheritance |
| 3 | Create tools.json data file with all Wave 1 metadata |
| 4 | Create shared tool-layout.njk (SEO, breadcrumbs, related tools) |
| 5 | Add all tool hub + tool page CSS |
| 6 | Create tools hub index page (search, filters, card grid) |
| 7 | Create JSON Formatter (validates full chain) |
| 8 | Create remaining 13 Wave 1 tool pages |
| 9 | Migrate 3 existing tools to Eleventy templates |
| 10 | Update terminal tool URLs |
| 11 | Generate PNG OG image |
| 12 | Final verification |
