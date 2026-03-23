# Penumbra Forge Security Labs — Design Specification

**Author:** Shadoe Myers / Penumbra Forge
**Date:** 2026-03-22
**Status:** Draft

---

## 1. Vision

Penumbra Forge Security Labs is a free, browser-based, zero-setup security training platform with two tracks: **Red Team** (offensive — exploit real vulnerabilities) and **Blue Team** (defensive — investigate incidents, triage alerts, contain threats, build automation).

The defining feature: **each red team attack unlocks a blue team investigation of the same incident.** You break ShopStack via XSS, then switch chairs and investigate the ShopStack breach from the defender's perspective using the same logs the attacker generated.

No platform does this. TryHackMe and HackTheBox are red-only. CyberDefenders and LetsDefend are behind paywalls. Nobody teaches SOAR automation interactively. This fills all three gaps simultaneously.

### Design Principles

1. **Real, not simulated** — Vulnerabilities are real code running on real infrastructure. XSS actually executes. SQL injection hits a real SQLite database. SSRF makes real requests. Nothing is pattern-matched or faked.
2. **Secure by architecture** — Labs run on isolated Worker origins. The browser's same-origin policy and Cloudflare's V8 sandboxing make it mathematically impossible for lab exploits to affect penumbraforge.com.
3. **Zero friction** — No accounts, no VMs, no downloads, no setup. Open the page and start hacking.
4. **Privacy-first** — Progress stored locally. Optional passphrase-encrypted sync. We can't see your data. We don't know who you are.
5. **Evolving** — The lab engine is a framework. New labs are config + content. As the threat landscape evolves, new labs ship without engine changes.

---

## 2. Architecture

### 2.1 System Overview

```
penumbraforge.com                    (static site — GitHub Pages + Cloudflare)
├── /labs/                           (labs hub — index, profiles, skill trees)
├── /labs/red/xss-shopstack/         (red team lab page — workspace UI)
├── /labs/blue/investigate-breach/   (blue team lab page — workspace UI)
│
│   Each lab page embeds target via sandboxed iframe:
│   <iframe sandbox="allow-scripts allow-forms" src="https://lab-*.penumbraforge.workers.dev/...">
│
lab-xss.penumbraforge.workers.dev    (Worker — vulnerable ShopStack app)
lab-sqli.penumbraforge.workers.dev   (Worker — vulnerable VaultBank app)
lab-ssrf.penumbraforge.workers.dev   (Worker — vulnerable CloudSnap app)
lab-jwt.penumbraforge.workers.dev    (Worker — vulnerable DevPortal app)
lab-race.penumbraforge.workers.dev   (Worker — vulnerable GiftRush app)
lab-blue.penumbraforge.workers.dev   (Worker — blue team scenarios + log API)
lab-sync.penumbraforge.workers.dev   (Worker — encrypted progress storage)
```

### 2.2 Security Model

**Threat model:** An adversarial user attempts to use the intentionally vulnerable lab infrastructure to attack penumbraforge.com, other users, or third-party systems.

| Threat | Mitigation |
|--------|------------|
| XSS escaping lab iframe to penumbraforge.com | `sandbox` attribute without `allow-same-origin` creates a null origin. Same-origin policy blocks all access to the parent. |
| Stealing penumbraforge.com cookies via lab XSS | Different origin (workers.dev vs penumbraforge.com). Cookies are origin-scoped. Impossible. |
| Using SSRF lab to attack real internal services | Worker fetches route to a simulated internal endpoint on the same Worker, not real network requests. The "metadata endpoint" is just another Worker route returning fake data. |
| Using lab Workers to relay attacks to third parties | Workers only respond to predefined lab routes. No open proxy functionality. All fetch calls in Workers are to internal routes only. |
| DoS via lab endpoints | Per-IP rate limiting (configurable per lab). Cloudflare Worker CPU time limits (10ms free, 30ms paid). Workers auto-scale. |
| Corrupting shared lab state to affect other users | No shared state. Each request is independent. No database. SQLite (sql.js) runs in the browser per-user, not on the Worker. |
| Forging XP or progress | Progress is client-side (localStorage). Users can only "cheat" themselves. Certificates validate against a signed hash of completion data. |
| Reading other users' encrypted progress | AES-256-GCM encrypted client-side with user's passphrase. Worker stores ciphertext only. Without the passphrase, data is random bytes. |

**Key architectural decision:** SQL injection labs run sql.js (SQLite compiled to WASM) **in the user's browser**, not on the Worker. The Worker serves the vulnerable application UI, but the "database" is client-side. This means:
- Each user gets their own isolated database instance
- No shared state to corrupt
- No risk of a SQL injection escaping to real infrastructure
- The experience is identical to attacking a real database

### 2.3 Lab Engine Framework

The lab engine is a reusable system that all labs — red and blue — run on. Each lab is defined by a configuration object, not custom code.

**Lab definition structure:**

```javascript
{
  id: "red-xss-shopstack",
  type: "red",                    // "red" | "blue"
  title: "Reflected XSS",
  target: "ShopStack",
  difficulty: "beginner",         // "beginner" | "intermediate" | "advanced"
  estimatedTime: 10,              // minutes
  xpReward: 100,
  hintCost: [10, 25, 50],        // XP cost per hint
  tags: ["XSS", "CWE-79", "OWASP A03"],
  prerequisites: [],              // lab IDs that must be completed first
  unlocks: ["blue-investigate-shopstack"],

  // Objectives — sequential steps the user must complete
  objectives: [
    {
      id: "recon",
      step: 1,
      title: "Reconnaissance",
      description: "Enter a normal search query and observe how input is reflected",
      validation: "reflected_input",  // validation function name
    },
    {
      id: "inject",
      step: 2,
      title: "Test for injection",
      description: "Submit HTML markup and check if it renders in the results",
      validation: "html_injection",
    },
    // ...
  ],

  // Hints — progressive reveals
  hints: [
    { text: "The search results page displays your query...", cost: 10 },
    { text: "HTML elements with event handlers...", cost: 25 },
    { text: "Try: <img src=x onerror=alert(document.cookie)>", cost: 50 },
  ],

  // Worker URL for the target app
  workerUrl: "https://lab-xss.penumbraforge.workers.dev",

  // Source code to display in the Source tab
  sourceFiles: [
    {
      filename: "server/routes/search.js",
      language: "javascript",
      code: "...",
      vulnerableLine: 9,
    }
  ],

  // Debrief content shown after completion
  debrief: {
    vulnerability: "CWE-79: Improper Neutralization of Input During Web Page Generation",
    explanation: "...",
    fix: "...",
    realWorld: "British Airways breach (2018) — 380,000 credit cards stolen via XSS...",
    mitreAttack: "T1189 — Drive-by Compromise",
    references: ["https://owasp.org/Top10/A03_2021-Injection/"],
  }
}
```

**Lab engine components (client-side):**

| Component | Purpose |
|-----------|---------|
| `LabEngine` | Core orchestrator — loads lab config, manages state, validates objectives |
| `LabWorkspace` | Three-panel layout manager (mission, target, inspector) |
| `ObjectiveTracker` | Tracks step completion, shows toasts, triggers unlocks |
| `TargetFrame` | Manages the sandboxed iframe to the Worker target app |
| `HttpInspector` | Captures and displays HTTP traffic between frontend and Worker |
| `ServerLogs` | Receives and displays simulated server-side log entries |
| `LabConsole` | Terminal emulator for command input |
| `HintSystem` | Progressive hint reveals with XP cost deduction |
| `TimerSystem` | Elapsed time tracking per lab |
| `ProgressStore` | localStorage + encrypted sync adapter |
| `XpSystem` | XP calculation, level progression, skill tree state |

### 2.4 Worker Architecture

**Red team Workers** serve full HTML pages representing the vulnerable target application. They handle HTTP requests with intentionally vulnerable code.

**Worker structure (per lab):**

```
workers/lab-xss/
├── wrangler.toml          # Deployment config
├── worker.js              # Entry point — routes requests
├── app/
│   ├── pages.js           # HTML page templates (the "website")
│   ├── vulnerable.js      # The intentionally vulnerable endpoints
│   └── assets.js          # CSS/images for the target app
└── README.md              # Lab-specific notes
```

**Blue team Worker** serves scenario data — log files, alert queues, network captures — via API endpoints that the blue team workspace queries.

```
workers/lab-blue/
├── wrangler.toml
├── worker.js
├── scenarios/
│   ├── alert-triage.js     # Alert queue data
│   ├── shopstack-breach.js # Logs from the ShopStack XSS incident
│   ├── phishing.js         # Email headers and delivery logs
│   ├── log-analysis.js     # Mixed log sources
│   ├── containment.js      # Host list and network data
│   └── soar-playbook.js    # Alert stream for automation testing
└── README.md
```

---

## 3. Target Applications

Each red team lab features a distinct, visually complete "company" that looks and feels like a real web application.

### 3.1 ShopStack (XSS Lab)

**Type:** E-commerce storefront
**Visual identity:** Dark navy/coral gradient, modern e-commerce aesthetic
**Pages:**
- Homepage with featured products (cards with images, prices, ratings)
- Search page with results (the vulnerable endpoint)
- Product detail page
- Shopping cart
- Navigation bar, footer, breadcrumbs — full site feel

**Vulnerability:** Search query reflected via `innerHTML` without encoding. User input in the URL parameter `?q=` is inserted directly into the results HTML.

**Objectives:**
1. Search for a normal term, observe reflection in results
2. Search for `<b>test</b>`, observe HTML rendering
3. Craft a payload that executes JavaScript (e.g., `<img src=x onerror=alert(1)>`)
4. Modify payload to exfiltrate the session cookie (`document.cookie`)

### 3.2 VaultBank (SQL Injection Lab)

**Type:** Banking dashboard
**Visual identity:** Dark charcoal/blue, fintech aesthetic with transaction tables
**Pages:**
- Login page
- Dashboard with account summary
- Transaction history table
- Customer lookup form (the vulnerable endpoint)
- Settings page

**Vulnerability:** Customer lookup concatenates user input into a SQL query. sql.js (SQLite WASM) runs in the browser with a pre-populated database containing users, accounts, and transactions tables.

**Objectives:**
1. Search for a valid customer name, observe normal results
2. Enter a single quote `'` and observe the SQL error
3. Craft a UNION SELECT to determine column count
4. Extract the admin password hash from the users table
5. (Bonus) Dump the full database schema

### 3.3 CloudSnap (SSRF Lab)

**Type:** Image hosting / sharing SaaS
**Visual identity:** Deep purple/lavender, cloud-themed
**Pages:**
- Image gallery with thumbnails
- Upload page
- "Import from URL" feature (the vulnerable endpoint)
- Image detail/share page

**Vulnerability:** URL import feature fetches user-provided URLs server-side (in the Worker). An internal route simulates the cloud metadata endpoint at `/internal/metadata` that returns fake IAM credentials.

**Objectives:**
1. Import an image via a valid URL, observe the fetch
2. Try importing `http://localhost/` and observe the response
3. Discover the internal metadata endpoint
4. Fetch `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (simulated)
5. Extract the IAM access key and secret

### 3.4 DevPortal (JWT Lab)

**Type:** API documentation and developer portal
**Visual identity:** Dark green/mint, developer-focused
**Pages:**
- API documentation
- Authentication page with JWT playground
- API key management
- Dashboard showing API usage

**Vulnerability:** JWT validation accepts `alg: none` and is vulnerable to RS256→HS256 algorithm confusion. The Worker has a public key endpoint.

**Objectives:**
1. Authenticate as a regular user, receive a JWT
2. Decode the JWT, observe RS256 algorithm
3. Forge a token with `alg: none` and empty signature
4. Use the forged token to access the admin endpoint
5. (Bonus) Exploit algorithm confusion with the public key

### 3.5 GiftRush (Race Condition Lab)

**Type:** Gift card / rewards platform
**Visual identity:** Warm amber/brown, gift/rewards aesthetic
**Pages:**
- Gift card balance page
- Redemption form
- Purchase history
- Account settings

**Vulnerability:** Redemption endpoint checks balance and deducts in separate operations with no locking. Concurrent requests can both pass the balance check before either deducts.

**Objectives:**
1. View your gift card balance ($100)
2. Redeem $100 normally, observe balance update
3. Reset and attempt concurrent redemption (send 2+ requests simultaneously)
4. Achieve a negative balance or double-spend
5. Identify the exact TOCTOU window

---

## 4. Blue Team Labs

### 4.1 Workspace Differences

Blue team workspace replaces the Target App panel with an **Investigation Dashboard:**

```
┌──────────────────┬───────────────────────────────────────┐
│ MISSION          │ INVESTIGATION DASHBOARD               │
│                  │                                       │
│ Scenario         │ ┌─────────────────────────────┐      │
│ Objectives       │ │ Alert / Log Viewer          │      │
│ Evidence log     │ │ (searchable, filterable,     │      │
│                  │ │  multi-source)               │      │
│ Hints            │ └─────────────────────────────┘      │
│                  │                                       │
│                  │ ┌─────────────────────────────┐      │
│                  │ │ Timeline Builder             │      │
│                  │ │ (drag events, annotate)      │      │
│                  │ └─────────────────────────────┘      │
│                  │                                       │
│                  │ ┌───────────┬─────────────────┐      │
│                  │ │ Evidence  │ Network Map /    │      │
│                  │ │ Collector │ Host Inspector   │      │
│                  │ └───────────┴─────────────────┘      │
└──────────────────┴───────────────────────────────────────┘
```

**Blue team workspace components:**

| Component | Purpose |
|-----------|---------|
| `AlertQueue` | SIEM-like alert list with severity, timestamp, source. User classifies each. |
| `LogViewer` | Multi-source log viewer with search, regex filter, source toggle, timeline correlation. Supports JSON, syslog, CEF, Apache/nginx formats. |
| `TimelineBuilder` | Drag events onto a visual timeline. Same component as the IR Timeline tool, embedded in the workspace. |
| `EvidenceCollector` | Capture findings with annotations. Exported as an IR report on completion. |
| `HostInspector` | For containment lab — shows host list, process trees, network connections. Actions: isolate, kill process, block IP. |
| `PlaybookEditor` | For SOAR lab — visual flowchart builder for automation logic. Nodes: trigger, condition, action, enrichment. |

### 4.2 Blue Team Lab Details

**BLUE-01: Alert Triage — "Is This Real?"**
- Scenario: Night shift, 5 alerts fired. Classify each as true positive, false positive, or misconfigured rule.
- Data: SIEM alert JSON with varying severity, context, and indicators.
- Objectives: Correctly classify all 5 alerts, escalate the real incident, document reasoning.
- Teaches: Alert fatigue management, indicator analysis, escalation criteria.

**BLUE-02: Investigate the ShopStack Breach**
- Scenario: ShopStack reports stolen sessions. You have access logs, WAF logs, and CloudTrail.
- Data: Generated from the red team XSS lab — same attack, defender's view.
- Objectives: Find the XSS entry point in logs, identify affected users, build incident timeline, determine blast radius, write containment steps.
- Teaches: Log correlation, timeline construction, incident scoping.
- **Unlocked by completing RED-01 (ShopStack XSS).**

**BLUE-03: Phishing Campaign Analysis**
- Scenario: Targeted phishing bypassed the email gateway. Analyze the campaign.
- Data: Email headers (DKIM/SPF/DMARC results), message body with encoded payload, delivery logs showing which users received it, click tracking data.
- Objectives: Decode the phishing payload, identify the infrastructure, determine who clicked, assess credential compromise.
- Teaches: Email header analysis, payload deobfuscation, blast radius assessment.

**BLUE-04: Signal in the Noise**
- Scenario: 10,000 log lines from 4 sources (auth, web, DNS, firewall). One attacker.
- Data: Mostly normal traffic with injected attacker activity across multiple sources.
- Objectives: Identify the attacker's IP, trace their actions across all log sources, determine what they accessed.
- Teaches: Log correlation, pattern recognition, multi-source analysis.

**BLUE-05: Active Threat Containment**
- Scenario: Malware spreading laterally. 15-minute countdown. Stop it before it reaches the domain controller.
- Data: Live-updating host list, process trees, network connections (simulated real-time via Worker polling).
- Objectives: Identify patient zero, trace lateral movement path, isolate infected hosts (correct ones), verify containment.
- Teaches: Containment under pressure, lateral movement analysis, decision-making.
- **Has a real-time countdown.** If you isolate the wrong host or miss one, the malware reaches the DC and you fail.

**BLUE-06: Build the Playbook (SOAR)**
- Scenario: Your team gets 200 phishing alerts per week. Design a SOAR playbook to automate triage.
- Data: A stream of sample phishing alerts (mix of real and benign).
- Objectives: Build a playbook using the visual editor (trigger → enrich → decide → act). Then test it against the alert stream. Measure accuracy (true positive rate, false positive rate).
- Teaches: SOAR automation design, enrichment integration, threshold tuning.
- **This is the signature lab.** Shadoe's unique background makes this the lab nobody else could build.

---

## 5. Progress & Sync System

### 5.1 Local Storage (Default)

All progress is stored in `localStorage` under the key `pf-labs`:

```javascript
{
  version: 1,
  profile: {
    alias: "Anonymous Operator",  // user can customize
    level: 3,
    xp: 450,
    startedAt: "2026-03-22T00:00:00Z",
  },
  labs: {
    "red-xss-shopstack": {
      status: "completed",        // "not_started" | "in_progress" | "completed"
      score: 95,
      xpEarned: 90,              // base 100 minus hint costs
      hintsUsed: [0],            // indices of revealed hints
      timeElapsed: 154,          // seconds
      completedAt: "2026-03-22T01:00:00Z",
      objectivesCompleted: ["recon", "inject", "execute", "exfiltrate"],
    },
    // ...
  },
  skills: {
    "injection-reflected-xss": true,
    "injection-stored-xss": true,
    // ...
  }
}
```

### 5.2 Forge Key — Encrypted Cloud Sync

Instead of user-chosen passphrases (which collide), the system generates a **Forge Key** — a unique, memorable identifier that serves as both storage address and encryption seed.

**Forge Key format:** `{word}-{word}-{4-char hex}` (e.g., `ember-cascade-7x9k`)
- 2048-word curated list × 2048 × 65,536 hex suffix = **274 billion combinations**
- Birthday paradox collision at 1 million users: **0.0000018%** — effectively zero

**First-time sync flow:**
1. User clicks "Sync Progress"
2. Client generates a Forge Key using `crypto.getRandomValues()`
3. User is shown the key with instructions to write it down
4. Client derives a **storage key** from the first two words via SHA-256 hash (KV lookup key)
5. Client derives an **encryption key** from the full Forge Key via PBKDF2 (100,000 iterations, SHA-256)
6. Client encrypts progress JSON with AES-256-GCM using the encryption key
7. Client sends `{ storageKey, ciphertext, iv }` to the sync Worker
8. Worker stores in KV under the storage key

**Restore flow:**
1. User enters their Forge Key on any device
2. Client derives the storage key from first two words
3. Worker returns the ciphertext
4. Client derives the encryption key from the full Forge Key and decrypts locally

**The Worker never sees the Forge Key, the encryption key, or the plaintext progress.** It only stores and retrieves opaque ciphertext addressed by a hash.

**Sync Worker endpoints:**
```
POST /save   { storageKey, ciphertext, iv }
POST /load   { storageKey }  →  { ciphertext, iv }
```

**Brand messaging:** "Your Forge Key is your identity. No email. No password. No account. Write it down — it's the only way back. We can't see your progress. We can't recover your key. That's not a limitation. That's the design."

### 5.3 Gamification

**XP & Levels:**

| Level | Title | XP Required |
|-------|-------|-------------|
| 1 | Script Kiddie | 0 |
| 2 | Apprentice | 100 |
| 3 | Analyst | 300 |
| 4 | Operator | 600 |
| 5 | Specialist | 1000 |
| 6 | Expert | 1500 |
| 7 | Elite | 2200 |
| 8 | Architect | 3000 |
| 9 | Adversary | 4000 |
| 10 | Shadow | 5000 |

**XP Bonuses:**
- No hints used: +25% XP
- Completed in under estimated time: +15% XP
- All objectives completed (including bonus): +10% XP

**Skill Trees:**
Two trees (red and blue), each with branches representing vulnerability/skill categories. Completing a lab fills in the corresponding node. Some nodes have prerequisites (e.g., DOM XSS requires Reflected XSS).

**Completion Certificates:**
Generated as client-side SVG images. Include: lab name, completion date, score, time, and a verification hash. The hash is `HMAC-SHA256(labId + score + completedAt, siteSecret)` — anyone can verify the certificate is authentic by checking the hash against the public verification endpoint.

---

## 6. UI/UX Specification

### 6.1 Labs Hub (`/labs/`)

- Hero section: "Attack it. Investigate it. Fix it."
- Profile bar: alias, level, XP progress bar, labs completed, sync button
- Track selector: Red Team / Blue Team toggle with progress bars
- Skill tree: horizontal scrollable branches with nodes
- Lab cards: grid layout, each with target app branding, difficulty, tags, XP, CWE/OWASP references

### 6.2 Red Team Workspace (`/labs/red/[lab-slug]/`)

Three-panel layout filling the viewport below a compact top bar:

**Top bar (48px):** Penumbra Forge brand, back arrow, lab title, difficulty badge, timer, reset button.

**Left panel — Mission (320px, resizable):**
- Tabs: Mission | Source | Hints
- Mission: scenario narrative, objectives with step checkmarks, security context (CWE, MITRE ATT&CK)
- Source: syntax-highlighted vulnerable code with line numbers, vulnerable line highlighted in red, fix shown after completion
- Hints: progressive reveals with XP cost per hint

**Center panel — Target App (flex, fills remaining width):**
- Fake browser chrome: colored dots, URL bar with lock icon, navigation
- Full target application rendered inside a sandboxed iframe
- The target app looks and behaves like a real website

**Right panel — Inspector (380px, resizable):**
- Tabs: HTTP | Server Logs | Console
- HTTP: request/response viewer updating in real-time, vulnerable reflection highlighted
- Server Logs: timestamped entries with level (INFO/WARN/ERROR/CRITICAL), populated as user interacts
- Console: terminal with $ prompt, commands for additional interaction

### 6.3 Blue Team Workspace (`/labs/blue/[lab-slug]/`)

**Left panel — Mission (same as red team)**

**Center panel — Investigation Dashboard (fills remaining width):**
- Top half: Log Viewer or Alert Queue (depending on lab type)
  - Multi-source toggle (auth, web, DNS, firewall, etc.)
  - Search bar with regex support
  - Severity filter
  - Timestamp range selector
  - Log entries with syntax highlighting per format
- Bottom half: Timeline Builder
  - Visual timeline with draggable events
  - Add event button
  - Export to JSON/PDF

**Right panel — Evidence & Tools (380px, resizable):**
- Tabs: Evidence | Network | Actions
- Evidence: captured findings with annotations, exported as IR report
- Network: host map or topology (for containment lab)
- Actions: available response actions (isolate host, block IP, disable account)

### 6.4 Completion Flow

When all objectives are met:
1. Trophy overlay with stats (time, score, hints, XP earned)
2. Level-up animation if threshold crossed
3. "View Debrief" button → scrollable debrief panel with vulnerability explanation, fix code, real-world references, MITRE ATT&CK mapping
4. "Unlock Blue Team" button (if applicable) → navigates to the corresponding blue team lab
5. "Next Lab" button → next lab in the skill tree

### 6.5 Mobile Considerations

The three-panel layout is desktop-first. On mobile (< 900px):
- Panels stack vertically: Mission (collapsible) → Target/Dashboard → Inspector (collapsible)
- Bottom tab bar for switching between panels
- Target app renders at full width
- Functional but optimized for desktop (this is consistent with the pentest tool genre)

---

## 7. Implementation Plan

### Phase 1: Foundation (Engine + First Red Lab)

**Goal:** Lab engine framework + one perfect red team lab (ShopStack XSS).

1. Lab engine core (`LabEngine`, `ObjectiveTracker`, `ProgressStore`, `XpSystem`)
2. Workspace layout components (`LabWorkspace`, `TargetFrame`, `HttpInspector`, `ServerLogs`, `LabConsole`)
3. Labs hub page (`/labs/`) with profile bar, track selector, skill tree, lab cards
4. ShopStack target app (Worker — full e-commerce UI with vulnerable search)
5. RED-01 lab definition (config, objectives, hints, debrief)
6. Completion flow (trophy overlay, debrief panel, XP calculation)
7. Progress persistence (localStorage)

**Deliverable:** One complete, polished red team lab that sets the quality bar.

### Phase 2: Blue Team + Sync

**Goal:** First blue team lab + encrypted sync system.

1. Blue team workspace components (`AlertQueue`, `LogViewer`, `TimelineBuilder`, `EvidenceCollector`)
2. Blue team Worker (`lab-blue`) with scenario data for BLUE-01
3. BLUE-01 lab definition (Alert Triage)
4. Red→Blue unlock mechanism
5. Sync Worker (`lab-sync`) with KV storage
6. Client-side encryption (PBKDF2 + AES-256-GCM)
7. Sync UI (passphrase modal, save/restore flow)

**Deliverable:** One complete blue team lab + cross-device sync.

### Phase 3: Remaining Red Labs

**Goal:** Ship the remaining 4 red team labs.

1. VaultBank Worker + RED-02 (SQL Injection) — includes sql.js integration
2. CloudSnap Worker + RED-03 (SSRF)
3. DevPortal Worker + RED-04 (JWT)
4. GiftRush Worker + RED-05 (Race Condition)

**Deliverable:** All 5 red team labs live.

### Phase 4: Remaining Blue Labs + SOAR

**Goal:** Ship the remaining 5 blue team labs including the signature SOAR lab.

1. BLUE-02 (Investigate ShopStack Breach) — uses generated logs from RED-01
2. BLUE-03 (Phishing Analysis)
3. BLUE-04 (Log Analysis — Signal in the Noise)
4. BLUE-05 (Active Threat Containment) — real-time countdown mechanic
5. BLUE-06 (SOAR Playbook Design) — visual playbook editor + alert stream testing

**Deliverable:** Full 11-lab platform.

### Phase 5: Polish + Certificates

**Goal:** Gamification polish, certificates, and public launch.

1. Certificate generation (SVG with verification hash)
2. Skill tree animations and progression effects
3. Level-up celebrations
4. SEO optimization for lab pages
5. Performance optimization (lazy loading, code splitting)
6. Public announcement content (blog post, social, HN submission)

**Deliverable:** Launch-ready platform.

---

## 8. Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| SQL database for SQLi lab | sql.js (SQLite WASM) in browser | Per-user isolation, no shared state, real SQL syntax |
| Target app rendering | Sandboxed iframe to Worker | Origin isolation, real HTTP, can't escape sandbox |
| Progress storage | localStorage + optional encrypted KV sync | Zero friction default, privacy-first sync option |
| Lab definition format | JavaScript config objects | Easy to author, no build step for new labs, full expressiveness |
| Workspace layout | CSS Grid with resizable panels | Native performance, no framework dependency |
| Syntax highlighting | Minimal hand-rolled highlighter | Avoids large library dependency, consistent with site aesthetic |
| HTTP interception | Service Worker or postMessage proxy | Captures real traffic between iframe and Worker |
| Worker deployment | One Worker per red team lab, one shared blue team Worker | Isolation between labs, simple deployment |
| Gamification state | Client-side only (localStorage / sync) | No backend auth, no account management, privacy-first |

---

## 9. Content Guidelines

### Lab Narrative Voice
- Second person, present tense: "You've been hired to pentest ShopStack's search feature."
- Professional but not dry. Respect the reader's intelligence.
- No hand-holding — guide the approach, not the exact keystrokes.
- Hints are progressive: direction → approach → solution.

### Debrief Content
Every lab debrief includes:
1. **What happened** — technical explanation of the vulnerability
2. **The vulnerable code** — exact lines with highlighting
3. **The fix** — corrected code with explanation
4. **Real-world impact** — named breach or CVE that used this technique
5. **MITRE ATT&CK mapping** — technique ID and link
6. **OWASP reference** — Top 10 category
7. **How to find this in the wild** — what to look for during real pentests/code review
8. **Further reading** — 2-3 authoritative links

### Blue Team Content
Blue team debriefs additionally include:
1. **Detection logic** — what SIEM rule or alert would catch this
2. **Response playbook** — step-by-step IR procedure
3. **Automation opportunity** — what parts could be automated via SOAR
4. **Metrics** — mean time to detect, contain, and remediate
