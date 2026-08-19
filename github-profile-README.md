### Hey, I'm Shadoe

Information security engineer on a CIRT, and the person behind **Penumbra Forge LLC** — a one-person company building developer and security tools that run locally.

Most of what's here is early. I'd rather say that up front than oversell it. If you try something and it breaks, an issue is genuinely useful to me.

---

#### Projects

**[Gate](https://github.com/penumbraforge/gate)** — *experimental* — A pre-commit hook that scans staged changes for credentials and can redact what it finds. Pattern-based detection across several languages, with optional verification for a few provider types. Expect false positives and misses; it's a safety net, not a guarantee. Runs locally.

**[vexes](https://github.com/penumbraforge/vexes)** — *experimental* — A dependency scanner covering several ecosystems. It flags things worth a second look: install scripts, unexpected network or filesystem access, names close to popular packages. These are heuristics, not verdicts, and it hasn't been proven against real-world attacks yet. No runtime dependencies.

**[mcp-librarian](https://github.com/penumbraforge/mcp-librarian)** — *experimental* — An MCP server that gives coding agents a local skill library. BM25 search over skills, Ed25519 signing on write and integrity checks on load, progressive disclosure to keep context small. Works with Claude Code and other MCP clients. No runtime dependencies.

**[penumbraforge.com](https://penumbraforge.com)** — Developer and security tools that run in the browser. There's also a machine-readable index and an MCP server, so coding agents can use the deterministic ones directly. No accounts, and the tools don't send your input anywhere unless the tool's job requires it (those are labelled).

---

#### In progress

**[Umbra](https://penumbraforge.com/umbra/)** — A local-first AI studio (GUI + TUI) for running and inspecting language models on your own hardware. Being built against an NVIDIA DGX Spark. Early development, not usable yet.

Also working on: expanding Gate's rules and SARIF output, broadening vexes' ecosystem coverage and cutting down its false positives, and adding skill packs for mcp-librarian.

---

#### Elsewhere

- **Site:** [penumbraforge.com](https://penumbraforge.com)
- **LinkedIn:** [shadoe-myers](https://www.linkedin.com/in/shadoe-myers)
- **Location:** Arizona
