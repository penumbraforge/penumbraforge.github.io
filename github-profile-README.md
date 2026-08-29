### Hey, I'm Shadoe

Information security engineer on a CIRT, and the person behind **Penumbra Forge LLC** — a one-person company building developer and security tools with local-first designs and explicit network boundaries.

Most of what's here is early. I'd rather say that up front than oversell it. If you try something and it breaks, an issue is genuinely useful to me.

---

#### Projects

**[Gate](https://github.com/penumbraforge/gate)** — *experimental* — A pre-commit hook that scans staged changes for credentials and can attempt bounded rewrites for supported source forms. Pattern-based detection across several languages, with optional verification for a few provider types. Expect false positives and misses; it's a safety net, not a guarantee. Runs locally by default; requested verification and update paths use the network.

**[vexes](https://github.com/penumbraforge/vexes)** — *experimental* — A local CLI that matches dependency coordinates to OSV across ten ecosystems and, for npm/PyPI, surfaces bounded source and registry heuristics. Findings may be incomplete and are not safety verdicts. Zero external runtime npm dependencies; scans still contact documented upstream services.

**[mcp-librarian](https://github.com/penumbraforge/mcp-librarian)** — *experimental* — An MCP server that gives coding agents a local skill library. BM25 search, Ed25519 signing on supported writes, and integrity status recorded during indexing. Current load responses do not enforce refusal of tampered content, so clients must check status. No external runtime dependencies.

**[penumbraforge.com](https://penumbraforge.com)** — Developer and security tools with browser, edge, direct-network, and selectable AI routes labelled on each page. There's also a machine-readable index and an MCP server for non-model utility functions. No accounts; check a tool's disclosure before entering sensitive data.

---

#### In progress

**[Umbra](https://penumbraforge.com/umbra/)** — A local-first AI studio (GUI + TUI) for running and inspecting language models on your own hardware. Being built against an NVIDIA DGX Spark. Early development, not usable yet.

Also working on: expanding Gate's rules and SARIF output, broadening vexes' ecosystem coverage and cutting down its false positives, and adding skill packs for mcp-librarian.

---

#### Elsewhere

- **Site:** [penumbraforge.com](https://penumbraforge.com)
- **LinkedIn:** [shadoe-myers](https://www.linkedin.com/in/shadoe-myers)
- **Location:** Arizona
