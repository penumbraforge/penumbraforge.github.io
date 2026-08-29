#!/usr/bin/env node
/* Penumbra Forge — local MCP server (stdio).
   The MCP process runs on this machine. Net-labelled tools still contact the
   destinations disclosed by tools/list; other tools make no outbound request.
   Connect (Claude Code): claude mcp add penumbra -- node /path/to/local.mjs
   or in a client config: { "command": "node", "args": ["/path/to/local.mjs"] } */
import { handleRpc } from '../../src/js/mcp-handler.js';

let buf = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', async (chunk) => {
  buf += chunk;
  let idx;
  while ((idx = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, idx).trim();
    buf = buf.slice(idx + 1);
    if (!line) continue;
    let msg;
    try { msg = JSON.parse(line); }
    catch (e) { process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n'); continue; }
    const res = await handleRpc(msg);
    if (res !== null) process.stdout.write((Array.isArray(res) ? res.map(r => JSON.stringify(r)).join('\n') : JSON.stringify(res)) + '\n');
  }
});
process.stdin.on('end', () => process.exit(0));
