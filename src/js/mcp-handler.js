/* ============================================================
   Penumbra Forge — MCP request handler (transport-agnostic)
   Implements MCP over JSON-RPC 2.0 on top of tools-lib. Used by
   both the Cloudflare Worker (remote HTTP) and the local stdio
   server. Pure + isomorphic: give it a parsed JSON-RPC message,
   get back a response object (or null for notifications).
   ============================================================ */
import { TOOLS as PURE_TOOLS } from './tools-lib.js';
import { NET_TOOLS } from './tools-net.js';

const TOOLS = { ...PURE_TOOLS, ...NET_TOOLS };

const SERVER = { name: 'penumbra-forge-tools', version: '1.0.0' };
const PROTOCOL = '2025-06-18';

function inputSchema(schema) {
  const props = {}, required = [];
  const primary = ['text', 'token', 'input', 'value', 'uuid', 'key'];
  for (const k in schema) {
    props[k] = { type: 'string', description: String(schema[k]) };
    if (primary.includes(k)) required.push(k);
  }
  return { type: 'object', properties: props, required };
}

function listTools() {
  return Object.keys(TOOLS).map(name => ({
    name,
    description: TOOLS[name].description,
    inputSchema: inputSchema(TOOLS[name].schema)
  }));
}

function ok(id, result) { return { jsonrpc: '2.0', id, result }; }
function err(id, code, message) { return { jsonrpc: '2.0', id, error: { code, message } }; }

async function handleOne(msg) {
  if (!msg || msg.jsonrpc !== '2.0') return err(msg && msg.id != null ? msg.id : null, -32600, 'Invalid Request');
  const { id, method, params } = msg;
  const isNotification = id === undefined || id === null;

  switch (method) {
    case 'initialize':
      return ok(id, { protocolVersion: PROTOCOL, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER,
        instructions: 'Privacy-first client-side dev & security tools. Call tools/list, then tools/call.' });
    case 'notifications/initialized':
    case 'notifications/cancelled':
      return null; // notifications get no response
    case 'ping':
      return ok(id, {});
    case 'tools/list':
      return ok(id, { tools: listTools() });
    case 'tools/call': {
      const name = params && params.name;
      const tool = TOOLS[name];
      if (!tool) return ok(id, { content: [{ type: 'text', text: 'Unknown tool: ' + name }], isError: true });
      try {
        const out = await tool.run((params && params.arguments) || {});
        return ok(id, { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] });
      } catch (e) {
        return ok(id, { content: [{ type: 'text', text: 'Error: ' + e.message }], isError: true });
      }
    }
    default:
      if (isNotification) return null;
      return err(id, -32601, 'Method not found: ' + method);
  }
}

export async function handleRpc(payload) {
  if (Array.isArray(payload)) {
    const out = [];
    for (const m of payload) { const r = await handleOne(m); if (r) out.push(r); }
    return out.length ? out : null;
  }
  return handleOne(payload);
}

export { listTools, SERVER, PROTOCOL };
