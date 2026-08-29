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
const NETWORK_TOOL_NAMES = new Set(Object.keys(NET_TOOLS));
const NETWORK_DESCRIPTIONS = {
  breach_check: 'Check Pwned Passwords using k-anonymity. The MCP server receives the password argument, hashes it there, and sends the first five SHA-1 hex characters to the HIBP range API.',
  security_headers: 'Fetch a public HTTPS URL from the MCP server and run a fixed eight-response-header checklist. This is not an overall security grade. The destination and validated redirect targets observe server-side requests.',
  dns: 'Send the domain and record type from the MCP server to Cloudflare DNS-over-HTTPS and return the answers.',
  http_probe: 'Fetch a public HTTPS URL from the MCP server, follow validated HTTPS redirects, and return status and response headers. Each destination can observe the request.'
};

const SERVER = { name: 'penumbra-forge-tools', version: '1.0.0' };
const PROTOCOL = '2025-06-18';
const SUPPORTED_PROTOCOLS = [PROTOCOL, '2025-03-26'];

const REQUIRED_FIELDS = {
  hash: ['text'],
  hmac: ['text', 'key'],
  base64: ['text'],
  base64url: ['text'],
  hex: ['text'],
  url_encode: ['text'],
  jwt_decode: ['token'],
  uuid_inspect: ['uuid'],
  entropy: ['text'],
  epoch: ['value'],
  json: ['text'],
  color: ['input'],
  cidr: ['input'],
  case_convert: ['text'],
  slugify: ['text'],
  jwt_sign: ['text', 'key'],
  jwt_verify: ['token', 'key'],
  totp: ['key'],
  sri: ['text'],
  gzip: ['text'],
  text_diff: ['text', 'b'],
  csv_to_json: ['text'],
  json_to_csv: ['text'],
  breach_check: ['password'],
  security_headers: ['url'],
  dns: ['name'],
  http_probe: ['url']
};

function inputProperty(description) {
  const text = String(description);
  if (/^(?:bool|boolean)$/i.test(text)) return { type: 'boolean', description: text };
  if (/^(?:number|seconds\b|default\s+\d+)/i.test(text)) return { type: 'number', description: text };
  const values = text.split('|').map(value => value.trim());
  if (values.length > 1 && values.every(value => value && !/\s/.test(value))) {
    return { type: 'string', enum: values, description: text };
  }
  return { type: 'string', description: text };
}

function inputSchema(schema, name) {
  const props = {};
  for (const k in schema) {
    props[k] = inputProperty(schema[k]);
  }
  return { type: 'object', properties: props, required: REQUIRED_FIELDS[name] || [], additionalProperties: false };
}

function toolRoute(name) {
  return NETWORK_TOOL_NAMES.has(name) ? 'outbound-network' : 'mcp-process';
}

function listTools() {
  return Object.keys(TOOLS).map(name => ({
    name,
    description: NETWORK_TOOL_NAMES.has(name)
      ? NETWORK_DESCRIPTIONS[name]
      : TOOLS[name].description + ' Data route: computed inside this MCP server process with no tool-initiated outbound request. A remote MCP host still receives the call arguments.',
    inputSchema: inputSchema(TOOLS[name].schema, name)
  }));
}

function ok(id, result) { return { jsonrpc: '2.0', id, result }; }
function err(id, code, message) { return { jsonrpc: '2.0', id, error: { code, message } }; }

async function handleOne(msg) {
  if (!msg || msg.jsonrpc !== '2.0') return err(msg && msg.id != null ? msg.id : null, -32600, 'Invalid Request');
  if (!Object.prototype.hasOwnProperty.call(msg, 'method') &&
      (Object.prototype.hasOwnProperty.call(msg, 'result') || Object.prototype.hasOwnProperty.call(msg, 'error'))) return null;
  const { id, method, params } = msg;
  const isNotification = id === undefined;

  switch (method) {
    case 'initialize': {
      if (isNotification) return null;
      const requested = params && params.protocolVersion;
      const selected = SUPPORTED_PROTOCOLS.includes(requested) ? requested : PROTOCOL;
      return ok(id, { protocolVersion: selected, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER,
        instructions: 'Tools run in the MCP server process, not automatically in your browser. With the remote HTTP endpoint, arguments are sent to the hosted server. With local stdio, arguments stay on that machine unless a tool description says it makes an outbound request. Call tools/list and read each data-route disclosure before tools/call.' });
    }
    case 'notifications/initialized':
    case 'notifications/cancelled':
      return null; // notifications get no response
    case 'ping':
      return isNotification ? null : ok(id, {});
    case 'tools/list':
      return isNotification ? null : ok(id, { tools: listTools() });
    case 'tools/call': {
      const name = params && params.name;
      const tool = TOOLS[name];
      if (!tool) return isNotification ? null : ok(id, { content: [{ type: 'text', text: 'Unknown tool: ' + name }], isError: true });
      try {
        const out = await tool.run((params && params.arguments) || {});
        return isNotification ? null : ok(id, { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] });
      } catch (e) {
        return isNotification ? null : ok(id, { content: [{ type: 'text', text: 'Error: ' + e.message }], isError: true });
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

export { listTools, toolRoute, SERVER, PROTOCOL, SUPPORTED_PROTOCOLS };
