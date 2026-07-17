/* Penumbra Forge — remote MCP server (Cloudflare Worker, streamable HTTP).
   Stateless: exposes the tools-lib functions to any MCP client over HTTP.
   Deploy: cd workers/mcp && npx wrangler deploy
   Connect (e.g. Claude Code): claude mcp add --transport http penumbra https://mcp.penumbraforge.com */
import { handleRpc, listTools, SERVER, PROTOCOL } from '../../src/js/mcp-handler.js';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Authorization',
  'Access-Control-Expose-Headers': 'Mcp-Session-Id'
};

export default {
  async fetch(request) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

    if (request.method === 'GET') {
      return Response.json({
        server: SERVER, protocol: PROTOCOL, transport: 'streamable-http',
        description: 'Penumbra Forge MCP — privacy-first dev & security tools for AI agents.',
        tools: listTools().map(t => ({ name: t.name, description: t.description })),
        usage: 'POST JSON-RPC 2.0 (initialize, tools/list, tools/call) to this URL.'
      }, { headers: CORS });
    }

    if (request.method === 'POST') {
      let body;
      try { body = await request.json(); }
      catch (e) { return Response.json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }, { status: 400, headers: CORS }); }
      const res = await handleRpc(body);
      if (res === null) return new Response(null, { status: 202, headers: CORS }); // notification
      return Response.json(res, { headers: { ...CORS } });
    }

    return new Response('Method Not Allowed', { status: 405, headers: CORS });
  }
};
