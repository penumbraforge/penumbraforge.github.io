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
  async fetch(request, env) {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

    // Per-IP rate limit — generous (agents burst), but caps abuse.
    if (env.RL_MCP) {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const { success } = await env.RL_MCP.limit({ key: ip });
      if (!success) {
        return Response.json(
          { jsonrpc: '2.0', id: null, error: { code: -32000, message: 'Rate limited. Try again in a minute.' } },
          { status: 429, headers: { ...CORS, 'Retry-After': '60' } }
        );
      }
    }

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
