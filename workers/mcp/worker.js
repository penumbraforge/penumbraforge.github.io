/* Penumbra Forge — remote MCP server (Cloudflare Worker, streamable HTTP).
   Stateless: exposes the tools-lib functions to any MCP client over HTTP.
   Deploy: cd workers/mcp && npx wrangler deploy
   Connect (e.g. Claude Code): claude mcp add --transport http penumbra https://mcp.penumbraforge.com */
import { handleRpc, SUPPORTED_PROTOCOLS } from '../../src/js/mcp-handler.js';

function allowedOrigin(request, env) {
  const origin = request.headers.get('Origin');
  return !origin || origin === (env.ALLOWED_ORIGIN || 'https://penumbraforge.com');
}

function corsHeaders(request, env) {
  const origin = request.headers.get('Origin');
  const headers = {
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Authorization',
    'Access-Control-Expose-Headers': 'Mcp-Session-Id',
    'Vary': 'Origin'
  };
  if (origin && allowedOrigin(request, env)) headers['Access-Control-Allow-Origin'] = origin;
  return headers;
}

function rpcHttpError(message, status, headers) {
  return Response.json(
    { jsonrpc: '2.0', id: null, error: { code: -32600, message } },
    { status, headers }
  );
}

export default {
  async fetch(request, env) {
    const headers = corsHeaders(request, env);
    if (!allowedOrigin(request, env)) return rpcHttpError('Origin not allowed', 403, headers);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers });
    if (request.method === 'GET') {
      return new Response('Method Not Allowed', { status: 405, headers: { ...headers, 'Allow': 'POST, OPTIONS' } });
    }
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405, headers: { ...headers, 'Allow': 'POST, OPTIONS' } });
    }

    // Per-IP rate limit — generous (agents burst), but caps abuse.
    if (env.RL_MCP) {
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const { success } = await env.RL_MCP.limit({ key: ip });
      if (!success) {
        return Response.json(
          { jsonrpc: '2.0', id: null, error: { code: -32000, message: 'Rate limited. Try again in a minute.' } },
          { status: 429, headers: { ...headers, 'Retry-After': '60' } }
        );
      }
    }

    const contentType = (request.headers.get('Content-Type') || '').toLowerCase();
    if (!contentType.startsWith('application/json')) {
      return rpcHttpError('Content-Type must be application/json', 415, headers);
    }
    const accept = (request.headers.get('Accept') || '').toLowerCase();
    if (!accept.includes('application/json') || !accept.includes('text/event-stream')) {
      return rpcHttpError('Accept must list application/json and text/event-stream', 406, headers);
    }

    let body;
    try { body = await request.json(); }
    catch (e) {
      return Response.json(
        { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } },
        { status: 400, headers }
      );
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return rpcHttpError('A single JSON-RPC message is required; batches are not supported', 400, headers);
    }

    const suppliedVersion = request.headers.get('Mcp-Protocol-Version');
    const effectiveVersion = suppliedVersion || (body.method === 'initialize' ? null : '2025-03-26');
    if (effectiveVersion && !SUPPORTED_PROTOCOLS.includes(effectiveVersion)) {
      return rpcHttpError('Unsupported Mcp-Protocol-Version', 400, headers);
    }

    const res = await handleRpc(body);
    if (res === null) return new Response(null, { status: 202, headers });
    return Response.json(res, { headers });
  }
};
