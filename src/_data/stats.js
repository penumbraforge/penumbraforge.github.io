/* Computed site stats — derived from real sources so they can't drift.
   tools.json is the tool catalog; mcp-handler.js is the same module the
   MCP worker serves, so the "callable over MCP" count is the live truth. */
import { createRequire } from 'node:module';
import { listTools } from '../js/mcp-handler.js';

const require = createRequire(import.meta.url);
const tools = require('./tools.json');

export default {
  liveTools: tools.filter(t => t.status === 'live').length,
  browserOnlyTools: tools.filter(t => t.badge === 'local' && !t.usesAiEngine).length,
  mcpTools: listTools().length,
  urlInvocableTools: tools.filter(t => t.status === 'live' && t.invoke).length
};
