// Spark Terminal MCP - zero-dependency MCP server for Gemini Spark custom apps.
// Transport: Streamable HTTP (JSON responses) at /mcp
// Auth: OAuth 2.1 with Dynamic Client Registration + PKCE S256 (stateless, HMAC-signed)
'use strict';
const http = require('http');
const crypto = require('crypto');
const { exec } = require('child_process');
const { URL, URLSearchParams } = require('url');

const PORT = process.env.PORT || 10000;
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const CONSENT_PASSWORD = process.env.CONSENT_PASSWORD || '';
const SERVER_NAME = 'spark-terminal-mcp';
const VERSION = '0.1.0';

function log(...a) { console.log(new Date().toISOString(), ...a); }

// ---------- signed tokens ----------
const b64u = (b) => Buffer.from(b).toString('base64url');
function sign(payload) {
  const body = b64u(JSON.stringify(payload));
  const mac = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + mac;
}
function verify(token, type) {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const [body, mac] = token.split('.');
  const exp = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (!mac || mac.length !== exp.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(exp))) return null;
  let p; try { p = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch { return null; }
  if (type && p.t !== type) return null;
  if (p.exp && Date.now() / 1000 > p.exp) return null;
  return p;
}
const now = () => Math.floor(Date.now() / 1000);

// ---------- helpers ----------
function baseUrl(req) {
  if (process.env.PUBLIC_URL) return process.env.PUBLIC_URL.replace(/\/$/, '');
  if (process.env.RENDER_EXTERNAL_URL) return process.env.RENDER_EXTERNAL_URL.replace(/\/$/, '');
  const proto = (req.headers['x-forwarded-proto'] || 'http').split(',')[0];
  return `${proto}://${req.headers.host}`;
}
function send(res, status, obj, headers = {}) {
  const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': typeof obj === 'string' ? 'text/html; charset=utf-8' : 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Expose-Headers': 'WWW-Authenticate, Mcp-Session-Id',
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve) => {
    let d = '';
    req.on('data', (c) => { d += c; if (d.length > 1e6) req.destroy(); });
    req.on('end', () => resolve(d));
  });
}
function parseBody(req, raw) {
  const ct = req.headers['content-type'] || '';
  if (ct.includes('application/json')) { try { return JSON.parse(raw || '{}'); } catch { return null; } }
  return Object.fromEntries(new URLSearchParams(raw));
}
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ---------- OAuth metadata ----------
function protectedResource(req) {
  const b = baseUrl(req);
  return { resource: b + '/mcp', authorization_servers: [b], bearer_methods_supported: ['header'], scopes_supported: ['mcp'] };
}
function authServer(req) {
  const b = baseUrl(req);
  return {
    issuer: b,
    authorization_endpoint: b + '/authorize',
    token_endpoint: b + '/token',
    registration_endpoint: b + '/register',
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
    scopes_supported: ['mcp'],
  };
}

// ---------- OAuth endpoints ----------
function register(req, res, body) {
  if (!body) return send(res, 400, { error: 'invalid_client_metadata' });
  const uris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
  if (!uris.length || !uris.every((u) => /^https:\/\//.test(u) || /^http:\/\/(localhost|127\.0\.0\.1)/.test(u))) {
    return send(res, 400, { error: 'invalid_redirect_uri' });
  }
  const method = body.token_endpoint_auth_method || 'client_secret_basic';
  const client_id = sign({ t: 'client', r: uris, m: method, n: crypto.randomBytes(6).toString('hex') });
  const out = {
    client_id, client_id_issued_at: now(), redirect_uris: uris,
    token_endpoint_auth_method: method,
    grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
    client_name: body.client_name || 'client', scope: 'mcp',
  };
  if (method !== 'none') { out.client_secret = crypto.createHmac('sha256', SECRET).update('cs:' + client_id).digest('hex'); out.client_secret_expires_at = 0; }
  log('[register]', body.client_name, uris.join(','), method);
  send(res, 201, out);
}

function consentPage(q, error) {
  const hidden = ['client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method', 'scope', 'resource', 'response_type']
    .map((k) => `<input type="hidden" name="${k}" value="${esc(q[k])}">`).join('');
  return `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize Terminal MCP</title>
<style>body{font-family:system-ui;max-width:420px;margin:60px auto;padding:0 16px}input[type=password]{width:100%;padding:10px;font-size:16px;margin:8px 0}button{padding:10px 18px;font-size:16px}.e{color:#b00}</style></head>
<body><h2>Authorize Terminal MCP</h2><p>An app (Gemini Spark) wants to run shell commands on this server.</p>
${error ? `<p class="e">${esc(error)}</p>` : ''}
<form method="POST" action="/authorize">${hidden}<label>Consent password</label><input type="password" name="password" autofocus><button type="submit">Approve</button></form></body></html>`;
}

function checkAuthReq(q) {
  const c = verify(q.client_id, 'client');
  if (!c) return 'unknown client_id';
  if (!c.r.includes(q.redirect_uri)) return 'redirect_uri not registered';
  if (q.response_type && q.response_type !== 'code') return 'unsupported response_type';
  if (!q.code_challenge || (q.code_challenge_method || 'S256') !== 'S256') return 'PKCE S256 required';
  return null;
}

function authorizeGet(req, res, q) {
  const err = checkAuthReq(q);
  log('[authorize GET]', err || 'ok');
  if (err) return send(res, 400, `<p>${esc(err)}</p>`);
  send(res, 200, consentPage(q));
}

function authorizePost(req, res, q) {
  const err = checkAuthReq(q);
  if (err) return send(res, 400, `<p>${esc(err)}</p>`);
  if (!CONSENT_PASSWORD || q.password !== CONSENT_PASSWORD) {
    log('[authorize POST] bad password');
    return send(res, 200, consentPage(q, 'Wrong password'));
  }
  const code = sign({ t: 'code', c: q.client_id, r: q.redirect_uri, ch: q.code_challenge, exp: now() + 300, j: crypto.randomBytes(8).toString('hex') });
  const u = new URL(q.redirect_uri);
  u.searchParams.set('code', code);
  if (q.state) u.searchParams.set('state', q.state);
  log('[authorize POST] approved -> 302');
  res.writeHead(302, { Location: u.toString(), 'Cache-Control': 'no-store' });
  res.end();
}

const usedCodes = new Map();
function token(req, res, body) {
  if (!body) return send(res, 400, { error: 'invalid_request' });
  // client auth (basic or post)
  let client_id = body.client_id, client_secret = body.client_secret;
  const ah = req.headers.authorization || '';
  if (ah.startsWith('Basic ')) {
    const [id, sec] = Buffer.from(ah.slice(6), 'base64').toString().split(':');
    client_id = decodeURIComponent(id); client_secret = decodeURIComponent(sec || '');
  }
  const c = verify(client_id, 'client');
  if (!c) return send(res, 401, { error: 'invalid_client' });
  if (c.m !== 'none') {
    const exp = crypto.createHmac('sha256', SECRET).update('cs:' + client_id).digest('hex');
    if (client_secret !== exp) return send(res, 401, { error: 'invalid_client' });
  }
  const issue = () => ({
    access_token: sign({ t: 'access', c: client_id.slice(-16), exp: now() + 3600 }),
    token_type: 'Bearer', expires_in: 3600,
    refresh_token: sign({ t: 'refresh', c: client_id, exp: now() + 30 * 86400, j: crypto.randomBytes(6).toString('hex') }),
    scope: 'mcp',
  });
  if (body.grant_type === 'authorization_code') {
    const p = verify(body.code, 'code');
    if (!p || p.c !== client_id || usedCodes.has(p.j)) return send(res, 400, { error: 'invalid_grant' });
    if (body.redirect_uri && body.redirect_uri !== p.r) return send(res, 400, { error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
    const ch = crypto.createHash('sha256').update(body.code_verifier || '').digest('base64url');
    if (ch !== p.ch) return send(res, 400, { error: 'invalid_grant', error_description: 'PKCE failed' });
    usedCodes.set(p.j, p.exp);
    for (const [k, e] of usedCodes) if (e < now()) usedCodes.delete(k);
    log('[token] authorization_code ok');
    return send(res, 200, issue());
  }
  if (body.grant_type === 'refresh_token') {
    const p = verify(body.refresh_token, 'refresh');
    if (!p || p.c !== client_id) return send(res, 400, { error: 'invalid_grant' });
    log('[token] refresh ok');
    return send(res, 200, issue());
  }
  send(res, 400, { error: 'unsupported_grant_type' });
}

// ---------- MCP ----------
const TOOLS = [{
  name: 'execute_command',
  description: 'Run a bash command on the Ubuntu server and return stdout, stderr and exit code. Default timeout 60 seconds.',
  inputSchema: {
    type: 'object',
    properties: {
      command: { type: 'string', description: "Bash command to run, e.g. 'ls -la' or 'python3 --version'" },
      timeout: { type: 'integer', description: 'Timeout in seconds (default 60, max 300)' },
    },
    required: ['command'],
  },
}];

function runCommand(command, timeout) {
  const t = Math.min(Math.max(parseInt(timeout) || 60, 1), 300) * 1000;
  return new Promise((resolve) => {
    exec(command, { shell: '/bin/bash', timeout: t, maxBuffer: 5 * 1024 * 1024, cwd: process.env.HOME || '/' }, (err, stdout, stderr) => {
      const code = err ? (err.killed ? 'killed (timeout)' : err.code ?? 1) : 0;
      let out = `exit_code: ${code}\n`;
      if (stdout) out += `--- stdout ---\n${stdout}`;
      if (stderr) out += `\n--- stderr ---\n${stderr}`;
      if (out.length > 100000) out = out.slice(0, 100000) + '\n...[truncated]';
      resolve({ text: out, isError: code !== 0 });
    });
  });
}

const SUPPORTED = ['2025-06-18', '2025-03-26', '2024-11-05'];
async function handleRpc(msg) {
  const { id, method, params } = msg || {};
  const ok = (result) => ({ jsonrpc: '2.0', id, result });
  const fail = (code, message) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
  if (!msg || msg.jsonrpc !== '2.0' || !method) return fail(-32600, 'Invalid Request');
  if (id === undefined) return null; // notification
  switch (method) {
    case 'initialize': {
      const pv = SUPPORTED.includes(params?.protocolVersion) ? params.protocolVersion : SUPPORTED[0];
      return ok({ protocolVersion: pv, capabilities: { tools: { listChanged: false } }, serverInfo: { name: SERVER_NAME, version: VERSION },
        instructions: 'Terminal MCP: use execute_command to run bash commands on an Ubuntu server.' });
    }
    case 'ping': return ok({});
    case 'tools/list': return ok({ tools: TOOLS });
    case 'tools/call': {
      if (params?.name !== 'execute_command') return fail(-32602, 'Unknown tool: ' + params?.name);
      const cmd = params?.arguments?.command;
      if (!cmd || typeof cmd !== 'string') return fail(-32602, 'command is required');
      log('[tool] execute_command', JSON.stringify(cmd).slice(0, 200));
      const r = await runCommand(cmd, params.arguments.timeout);
      return ok({ content: [{ type: 'text', text: r.text }], isError: r.isError });
    }
    case 'resources/list': return ok({ resources: [] });
    case 'prompts/list': return ok({ prompts: [] });
    default: return fail(-32601, 'Method not found: ' + method);
  }
}

function unauthorized(req, res) {
  const b = baseUrl(req);
  send(res, 401, { error: 'unauthorized' }, {
    'WWW-Authenticate': `Bearer realm="mcp", resource_metadata="${b}/.well-known/oauth-protected-resource"`,
  });
}

async function mcp(req, res, raw) {
  const ah = req.headers.authorization || '';
  if (!ah.startsWith('Bearer ') || !verify(ah.slice(7), 'access')) { log('[mcp] 401', req.method); return unauthorized(req, res); }
  if (req.method === 'GET') return send(res, 405, { error: 'SSE stream not supported' }, { Allow: 'POST, DELETE' });
  if (req.method === 'DELETE') return send(res, 200, {});
  let body; try { body = JSON.parse(raw); } catch { return send(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }); }
  const headers = {};
  if (Array.isArray(body)) {
    const out = (await Promise.all(body.map(handleRpc))).filter(Boolean);
    if (!out.length) return send(res, 202, '');
    return send(res, 200, out, headers);
  }
  if (body?.method === 'initialize') headers['Mcp-Session-Id'] = crypto.randomUUID();
  const out = await handleRpc(body);
  if (!out) { res.writeHead(202, { 'Access-Control-Allow-Origin': '*' }); return res.end(); }
  log('[mcp]', body.method);
  send(res, 200, out, headers);
}

// ---------- router ----------
http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://x');
    const p = u.pathname.replace(/\/+$/, '') || '/';
    if (req.method === 'OPTIONS') return send(res, 204, '');
    if (p.startsWith('/.well-known/oauth-protected-resource')) return send(res, 200, protectedResource(req));
    if (p.startsWith('/.well-known/oauth-authorization-server') || p.startsWith('/.well-known/openid-configuration')) return send(res, 200, authServer(req));
    if (p === '/health') return send(res, 200, { ok: true, name: SERVER_NAME, version: VERSION });
    const raw = await readBody(req);
    if (p === '/register' && req.method === 'POST') return register(req, res, parseBody(req, raw));
    if (p === '/authorize' && req.method === 'GET') return authorizeGet(req, res, Object.fromEntries(u.searchParams));
    if (p === '/authorize' && req.method === 'POST') return authorizePost(req, res, parseBody(req, raw) || {});
    if (p === '/token' && req.method === 'POST') return token(req, res, parseBody(req, raw));
    if (p === '/mcp' || p === '/') {
      if (p === '/' && req.method === 'GET' && !req.headers.authorization && (req.headers.accept || '').includes('text/html')) {
        return send(res, 200, `<h3>${SERVER_NAME}</h3><p>MCP endpoint: <code>${esc(baseUrl(req))}/mcp</code></p>`);
      }
      return mcp(req, res, raw);
    }
    send(res, 404, { error: 'not_found' });
  } catch (e) {
    log('[error]', e);
    send(res, 500, { error: 'server_error' });
  }
}).listen(PORT, () => log(`${SERVER_NAME} listening on ${PORT}`));
