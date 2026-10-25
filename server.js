// Spark Terminal MCP - zero-dependency MCP server for Gemini Spark custom apps.
// Transport: Streamable HTTP (JSON) at /mcp. Auth: OAuth 2.1 + DCR + PKCE S256 (stateless, HMAC-signed).
'use strict';
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const os = require('os');
const zlib = require('zlib');
const { spawn, exec } = require('child_process');
const { URL, URLSearchParams } = require('url');
const ICONS = {};
for (const [k, f] of [['png64', 'icon-64.png'], ['png512', 'icon.png'], ['png192', 'icon-192.png'], ['apple', 'apple-touch-icon.png'], ['ico', 'favicon.ico'], ['svg', 'icon.svg']]) {
  try { const buf = require('fs').readFileSync(require('path').join(__dirname, 'assets', f)); ICONS[k] = k === 'svg' ? buf.toString() : buf.toString('base64'); } catch {}
}

const PORT = process.env.PORT || 10000;
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const CONSENT_PASSWORD = process.env.CONSENT_PASSWORD || '';
const SERVER_NAME = 'spark-terminal-mcp';
const SERVER_TITLE = 'Terminal MCP';
const VERSION = '1.2.0';
const MAX_OUT = 100000;
const SHARE_DIR = process.env.SHARE_DIR || path.join(os.tmpdir(), 'spark-mcp-share');
try { fs.mkdirSync(SHARE_DIR, { recursive: true }); } catch {}

const SERVER_SECRETS = ['JWT_SECRET', 'CONSENT_PASSWORD'];
function childEnv(extra) {
  const e = { ...process.env, ...(extra || {}) };
  for (const k of SERVER_SECRETS) delete e[k];
  return e;
}
const MAX_TIMER_SEC = 2147483;
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
    req.on('data', (c) => { d += c; if (d.length > 2e6) req.destroy(); });
    req.on('end', () => resolve(d));
  });
}
function parseBody(req, raw) {
  const ct = req.headers['content-type'] || '';
  if (ct.includes('application/json')) { try { return JSON.parse(raw || '{}'); } catch { return null; } }
  return Object.fromEntries(new URLSearchParams(raw));
}
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const clip = (s) => (s.length > MAX_OUT ? s.slice(0, MAX_OUT) + '\n...[truncated, ' + s.length + ' bytes total]' : s);
const HOME = process.env.HOME || '/root';
function resolvePath(p) {
  if (!p) return HOME;
  p = String(p);
  if (p.startsWith('~')) p = HOME + p.slice(1);
  return path.resolve(HOME, p);
}
const BLOCKED = ['/', '/etc', '/usr', '/bin', '/sbin', '/lib', '/lib64', '/boot', '/dev', '/proc', '/sys', '/var', '/root/.ssh'];
function guardDelete(abs) {
  const n = path.resolve(abs);
  if (BLOCKED.includes(n)) throw new Error('refusing to delete protected path: ' + n);
}

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
    logo_uri: baseUrl(req) + '/icon.png',
  };
  if (method !== 'none') { out.client_secret = crypto.createHmac('sha256', SECRET).update('cs:' + client_id).digest('hex'); out.client_secret_expires_at = 0; }
  log('[register]', body.client_name, uris.join(','), method);
  send(res, 201, out);
}

function logoTag(b) {
  return ICONS.png512 ? `<img src="${b}/icon.png" width="72" height="72" alt="" style="border-radius:16px">` : '';
}
function consentPage(req, q, error) {
  const b = baseUrl(req);
  const hidden = ['client_id', 'redirect_uri', 'state', 'code_challenge', 'code_challenge_method', 'scope', 'resource', 'response_type']
    .map((k) => `<input type="hidden" name="${k}" value="${esc(q[k])}">`).join('');
  return `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize ${SERVER_TITLE}</title>
<link rel="icon" href="${b}/favicon.ico">
<style>body{font-family:system-ui;max-width:440px;margin:56px auto;padding:0 18px;color:#1a1a1a}.h{display:flex;align-items:center;gap:14px}h2{margin:0}input[type=password]{width:100%;padding:11px;font-size:16px;margin:10px 0;box-sizing:border-box;border:1px solid #cbd3e1;border-radius:8px}button{padding:11px 20px;font-size:16px;border:0;border-radius:8px;background:#1e2a44;color:#fff;cursor:pointer}.e{color:#b00}p.m{color:#555}</style></head>
<body><div class="h">${logoTag(b)}<h2>Authorize ${SERVER_TITLE}</h2></div>
<p class="m">An app (Gemini Spark) wants to run shell commands and manage files on this server.</p>
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
  send(res, 200, consentPage(req, q));
}
function authorizePost(req, res, q) {
  const err = checkAuthReq(q);
  if (err) return send(res, 400, `<p>${esc(err)}</p>`);
  if (!CONSENT_PASSWORD || q.password !== CONSENT_PASSWORD) {
    log('[authorize POST] bad password');
    return send(res, 200, consentPage(req, q, 'Wrong password'));
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

// ====================== TOOL IMPLEMENTATIONS ======================
const ok = (text, isError) => ({ content: [{ type: 'text', text: clip(String(text)) }], isError: !!isError });
const errOut = (e) => ok('Error: ' + (e && e.message ? e.message : e), true);

// background process registry
const procs = new Map();
let procSeq = 0;

function execCapture(command, { cwd, timeout, env } = {}) {
  const t = Math.min(Math.max(parseInt(timeout) || 60, 1), MAX_TIMER_SEC) * 1000;
  return new Promise((resolve) => {
    exec(command, { shell: '/bin/bash', timeout: t, maxBuffer: 20 * 1024 * 1024, cwd: resolvePath(cwd), env: childEnv(env) },
      (err, stdout, stderr) => {
        const code = err ? (err.killed ? 'killed (timeout)' : err.code ?? 1) : 0;
        let out = `exit_code: ${code}\n`;
        if (stdout) out += `--- stdout ---\n${stdout}`;
        if (stderr) out += `\n--- stderr ---\n${stderr}`;
        resolve({ text: out, isError: code !== 0 });
      });
  });
}

async function toolRunCommand(a) {
  if (!a.command) throw new Error('command is required');
  if (a.background) {
    const id = ++procSeq;
    const child = spawn('/bin/bash', ['-lc', a.command], { cwd: resolvePath(a.cwd), env: childEnv(a.env), detached: true });
    const rec = { id, command: a.command, pid: child.pid, out: '', done: false, code: null, started: Date.now(), waiters: [] };
    child.stdout.on('data', (d) => { rec.out += d; if (rec.out.length > 2 * MAX_OUT) rec.out = rec.out.slice(-2 * MAX_OUT); });
    child.stderr.on('data', (d) => { rec.out += d; if (rec.out.length > 2 * MAX_OUT) rec.out = rec.out.slice(-2 * MAX_OUT); });
    child.on('close', (code) => { rec.done = true; rec.code = code; rec.child = null; rec.waiters.forEach((w) => w()); rec.waiters = []; });
    rec.child = child;
    procs.set(id, rec);
    return ok(`Started background process_id=${id} (pid ${child.pid}).\nUse manage_background_process with action "output"/"wait"/"kill" and process_id ${id}.`);
  }
  const r = await execCapture(a.command, a);
  return ok(r.text, r.isError);
}

async function toolProcess(a) {
  const action = a.action || 'list';
  if (action === 'list') {
    const all = a.all;
    const list = [...procs.values()].map((r) => ({ process_id: r.id, pid: r.pid, done: r.done, exit_code: r.code, command: r.command.slice(0, 120), running_sec: Math.round((Date.now() - r.started) / 1000) }))
      .filter((r) => all || !r.done);
    return ok(JSON.stringify(list, null, 2));
  }
  const rec = procs.get(parseInt(a.process_id));
  if (!rec) throw new Error('unknown process_id: ' + a.process_id);
  if (action === 'output') { const o = rec.out; if (a.clear) rec.out = ''; return ok(`done: ${rec.done}  exit_code: ${rec.code}\n--- output ---\n${o}`); }
  if (action === 'kill') { if (rec.child) { try { process.kill(-rec.child.pid, a.force ? 'SIGKILL' : 'SIGTERM'); } catch {} try { rec.child.kill(a.force ? 'SIGKILL' : 'SIGTERM'); } catch {} } return ok('kill signal sent to process_id ' + rec.id); }
  if (action === 'wait') {
    const ms = Math.min(Math.max(parseInt(a.timeout) || 60, 1), MAX_TIMER_SEC) * 1000;
    await new Promise((resolve) => { if (rec.done) return resolve(); const to = setTimeout(resolve, ms); rec.waiters.push(() => { clearTimeout(to); resolve(); }); });
    return ok(`done: ${rec.done}  exit_code: ${rec.code}\n--- output ---\n${rec.out}`);
  }
  throw new Error('unknown action: ' + action);
}

async function toolFsRead(a) {
  const action = a.action || 'read';
  const p = resolvePath(a.path);
  if (action === 'read') {
    const buf = await fsp.readFile(p);
    let text = buf.toString('utf8');
    if (a.start_line || a.end_line) {
      const lines = text.split('\n');
      text = lines.slice((a.start_line || 1) - 1, a.end_line || lines.length).join('\n');
    }
    return ok(text);
  }
  if (action === 'info') {
    const s = await fsp.stat(p);
    return ok(JSON.stringify({ path: p, type: s.isDirectory() ? 'dir' : s.isFile() ? 'file' : 'other', size: s.size, mode: (s.mode & 0o777).toString(8), mtime: s.mtime.toISOString() }, null, 2));
  }
  if (action === 'list') {
    const depth = Math.min(parseInt(a.depth) || 1, 6);
    const lines = [];
    async function walk(dir, d, prefix) {
      let items; try { items = await fsp.readdir(dir, { withFileTypes: true }); } catch (e) { lines.push(prefix + '[error: ' + e.message + ']'); return; }
      items.sort((x, y) => x.name.localeCompare(y.name));
      for (const it of items) {
        if (!a.hidden && it.name.startsWith('.')) continue;
        lines.push(prefix + it.name + (it.isDirectory() ? '/' : ''));
        if (it.isDirectory() && d < depth) await walk(path.join(dir, it.name), d + 1, prefix + '  ');
      }
    }
    await walk(p, 1, '');
    return ok(p + '\n' + lines.join('\n'));
  }
  if (action === 'find') {
    const r = await execCapture(`find ${JSON.stringify(p)} -iname ${JSON.stringify(a.pattern || '*')} 2>/dev/null | head -n 500`, {});
    return ok(r.text);
  }
  if (action === 'grep') {
    if (!a.pattern) throw new Error('pattern is required for grep');
    const r = await execCapture(`grep -rnI ${a.ignore_case ? '-i ' : ''}-e ${JSON.stringify(a.pattern)} ${JSON.stringify(p)} 2>/dev/null | head -n 500`, {});
    return ok(r.text || '(no matches)');
  }
  throw new Error('unknown action: ' + action);
}

async function toolFsWrite(a) {
  const action = a.action;
  const p = resolvePath(a.path);
  if (action === 'write') { await fsp.mkdir(path.dirname(p), { recursive: true }); await fsp.writeFile(p, a.content ?? ''); return ok('wrote ' + Buffer.byteLength(a.content ?? '') + ' bytes to ' + p); }
  if (action === 'append') { await fsp.mkdir(path.dirname(p), { recursive: true }); await fsp.appendFile(p, a.content ?? ''); return ok('appended to ' + p); }
  if (action === 'edit') {
    if (a.find == null) throw new Error('find is required for edit');
    const cur = await fsp.readFile(p, 'utf8');
    const count = cur.split(a.find).length - 1;
    if (count === 0) throw new Error('find string not found');
    if (count > 1 && !a.replace_all) throw new Error(`find string matches ${count} times; set replace_all:true or make it unique`);
    await fsp.writeFile(p, a.replace_all ? cur.split(a.find).join(a.replace ?? '') : cur.replace(a.find, a.replace ?? ''));
    return ok(`replaced ${a.replace_all ? count : 1} occurrence(s) in ` + p);
  }
  if (action === 'mkdir') { await fsp.mkdir(p, { recursive: true }); return ok('created ' + p); }
  if (action === 'copy') { const d = resolvePath(a.dest); await fsp.cp(p, d, { recursive: true }); return ok(`copied ${p} -> ${d}`); }
  if (action === 'move') { const d = resolvePath(a.dest); await fsp.mkdir(path.dirname(d), { recursive: true }); await fsp.rename(p, d); return ok(`moved ${p} -> ${d}`); }
  if (action === 'delete') {
    guardDelete(p);
    const s = await fsp.stat(p);
    if (s.isDirectory() && !a.recursive) throw new Error('path is a directory; set recursive:true to delete it');
    await fsp.rm(p, { recursive: !!a.recursive, force: true });
    return ok('deleted ' + p);
  }
  throw new Error('unknown action: ' + action);
}

function haveCmd(c) { try { require('child_process').execSync('command -v ' + c, { stdio: 'ignore' }); return true; } catch { return false; } }

async function toolArchive(a, req) {
  const action = a.action || 'create';
  if (action === 'create') {
    const srcs = (Array.isArray(a.paths) ? a.paths : [a.path]).filter(Boolean).map(resolvePath);
    if (!srcs.length) throw new Error('paths is required');
    const fmt = a.format || 'zip';
    const out = resolvePath(a.output || path.join(os.tmpdir(), 'archive-' + Date.now() + '.' + (fmt === 'tar.gz' ? 'tgz' : fmt)));
    const quoted = srcs.map((s) => JSON.stringify(path.basename(s))).join(' ');
    const parent = path.dirname(srcs[0]);
    let cmd;
    if (fmt === 'zip') cmd = `cd ${JSON.stringify(parent)} && zip -r -q ${JSON.stringify(out)} ${quoted}`;
    else if (fmt === 'tar.gz') cmd = `cd ${JSON.stringify(parent)} && tar czf ${JSON.stringify(out)} ${quoted}`;
    else if (fmt === 'tar') cmd = `cd ${JSON.stringify(parent)} && tar cf ${JSON.stringify(out)} ${quoted}`;
    else if (fmt === '7z') cmd = `cd ${JSON.stringify(parent)} && 7z a -y ${JSON.stringify(out)} ${quoted}`;
    else throw new Error('unknown format: ' + fmt);
    const r = await execCapture(cmd, { timeout: 600 });
    if (r.isError) return ok('archive failed:\n' + r.text, true);
    const st = await fsp.stat(out);
    let text = `created ${out} (${st.size} bytes)`;
    if (a.share) { const link = makeShareLink(out, baseUrl(req), a.expires_hours, a.max_downloads); text += `\ndownload: ${link}`; }
    return ok(text);
  }
  if (action === 'extract') {
    const src = resolvePath(a.path);
    const dest = resolvePath(a.dest || path.dirname(src));
    await fsp.mkdir(dest, { recursive: true });
    let cmd;
    if (/\.zip$/i.test(src)) cmd = `unzip -o -q ${JSON.stringify(src)} -d ${JSON.stringify(dest)}`;
    else if (/\.(tar\.gz|tgz)$/i.test(src)) cmd = `tar xzf ${JSON.stringify(src)} -C ${JSON.stringify(dest)}`;
    else if (/\.tar$/i.test(src)) cmd = `tar xf ${JSON.stringify(src)} -C ${JSON.stringify(dest)}`;
    else if (/\.7z$/i.test(src)) cmd = `7z x -y -o${JSON.stringify(dest)} ${JSON.stringify(src)}`;
    else if (/\.rar$/i.test(src)) cmd = `unrar x -o+ ${JSON.stringify(src)} ${JSON.stringify(dest)}/`;
    else throw new Error('unsupported archive type');
    const r = await execCapture(cmd, { timeout: 600 });
    return ok((r.isError ? 'extract failed:\n' : `extracted to ${dest}\n`) + r.text, r.isError);
  }
  if (action === 'list') {
    const src = resolvePath(a.path);
    let cmd;
    if (/\.zip$/i.test(src)) cmd = `unzip -l ${JSON.stringify(src)}`;
    else if (/\.(tar\.gz|tgz|tar)$/i.test(src)) cmd = `tar tf ${JSON.stringify(src)}`;
    else if (/\.7z$/i.test(src)) cmd = `7z l ${JSON.stringify(src)}`;
    else if (/\.rar$/i.test(src)) cmd = `unrar l ${JSON.stringify(src)}`;
    else throw new Error('unsupported archive type');
    const r = await execCapture(cmd, {});
    return ok(r.text, r.isError);
  }
  throw new Error('unknown action: ' + action);
}

// ---------- share / download links ----------
function makeShareLink(absPath, base, expires_hours, max_downloads) {
  const exp = now() + Math.min(Math.max(parseInt(expires_hours) || 24, 1), 24 * 30) * 3600;
  const token = sign({ t: 'dl', p: absPath, exp, md: max_downloads ? parseInt(max_downloads) : 0, j: crypto.randomBytes(6).toString('hex') });
  shares.set(token, { path: absPath, exp, created: now() });
  return `${base}/dl/${token}/${encodeURIComponent(path.basename(absPath))}`;
}
const dlCounts = new Map();
const shares = new Map(); // token -> {path, exp, created}
const revoked = new Set();

async function toolShareFile(a, req) {
  const action = a.action || 'create';
  if (action === 'create') {
    let p = resolvePath(a.path);
    const st = await fsp.stat(p);
    if (st.isDirectory()) {
      const out = path.join(os.tmpdir(), path.basename(p) + '-' + Date.now() + '.zip');
      const r = await execCapture(`cd ${JSON.stringify(path.dirname(p))} && zip -r -q ${JSON.stringify(out)} ${JSON.stringify(path.basename(p))}`, { timeout: 600 });
      if (r.isError) return ok('zip failed:\n' + r.text, true);
      p = out;
    }
    const link = makeShareLink(p, baseUrl(req), a.expires_hours, a.max_downloads);
    const sz = (await fsp.stat(p)).size;
    return ok(`download link (${sz} bytes, opening it starts the download):\n${link}`);
  }
  if (action === 'list') {
    const b = baseUrl(req);
    const list = [...shares.entries()].filter(([t, s]) => s.exp > now() && !revoked.has(t))
      .map(([t, s]) => ({ file: s.path, downloads: dlCounts.get(t) || 0, expires: new Date(s.exp * 1000).toISOString(), link: `${b}/dl/${t}/${encodeURIComponent(path.basename(s.path))}` }));
    return ok(list.length ? JSON.stringify(list, null, 2) : '(no active links since last restart)');
  }
  if (action === 'revoke') {
    let t = a.token || '';
    if (t.includes('/dl/')) t = t.split('/dl/')[1].split('/')[0];
    if (!t && a.path) { const ap = resolvePath(a.path); for (const [k, s] of shares) if (s.path === ap) { revoked.add(k); t = k; } }
    if (!t) throw new Error('give token (or the link) or path');
    revoked.add(t);
    return ok('link revoked');
  }
  throw new Error('unknown action: ' + action);
}

function serveDownload(req, res, token, suppliedName) {
  const p = verify(token, 'dl');
  if (!p || revoked.has(token)) return send(res, 404, { error: 'invalid, expired or revoked link' });
  if (p.md) { const c = (dlCounts.get(token) || 0); if (c >= p.md) return send(res, 410, { error: 'download limit reached' }); dlCounts.set(token, c + 1); }
  let st; try { st = fs.statSync(p.p); } catch { return send(res, 404, { error: 'file no longer exists (server may have restarted)' }); }
  const name = path.basename(p.p);
  const range = req.headers.range;
  const common = {
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': `attachment; filename="${name.replace(/"/g, '')}"`,
    'Accept-Ranges': 'bytes',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-store',
  };
  if (range) {
    const m = /bytes=(\d*)-(\d*)/.exec(range);
    let start = m[1] ? parseInt(m[1]) : 0;
    let end = m[2] ? parseInt(m[2]) : st.size - 1;
    if (start > end || start >= st.size) { res.writeHead(416, { 'Content-Range': `bytes */${st.size}` }); return res.end(); }
    res.writeHead(206, { ...common, 'Content-Range': `bytes ${start}-${end}/${st.size}`, 'Content-Length': end - start + 1 });
    fs.createReadStream(p.p, { start, end }).pipe(res);
  } else {
    res.writeHead(200, { ...common, 'Content-Length': st.size });
    fs.createReadStream(p.p).pipe(res);
  }
  log('[dl]', name, st.size);
}

async function toolRunCode(a) {
  if (!a.code) throw new Error('code is required');
  const lang = (a.language || 'python').toLowerCase();
  const tmp = path.join(os.tmpdir(), 'code-' + crypto.randomBytes(5).toString('hex'));
  let file, cmd;
  if (lang === 'python' || lang === 'py') { file = tmp + '.py'; cmd = `python3 ${JSON.stringify(file)}`; }
  else if (lang === 'node' || lang === 'js' || lang === 'javascript') { file = tmp + '.js'; cmd = `node ${JSON.stringify(file)}`; }
  else if (lang === 'bash' || lang === 'sh') { file = tmp + '.sh'; cmd = `bash ${JSON.stringify(file)}`; }
  else throw new Error('unsupported language: ' + lang);
  await fsp.writeFile(file, a.code);
  try {
    const full = a.stdin != null ? `printf %s ${JSON.stringify(a.stdin)} | ${cmd}` : cmd;
    const r = await execCapture(full, { timeout: a.timeout, cwd: a.cwd, env: a.env });
    return ok(r.text, r.isError);
  } finally { fsp.unlink(file).catch(() => {}); }
}

async function toolPackage(a) {
  const mgr = (a.manager || '').toLowerCase();
  const action = a.action || 'install';
  const pkgs = (Array.isArray(a.packages) ? a.packages : [a.packages || a.name]).filter(Boolean).map((x) => JSON.stringify(x)).join(' ');
  let cmd;
  if (mgr === 'apt') {
    if (action === 'install') cmd = `apt-get update && apt-get install -y ${pkgs}`;
    else if (action === 'uninstall') cmd = `apt-get remove -y ${pkgs}`;
    else if (action === 'list') cmd = `dpkg -l | tail -n +6`;
    else if (action === 'search') cmd = `apt-cache search ${pkgs} | head -n 60`;
  } else if (mgr === 'pip') {
    if (action === 'install') cmd = `pip install --break-system-packages ${pkgs}`;
    else if (action === 'uninstall') cmd = `pip uninstall -y ${pkgs}`;
    else if (action === 'list') cmd = `pip list`;
    else if (action === 'search') throw new Error('pip search is disabled by PyPI');
  } else if (mgr === 'npm') {
    if (action === 'install') cmd = `npm install -g ${pkgs}`;
    else if (action === 'uninstall') cmd = `npm uninstall -g ${pkgs}`;
    else if (action === 'list') cmd = `npm list -g --depth=0`;
    else if (action === 'search') cmd = `npm search ${pkgs} | head -n 60`;
  } else throw new Error('manager must be apt, pip or npm');
  if (!cmd) throw new Error('unknown action: ' + action);
  const r = await execCapture(cmd, { timeout: a.timeout || 600 });
  return ok(r.text, r.isError);
}

async function toolHttp(a, req) {
  if (!a.url) throw new Error('url is required');
  const mode = a.mode || 'raw';
  const u = new URL(a.url);
  const isHttps = u.protocol === 'https:';
  const lib = isHttps ? require('https') : require('http');
  const method = (a.method || 'GET').toUpperCase();
  let body = a.body;
  const headers = { 'User-Agent': 'spark-terminal-mcp', ...(a.headers || {}) };
  if (a.json != null) { body = JSON.stringify(a.json); headers['Content-Type'] = headers['Content-Type'] || 'application/json'; }
  return new Promise((resolve, reject) => {
    const r = lib.request(u, { method, headers, timeout: (a.timeout || 60) * 1000 }, (resp) => {
      if (mode === 'download') {
        const dest = resolvePath(a.save_to || path.join(os.tmpdir(), path.basename(u.pathname) || 'download-' + Date.now()));
        fsp.mkdir(path.dirname(dest), { recursive: true }).then(() => {
          const ws = fs.createWriteStream(dest);
          resp.pipe(ws);
          ws.on('finish', () => {
            fs.stat(dest, (e, st) => {
              let text = `HTTP ${resp.statusCode} -> saved ${dest} (${st ? st.size : '?'} bytes)`;
              if (a.share) text += `\ndownload: ${makeShareLink(dest, baseUrl(req), a.expires_hours, a.max_downloads)}`;
              resolve(ok(text, resp.statusCode >= 400));
            });
          });
          ws.on('error', (e) => resolve(errOut(e)));
        });
        return;
      }
      const chunks = [];
      let enc = resp.headers['content-encoding'];
      let stream = resp;
      if (enc === 'gzip') stream = resp.pipe(zlib.createGunzip());
      else if (enc === 'deflate') stream = resp.pipe(zlib.createInflate());
      else if (enc === 'br') stream = resp.pipe(zlib.createBrotliDecompress());
      stream.on('data', (c) => chunks.push(c));
      stream.on('end', () => {
        let text = Buffer.concat(chunks).toString('utf8');
        if (mode === 'text') text = text.replace(/<script[\s\S]*?<\/script>/gi, '').replace(/<style[\s\S]*?<\/style>/gi, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
        const head = `HTTP ${resp.statusCode}\n` + Object.entries(resp.headers).map(([k, v]) => `${k}: ${v}`).join('\n') + '\n\n';
        resolve(ok((mode === 'raw' ? head : '') + text, resp.statusCode >= 400));
      });
      stream.on('error', (e) => resolve(errOut(e)));
    });
    r.on('timeout', () => { r.destroy(); resolve(errOut(new Error('request timed out'))); });
    r.on('error', (e) => resolve(errOut(e)));
    if (body) r.write(body);
    r.end();
  });
}

const SENSITIVE = /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|JWT)/i;
async function toolEnv(a) {
  const action = a.action || 'list';
  if (action === 'get') {
    if (SERVER_SECRETS.includes(a.name)) return ok(a.name + '=*** (hidden)');
    const v = process.env[a.name];
    return ok(a.name + '=' + (v === undefined ? '(unset)' : (SENSITIVE.test(a.name) ? '***' : v)));
  }
  if (action === 'set') { if (SERVER_SECRETS.includes(a.name)) throw new Error('cannot modify protected server secret'); process.env[a.name] = String(a.value ?? ''); return ok('set ' + a.name); }
  if (action === 'unset') { if (SERVER_SECRETS.includes(a.name)) throw new Error('cannot modify protected server secret'); delete process.env[a.name]; return ok('unset ' + a.name); }
  if (action === 'list') {
    const lines = Object.keys(process.env).sort().map((k) => `${k}=${SERVER_SECRETS.includes(k) || SENSITIVE.test(k) ? '***' : String(process.env[k]).replace(/\/\/[^\/@\s]+@/g, '//***@')}`);
    return ok(lines.join('\n'));
  }
  throw new Error('unknown action: ' + action);
}

async function toolSystemInfo() {
  const toGB = (b) => (b / 1073741824).toFixed(2) + ' GB';
  let versions = {};
  for (const [k, c] of [['node', 'node -v'], ['python', 'python3 --version'], ['npm', 'npm -v'], ['pip', 'pip --version'], ['git', 'git --version']]) {
    try { versions[k] = require('child_process').execSync(c, { encoding: 'utf8' }).trim(); } catch { versions[k] = '(not found)'; }
  }
  let disk = ''; try { disk = require('child_process').execSync('df -h / | tail -1', { encoding: 'utf8' }).trim(); } catch {}
  const info = {
    os: `${os.type()} ${os.release()}`, platform: os.platform(), arch: os.arch(),
    cpus: os.cpus().length + ' x ' + (os.cpus()[0] ? os.cpus()[0].model : '?'),
    memory: { total: toGB(os.totalmem()), free: toGB(os.freemem()) },
    disk_root: disk, uptime_sec: Math.round(os.uptime()), load_avg: os.loadavg().map((x) => x.toFixed(2)),
    cwd: HOME, versions,
    background_processes: [...procs.values()].filter((r) => !r.done).length,
  };
  return ok(JSON.stringify(info, null, 2));
}

// ====================== TOOL SCHEMAS ======================
const RO = { readOnlyHint: true };
const DEST = { destructiveHint: true };
// User choice: run_shell_command and run_code_snippet run without a confirmation prompt in Spark.
const SAFE = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };
const TOOLS = [
  { name: 'run_shell_command', title: 'Run Shell Command',
    description: 'Run any bash command on this Ubuntu 24.04 Linux server (full shell with internet access) and get back its stdout, stderr and exit code. Use it for anything a terminal can do: git clone, building projects, running scripts, curl, compiling, starting servers. Runs in /bin/bash, so pipes, redirects and && work. For jobs that take long or never end (servers, watchers, big builds) set background:true; you get a process_id, then use manage_background_process to read output, wait or stop it. Output longer than ~100 KB is truncated. Preinstalled: Node.js 26 + npm, Python 3.15 + pip (cloudscraper, requests), git, build-essential, zip/unzip/7z/tar/unrar, jq, curl, wget. Example: {"command":"git clone https://github.com/user/repo && ls repo"}.',
    annotations: SAFE,
    inputSchema: { type: 'object', required: ['command'], properties: {
      command: { type: 'string', description: 'The bash command line to run, exactly as typed in a terminal, e.g. "ls -la", "python3 app.py", "cd proj && npm install".' },
      cwd: { type: 'string', description: 'Folder to run the command in. Defaults to the home folder. Absolute path or ~/path.' },
      timeout: { type: 'integer', description: 'Seconds to wait before the command is killed. Default 60. No fixed upper limit: pass a bigger number (e.g. 600, 3600) for long installs or builds. Ignored when background is true.' },
      env: { type: 'object', description: 'Extra environment variables for this one command only, as {"NAME":"value"}.' },
      background: { type: 'boolean', description: 'true = start detached and return immediately with a process_id (for servers or very long jobs). Then use manage_background_process.' },
    } } },
  { name: 'manage_background_process', title: 'Manage Background Process',
    description: 'Control commands started with run_shell_command background:true. action "list" shows every background process with its process_id, command, status and runtime. action "output" returns what the process has printed so far (stdout+stderr). action "wait" blocks until it finishes (or timeout) and returns exit code and output. action "kill" stops it. Pass the process_id returned by run_shell_command (not needed for list).',
    inputSchema: { type: 'object', required: ['action'], properties: {
      action: { type: 'string', enum: ['list', 'output', 'wait', 'kill'], description: 'list | output | wait | kill' },
      process_id: { type: 'integer', description: 'The process_id returned when the background command started. Required for output, wait and kill.' },
      all: { type: 'boolean', description: 'list only: also show processes that already finished.' },
      clear: { type: 'boolean', description: 'output only: empty the buffer after reading so the next read shows only new output.' },
      timeout: { type: 'integer', description: 'wait only: maximum seconds to wait. Default 60, no upper limit.' },
      force: { type: 'boolean', description: 'kill only: true sends SIGKILL (hard stop) instead of SIGTERM (polite stop).' },
    } } },
  { name: 'read_files', title: 'Read Files and Folders',
    description: 'Look at files and folders on the server without changing anything. action "read": return a text file\'s content, optionally only lines start_line..end_line (use this to view source code). action "info": size, type, permissions and modified time of a path. action "list": list a folder\'s contents, recursive up to depth levels. action "find": search a folder tree for file names matching a glob like "*.py". action "grep": search inside files under a path for a text pattern and return matching lines with file and line number.',
    annotations: RO,
    inputSchema: { type: 'object', required: ['action', 'path'], properties: {
      action: { type: 'string', enum: ['read', 'info', 'list', 'find', 'grep'], description: 'read | info | list | find | grep' },
      path: { type: 'string', description: 'File (read, info) or folder (list, find, grep) to look at. Absolute path or ~/path.' },
      start_line: { type: 'integer', description: 'read only: first line to return (1-based).' },
      end_line: { type: 'integer', description: 'read only: last line to return.' },
      depth: { type: 'integer', description: 'list only: how many folder levels deep to go. Default 1.' },
      hidden: { type: 'boolean', description: 'list only: include hidden dotfiles.' },
      pattern: { type: 'string', description: 'find: file name glob such as "*.kt" or "build.gradle*". grep: the text or regex to search for.' },
      ignore_case: { type: 'boolean', description: 'find/grep: ignore upper/lower case.' },
    } } },
  { name: 'write_files', title: 'Write and Edit Files',
    description: 'Create, change, copy, move or delete files and folders on the server. action "write": create or overwrite a file with content (parent folders are created). action "append": add content to the end of a file. action "edit": replace the exact text find with replace inside a file (first match, or all with replace_all) - the best way to change part of source code. action "mkdir": create a folder. action "copy" / "move": copy or move/rename path to dest. action "delete": remove a file, or a folder with recursive:true. Core system folders such as /, /etc, /usr, /bin cannot be deleted.',
    annotations: DEST,
    inputSchema: { type: 'object', required: ['action', 'path'], properties: {
      action: { type: 'string', enum: ['write', 'append', 'edit', 'mkdir', 'copy', 'move', 'delete'], description: 'write | append | edit | mkdir | copy | move | delete' },
      path: { type: 'string', description: 'The file or folder to act on.' },
      content: { type: 'string', description: 'write/append: the full text to write.' },
      find: { type: 'string', description: 'edit: the exact existing text to replace (must match exactly, including spaces).' },
      replace: { type: 'string', description: 'edit: the new text that replaces find.' },
      replace_all: { type: 'boolean', description: 'edit: replace every match instead of only the first.' },
      dest: { type: 'string', description: 'copy/move: destination path.' },
      recursive: { type: 'boolean', description: 'delete: required to delete a folder that is not empty.' },
    } } },
  { name: 'manage_archives', title: 'Zip / Unzip Archives',
    description: 'Compress and extract files. action "create": pack one path or several paths into a zip, tar.gz, tar or 7z archive (default zip); set share:true to also get a direct download link for it. action "extract": unpack a zip, tar, tar.gz, tar.xz, tar.bz2, 7z or rar file into dest. action "list": show what is inside an archive without extracting.',
    annotations: DEST,
    inputSchema: { type: 'object', required: ['action'], properties: {
      action: { type: 'string', enum: ['create', 'extract', 'list'], description: 'create | extract | list' },
      path: { type: 'string', description: 'create: the single file/folder to pack. extract/list: the archive file.' },
      paths: { type: 'array', items: { type: 'string' }, description: 'create: several files/folders to pack together (instead of path).' },
      format: { type: 'string', enum: ['zip', 'tar.gz', 'tar', '7z'], description: 'create: archive type. Default zip.' },
      output: { type: 'string', description: 'create: where to save the archive, e.g. ~/project.zip. Default: next to the source.' },
      dest: { type: 'string', description: 'extract: folder to unpack into. Default: next to the archive.' },
      share: { type: 'boolean', description: 'create: also return a download link for the new archive.' },
      expires_hours: { type: 'integer', description: 'create+share: link lifetime in hours (default 24, max 720).' },
      max_downloads: { type: 'integer', description: 'create+share: optional limit on how many times the link works.' },
    } } },
  { name: 'create_download_link', title: 'Create Download Link',
    description: 'Give the user a direct download link (public HTTPS URL) for ANY file on the server: .py, .kt, .apk, .zip, images, videos, PDFs, anything. Opening the link starts the download right away with the correct file name; resume is supported. A folder is zipped automatically first. Use this whenever the user wants to download or receive a file, and show them the returned URL. action "list" shows active links, action "revoke" disables one. Links last 24 hours by default (max 30 days) and stop working if the server restarts.',
    inputSchema: { type: 'object', required: ['action'], properties: {
      action: { type: 'string', enum: ['create', 'list', 'revoke'], description: 'create | list | revoke' },
      path: { type: 'string', description: 'create: the file or folder to share. revoke: disable every link for this file.' },
      expires_hours: { type: 'integer', description: 'create: how many hours the link works. Default 24, max 720.' },
      max_downloads: { type: 'integer', description: 'create: optional cap on number of downloads.' },
      token: { type: 'string', description: 'revoke: the link URL (or its token) to disable.' },
    } } },
  { name: 'run_code_snippet', title: 'Run Code Snippet',
    description: 'Run a piece of Python 3.15, Node.js 26 or Bash code directly (no need to save a file first) and return what it prints, plus errors and exit code. Good for calculations, data processing, quick tests, scraping and API calls. Python has cloudscraper and requests preinstalled: for websites behind a Cloudflare anti-bot page use `import cloudscraper; s = cloudscraper.create_scraper(); r = s.get(url); print(r.status_code, r.text[:2000])`. Install more libraries with manage_packages. Optional stdin is fed to the program.',
    annotations: SAFE,
    inputSchema: { type: 'object', required: ['code'], properties: {
      language: { type: 'string', enum: ['python', 'node', 'bash'], description: 'python (default) | node | bash' },
      code: { type: 'string', description: 'The full source code to run. Use print()/console.log to show results.' },
      stdin: { type: 'string', description: 'Optional text passed to the program on standard input.' },
      cwd: { type: 'string', description: 'Folder to run in (relative file paths resolve here). Default home.' },
      timeout: { type: 'integer', description: 'Seconds before it is stopped. Default 60, no upper limit.' },
      env: { type: 'object', description: 'Extra environment variables as {"NAME":"value"}.' },
    } } },
  { name: 'manage_packages', title: 'Install Software Packages',
    description: 'Install, remove, list or search software packages. manager "apt" = Ubuntu system programs (e.g. ffmpeg, openjdk-21-jdk, sqlite3). manager "pip" = Python libraries (e.g. pandas, flask, yt-dlp). manager "npm" = Node.js packages, installed globally (e.g. typescript, pm2). action "install" / "uninstall" take packages (a list of names). action "list" shows what is installed. action "search" looks up a name.',
    annotations: DEST,
    inputSchema: { type: 'object', required: ['manager', 'action'], properties: {
      manager: { type: 'string', enum: ['apt', 'pip', 'npm'], description: 'apt (system) | pip (Python) | npm (Node.js)' },
      action: { type: 'string', enum: ['install', 'uninstall', 'list', 'search'], description: 'install | uninstall | list | search' },
      packages: { type: 'array', items: { type: 'string' }, description: 'install/uninstall: package names, e.g. ["requests","flask==3.1"].' },
      name: { type: 'string', description: 'search: the name to search for; list: optional filter.' },
      timeout: { type: 'integer', description: 'Seconds to allow. No upper limit.' },
    } } },
  { name: 'http_request', title: 'HTTP Request / Download URL',
    description: 'Call a URL from the server. mode "raw" (default): returns status code, response headers and body - use for REST/JSON APIs with any method (GET, POST, PUT, PATCH, DELETE), custom headers and a body or json. mode "text": fetch a web page and return only its readable text. mode "download": save the file at the URL onto the server at save_to (any size or type); add share:true to also get a download link for the user. For Cloudflare-protected sites use run_code_snippet with cloudscraper instead.',
    inputSchema: { type: 'object', required: ['url'], properties: {
      url: { type: 'string', description: 'Full http:// or https:// address.' },
      method: { type: 'string', description: 'HTTP method. Default GET.' },
      headers: { type: 'object', description: 'Request headers as {"Name":"value"}, e.g. Authorization.' },
      body: { type: 'string', description: 'Raw request body text.' },
      json: { description: 'A JSON value to send as the body (sets Content-Type: application/json).' },
      mode: { type: 'string', enum: ['raw', 'text', 'download'], description: 'raw (default) | text | download' },
      save_to: { type: 'string', description: 'download: path to save the file to on the server.' },
      share: { type: 'boolean', description: 'download: also return a download link.' },
      expires_hours: { type: 'integer', description: 'download+share: link lifetime in hours.' },
      max_downloads: { type: 'integer', description: 'download+share: optional download cap.' },
      timeout: { type: 'integer', description: 'Seconds to wait. Default 60.' },
    } } },
  { name: 'manage_env_variables', title: 'Environment Variables',
    description: 'Read or change the server\'s environment variables, which later commands inherit. action "list": all variables (secret-looking values such as keys and tokens are masked). action "get": one variable. action "set": create or change name=value. action "unset": remove one. The server\'s own login secrets are never shown and cannot be changed.',
    inputSchema: { type: 'object', required: ['action'], properties: {
      action: { type: 'string', enum: ['get', 'set', 'unset', 'list'], description: 'list | get | set | unset' },
      name: { type: 'string', description: 'Variable name, e.g. API_KEY (get/set/unset).' },
      value: { type: 'string', description: 'set: the new value.' },
    } } },
  { name: 'get_system_info', title: 'Get System Info',
    description: 'Report the server\'s OS, CPU, RAM, free disk space, uptime, load, current folder, installed runtime versions (Node, npm, Python, pip, git) and how many background processes are running. Takes no input. Use it to check the machine before installing or building.',
    annotations: RO, inputSchema: { type: 'object', properties: {} } },
];

const HANDLERS = {
  run_shell_command: toolRunCommand, manage_background_process: toolProcess, read_files: toolFsRead, write_files: toolFsWrite,
  manage_archives: toolArchive, create_download_link: toolShareFile, run_code_snippet: toolRunCode, manage_packages: toolPackage,
  http_request: toolHttp, manage_env_variables: toolEnv, get_system_info: toolSystemInfo,
};
// old v1.x names still accepted
Object.assign(HANDLERS, { run_command: toolRunCommand, process: toolProcess, fs_read: toolFsRead, fs_write: toolFsWrite,
  archive: toolArchive, share_file: toolShareFile, run_code: toolRunCode, package: toolPackage, http: toolHttp, env: toolEnv, system_info: toolSystemInfo });

// ---------- MCP ----------
const SUPPORTED = ['2025-06-18', '2025-11-25', '2025-03-26', '2024-11-05'];
function serverInfo(req) {
  const si = { name: SERVER_NAME, title: SERVER_TITLE, version: VERSION };
  const b = baseUrl(req);
  // Same shape the GitHub MCP server uses (shows in Spark): PNG data URIs, light + dark theme, no "sizes".
  const png = ICONS.png64 || ICONS.png192;
  si.icons = [{ src: b + '/icon.png', mimeType: 'image/png' }];
  if (png) si.icons.push(
    { src: `data:image/png;base64,${png}`, mimeType: 'image/png', theme: 'light' },
    { src: `data:image/png;base64,${png}`, mimeType: 'image/png', theme: 'dark' });
  si.websiteUrl = b;
  return si;
}
async function handleRpc(msg, req) {
  const { id, method, params } = msg || {};
  const okr = (result) => ({ jsonrpc: '2.0', id, result });
  const fail = (code, message) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
  if (!msg || msg.jsonrpc !== '2.0' || !method) return fail(-32600, 'Invalid Request');
  if (id === undefined) return null;
  switch (method) {
    case 'initialize': {
      const pv = SUPPORTED.includes(params?.protocolVersion) ? params.protocolVersion : SUPPORTED[0];
      return okr({ protocolVersion: pv, capabilities: { tools: { listChanged: false } }, serverInfo: serverInfo(req),
        instructions: 'Terminal MCP: a full Ubuntu shell. Run shell commands (run_shell_command, background jobs via manage_background_process), read and edit files (read_files, write_files), zip/unzip (manage_archives), give the user direct download links for any file (create_download_link), run Python/Node/Bash code (run_code_snippet, cloudscraper preinstalled), install packages (manage_packages), call URLs and APIs (http_request), manage environment variables (manage_env_variables) and check the machine (get_system_info).' });
    }
    case 'ping': return okr({});
    case 'tools/list': return okr({ tools: TOOLS });
    case 'tools/call': {
      const h = HANDLERS[params?.name];
      if (!h) return fail(-32602, 'Unknown tool: ' + params?.name);
      log('[tool]', params.name, JSON.stringify(params.arguments || {}).slice(0, 200));
      try { const r = await h(params.arguments || {}, req); return okr(r); }
      catch (e) { return okr(errOut(e)); }
    }
    case 'resources/list': return okr({ resources: [] });
    case 'prompts/list': return okr({ prompts: [] });
    default: return fail(-32601, 'Method not found: ' + method);
  }
}

function unauthorized(req, res) {
  const b = baseUrl(req);
  send(res, 401, { error: 'unauthorized' }, { 'WWW-Authenticate': `Bearer realm="mcp", resource_metadata="${b}/.well-known/oauth-protected-resource"` });
}
async function mcp(req, res, raw) {
  const ah = req.headers.authorization || '';
  if (!ah.startsWith('Bearer ') || !verify(ah.slice(7), 'access')) { log('[mcp] 401', req.method); return unauthorized(req, res); }
  if (req.method === 'GET') return send(res, 405, { error: 'SSE stream not supported' }, { Allow: 'POST, DELETE' });
  if (req.method === 'DELETE') return send(res, 200, {});
  let body; try { body = JSON.parse(raw); } catch { return send(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }); }
  const headers = {};
  if (Array.isArray(body)) {
    const out = (await Promise.all(body.map((m) => handleRpc(m, req)))).filter(Boolean);
    if (!out.length) return send(res, 202, '');
    return send(res, 200, out, headers);
  }
  if (body?.method === 'initialize') headers['Mcp-Session-Id'] = crypto.randomUUID();
  const out = await handleRpc(body, req);
  if (!out) { res.writeHead(202, { 'Access-Control-Allow-Origin': '*' }); return res.end(); }
  log('[mcp]', body.method);
  send(res, 200, out, headers);
}

// ---------- logo serving ----------
function serveIcon(res, buf, type) {
  res.writeHead(200, { 'Content-Type': type, 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=86400' });
  res.end(buf);
}

// Google Search Console verification (so Google's favicon service, used by Spark, can learn our logo).
// Put the meta-tag code in assets/google-site-verification.txt, or HTML-file names (googleXXXX.html) one per line in assets/google-verify-files.txt
const readAsset = (f) => { try { return fs.readFileSync(path.join(__dirname, 'assets', f), 'utf8').trim(); } catch { return ''; } };
const GSV = process.env.GOOGLE_SITE_VERIFICATION || readAsset('google-site-verification.txt');
const GVFILES = readAsset('google-verify-files.txt').split(/\s+/).filter(Boolean);
// ---------- router ----------
http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://x');
    const p = u.pathname.replace(/\/+$/, '') || '/';
    if (req.method === 'OPTIONS') return send(res, 204, '');
    if (p.startsWith('/.well-known/oauth-protected-resource')) return send(res, 200, protectedResource(req));
    if (p.startsWith('/.well-known/oauth-authorization-server') || p.startsWith('/.well-known/openid-configuration')) return send(res, 200, authServer(req));
    if (p === '/robots.txt') return send(res, 200, `User-agent: *\nAllow: /\nSitemap: ${baseUrl(req)}/sitemap.xml\n`, { 'Content-Type': 'text/plain' });
    if (p === '/sitemap.xml') return send(res, 200, `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${baseUrl(req)}/</loc></url></urlset>`, { 'Content-Type': 'application/xml' });
    if (/^\/google[\w-]+\.html$/.test(p) && GVFILES.includes(p.slice(1))) return send(res, 200, `google-site-verification: ${p.slice(1)}`, { 'Content-Type': 'text/html' });
    if (p === '/health') return send(res, 200, { ok: true, name: SERVER_NAME, version: VERSION });
    // logo endpoints (no auth)
    const ip = p.startsWith('/mcp/') ? p.slice(4) : p;
    if (['/favicon.png', '/logo.png'].includes(ip) && ICONS.png512) return serveIcon(res, Buffer.from(ICONS.png512, 'base64'), 'image/png');
    if (ip === '/icon.png' && ICONS.png512) return serveIcon(res, Buffer.from(ICONS.png512, 'base64'), 'image/png');
    if (ip === '/icon-192.png' && ICONS.png192) return serveIcon(res, Buffer.from(ICONS.png192, 'base64'), 'image/png');
    if (ip === '/apple-touch-icon.png' && ICONS.apple) return serveIcon(res, Buffer.from(ICONS.apple, 'base64'), 'image/png');
    if (ip === '/icon.svg' && ICONS.svg) return serveIcon(res, Buffer.from(ICONS.svg), 'image/svg+xml');
    if (ip === '/favicon.ico' && ICONS.ico) return serveIcon(res, Buffer.from(ICONS.ico, 'base64'), 'image/x-icon');
    // download links (no auth; token is the capability)
    if (p.startsWith('/dl/')) { const parts = u.pathname.split('/'); return serveDownload(req, res, parts[2], parts[3]); }
    const raw = await readBody(req);
    if (p === '/register' && req.method === 'POST') return register(req, res, parseBody(req, raw));
    if (p === '/authorize' && req.method === 'GET') return authorizeGet(req, res, Object.fromEntries(u.searchParams));
    if (p === '/authorize' && req.method === 'POST') return authorizePost(req, res, parseBody(req, raw) || {});
    if (p === '/token' && req.method === 'POST') return token(req, res, parseBody(req, raw));
    if (p === '/mcp' || p === '/') {
      if (p === '/' && req.method === 'GET' && !req.headers.authorization) {
        const b = baseUrl(req);
        return send(res, 200, `<!DOCTYPE html>
<html lang="en">
<head>
${GSV ? `<meta name="google-site-verification" content="${GSV}" />` : ''}
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${SERVER_TITLE}</title>
<meta name="description" content="Terminal MCP: a full Ubuntu terminal for Gemini Spark custom apps." />
<link rel="icon" href="${b}/favicon.ico" sizes="any" />
<link rel="icon" type="image/png" sizes="192x192" href="${b}/icon-192.png" />
<link rel="apple-touch-icon" href="${b}/apple-touch-icon.png" />
<meta property="og:image" content="${b}/icon.png" />
<style>body{font-family:system-ui;max-width:560px;margin:60px auto;padding:0 18px;color:#1a1a1a}code{background:#f0f2f7;padding:2px 6px;border-radius:5px}.h{display:flex;align-items:center;gap:14px}</style>
</head>
<body>
<div class="h">${logoTag(b)}<h2>${SERVER_TITLE}</h2></div>
<p>A terminal MCP server for Gemini Spark custom apps.</p>
<p>MCP endpoint: <code>${b}/mcp</code></p>
</body>
</html>`);
      }
      return mcp(req, res, raw);
    }
    send(res, 404, { error: 'not_found' });
  } catch (e) {
    log('[error]', e);
    send(res, 500, { error: 'server_error' });
  }
}).listen(PORT, () => log(`${SERVER_NAME} v${VERSION} listening on ${PORT}`));
