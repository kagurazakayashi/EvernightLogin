// Step160 browser driver (Chrome CDP, no external npm dependencies).
// Uses the fixture session to simulate an already-authenticated browser; never prints secrets.
import { spawn } from 'node:child_process';
import { randomBytes, createHash } from 'node:crypto';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const fixture = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const base = fixture.base_url;
const app = (process.env.OIDC && fixture.oidc_app_id) ? fixture.oidc_app_id : fixture.app_id;
const session = readFileSync(fixture.session, 'utf8').trim();
const chromePath = process.env.CHROME_PATH || 'C:/Program Files/Google/Chrome/Application/chrome.exe';
let callbackCode = null;
let lastRedirect = null;
const callbackServer = http.createServer((req, res) => { const u = new URL(req.url, 'http://127.0.0.1:9999'); callbackCode = u.searchParams.get('code'); const err = u.searchParams.get('error'); res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); res.end('<html><body>callback ' + (callbackCode ? 'code' : 'error:' + err) + '</body></html>'); });
await new Promise((res, rej) => { callbackServer.once('error', rej); callbackServer.listen(9999, '127.0.0.1', res); });
const profile = mkdtempSync(join(tmpdir(), 'step160-chrome-'));
const port = 19333;
const chrome = spawn(chromePath, ['--headless=new', '--disable-gpu', '--no-first-run',
  '--no-default-browser-check', '--disable-extensions', '--disable-web-security', '--disable-features=BlockInsecurePrivateNetworkRequests', '--remote-debugging-port=' + port,
  '--user-data-dir=' + profile, '--unsafely-treat-insecure-origin-as-secure=http://127.0.0.1:19081,http://127.0.0.1:9999',
  'about:blank'], { stdio: 'ignore' });
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function waitVersion() {
  for (let i = 0; i < 80; i++) {
    try { const r = await fetch(`http://127.0.0.1:${port}/json/version`); if (r.ok) return r.json(); } catch {}
    await sleep(250);
  }
  throw new Error('chrome CDP not ready');
}
const version = await waitVersion();
const ws = new WebSocket(version.webSocketDebuggerUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
let seq = 0; const pending = new Map();
ws.onmessage = ev => { const m = JSON.parse(ev.data); if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.rej(new Error(JSON.stringify(m.error))) : p.res(m.result); } };
function cdp(method, params = {}, sessionId) { return new Promise((res, rej) => { const id = ++seq; pending.set(id, { res, rej }); ws.send(JSON.stringify({ id, method, params, sessionId })); }); }
const target = await cdp('Target.createTarget', { url: 'about:blank' });
const attached = await cdp('Target.attachToTarget', { targetId: target.targetId, flatten: true });
const sid = attached.sessionId;
await cdp('Page.enable', {}, sid); await cdp('Runtime.enable', {}, sid); await cdp('Network.enable', {}, sid);
await cdp('Network.setExtraHTTPHeaders', { headers: { Origin: base, Referer: base + '/oauth/authorize' } }, sid);
const cookie = await cdp('Network.setCookie', { name: '__Host-login_session', value: session,
  url: base + '/', path: '/', secure: true, httpOnly: true, sameSite: 'Lax' }, sid);
console.log('cookie set', cookie.success);
async function navigate(url) { await cdp('Page.navigate', { url }, sid); await sleep(1200); }
async function evalJs(expression) { const r = await cdp('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sid); return r.result?.value; }
const verifier = randomBytes(32).toString('base64url');
const challenge = createHash('sha256').update(verifier).digest('base64url');
const state = randomBytes(12).toString('hex');
const redirect = 'http://127.0.0.1:19081/callback';
const aud = process.env.NO_AUD ? '' : 'https://resource.example.test/api';
const authUrl = `${base}/oauth/authorize?client_id=${encodeURIComponent(app)}&redirect_uri=${encodeURIComponent(redirect)}&response_type=code&state=${state}&nonce=n${state}&scope=${encodeURIComponent('openid profile offline_access')}&code_challenge=${challenge}&code_challenge_method=S256` + (aud && !process.env.OIDC ? `&resource=${encodeURIComponent(aud)}` : '');
await navigate(authUrl);
let title = await evalJs('document.title');
let body = await evalJs('document.body ? document.body.innerText.slice(0,500) : ""');
console.log('consent page', title, JSON.stringify(body).slice(0,300));
const clicked = await evalJs(`(async () => { const f=[...document.querySelectorAll('form')].find(x => x.querySelector('[name=approve][value=true]') || x.querySelector('button[type=submit]')); if(!f) return 'no-form'; const body=new URLSearchParams(); for (const [k,v] of new FormData(f)) body.append(k,v); body.set('approve','true'); try { const r=await fetch('/oauth/authorize',{method:'POST',body,credentials:'include',redirect:'follow'}); return {status:r.status,url:r.url}; } catch(e) { return {error:String(e)}; } })()`);
console.log('approve submit', JSON.stringify({status: clicked?.status ?? null, ok: clicked?.status === 404})); await sleep(1500);
let href = await evalJs('location.href');
try { const u = new URL(href); console.log('after', u.origin + u.pathname); } catch { console.log('after', 'non-http'); }
let code = null;
if (clicked && clicked.url) { try { code = new URL(clicked.url).searchParams.get('code'); } catch {} }
if (code) {
  const tr = await fetch(base + '/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', client_id: app, code, redirect_uri: redirect, code_verifier: verifier }) });
  const token = await tr.json(); console.log('token status', tr.status, 'has access', !!token.access_token, 'has refresh', !!token.refresh_token);
  const decode = (jwt) => { try { const p = jwt.split('.')[1]; return JSON.parse(Buffer.from(p, 'base64url').toString()); } catch { return {}; } };
  const ac = decode(token.access_token), ic = token.id_token ? decode(token.id_token) : {};
  console.log('claims', JSON.stringify({iss:ac.iss, aud:ac.aud, sub:ac.sub, subject_type:ac.subject_type, scope:ac.scope, token_use:ac.token_use, id_iss:ic.iss, id_aud:ic.aud, id_sub:ic.sub}));
  if (token.access_token) {
    const ui = await fetch(base + '/oauth/userinfo', { headers: { authorization: 'Bearer ' + token.access_token } });
    console.log('userinfo', ui.status, (await ui.text()).slice(0,160));
    if (token.refresh_token) {
      const rr = await fetch(base + '/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'refresh_token', client_id: app, refresh_token: token.refresh_token }) });
      const rt = await rr.json(); console.log('refresh status', rr.status, 'rotated', !!rt.access_token, 'new refresh', !!rt.refresh_token);
      if (rt.refresh_token) {
        const replay = await fetch(base + '/oauth/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'refresh_token', client_id: app, refresh_token: token.refresh_token }) });
        const rp = await replay.json(); console.log('refresh replay', replay.status, 'error', rp.error);
        const rv = await fetch(base + '/oauth/revoke', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token: rt.access_token, client_id: app }) });
        console.log('revoke', rv.status);
        const after = await fetch(base + '/oauth/userinfo', { headers: { authorization: 'Bearer ' + rt.access_token } });
        console.log('userinfo after revoke', after.status);
      }
    }
  }
} else {
  console.log('no code; page body', (await evalJs('document.body ? document.body.innerText.slice(0,800) : ""')));
}
try { await cdp('Target.closeTarget', { targetId: target.targetId }); } catch {}
callbackServer.close(); ws.close(); chrome.kill(); await sleep(500); try { rmSync(profile, { recursive: true, force: true }); } catch {}
