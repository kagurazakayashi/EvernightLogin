// Staff fixture helper: register a real Passkey for an ordinary user, wait for the
// test harness to grant support permissions, then logout and log in with the Passkey.
// Env: E2E_BASE, E2E_USER, E2E_PASSWORD, E2E_OUT, E2E_READY, E2E_GRANTED, E2E_PROFILE.
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync, existsSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'http://localhost:0';
const USER = process.env.E2E_USER || '';
const PASSWORD = process.env.E2E_PASSWORD || '';
const OUT = process.env.E2E_OUT || 'staff-session.json';
const READY = process.env.E2E_READY || '';
const GRANTED = process.env.E2E_GRANTED || '';
const PROFILE = process.env.E2E_PROFILE || 'P:/go/tmp/staff-passkey/chrome';
const CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const PORT = 9226;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitHTTP(url, timeout = 15000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    try { const r = await fetch(url); if (r.ok) return; } catch {}
    await sleep(150);
  }
  throw new Error('CDP timeout');
}
class CDP {
  constructor(ws) { this.ws = ws; this.seq = 0; this.pending = new Map();
    ws.addEventListener('message', (ev) => { const m = JSON.parse(ev.data);
      if (m.id && this.pending.has(m.id)) { const p = this.pending.get(m.id); this.pending.delete(m.id);
        if (m.error) p.reject(new Error(JSON.stringify(m.error))); else p.resolve(m.result); } }); }
  send(method, params = {}, timeout = 20000) { const id = ++this.seq;
    return new Promise((resolve, reject) => { this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
      setTimeout(() => { if (this.pending.has(id)) { this.pending.delete(id); reject(new Error('CDP timeout ' + method)); } }, timeout); }); }
}

async function main() {
  try { rmSync(PROFILE, { recursive: true, force: true }); } catch {}
  mkdirSync(PROFILE, { recursive: true });
  const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    '--remote-debugging-port=' + PORT, '--user-data-dir=' + PROFILE, '--window-size=1280,900', 'about:blank'], { stdio: 'ignore' });
  let result = { ok: false };
  try {
    await waitHTTP(`http://127.0.0.1:${PORT}/json/version`);
    const target = await (await fetch(`http://127.0.0.1:${PORT}/json/new?${encodeURIComponent('about:blank')}`, { method: 'PUT' })).json();
    const ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((res, rej) => { ws.addEventListener('open', res); ws.addEventListener('error', rej); });
    const cdp = new CDP(ws);
    await cdp.send('Page.enable'); await cdp.send('Runtime.enable'); await cdp.send('Network.enable'); await cdp.send('WebAuthn.enable');
    const auth = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
    const evalJS = async (expression) => { const r = await cdp.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) throw new Error('JS ' + JSON.stringify(r.exceptionDetails)); return r.result.value; };
    const nav = async (url) => { await cdp.send('Page.navigate', { url }); await sleep(500); };
    let jar = {};
    const cookieHeader = () => Object.entries(jar).map(([k, v]) => k + '=' + v).join('; ');
    const remember = (setCookies) => { for (const sc of setCookies) { const nv = sc.split(';')[0]; const i = nv.indexOf('='); if (i > 0) jar[nv.slice(0, i)] = nv.slice(i + 1); } };
    const get = async (path) => { const r = await fetch(BASE + path, { redirect: 'manual', headers: { Cookie: cookieHeader() } }); const text = await r.text(); remember(r.headers.getSetCookie ? r.headers.getSetCookie() : []); return { status: r.status, text, location: r.headers.get('location') }; };
    const post = async (path, fields) => { const r = await fetch(BASE + path, { method: 'POST', redirect: 'manual', body: new URLSearchParams(fields).toString(), headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: BASE, Referer: BASE + path, Cookie: cookieHeader() } }); const text = await r.text(); remember(r.headers.getSetCookie ? r.headers.getSetCookie() : []); return { status: r.status, text, location: r.headers.get('location') }; };
    const csrf = (html) => (html.match(/name="csrf_token" value="([^"]+)"/) || [])[1] || '';
    const textOf = (html) => html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    const optionsOf = (html) => { const raw = (html.match(/data-ln-options="([^"]*)"/) || [])[1] || ''; return raw ? JSON.parse(raw.replaceAll('&quot;', '"').replaceAll('&#34;', '"').replaceAll('&amp;', '&')) : null; };
    const ceremonyOf = (html) => (html.match(/name="(?:passkey_)?ceremony_id" value="([^"]+)"/) || [])[1] || '';
    const inject = async () => { for (const [name, value] of Object.entries(jar)) { if (name.startsWith('__Host-')) await cdp.send('Network.setCookie', { name, value, url: BASE, path: '/', secure: true, httpOnly: true, sameSite: 'Lax' }); else await cdp.send('Network.setCookie', { name, value, url: BASE, path: '/', secure: false, httpOnly: true, sameSite: 'Lax' }); } };
    const createScript = (options) => `(async () => {
      const opts = ${JSON.stringify(options)};
      const fromB64 = (v) => { const s = v.split('-').join('+').split('_').join('/'); const pad = s.length % 4 ? '='.repeat(4 - s.length % 4) : ''; const bin = atob(s + pad); const out = new Uint8Array(bin.length); for (let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out.buffer; };
      const toB64 = (buf) => { const bytes = new Uint8Array(buf); let bin=''; for (const b of bytes) bin += String.fromCharCode(b); return btoa(bin).split('+').join('-').split('/').join('_').split('=').join(''); };
      const conv = (o) => { if (o.challenge) o.challenge = fromB64(o.challenge); if (o.user && o.user.id) o.user.id = fromB64(o.user.id); for (const key of ['excludeCredentials','allowCredentials']) for (const c of (o[key] || [])) if (c.id) c.id = fromB64(c.id); return o; };
      const cred = await navigator.credentials.create({ publicKey: conv(opts) });
      return JSON.stringify({ id: cred.id, rawId: toB64(cred.rawId), type: cred.type, response: { clientDataJSON: toB64(cred.response.clientDataJSON), attestationObject: toB64(cred.response.attestationObject), transports: cred.response.getTransports ? cred.response.getTransports() : [] }, clientExtensionResults: cred.getClientExtensionResults() });
    })()`;
    const assertScript = (options) => `(async () => {
      const opts = ${JSON.stringify(options)};
      const fromB64 = (v) => { const s = v.split('-').join('+').split('_').join('/'); const pad = s.length % 4 ? '='.repeat(4 - s.length % 4) : ''; const bin = atob(s + pad); const out = new Uint8Array(bin.length); for (let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out.buffer; };
      const toB64 = (buf) => { const bytes = new Uint8Array(buf); let bin=''; for (const b of bytes) bin += String.fromCharCode(b); return btoa(bin).split('+').join('-').split('/').join('_').split('=').join(''); };
      const conv = (o) => { if (o.challenge) o.challenge = fromB64(o.challenge); for (const c of (o.allowCredentials || [])) if (c.id) c.id = fromB64(c.id); return o; };
      const cred = await navigator.credentials.get({ publicKey: conv(opts) });
      return JSON.stringify({ id: cred.id, rawId: toB64(cred.rawId), type: cred.type, response: { clientDataJSON: toB64(cred.response.clientDataJSON), authenticatorData: toB64(cred.response.authenticatorData), signature: toB64(cred.response.signature), userHandle: cred.response.userHandle ? toB64(cred.response.userHandle) : '' }, clientExtensionResults: cred.getClientExtensionResults() });
    })()`;

    // 1) normal password login (no support permission yet)
    let lp = await get('/login');
    let lr = await post('/login', { csrf_token: csrf(lp.text), identifier: USER, password: PASSWORD });
    result.initialLogin = [lr.status, lr.location || ''];
    if (lr.status !== 303) throw new Error('initial login failed: ' + textOf(lr.text).slice(0, 200));
    // 2) security center passkey registration with page-level reauth
    const passPage = await get('/account/security/passkeys');
    const token = csrf(passPage.text);
    const start = await post('/account/security/passkeys/register', { csrf_token: token, current_password: PASSWORD });
    const opts = optionsOf(start.text);
    const ceremony = ceremonyOf(start.text);
    if (!opts) throw new Error('passkey start failed: ' + textOf(start.text).slice(0, 250));
    await inject(); await nav(BASE + '/');
    const cred = await evalJS(createScript(opts.publicKey || opts));
    const fin = await post('/account/security/passkeys/register/finish', { csrf_token: csrf(start.text), ceremony_id: ceremony, passkey_response: cred, name: 'Staff Passkey', current_password: PASSWORD });
    result.passkeyFinishStatus = fin.status;
    if (fin.status !== 200) throw new Error('passkey finish failed: ' + textOf(fin.text).slice(0, 250));
    // signal harness that the credential is registered, then wait for role grant
    if (READY) writeFileSync(READY, 'ready', 'utf8');
    const deadline = Date.now() + 90000;
    while (GRANTED && !existsSync(GRANTED) && Date.now() < deadline) await sleep(300);
    result.roleGranted = !GRANTED || existsSync(GRANTED);
    // 3) start a fresh client session (drop the pre-role session) and log in with the Passkey
    jar = {};
    lp = await get('/login');
    lr = await post('/login', { csrf_token: csrf(lp.text), identifier: USER, password: PASSWORD });
    result.loginWithMfaStatus = [lr.status, lr.location || ''];
    let second = lr;
    if (lr.status === 303 && lr.location) second = await get(lr.location.startsWith('/') ? lr.location : new URL(lr.location, BASE).pathname);
    if (second.status === 303 && second.location) second = await get(second.location.startsWith('/') ? second.location : new URL(second.location, BASE).pathname);
    result.secondFactorPageStatus = second.status;
    const opts2 = optionsOf(second.text);
    const ceremony2 = ceremonyOf(second.text);
    if (!opts2) throw new Error('second factor options missing: ' + textOf(second.text).slice(0, 250));
    const assertion = await evalJS(assertScript(opts2.publicKey || opts2));
    const hidden = {}; const re = /name="([^"]+)" value="([^"]*)"/g; let m;
    while ((m = re.exec(second.text)) !== null) hidden[m[1]] = m[2];
    const verify = await post('/login/second-factor', { ...hidden, passkey_ceremony_id: ceremony2, passkey_response: assertion });
    result.secondFactorVerify = [verify.status, verify.location || ''];
    if (verify.status !== 303) throw new Error('second factor failed: ' + textOf(verify.text).slice(0, 250));
    result.cookies = Object.entries(jar).map(([name, value]) => ({ name, value }));
    result.authenticatorId = auth.authenticatorId;
    // probe support pages with the strong session
    const probes = {};
    for (const path of ['/support/cases', '/admin/v1/support/cases', '/admin/users', '/admin/v1/users', '/home']) {
      const r = await get(path); probes[path] = { status: r.status, snippet: textOf(r.text).slice(0, 100) };
    }
    result.probes = probes;
    result.ok = result.secondFactorVerify[0] === 303;
    writeFileSync(OUT, JSON.stringify(result, null, 2), 'utf8');
    ws.close();
  } catch (e) {
    result.error = String(e && e.stack || e);
    try { writeFileSync(OUT, JSON.stringify(result, null, 2), 'utf8'); } catch {}
    throw e;
  } finally {
    chrome.kill('SIGKILL');
  }
}
main().then(() => process.exit(0)).catch((e) => { console.error('STAFF_PASSKEY_FAIL', e.stack || e); process.exit(1); });
