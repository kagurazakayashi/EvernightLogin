// Strong-auth fixture helper: real root Passkey strong-setup + relogin + second factor.
// Env: E2E_BASE, E2E_USER, E2E_PASSWORD, E2E_OUT. Output includes session cookies
// for the fixture's in-process use; never copy the output into committed evidence.
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';

const BASE = process.env.E2E_BASE || 'http://localhost:0';
const USER = process.env.E2E_USER || 'root';
const PASSWORD = process.env.E2E_PASSWORD || '';
const OUT = process.env.E2E_OUT || 'strong-session.json';
const PROFILE = process.env.E2E_PROFILE || 'P:/go/tmp/strong-auth-fixture/chrome-profile';
const CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const PORT = 9225;
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
    const version = await cdp.send('Browser.getVersion');
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
    const ceremonyOf = (html) => (html.match(/name="passkey_ceremony_id" value="([^"]+)"/) || [])[1] || '';
    const inject = async () => { for (const [name, value] of Object.entries(jar)) { if (name.startsWith('__Host-')) await cdp.send('Network.setCookie', { name, value, url: BASE, path: '/', secure: true, httpOnly: true, sameSite: 'Lax' }); else await cdp.send('Network.setCookie', { name, value, url: BASE, path: '/', secure: false, httpOnly: true, sameSite: 'Lax' }); } };
    const serializeCredential = (kind) => `(async () => {
      const opts = ${kind};
      const fromB64 = (v) => { const s = v.split('-').join('+').split('_').join('/'); const pad = s.length % 4 ? '='.repeat(4 - s.length % 4) : ''; const bin = atob(s + pad); const out = new Uint8Array(bin.length); for (let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out.buffer; };
      const toB64 = (buf) => { const bytes = new Uint8Array(buf); let bin=''; for (const b of bytes) bin += String.fromCharCode(b); return btoa(bin).split('+').join('-').split('/').join('_').split('=').join(''); };
      const conv = (o) => { if (o.challenge) o.challenge = fromB64(o.challenge); if (o.user && o.user.id) o.user.id = fromB64(o.user.id); for (const key of ['excludeCredentials','allowCredentials']) for (const c of (o[key] || [])) if (c.id) c.id = fromB64(c.id); return o; };
      const cred = await navigator.credentials.create({ publicKey: conv(opts) });
      return JSON.stringify({ id: cred.id, rawId: toB64(cred.rawId), type: cred.type, response: { clientDataJSON: toB64(cred.response.clientDataJSON), attestationObject: toB64(cred.response.attestationObject), transports: cred.response.getTransports ? cred.response.getTransports() : [] }, clientExtensionResults: cred.getClientExtensionResults() });
    })()`;
    const serializeAssertion = (kind) => `(async () => {
      const opts = ${kind};
      const fromB64 = (v) => { const s = v.split('-').join('+').split('_').join('/'); const pad = s.length % 4 ? '='.repeat(4 - s.length % 4) : ''; const bin = atob(s + pad); const out = new Uint8Array(bin.length); for (let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out.buffer; };
      const toB64 = (buf) => { const bytes = new Uint8Array(buf); let bin=''; for (const b of bytes) bin += String.fromCharCode(b); return btoa(bin).split('+').join('-').split('/').join('_').split('=').join(''); };
      const conv = (o) => { if (o.challenge) o.challenge = fromB64(o.challenge); for (const c of (o.allowCredentials || [])) if (c.id) c.id = fromB64(c.id); return o; };
      const cred = await navigator.credentials.get({ publicKey: conv(opts) });
      return JSON.stringify({ id: cred.id, rawId: toB64(cred.rawId), type: cred.type, response: { clientDataJSON: toB64(cred.response.clientDataJSON), authenticatorData: toB64(cred.response.authenticatorData), signature: toB64(cred.response.signature), userHandle: cred.response.userHandle ? toB64(cred.response.userHandle) : '' }, clientExtensionResults: cred.getClientExtensionResults() });
    })()`;

    // 1) password login -> restricted strong setup
    const lp = await get('/login');
    const lr = await post('/login', { csrf_token: csrf(lp.text), identifier: USER, password: PASSWORD });
    result.passwordLoginStatus = lr.status;
    result.passwordLoginLocation = lr.location || '';
    let loc = lr.location || '/login/strong-setup';
    if (!loc.startsWith('/')) loc = new URL(loc, BASE).pathname;
    let sp = await get(loc);
    if (sp.status === 303 && sp.location) { loc = sp.location; sp = await get(loc); }
    result.strongSetupStatus = sp.status;
    result.strongSetupSnippet = textOf(sp.text).slice(0, 300);
    const st = await post('/login/strong-setup/passkey/start', { csrf_token: csrf(sp.text), current_password: PASSWORD });
    result.strongSetupStartStatus = st.status;
    const opts = optionsOf(st.text);
    const ceremony = ceremonyOf(st.text);
    if (!opts) throw new Error('strong setup start missing options: ' + textOf(st.text).slice(0, 300));
    await inject(); await nav(BASE + '/');
    const cred = await evalJS(serializeCredential(JSON.stringify(opts.publicKey || opts)));
    const fin = await post('/login/strong-setup/passkey/finish', { csrf_token: csrf(st.text), passkey_ceremony_id: ceremony, passkey_response: cred, current_password: PASSWORD });
    result.strongSetupFinishStatus = fin.status;
    result.strongSetupFinishSnippet = textOf(fin.text).slice(0, 300);

    // 2) password login again -> passkey second factor
    const lp2 = await get('/login');
    const lr2 = await post('/login', { csrf_token: csrf(lp2.text), identifier: USER, password: PASSWORD });
    result.secondLoginStatus = lr2.status;
    result.secondLoginLocation = lr2.location || '';
    let secondLoc = lr2.location || '';
    let sp2 = await get(secondLoc);
    if (sp2.status === 303 && sp2.location) { secondLoc = sp2.location; sp2 = await get(secondLoc); }
    result.secondFactorStatus = sp2.status;
    result.secondFactorSnippet = textOf(sp2.text).slice(0, 300);
    const opts2 = optionsOf(sp2.text);
    const ceremony2 = ceremonyOf(sp2.text);
    if (opts2) {
      const assertion = await evalJS(serializeAssertion(JSON.stringify(opts2.publicKey || opts2)));
      const hidden2 = {}; const re2 = /name="([^"]+)" value="([^"]*)"/g; let hm; while ((hm = re2.exec(sp2.text)) !== null) hidden2[hm[1]] = hm[2];
      const verify = await post(secondLoc, { ...hidden2, passkey_ceremony_id: ceremony2, passkey_response: assertion });
      result.secondFactorVerifyStatus = verify.status;
      result.secondFactorVerifyLocation = verify.location || '';
      result.secondFactorVerifySnippet = textOf(verify.text).slice(0, 300);
      result.secondCeremonyLen = ceremony2.length;
    } else {
      result.secondFactorNoOptions = true;
    }
    const probes = {};
    for (const path of ['/home','/account/security','/admin','/admin/users','/admin/applications','/admin/roles','/admin/audit','/admin/reports','/admin/v1/users','/admin/v1/applications','/admin/v1/audit/events','/admin/v1/audit/retention','/admin/v1/reports','/admin/v1/backups','/admin/v1/notifications','/admin/v1/sessions']) {
      const r = await get(path);
      probes[path] = { status: r.status, snippet: textOf(r.text).slice(0, 100) };
    }
    result.probes = probes;
    result.cookies = Object.entries(jar).map(([name, value]) => ({ name, value }));
    result.cookieCount = result.cookies.length;
    result.authenticatorId = auth.authenticatorId;
    result.browser = version.product;
    result.ok = result.passwordLoginStatus === 303 && result.strongSetupFinishStatus === 200 &&
      (result.secondFactorVerifyStatus === 303 || result.secondLoginStatus === 303);
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
main().then(() => process.exit(0)).catch((e) => { console.error('STRONG_AUTH_PASSKEY_FAIL', e.stack || e); process.exit(1); });
