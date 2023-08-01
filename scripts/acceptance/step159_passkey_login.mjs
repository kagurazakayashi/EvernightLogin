// Step 159: real Chrome/CDP virtual authenticator — register Passkey on the account
// security page, then passwordless /login/passkey login. Test-only.
import { spawn } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';

const BASE = process.env.E2E_BASE || 'http://127.0.0.1:8080';
const ORIGIN = process.env.E2E_ORIGIN || BASE;
const USER = process.env.E2E_USER || 'step159user';
const PASSWORD = process.env.E2E_PASSWORD || '';
const SECRET = process.env.E2E_TOTP || '';
const OUT = process.env.E2E_OUT || 'step159-passkey-login-result.json';
const PROFILE = process.env.E2E_PROFILE || 'P:/go/tmp/step159-passkey-profile';
const PORT = 9232;
const CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const result = { ok: false, steps: [] };
const step = (name, ok, extra = {}) => { result.steps.push({ name, ok, ...extra }); if (!ok) result.ok = false; };

function totp(secret, at = Date.now()) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0; const out = [];
  for (const ch of secret.toUpperCase()) { value = (value << 5) | alphabet.indexOf(ch); bits += 5; if (bits >= 8) { out.push((value >> (bits - 8)) & 0xff); bits -= 8; } }
  const counter = Math.floor(at / 1000 / 30);
  const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', Buffer.from(out)).update(buf).digest();
  const off = digest[digest.length - 1] & 0x0f;
  const code = ((digest[off] & 0x7f) << 24 | digest[off+1] << 16 | digest[off+2] << 8 | digest[off+3]) % 1000000;
  return String(code).padStart(6, '0');
}
async function waitHTTP(url, timeout = 20000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) { try { const r = await fetch(url); if (r.ok) return; } catch {} await sleep(150); }
  throw new Error('CDP timeout');
}
class CDP {
  constructor(ws) { this.ws = ws; this.seq = 0; this.pending = new Map();
    ws.addEventListener('message', (ev) => { const m = JSON.parse(ev.data);
      if (m.id && this.pending.has(m.id)) { const p = this.pending.get(m.id); this.pending.delete(m.id);
        if (m.error) p.reject(new Error(JSON.stringify(m.error))); else p.resolve(m.result); } }); }
  send(method, params = {}, timeout = 30000) { const id = ++this.seq;
    return new Promise((resolve, reject) => { this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
      setTimeout(() => { if (this.pending.has(id)) { this.pending.delete(id); reject(new Error('CDP timeout ' + method)); } }, timeout); }); }
}
const CREATE = `(async () => {
  const opts = __OPTS__;
  const fromB64 = (v) => { const s = v.split('-').join('+').split('_').join('/'); const pad = s.length % 4 ? '='.repeat(4 - s.length % 4) : ''; const bin = atob(s + pad); const out = new Uint8Array(bin.length); for (let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out.buffer; };
  const toB64 = (buf) => { const bytes = new Uint8Array(buf); let bin=''; for (const b of bytes) bin += String.fromCharCode(b); return btoa(bin).split('+').join('-').split('/').join('_').split('=').join(''); };
  const conv = (o) => { if (o.challenge) o.challenge = fromB64(o.challenge); if (o.user && o.user.id) o.user.id = fromB64(o.user.id); for (const key of ['excludeCredentials','allowCredentials']) for (const c of (o[key] || [])) if (c.id) c.id = fromB64(c.id); return o; };
  const cred = await navigator.credentials.create({ publicKey: conv(opts) });
  return JSON.stringify({ id: cred.id, rawId: toB64(cred.rawId), type: cred.type, response: { clientDataJSON: toB64(cred.response.clientDataJSON), attestationObject: toB64(cred.response.attestationObject), transports: cred.response.getTransports ? cred.response.getTransports() : [] }, clientExtensionResults: cred.getClientExtensionResults() });
})()`;
const GET = `(async () => {
  const opts = __OPTS__;
  const fromB64 = (v) => { const s = v.split('-').join('+').split('_').join('/'); const pad = s.length % 4 ? '='.repeat(4 - s.length % 4) : ''; const bin = atob(s + pad); const out = new Uint8Array(bin.length); for (let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out.buffer; };
  const toB64 = (buf) => { const bytes = new Uint8Array(buf); let bin=''; for (const b of bytes) bin += String.fromCharCode(b); return btoa(bin).split('+').join('-').split('/').join('_').split('=').join(''); };
  const conv = (o) => { if (o.challenge) o.challenge = fromB64(o.challenge); for (const c of (o.allowCredentials || [])) if (c.id) c.id = fromB64(c.id); return o; };
  const cred = await navigator.credentials.get({ publicKey: conv(opts) });
  return JSON.stringify({ id: cred.id, rawId: toB64(cred.rawId), type: cred.type, response: { clientDataJSON: toB64(cred.response.clientDataJSON), authenticatorData: toB64(cred.response.authenticatorData), signature: toB64(cred.response.signature), userHandle: cred.response.userHandle ? toB64(cred.response.userHandle) : '' }, clientExtensionResults: cred.getClientExtensionResults() });
})()`;

async function main() {
  try { rmSync(PROFILE, { recursive: true, force: true }); } catch {}
  mkdirSync(PROFILE, { recursive: true });
  const chrome = spawn(CHROME, ['--headless=new','--disable-gpu','--no-first-run','--no-default-browser-check',
    '--remote-debugging-port='+PORT,'--user-data-dir='+PROFILE,'--window-size=1280,900','about:blank'], { stdio: 'ignore' });
  try {
    await waitHTTP(`http://127.0.0.1:${PORT}/json/version`);
    const target = await (await fetch(`http://127.0.0.1:${PORT}/json/new?${encodeURIComponent('about:blank')}`, { method: 'PUT' })).json();
    const ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((res, rej) => { ws.addEventListener('open', res); ws.addEventListener('error', rej); });
    const cdp = new CDP(ws);
    await cdp.send('Page.enable'); await cdp.send('Runtime.enable'); await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol:'ctap2', ctap2Version:'ctap2_1', transport:'internal', hasResidentKey:true, hasUserVerification:true, isUserVerified:true, automaticPresenceSimulation:true } });
    await cdp.send('Page.navigate', { url: ORIGIN + '/' }); await sleep(400);
    const evalJS = async (expression) => { const r = await cdp.send('Runtime.evaluate', { expression, awaitPromise:true, returnByValue:true }); if (r.exceptionDetails) throw new Error('JS '+JSON.stringify(r.exceptionDetails)); return r.result.value; };
    let jar = {};
    const cookie = () => Object.entries(jar).map(([k,v]) => k+'='+v).join('; ');
    const remember = (scs) => { for (const sc of scs || []) { const nv = sc.split(';')[0]; const i = nv.indexOf('='); if (i>0) jar[nv.slice(0,i)] = nv.slice(i+1); } };
    const get = async (path) => { const r = await fetch(BASE+path,{redirect:'manual',headers:{Cookie:cookie()}}); const text=await r.text(); remember(r.headers.getSetCookie?r.headers.getSetCookie():[]); return {status:r.status,text,location:r.headers.get('location')}; };
    const post = async (path,fields) => { const r = await fetch(BASE+path,{method:'POST',redirect:'manual',body:new URLSearchParams(fields).toString(),headers:{'Content-Type':'application/x-www-form-urlencoded',Origin:BASE,Referer:BASE+path,Cookie:cookie()}}); const text=await r.text(); remember(r.headers.getSetCookie?r.headers.getSetCookie():[]); return {status:r.status,text,location:r.headers.get('location')}; };
    const csrf = (html) => (html.match(/name="csrf_token" value="([^"]+)"/)||[])[1]||'';
    const hidden = (html,name) => (html.match(new RegExp('name="'+name+'"[^>]*value="([^"]*)"'))||[])[1]||'';
    const optsOf = (html) => { const raw=(html.match(/data-ln-options="([^"]*)"/)||[])[1]||''; return raw?JSON.parse(raw.replaceAll('&quot;','"').replaceAll('&#34;','"').replaceAll('&amp;','&')):null; };
    const insecure = () => { /* fetch jar has no Secure restrictions */ };
    // 1) password + TOTP login
    let r = await get('/login'); let status = r.status;
    r = await post('/login',{csrf_token:csrf(r.text),identifier:USER,password:PASSWORD});
    let mfa = null;
    if (r.status === 303 && (r.location||'').includes('second-factor')) {
      mfa = await get(r.location);
      const payload = { csrf_token: csrf(mfa.text), challenge_id: hidden(mfa.text,'challenge_id'), attempt_token: hidden(mfa.text,'attempt_token'), code: totp(SECRET) };
      mfa = await post('/login/second-factor', payload);
    }
    step('password+totp login', mfa ? mfa.status === 303 : r.status === 303, { status: mfa ? mfa.status : r.status });
    // 2) account security page -> passkey register start/create/finish
    let page = await get('/account/security/passkeys');
    let start = await post('/account/security/passkeys/register', { csrf_token: csrf(page.text) });
    const createOpts = optsOf(start.text), ceremony = hidden(start.text,'ceremony_id');
    await cdp.send('Page.navigate', { url: ORIGIN + '/' }); await sleep(300);
    const credential = await evalJS(CREATE.replace('__OPTS__', JSON.stringify(createOpts && (createOpts.publicKey || createOpts))));
    let finish = await post('/account/security/passkeys/register/finish', { csrf_token: csrf(start.text), ceremony_id: ceremony, passkey_response: credential, name: 'Step159 Virtual Key', current_password: PASSWORD });
    step('passkey register', finish.status === 200, { status: finish.status });
    // 3) logout
    page = await get('/home');
    let logout = await post('/logout', { csrf_token: csrf(page.text) });
    // 4) passwordless login
    page = await get('/login/passkey');
    const getOpts = optsOf(page.text), getCeremony = hidden(page.text,'passkey_ceremony_id');
    await cdp.send('Page.navigate', { url: ORIGIN + '/' }); await sleep(300);
    const assertion = await evalJS(GET.replace('__OPTS__', JSON.stringify(getOpts && (getOpts.publicKey || getOpts))));
    const login = await post('/login/passkey/finish', { csrf_token: csrf(page.text), passkey_ceremony_id: getCeremony, passkey_response: assertion });
    step('passkey passwordless login', login.status === 303, { status: login.status, location: login.location || '' });
    if (login.status === 303) {
      const home = await get('/home');
      step('passwordless session reaches /home', home.status === 200, { status: home.status });
    }
    result.cookieCount = Object.keys(jar).length;
    result.browser = 'Chrome virtual authenticator';
    result.ok = result.steps.every((s) => s.ok);
    writeFileSync(OUT, JSON.stringify(result, null, 2), 'utf8');
    ws.close();
  } finally { chrome.kill('SIGKILL'); }
}
main().then(()=>process.exit(result.ok?0:1)).catch((e)=>{ result.error=String(e&&e.stack||e); try{writeFileSync(OUT,JSON.stringify(result,null,2),'utf8');}catch{} console.error('PASSKEY_LOGIN_FAIL',e); process.exit(1); });
