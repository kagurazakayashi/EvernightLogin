// Persistent test-only WebAuthn virtual-authenticator helper (real Chrome + CDP).
// Usage: node webauthn_session.mjs <baseURL>
// stdin: one JSON per line: {"cmd":"create"|"get","options":{...}}
// stdout: one JSON per line: {"ok":true,"credential":"<json>"} / {"ok":false,"error":"..."}
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { mkdirSync, rmSync } from 'node:fs';

const BASE = process.argv[2] || 'http://127.0.0.1:8080';
const PORT = 9231;
const PROFILE = 'P:/go/tmp/webauthn-session-profile';
const CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitHTTP(url, timeout = 20000) {
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

try { rmSync(PROFILE, { recursive: true, force: true }); } catch {}
mkdirSync(PROFILE, { recursive: true });
const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
  '--remote-debugging-port=' + PORT, '--user-data-dir=' + PROFILE, '--window-size=1280,900', 'about:blank'], { stdio: 'ignore' });
try {
  await waitHTTP(`http://127.0.0.1:${PORT}/json/version`);
  const target = await (await fetch(`http://127.0.0.1:${PORT}/json/new?${encodeURIComponent('about:blank')}`, { method: 'PUT' })).json();
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.addEventListener('open', res); ws.addEventListener('error', rej); });
  const cdp = new CDP(ws);
  await cdp.send('Page.enable'); await cdp.send('Runtime.enable'); await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await cdp.send('Page.navigate', { url: BASE + '/' });
  await sleep(400);
  const evalJS = async (expression) => { const r = await cdp.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }); if (r.exceptionDetails) throw new Error('JS ' + JSON.stringify(r.exceptionDetails)); return r.result.value; };
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let req;
    try {
      req = JSON.parse(line);
      const opts = req.options && (req.options.publicKey || req.options);
      const expression = (req.cmd === 'get' ? GET : CREATE).replace('__OPTS__', JSON.stringify(opts || {}));
      const credential = await evalJS(expression);
      process.stdout.write(JSON.stringify({ ok: true, credential }) + '\n');
    } catch (e) {
      process.stdout.write(JSON.stringify({ ok: false, error: String(e && e.message || e) }) + '\n');
    }
  }
  ws.close();
} catch (e) {
  process.stderr.write('WEBAUTHN_SESSION_FAIL ' + String(e && e.stack || e) + '\n');
  process.exitCode = 1;
} finally {
  chrome.kill('SIGKILL');
}
