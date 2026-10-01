// End-to-end: the native CLI pairs with the real Chrome extension over the
// internet (iroh relays), then the popup lists, searches and fills a login.
// Run: scripts/docker.sh extension-test (needs network access).
import { chromium } from 'playwright';
import { spawn, execFileSync } from 'node:child_process';
import http from 'node:http';
const env = { ...process.env, VAULTI_PASSWORD: 'test-password', VAULTI_NEW_PASSWORD: 'test-password', VAULTI_VAULT: '/tmp/host2.json' };
execFileSync('/bin-vaulti/vaulti', ['init'], { env });
execFileSync('/bin-vaulti/vaulti', ['add', 'Local test', '-u', 'alice@example.org', '--url', 'http://localhost:8097', '--generate', '--totp', 'JBSWY3DPEHPK3PXP'], { env });
execFileSync('/bin-vaulti/vaulti', ['add', 'GitHub', '-u', 'n3amil', '--url', 'https://github.com', '--generate'], { env });
const host = spawn('/bin-vaulti/vaulti', ['pair'], { env });
let out = '';
const ticket = await new Promise((res) => host.stdout.on('data', (d) => {
  out += d; const m = out.match(/vaulti join (\S+)/); if (m) res(m[1]);
  if (/wants to join/.test(out) && !host.answered) { host.answered = true; host.stdin.write('y\n'); }
}));
http.createServer((q, r) => { r.writeHead(200, { 'content-type': 'text/html' });
  r.end('<form><input name="email" type="email"><input name="pw" type="password"><button>Sign in</button></form>'); }).listen(8097);

const ctx = await chromium.launchPersistentContext('/tmp/profile', {
  channel: 'chromium', headless: true,
  args: ['--disable-extensions-except=/ext', '--load-extension=/ext'],
});
let [sw] = ctx.serviceWorkers(); if (!sw) sw = await ctx.waitForEvent('serviceworker');
const fail = (m) => { console.error('FAIL:', m); process.exitCode = 1; };
const extId = sw.url().split('/')[2];
const site = await ctx.newPage(); await site.goto('http://localhost:8097/');
const popup = await ctx.newPage();
popup.on('pageerror', (e) => console.log('[popup error]', e.message));
popup.on('console', (m) => m.type() === 'error' && console.log('[popup console]', m.text()));
// A real popup sees the page's tab as active; here the popup is a tab itself.
await popup.addInitScript(() => {
  const q = chrome.tabs.query.bind(chrome.tabs);
  chrome.tabs.query = async () => (await q({ url: 'http://localhost:8097/*' })).slice(0, 1);
});
await popup.goto(`chrome-extension://${extId}/popup.html`);
await popup.waitForSelector('#screen-pair:not([hidden])');
console.log('device name prefilled:', await popup.inputValue('[name=device]'));
await popup.fill('[name=ticket]', ticket);
await popup.click('#pair-form [type=submit]');
await popup.waitForSelector('#screen-lock:not([hidden])', { timeout: 60000 });
console.log('host saw:', (out.match(/code:\s+(\d{3} \d{3})/) || [])[1]);
await popup.fill('#unlock-form [name=password]', 'test-password');
await popup.click('#unlock-form [type=submit]');
await popup.waitForSelector('#screen-main:not([hidden])', { timeout: 60000 });
await popup.waitForTimeout(3000);
const title = await popup.textContent('#list-title'); console.log('title:', title); if (title !== 'Logins for localhost') fail('list title');
const rows = await popup.$$eval('#entries li .t', (els) => els.map((e) => e.textContent)); console.log('rows:', rows); if (rows.join() !== 'Local test') fail('rows for site');
console.log('totp:', await popup.textContent('#entries .totp'));
console.log('sync:', await popup.textContent('#sync-text'));
await popup.fill('#search', 'git');
const found = await popup.$$eval('#entries li .t', (els) => els.map((e) => e.textContent)); console.log('search rows:', found); if (found.join() !== 'GitHub') fail('search');
await popup.fill('#search', '');
await popup.click('#entries li button.primary');
await site.waitForTimeout(500);
const user = await site.inputValue('[name=email]'); const pwLen = (await site.inputValue('[name=pw]')).length; console.log('filled:', user, '/', pwLen, 'chars'); if (user !== 'alice@example.org' || pwLen < 10) fail('fill');
// Reopen the popup: should stay unlocked via the session key.
const again = await ctx.newPage();
await again.addInitScript(() => { const q = chrome.tabs.query.bind(chrome.tabs); chrome.tabs.query = async () => (await q({ url: 'http://localhost:8097/*' })).slice(0, 1); });
await again.goto(`chrome-extension://${extId}/popup.html`);
await again.waitForTimeout(1500);
const screen = await again.$eval('section:not([hidden])', (s) => s.id); console.log('reopened screen:', screen); if (screen !== 'screen-main') fail('session unlock');
// Copied passwords are cleared after 30 s (background alarm; offscreen page in Chrome).
await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: 'http://localhost:8097' });
const before = await again.evaluate(async () => { const b = [...document.querySelectorAll('#entries li button')].find((x) => /Password|Passwort/.test(x.textContent)); b.click(); await new Promise((r) => setTimeout(r, 300)); return true; });
const readClip = () => site.evaluate(() => navigator.clipboard.readText());
await site.bringToFront();
const copied = await readClip();
console.log('copied length:', copied.length); if (copied.length < 10) fail('copy password');
await site.waitForTimeout(35000);
const after = await readClip();
console.log('after 35 s:', JSON.stringify(after)); if (after.trim() !== '') fail('clipboard not cleared');
host.kill(); await ctx.close(); console.log(process.exitCode ? 'extension-test: FAILED' : 'extension-test: ok'); process.exit(process.exitCode ?? 0);
