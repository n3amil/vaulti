// Clicks through every screen and dialog against a fake backend (mock.js) and
// fails on any script error or error message shown. Run: scripts/docker.sh ui-test
import { chromium } from 'playwright';
import http from 'node:http'; import fs from 'node:fs'; import path from 'node:path';
const mock = fs.readFileSync(new URL('./mock.js', import.meta.url), 'utf8');
http.createServer((q, r) => { const f = path.join('/ui', q.url === '/' ? 'index.html' : q.url); let b = fs.readFileSync(f);
  if (f.endsWith('index.html')) b = b.toString().replace('<script type="module"', `<script>${mock}</script><script type="module"`);
  r.writeHead(200, { 'content-type': f.endsWith('.js') ? 'text/javascript' : f.endsWith('.css') ? 'text/css' : f.endsWith('.svg') ? 'image/svg+xml' : 'text/html' }); r.end(b); }).listen(8099);
const b = await chromium.launch(); const errors = [];
for (const locale of ['de-DE', 'en-US']) {
  const p = await b.newPage({ locale, viewport: { width: 1200, height: 800 } });
  p.on('pageerror', (e) => errors.push(`${locale} pageerror: ${e.message}`));
  // Errors shown to the user land in the toast or a form's [data-error].
  await p.exposeFunction('report', (m) => errors.push(`${locale} shown: ${m}`));
  await p.addInitScript(() => new MutationObserver(() => {
    for (const el of document.querySelectorAll('#toast, [data-error]')) if (/Error|undefined|null/.test(el.textContent)) report(el.textContent);
  }).observe(document, { subtree: true, childList: true, characterData: true }));
  await p.goto('http://localhost:8099/'); await p.waitForTimeout(400);
  const step = async (label, fn) => { try { await fn(); await p.waitForTimeout(250); } catch (e) { errors.push(`${locale} ${label}: ${e.message.split('\n')[0]}`); } };
  const close = () => p.evaluate(() => document.querySelectorAll('dialog[open]').forEach((d) => d.close()));
  await step('select entry', () => p.click('#entry-list li:nth-child(2)'));
  await step('reveal', () => p.click('#detail .field button >> nth=1'));
  await step('copy', () => p.click('#detail .field button >> nth=0'));
  await step('history', () => p.click('text=/Verlauf|History/')); await close();
  await step('edit', () => p.click('#detail .detail-actions button >> nth=0'));
  await step('generate', () => p.click('[data-action=generate]'));
  await step('passphrase', () => p.click('[data-mode=passphrase]'));
  await step('save entry', () => p.click('#entry-form [type=submit]')); await close();
  await step('new entry', () => p.click('#new-entry')); await close();
  await step('new collection', () => p.click('#new-collection')); await close();
  await step('collection', () => p.click('#collection-list button >> nth=0'));
  await step('share', async () => { if (await p.isVisible('#share-collection')) await p.click('#share-collection'); }); await close();
  await step('devices', () => p.click('#open-devices'));
  await step('pair', () => p.click('[data-action=pair]'));
  await step('pair visible', async () => { if (await p.isHidden('[data-pairing]')) throw new Error('pairing panel not shown'); });
  await step('copy ticket', () => p.click('[data-action=copy-ticket]'));
  await step('cancel pair', () => p.click('[data-action=cancel-pair]')); await close();
  await step('contacts', () => p.click('#open-contacts'));
  await step('details', () => p.click('[data-action=details]'));
  await step('copy card', () => p.click('[data-action=copy-card]')); await close();
  await step('settings', () => p.click('#open-settings'));
  await step('language', () => p.selectOption('#language', locale === 'de-DE' ? 'en' : 'de')); await close();
  await step('trash', () => p.click('[data-collection=trash]'));
  await step('trash entry', () => p.click('#entry-list li:first-child'));
  await step('sync now', () => p.click('#sync-status'));
  await step('lock', () => p.click('#lock-now'));
  await p.close();
}
console.log(errors.length ? errors.join('\n') : 'smoke: no errors'); process.exit(errors.length ? 1 : 0);
