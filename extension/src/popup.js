// Vaulti browser extension popup. The extension is its own Vaulti device: it
// was paired like a phone, keeps the encrypted vault file in extension storage
// and syncs P2P via WebAssembly. All user data is rendered with textContent.

import init, { join, Device } from './pkg/vaulti_wasm.js';
import { t, translatePage, translateError } from './i18n.js';

const $ = (sel, root = document) => root.querySelector(sel);
const LOCK_AFTER_MS = 5 * 60 * 1000;

let device = null; // unlocked Device
let pending = null; // received during pairing, not yet unlocked
let tab = null;

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const c of children) if (c != null) el.append(c);
  return el;
}

function show(name) {
  for (const s of document.querySelectorAll('section')) s.hidden = s.id !== `screen-${name}`;
  $(`#screen-${name} [autofocus]`)?.focus();
}

let toastTimer;
function toast(msg) {
  const el = $('#toast');
  el.textContent = translateError(msg);
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.hidden = true), 2000);
}

function setError(root, msg) {
  const el = $('[data-error]', root);
  if (el) el.textContent = msg ? translateError(msg) : '';
}

// --- storage -------------------------------------------------------------------------

const loadFile = async () => (await chrome.storage.local.get('vault')).vault ?? null;
const saveFile = (json) => chrome.storage.local.set({ vault: json });

const toB64 = (bytes) => btoa(String.fromCharCode(...bytes));
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

/** Keeps the vault key in session-only memory and (re)starts the auto-lock timer. */
async function touch() {
  if (!device) return;
  await chrome.storage.session.set({ key: toB64(device.sessionKey()), until: Date.now() + LOCK_AFTER_MS });
  chrome.runtime.sendMessage('touch').catch(() => {});
}

async function lock() {
  await chrome.storage.session.clear();
  device = null;
  $('#unlock-form').reset();
  $('#lock-hint').hidden = true;
  show('lock');
}

// --- start ---------------------------------------------------------------------------

async function boot() {
  translatePage();
  await init();
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const file = await loadFile();
  if (!file) {
    $('#pair-form').elements.device.value = navigator.userAgent.includes('Firefox') ? 'Firefox' : 'Chrome';
    return show('pair');
  }
  const { key, until } = await chrome.storage.session.get(['key', 'until']);
  if (key && until > Date.now()) {
    try {
      device = Device.unlockWithSessionKey(file, fromB64(key));
      return enterMain();
    } catch {
      await chrome.storage.session.clear();
    }
  }
  show('lock');
}

// --- pairing -------------------------------------------------------------------------

$('#pair-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  const submit = $('[data-submit]', form);
  setError(form, '');
  submit.disabled = true;
  submit.textContent = t('Connecting…');
  try {
    pending = await join(form.elements.ticket.value.trim(), form.elements.device.value.trim() || 'Browser', (code) => {
      $('[data-code]', form).textContent = code;
      $('#pair-code').hidden = false;
      submit.textContent = t('Waiting for confirmation…');
    });
    $('#lock-hint').hidden = false;
    show('lock');
  } catch (err) {
    setError(form, err.message || err);
  } finally {
    $('#pair-code').hidden = true;
    submit.disabled = false;
    submit.textContent = t('Connect');
  }
});

// --- unlock --------------------------------------------------------------------------

$('#unlock-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  const pw = form.elements.password;
  const button = $('[type=submit]', form);
  setError(form, '');
  button.disabled = true;
  try {
    // Argon2 takes a moment; let the button state paint first.
    await new Promise((r) => setTimeout(r, 30));
    if (pending) {
      device = pending.unlock(pw.value);
      pending = null;
    } else {
      device = Device.unlock(await loadFile(), pw.value);
    }
    pw.value = '';
    await saveFile(device.toFile());
    await enterMain();
  } catch (err) {
    pw.select();
    setError(form, /decrypt|password/i.test(err.message || err) ? t('Wrong master password') : err.message || err);
  } finally {
    button.disabled = false;
  }
});

$('#lock').addEventListener('click', lock);

// --- main list -----------------------------------------------------------------------

function avatar(title) {
  let hash = 0;
  for (const ch of title) hash = (hash * 31 + ch.codePointAt(0)) | 0;
  const el = h('div', { class: 'avatar', text: [...title.trim()][0] || '?' });
  el.style.backgroundColor = `hsl(${Math.abs(hash) % 360} 50% 45%)`;
  return el;
}

const pageHost = () => {
  try {
    return new URL(tab.url).hostname.replace(/^www\./, '');
  } catch {
    return '';
  }
};

async function enterMain() {
  await touch();
  show('main');
  render();
  sync();
}

function render() {
  const q = $('#search').value.trim().toLowerCase();
  const forPage = tab?.url ? JSON.parse(device.entriesFor(tab.url)) : [];
  const matching = new Set(forPage.map((e) => e.id));
  let list;
  if (q) {
    list = JSON.parse(device.entries()).filter((e) => [e.title, e.username, e.url].some((v) => v && v.toLowerCase().includes(q)));
    $('#list-title').textContent = t('All logins');
  } else {
    list = forPage;
    $('#list-title').textContent = pageHost() ? t('Logins for {site}', { site: pageHost() }) : t('All logins');
  }
  $('#empty').hidden = list.length > 0;
  $('#empty').textContent = q ? t('No matches.') : t('No logins for this site. Search to find others.');
  $('#entries').replaceChildren(...list.map((e) => row(e, matching.has(e.id))));
}

$('#search').addEventListener('input', () => {
  render();
  touch();
});

function row(e, forThisPage) {
  const actions = h('div', { class: 'actions' });
  if (forThisPage) actions.append(h('button', { class: 'primary', text: t('Fill'), onclick: () => fill(e) }));
  if (e.username) actions.append(h('button', { text: t('Username'), onclick: () => copy(secret(e).username, t('Username')) }));
  actions.append(h('button', { text: t('Password'), onclick: () => copy(secret(e).password, t('Password')) }));
  if (e.has_totp) {
    const code = h('button', { class: 'totp', text: '··· ···', onclick: () => copy(JSON.parse(device.totp(e.id)).code, t('Code')) });
    const tick = () => {
      if (!document.body.contains(code)) return clearInterval(timer);
      const { code: c, remaining } = JSON.parse(device.totp(e.id));
      code.textContent = `${c.slice(0, c.length / 2)} ${c.slice(c.length / 2)} · ${remaining}s`;
    };
    const timer = setInterval(tick, 1000);
    queueMicrotask(tick);
    actions.append(code);
  }
  return h(
    'li',
    {},
    avatar(e.title),
    h('div', { class: 'text' }, h('div', { class: 't', text: e.title }), h('div', { class: 'u', text: e.username || e.collection })),
    actions,
  );
}

const secret = (e) => JSON.parse(device.secret(e.id));

async function copy(value, label) {
  await navigator.clipboard.writeText(value);
  toast(t('{label} copied', { label }));
  touch();
}

// --- filling -------------------------------------------------------------------------

/** Runs inside the page: fills the visible login fields and tells the page it changed. */
function fillPage(username, password) {
  const visible = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) && !el.disabled && !el.readOnly;
  const set = (el, value) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    el.focus();
    setter.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };
  const inputs = [...document.querySelectorAll('input')].filter(visible);
  const pw = inputs.find((i) => i.type === 'password');
  const userTypes = ['text', 'email', 'tel', ''];
  let user = null;
  if (pw) {
    const before = inputs.slice(0, inputs.indexOf(pw)).filter((i) => userTypes.includes(i.type));
    user = before.at(-1) ?? null;
  } else {
    // Two-step logins: username page without a password field.
    user = inputs.find((i) => userTypes.includes(i.type) && /user|mail|login|name|account/i.test(i.name + i.id + i.autocomplete)) ?? null;
  }
  if (user && username) set(user, username);
  if (pw) set(pw, password);
  return { user: !!user, password: !!pw };
}

async function fill(e) {
  const s = secret(e);
  try {
    const [res] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: fillPage, args: [s.username ?? '', s.password] });
    if (!res?.result?.user && !res?.result?.password) return toast(t('No login form found on this page'));
    window.close();
  } catch (err) {
    toast(err.message || err);
  }
}

// --- sync ----------------------------------------------------------------------------

async function sync() {
  const dot = $('#sync-dot');
  const text = $('#sync-text');
  dot.className = 'dot';
  text.textContent = t('Syncing…');
  try {
    await device.startSync((json) => {
      saveFile(json);
      render();
    });
    const ok = await device.syncNow();
    dot.className = ok ? 'dot ok' : 'dot warn';
    text.textContent = ok ? t('Synced with {n} devices', { n: ok }) : t('Other devices offline');
  } catch (err) {
    dot.className = 'dot warn';
    text.textContent = translateError(err.message || err);
  }
}

boot().catch((err) => {
  document.body.replaceChildren(h('p', { class: 'error', text: t('Failed to start: {err}', { err: translateError(err.message || err) }) }));
});
