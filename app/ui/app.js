// Vaulti UI. Plain JS, no build step. All user data is rendered with
// textContent (never innerHTML) — this is a password manager.

import { t, translateError, translatePage, setRich, lang, langPref, setLangPref, LANGUAGES } from './i18n.js';
import { friendlyName } from './names.js';

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const $ = (sel, root = document) => root.querySelector(sel);

const AUTO_LOCK_MS = 5 * 60 * 1000;
const MASK = '••••••••••••';

const state = {
  overview: null,   // { collections, entries } without passwords
  collection: null, // selected collection id, null = all
  entry: null,      // selected entry id
  query: '',
  unlocked: false,
  afterBackup: null,
  platform: 'desktop',
};

const isPhone = () => window.matchMedia('(max-width: 760px)').matches;

// --- helpers -----------------------------------------------------------------

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
  for (const s of document.querySelectorAll('.screen')) s.hidden = s.id !== `screen-${name}`;
  $(`#screen-${name} [autofocus]`)?.focus();
}

let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = translateError(msg);
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 2200);
}

function setError(root, msg) {
  const el = $('[data-error]', root);
  if (el) el.textContent = msg ? translateError(msg) : '';
}

async function busy(button, fn) {
  button.disabled = true;
  try {
    return await fn();
  } finally {
    button.disabled = false;
  }
}

function confirmDialog(message, okLabel = t('Delete')) {
  const d = $('#confirm-dialog');
  $('[data-message]', d).textContent = message;
  $('[data-ok]', d).textContent = okLabel;
  d.returnValue = '';
  d.showModal();
  return new Promise((resolve) => d.addEventListener('close', () => resolve(d.returnValue === 'yes'), { once: true }));
}

function avatar(title) {
  let hash = 0;
  for (const ch of title) hash = (hash * 31 + ch.codePointAt(0)) | 0;
  const el = h('div', { class: 'avatar', text: [...title.trim()][0] || '?' });
  el.style.backgroundColor = `hsl(${Math.abs(hash) % 360} 50% 45%)`;
  return el;
}

const collectionById = (id) => state.overview?.collections.find((c) => c.id === id);
const collectionName = (id) => collectionById(id)?.name ?? '';
const canWrite = (c) => c && (c.my_role === 'owner' || c.my_role === 'editor');
const writableCollections = () => state.overview.collections.filter(canWrite);

function timeAgo(secs) {
  const d = Math.max(0, Math.round(Date.now() / 1000 - secs));
  if (d < 60) return t('just now');
  if (d < 3600) return t('{n} min ago', { n: Math.floor(d / 60) });
  return new Date(secs * 1000).toLocaleTimeString(lang, { hour: '2-digit', minute: '2-digit' });
}

// --- auth flows ----------------------------------------------------------------

async function boot() {
  translatePage();
  renderLanguageSelect();
  state.platform = await invoke('platform');
  document.documentElement.dataset.platform = state.platform;
  document.documentElement.dataset.mobile = String(isMobile());
  if (isMobile()) setupMobile();
  const s = await invoke('status');
  $('#vault-path').textContent = s.path;
  if (s.pending_join) showJoinStep('password');
  else if (!s.exists) show('setup');
  else if (!s.unlocked) show('lock');
  else await enterMain();
}

function showBackup(code, next) {
  $('#backup-code').textContent = code.replaceAll('-', ' ');
  $('#backup-ack').checked = false;
  $('#backup-done').disabled = true;
  state.afterBackup = next;
  show('backup');
}

$('#backup-ack').addEventListener('change', (e) => ($('#backup-done').disabled = !e.target.checked));
$('#backup-done').addEventListener('click', () => {
  $('#backup-code').textContent = '';
  state.afterBackup?.();
});

$('#setup-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  const { password, repeat } = form.elements;
  if (password.value !== repeat.value) return setError(form, t('Passwords do not match'));
  setError(form, '');
  await busy(form.querySelector('[type=submit]'), async () => {
    try {
      const code = await invoke('create_vault', { password: password.value });
      form.reset();
      await localizeDefaultCollection();
      showBackup(code, enterMain);
    } catch (err) {
      setError(form, err);
    }
  });
});

$('#unlock-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  const pw = form.elements.password;
  setError(form, '');
  await busy(form.querySelector('[type=submit]'), async () => {
    try {
      await invoke('unlock', { password: pw.value });
      pw.value = '';
      await enterMain();
    } catch (err) {
      pw.select();
      setError(form, err);
    }
  });
});

// --- phones (Android, iOS) -----------------------------------------------------------------

const isMobile = () => state.platform === 'android' || state.platform === 'ios';

// On phones pairing means scanning the other device's QR code.
function setupMobile() {
  $('#join-intro').dataset.i18n =
    'On your other device open **Devices → Pair new device** and scan the QR code shown there. Both devices need to be online.';
  translatePage($('#screen-join'));
  $('#scan-ticket').hidden = false;

  // Lock when the app was in the background for more than a minute.
  let hiddenAt = 0;
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) hiddenAt = Date.now();
    else if (state.unlocked && hiddenAt && Date.now() - hiddenAt > 60_000) lock();
  });
}

async function scanQr() {
  const scanner = window.__TAURI__.barcodeScanner;
  if (scanner) {
    if ((await scanner.checkPermissions()) !== 'granted' && (await scanner.requestPermissions()) !== 'granted') {
      throw new Error(t('Camera permission is needed to scan the code. You can paste it instead.'));
    }
    return (await scanner.scan({ windowed: false, formats: ['QR_CODE'] })).content;
  }
  return (await invoke('plugin:barcode-scanner|scan', { windowed: false, formats: ['QR_CODE'] })).content;
}

$('#scan-ticket').addEventListener('click', async () => {
  setError(joinForm, '');
  try {
    const content = await scanQr();
    if (!content?.startsWith('vaulti-pair:')) throw new Error(t("That QR code isn't a Vaulti pairing code"));
    joinForm.elements.ticket.value = content;
    if (!joinForm.elements.device.value) joinForm.elements.device.value = state.platform === 'ios' ? 'iPhone' : 'Android';
    joinForm.requestSubmit();
  } catch (err) {
    if (String(err) !== 'cancelled') setError(joinForm, err.message || String(err));
  }
});

// --- phone navigation: one pane at a time, Android back button goes back ---------------------

function setView(view) {
  const main = $('#screen-main');
  if (!isPhone() || main.dataset.view === view) return;
  if (view !== 'list') history.pushState({ view }, '');
  main.dataset.view = view;
}

window.addEventListener('popstate', () => {
  $('#screen-main').dataset.view = 'list';
});

function backToList() {
  if (history.state?.view) history.back();
  else $('#screen-main').dataset.view = 'list';
}

$('#open-nav').addEventListener('click', () => setView('nav'));
$('#close-nav').addEventListener('click', backToList);

// --- join from another device ---------------------------------------------------------

const joinForm = $('#join-form');
let joinStep = 'ticket';

function showJoinStep(step) {
  joinStep = step;
  for (const el of joinForm.querySelectorAll('[data-step]')) el.hidden = el.dataset.step !== step;
  $('[data-submit]', joinForm).textContent = step === 'ticket' ? t('Connect') : t('Unlock');
  setError(joinForm, '');
  show('join');
  (step === 'ticket' ? joinForm.elements.ticket : joinForm.elements.password).focus();
}

$('#go-join').addEventListener('click', () => {
  joinForm.reset();
  showJoinStep('ticket');
});
$('#back-to-setup').addEventListener('click', async () => {
  await invoke('join_cancel');
  joinForm.reset();
  show('setup');
});

joinForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = joinForm.elements;
  setError(joinForm, '');
  await busy($('[data-submit]', joinForm), async () => {
    try {
      if (joinStep === 'ticket') {
        $('[data-submit]', joinForm).textContent = t('Connecting…');
        try {
          await invoke('join_fetch', { ticket: f.ticket.value, deviceName: f.device.value });
        } finally {
          $('[data-join-code]', joinForm).hidden = true;
        }
        showJoinStep('password');
      } else {
        await invoke('join_unlock', { password: f.password.value });
        joinForm.reset();
        await enterMain();
        toast(t('This device is now paired'));
      }
    } catch (err) {
      if (joinStep === 'ticket') $('[data-submit]', joinForm).textContent = t('Connect');
      setError(joinForm, err);
    }
  });
});

$('#go-recover').addEventListener('click', () => show('recover'));
$('#back-to-lock').addEventListener('click', () => show('lock'));

$('#recover-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  const { code, password, repeat } = form.elements;
  if (password.value !== repeat.value) return setError(form, t('Passwords do not match'));
  setError(form, '');
  await busy(form.querySelector('[type=submit]'), async () => {
    try {
      const newCode = await invoke('recover', { code: code.value, newPassword: password.value });
      form.reset();
      showBackup(newCode, enterMain);
    } catch (err) {
      setError(form, err);
    }
  });
});

async function lock() {
  await invoke('lock');
  state.unlocked = false;
  Object.assign(state, { overview: null, entry: null, collection: null, query: '' });
  for (const d of document.querySelectorAll('dialog[open]')) d.close();
  $('#entry-list').replaceChildren();
  $('#collection-list').replaceChildren();
  $('#detail').replaceChildren(h('p', { class: 'muted empty', text: t('Select an entry') }));
  $('#search').value = '';
  renderSyncStatus(null);
  stopTotp();
  $('#screen-main').dataset.view = 'list';
  show('lock');
}

$('#lock-now').addEventListener('click', lock);

// --- idle auto-lock ---------------------------------------------------------------

let lastActivity = Date.now();
for (const ev of ['mousemove', 'mousedown', 'keydown', 'wheel', 'touchstart']) {
  window.addEventListener(ev, () => (lastActivity = Date.now()), { passive: true });
}
setInterval(() => {
  if (state.unlocked && Date.now() - lastActivity > AUTO_LOCK_MS) lock();
}, 10_000);

// --- main view --------------------------------------------------------------------

async function enterMain() {
  state.unlocked = true;
  lastActivity = Date.now();
  await refresh();
  renderSyncStatus(await invoke('sync_status'));
  show('main');
}

async function refresh() {
  state.overview = await invoke('overview');
  if (state.collection && !state.overview.collections.some((c) => c.id === state.collection)) state.collection = null;
  renderSidebar();
  renderList();
  if (state.entry && state.overview.entries.some((e) => e.id === state.entry)) await renderDetail();
  else clearDetail();
}

function renderSidebar() {
  const { collections, entries } = state.overview;
  $('#count-all').textContent = entries.length;
  $('[data-collection=""]').classList.toggle('active', state.collection === null);
  $('#collection-list').replaceChildren(
    ...collections
      .slice()
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((c) =>
        h(
          'button',
          {
            class: 'nav-item' + (c.id === state.collection ? ' active' : ''),
            onclick: () => selectCollection(c.id),
          },
          h('span', { class: 'name' }, c.name, c.members.length > 1 ? h('span', { class: 'badge', text: t('shared') }) : null),
          h('span', { class: 'count', text: c.count }),
        ),
      ),
  );
}

function visibleEntries() {
  const q = state.query.trim().toLowerCase();
  return state.overview.entries
    .filter((e) => state.collection === null || e.collection_id === state.collection)
    .filter((e) => !q || [e.title, e.username, e.url].some((v) => v && v.toLowerCase().includes(q)))
    .sort((a, b) => a.title.localeCompare(b.title));
}

function renderList() {
  const rows = visibleEntries();
  const c = collectionById(state.collection);
  $('#list-title').textContent = c ? c.name : t('All items');
  $('#edit-collection').hidden = c?.my_role !== 'owner';
  $('#share-collection').hidden = c?.my_role !== 'owner';
  const info = $('#collection-info');
  info.hidden = !c || c.members.length < 2;
  if (c && c.my_role !== 'owner') {
    info.textContent = t(c.my_role === 'viewer' ? 'Shared by {name} · view only' : 'Shared by {name} · you can edit', { name: c.owner_name });
  } else if (c) {
    info.textContent = t('Shared with {names}', { names: c.members.filter((m) => !m.is_me).map((m) => m.name).join(', ') });
  }
  $('#new-entry').disabled = c ? !canWrite(c) : writableCollections().length === 0;
  $('#empty-list').hidden = rows.length > 0;
  $('#empty-list').textContent = state.query ? t('No matches.') : t('No entries yet.');
  $('#entry-list').replaceChildren(
    ...rows.map((e) =>
      h(
        'li',
        { class: e.id === state.entry ? 'active' : '', onclick: () => selectEntry(e.id) },
        avatar(e.title),
        h(
          'div',
          { class: 'entry-text' },
          h('div', { class: 't', text: e.title }),
          h('div', { class: 'u', text: e.username || (state.collection ? '' : collectionName(e.collection_id)) }),
        ),
      ),
    ),
  );
}

function selectCollection(id) {
  state.collection = id;
  renderSidebar();
  renderList();
  if ($('#screen-main').dataset.view === 'nav') backToList();
}
$('[data-collection=""]').addEventListener('click', () => selectCollection(null));

$('#search').addEventListener('input', (e) => {
  state.query = e.target.value;
  renderList();
});

async function selectEntry(id) {
  state.entry = id;
  renderList();
  await renderDetail();
  setView('detail');
}

function clearDetail() {
  stopTotp();
  state.entry = null;
  $('#detail').replaceChildren(h('p', { class: 'muted empty', text: t('Select an entry') }));
}

async function copy(id, field, label) {
  try {
    await invoke('copy_field', { id, field });
    toast(field === 'password' || field === 'totp' ? t(field === 'totp' ? 'Code copied, clears in 30 s' : 'Password copied, clears in 30 s') : t('{label} copied', { label }));
  } catch (err) {
    toast(String(err));
  }
}

let totpTimer = null;
function stopTotp() {
  clearInterval(totpTimer);
  totpTimer = null;
}

function startTotp(id, codeEl, leftEl) {
  stopTotp();
  let remaining = 0;
  const fetchCode = async () => {
    try {
      const t = await invoke('totp_code', { id });
      const c = t.code;
      codeEl.textContent = c.length === 6 ? `${c.slice(0, 3)} ${c.slice(3)}` : c.length === 8 ? `${c.slice(0, 4)} ${c.slice(4)}` : c;
      remaining = t.remaining;
    } catch (err) {
      codeEl.textContent = '—';
      leftEl.textContent = '';
      stopTotp();
    }
  };
  const tick = async () => {
    if (!document.body.contains(codeEl)) return stopTotp();
    if (remaining <= 0) await fetchCode();
    leftEl.textContent = `${remaining}s`;
    leftEl.classList.toggle('soon', remaining <= 5);
    remaining -= 1;
  };
  tick();
  totpTimer = setInterval(tick, 1000);
}

async function renderDetail() {
  stopTotp();
  const e = await invoke('get_entry', { id: state.entry });
  let revealed = false;
  const pwText = h('span', { class: 'mono', text: MASK });
  const revealBtn = h('button', {
    text: t('Show'),
    onclick: () => {
      revealed = !revealed;
      pwText.textContent = revealed ? e.password : MASK;
      revealBtn.textContent = revealed ? t('Hide') : t('Show');
    },
  });

  const field = (label, value, ...buttons) =>
    h('div', { class: 'field' }, h('div', { class: 'k', text: label }), h('div', { class: 'v' }, value, ...buttons));

  const fields = [];
  if (e.username) {
    fields.push(field(t('Username'), h('span', { text: e.username }), h('button', { text: t('Copy'), onclick: () => copy(e.id, 'username', t('Username')) })));
  }
  fields.push(field(t('Password'), pwText, revealBtn, h('button', { text: t('Copy'), onclick: () => copy(e.id, 'password') })));
  if (e.totp) {
    const code = h('span', { class: 'totp-code', text: '··· ···' });
    const left = h('span', { class: 'totp-left' });
    fields.push(field(t('One-time code'), code, left, h('button', { text: t('Copy'), onclick: () => copy(e.id, 'totp') })));
    startTotp(e.id, code, left);
  }
  if (e.url) fields.push(field(t('Website'), h('span', { text: e.url }), h('button', { text: t('Copy'), onclick: () => copy(e.id, 'url', t('Website')) })));
  if (e.notes) fields.push(field(t('Notes'), h('span', { text: e.notes })));

  const writable = canWrite(collectionById(e.collection_id));
  $('#detail').replaceChildren(
    h('button', { class: 'link mobile-only back', text: t('‹ Back'), onclick: backToList }),
    h('div', { class: 'detail-head' }, avatar(e.title), h('div', {}, h('h2', { text: e.title }), h('div', { class: 'muted', text: collectionName(e.collection_id) }))),
    ...fields,
    writable
      ? h(
          'div',
          { class: 'detail-actions' },
          h('button', { text: t('Edit'), onclick: () => openEntryDialog(e) }),
          h('button', { class: 'danger', text: t('Delete'), onclick: () => deleteEntry(e) }),
        )
      : h('p', { class: 'muted small', text: t('View only: this collection is shared with you read-only.') }),
    h('div', { class: 'meta', text: t('Updated {date}', { date: new Date(e.updated_at * 1000).toLocaleString(lang) }) }),
  );
}

async function deleteEntry(e) {
  if (!(await confirmDialog(t('Delete "{title}"? This can\'t be undone.', { title: e.title })))) return;
  try {
    await invoke('delete_entry', { id: e.id });
    state.entry = null;
    if ($('#screen-main').dataset.view === 'detail') backToList();
    await refresh();
    toast(t('Entry deleted'));
  } catch (err) {
    toast(String(err));
  }
}

// --- entry dialog ---------------------------------------------------------------------

const entryDialog = $('#entry-dialog');
const entryForm = $('#entry-form');
let editing = null;

function openEntryDialog(existing = null) {
  editing = existing;
  const f = entryForm.elements;
  entryForm.reset();
  setError(entryForm, '');
  $('[data-title]', entryForm).textContent = existing ? t('Edit entry') : t('New entry');
  f.password.type = 'password';
  $('[data-action=reveal]', entryForm).textContent = t('Show');
  $('[data-generator]', entryForm).hidden = true;
  applyGenPrefs();

  f.collection.replaceChildren(
    ...writableCollections()
      .slice()
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((c) => h('option', { value: c.id, text: c.name })),
  );
  const preferred = canWrite(collectionById(state.collection)) ? state.collection : null;
  f.collection.value = existing?.collection_id ?? preferred ?? writableCollections()[0]?.id;

  if (existing) {
    f.title.value = existing.title;
    f.username.value = existing.username ?? '';
    f.password.value = existing.password;
    f.url.value = existing.url ?? '';
    f.notes.value = existing.notes ?? '';
    f.totp.value = existing.totp ?? '';
  }
  checkTotpField();
  entryDialog.showModal();
  f.title.focus();
}

$('#new-entry').addEventListener('click', () => openEntryDialog());

entryForm.addEventListener('click', async (e) => {
  const action = e.target.dataset?.action;
  const pw = entryForm.elements.password;
  if (action === 'cancel') entryDialog.close();
  if (action === 'reveal') {
    pw.type = pw.type === 'password' ? 'text' : 'password';
    e.target.textContent = pw.type === 'password' ? t('Show') : t('Hide');
  }
  if (action === 'generate') {
    const panel = $('[data-generator]', entryForm);
    panel.hidden = !panel.hidden;
    if (!panel.hidden) await generatePreview();
  }
  if (e.target.dataset?.mode) {
    genPrefs.mode = e.target.dataset.mode;
    applyGenPrefs();
    await generatePreview();
  }
  if (action === 'regen') await generatePreview();
  if (action === 'use') {
    pw.value = genPreview;
    pw.type = 'text';
    $('[data-action=reveal]', entryForm).textContent = t('Hide');
    $('[data-generator]', entryForm).hidden = true;
  }
  if (action === 'scan-totp') {
    try {
      entryForm.elements.totp.value = await scanQr();
      checkTotpField();
    } catch (err) {
      if (String(err) !== 'cancelled') setError(entryForm, err.message || String(err));
    }
  }
});

// --- password / passphrase generator (settings remembered per device) ---

const GEN_KEY = 'vaulti.generator';
const GEN_DEFAULTS = {
  mode: 'password', length: 20, upper: true, lower: true, digits: true, symbols: true, ambiguous: false,
  words: 5, sep: '-', sepCustom: '', cap: false, num: false,
};
let genPrefs = { ...GEN_DEFAULTS };
try {
  genPrefs = { ...GEN_DEFAULTS, ...JSON.parse(localStorage.getItem(GEN_KEY) || '{}') };
} catch {}
let genPreview = '';

function saveGenPrefs() {
  try {
    localStorage.setItem(GEN_KEY, JSON.stringify(genPrefs));
  } catch {}
}

function applyGenPrefs() {
  const f = entryForm.elements;
  for (const b of entryForm.querySelectorAll('[data-mode]')) b.classList.toggle('on', b.dataset.mode === genPrefs.mode);
  $('[data-gen=password]', entryForm).hidden = genPrefs.mode !== 'password';
  $('[data-gen=passphrase]', entryForm).hidden = genPrefs.mode !== 'passphrase';
  f.g_length.value = genPrefs.length;
  f.g_upper.checked = genPrefs.upper;
  f.g_lower.checked = genPrefs.lower;
  f.g_digits.checked = genPrefs.digits;
  f.g_symbols.checked = genPrefs.symbols;
  f.g_ambiguous.checked = genPrefs.ambiguous;
  f.g_words.value = genPrefs.words;
  const known = [...f.g_sep.options].some((o) => o.value === genPrefs.sep);
  f.g_sep.value = known ? genPrefs.sep : 'custom';
  f.g_sep_custom.value = genPrefs.sepCustom;
  f.g_sep_custom.hidden = f.g_sep.value !== 'custom';
  f.g_cap.checked = genPrefs.cap;
  f.g_num.checked = genPrefs.num;
  $('[data-out=length]', entryForm).textContent = genPrefs.length;
  $('[data-out=words]', entryForm).textContent = genPrefs.words;
}

function readGenPrefs() {
  const f = entryForm.elements;
  Object.assign(genPrefs, {
    length: Number(f.g_length.value),
    upper: f.g_upper.checked,
    lower: f.g_lower.checked,
    digits: f.g_digits.checked,
    symbols: f.g_symbols.checked,
    ambiguous: f.g_ambiguous.checked,
    words: Number(f.g_words.value),
    sep: f.g_sep.value === 'custom' ? f.g_sep_custom.value : f.g_sep.value,
    sepCustom: f.g_sep_custom.value,
    cap: f.g_cap.checked,
    num: f.g_num.checked,
  });
  f.g_sep_custom.hidden = f.g_sep.value !== 'custom';
  $('[data-out=length]', entryForm).textContent = genPrefs.length;
  $('[data-out=words]', entryForm).textContent = genPrefs.words;
  saveGenPrefs();
}

function strengthLabel(bits) {
  if (bits < 50) return ['weak', t('Weak')];
  if (bits < 70) return ['fair', t('Fair')];
  if (bits < 100) return ['strong', t('Strong')];
  return ['great', t('Very strong')];
}

async function generatePreview() {
  const out = $('[data-preview]', entryForm);
  const strength = $('[data-strength]', entryForm);
  try {
    const g =
      genPrefs.mode === 'passphrase'
        ? await invoke('generate_passphrase', {
            spec: { words: genPrefs.words, separator: genPrefs.sep, capitalize: genPrefs.cap, include_number: genPrefs.num },
          })
        : await invoke('generate_password', {
            spec: {
              length: genPrefs.length,
              lower: genPrefs.lower,
              upper: genPrefs.upper,
              digits: genPrefs.digits,
              symbols: genPrefs.symbols,
              avoid_ambiguous: genPrefs.ambiguous,
            },
          });
    genPreview = g.value;
    out.textContent = g.value;
    const [cls, label] = strengthLabel(g.bits);
    strength.className = `strength ${cls}`;
    strength.textContent = t('{label} · ~{bits} bits', { label, bits: Math.round(g.bits) });
    $('[data-action=use]', entryForm).disabled = false;
  } catch (err) {
    genPreview = '';
    out.textContent = '';
    strength.className = 'strength weak';
    strength.textContent = translateError(err);
    $('[data-action=use]', entryForm).disabled = true;
  }
}

for (const el of entryForm.querySelectorAll('[data-generator] input, [data-generator] select')) {
  el.addEventListener('input', async () => {
    readGenPrefs();
    await generatePreview();
  });
}

// --- TOTP field validation while typing ---

let totpCheck = 0;
async function checkTotpField() {
  const hint = $('[data-totp-hint]', entryForm);
  const value = entryForm.elements.totp.value.trim();
  const mine = ++totpCheck;
  if (!value) {
    hint.textContent = '';
    hint.classList.remove('bad');
    return;
  }
  try {
    const label = await invoke('check_totp', { totp: value });
    if (mine !== totpCheck) return;
    hint.textContent = label ? t('✓ Valid ({label})', { label }) : t('✓ Valid');
    hint.classList.remove('bad');
  } catch (err) {
    if (mine !== totpCheck) return;
    hint.textContent = translateError(err);
    hint.classList.add('bad');
  }
}
entryForm.elements.totp.addEventListener('input', checkTotpField);

entryForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = entryForm.elements;
  const entry = {
    title: f.title.value,
    username: f.username.value,
    password: f.password.value,
    url: f.url.value,
    notes: f.notes.value,
    totp: f.totp.value,
  };
  const collectionId = f.collection.value;
  const wasEditing = editing;
  await busy(entryForm.querySelector('[type=submit]'), async () => {
    try {
      const id = wasEditing
        ? await invoke('update_entry', { id: wasEditing.id, collectionId, entry })
        : await invoke('add_entry', { collectionId, entry });
      entryDialog.close();
      entryForm.reset();
      state.entry = id;
      if (state.collection && state.collection !== collectionId) state.collection = collectionId;
      await refresh();
      toast(wasEditing ? t('Saved') : t('Entry added'));
    } catch (err) {
      setError(entryForm, err);
    }
  });
});

entryDialog.addEventListener('close', () => {
  entryForm.elements.password.value = '';
  entryForm.elements.totp.value = '';
  genPreview = '';
  $('[data-preview]', entryForm).textContent = '';
  editing = null;
});

// --- collection dialog -------------------------------------------------------------------

const collectionDialog = $('#collection-dialog');
const collectionForm = $('#collection-form');
let editingCollection = null;

function openCollectionDialog(id = null) {
  editingCollection = id;
  collectionForm.reset();
  setError(collectionForm, '');
  $('[data-title]', collectionForm).textContent = id ? t('Edit collection') : t('New collection');
  $('[data-action=delete]', collectionForm).hidden = !id;
  if (id) collectionForm.elements.name.value = collectionName(id);
  collectionDialog.showModal();
  collectionForm.elements.name.focus();
}

$('#new-collection').addEventListener('click', () => openCollectionDialog());
$('#edit-collection').addEventListener('click', () => openCollectionDialog(state.collection));

collectionForm.addEventListener('click', async (e) => {
  const action = e.target.dataset?.action;
  if (action === 'cancel') collectionDialog.close();
  if (action === 'delete') {
    const c = state.overview.collections.find((c) => c.id === editingCollection);
    collectionDialog.close();
    const msg = c.count
      ? t('Delete "{name}" and its {n} entries? This can\'t be undone.', { name: c.name, n: c.count })
      : t('Delete "{name}"?', { name: c.name });
    if (!(await confirmDialog(msg))) return;
    try {
      await invoke('delete_collection', { id: c.id });
      state.collection = null;
      await refresh();
      toast(t('Collection deleted'));
    } catch (err) {
      toast(String(err));
    }
  }
});

collectionForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = collectionForm.elements.name.value;
  try {
    if (editingCollection) {
      await invoke('rename_collection', { id: editingCollection, name });
    } else {
      state.collection = await invoke('create_collection', { name });
    }
    collectionDialog.close();
    await refresh();
  } catch (err) {
    setError(collectionForm, err);
  }
});

// --- settings ----------------------------------------------------------------------------

const settingsDialog = $('#settings-dialog');
$('#open-settings').addEventListener('click', async () => {
  $('#password-form').reset();
  setError($('#password-form'), '');
  setError($('#profile-form'), '');
  for (const id of ['#backup-export-form', '#backup-import-form']) {
    $(id).reset();
    setError($(id), '');
  }
  $('#profile-form').elements.name.value = (await invoke('profile')).name;
  renderLanguageSelect();
  settingsDialog.showModal();
});

$('#profile-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await invoke('set_profile_name', { name: e.target.elements.name.value });
    toast(t('Name saved'));
  } catch (err) {
    setError(e.target, err);
  }
});
settingsDialog.addEventListener('click', (e) => {
  if (e.target.dataset?.action === 'close') settingsDialog.close();
});

$('#password-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  const { password, repeat } = form.elements;
  if (password.value !== repeat.value) return setError(form, t('Passwords do not match'));
  setError(form, '');
  await busy(form.querySelector('[type=submit]'), async () => {
    try {
      await invoke('change_password', { newPassword: password.value });
      form.reset();
      toast(t('Master password changed'));
    } catch (err) {
      setError(form, err);
    }
  });
});

const backupFilters = () => [{ name: t('Vaulti backup'), extensions: ['vaulti'] }];

$('#backup-export-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  const { password, repeat } = form.elements;
  if (password.value !== repeat.value) return setError(form, t('Passwords do not match'));
  setError(form, '');
  await busy(form.querySelector('[type=submit]'), async () => {
    try {
      const contents = await invoke('export_backup', { password: password.value });
      const date = new Date().toISOString().slice(0, 10);
      const path = await window.__TAURI__.dialog.save({ defaultPath: `vaulti-backup-${date}.vaulti`, filters: backupFilters() });
      if (!path) return;
      await window.__TAURI__.fs.writeTextFile(path, contents);
      form.reset();
      toast(t('Backup saved'));
    } catch (err) {
      setError(form, err);
    }
  });
});

$('#backup-import-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  setError(form, '');
  await busy(form.querySelector('[type=submit]'), async () => {
    try {
      const path = await window.__TAURI__.dialog.open({ multiple: false, directory: false, filters: backupFilters() });
      if (!path) return;
      const contents = await window.__TAURI__.fs.readTextFile(path);
      const r = await invoke('import_backup', { contents, password: form.elements.password.value });
      form.reset();
      await refresh();
      toast(
        r.entries_skipped
          ? t('Imported {n} entries, {skipped} already there', { n: r.entries_added, skipped: r.entries_skipped })
          : t('Imported {n} entries', { n: r.entries_added }),
      );
    } catch (err) {
      setError(form, err);
    }
  });
});

$('#rotate-code').addEventListener('click', async () => {
  settingsDialog.close();
  if (!(await confirmDialog(t('Create a new backup code? Your current code will stop working.'), t('Create new code')))) return;
  try {
    const code = await invoke('rotate_backup_code');
    showBackup(code, () => show('main'));
  } catch (err) {
    toast(String(err));
  }
});

// --- sharing -------------------------------------------------------------------------------------

const shareDialog = $('#share-dialog');
const shareAdd = $('[data-add]', shareDialog);

async function renderShareDialog() {
  const c = collectionById(state.collection);
  if (!c) return shareDialog.close();
  $('[data-title]', shareDialog).textContent = t('Share "{name}"', { name: c.name });
  $('[data-members]', shareDialog).replaceChildren(
    ...c.members.map((m) => {
      const who = person(m.is_me ? t('{name} (you)', { name: m.name }) : m.name, m.fingerprint);
      if (m.role === 'owner') return h('li', {}, who, h('span', { class: 'muted small', text: t('Owner') }));
      const role = h('select', { onchange: (e) => share(m.user_id, e.target.value) },
        h('option', { value: 'editor', text: t('Can edit') }), h('option', { value: 'viewer', text: t('Can view') }));
      role.value = m.role;
      return h('li', {}, who, role, h('button', { class: 'danger', text: t('Remove'), onclick: () => unshare(m) }));
    }),
  );
  const members = new Set(c.members.map((m) => m.user_id));
  const contacts = await invoke('contacts');
  const candidates = contacts.filter((x) => !members.has(x.user_id));
  shareAdd.elements.contact.replaceChildren(...candidates.map((x) => h('option', { value: x.user_id, text: `${x.name} · ${friendlyName(x.fingerprint)}` })));
  $('[data-has-contacts]', shareDialog).hidden = candidates.length === 0;
  $('[data-no-contacts]', shareDialog).hidden = candidates.length > 0;
  setRich(
    $('[data-no-contacts]', shareDialog),
    contacts.length === 0
      ? t('Add people under **Contacts** first, then share with them here.')
      : t('Everyone in your contacts is already a member.'),
  );
}

async function share(userId, role) {
  try {
    await invoke('share_collection', { id: state.collection, userId, role });
    await refresh();
    await renderShareDialog();
  } catch (err) {
    setError(shareAdd, err);
  }
}

async function unshare(m) {
  if (!(await confirmDialog(t('Remove {name} from this collection? They keep what they already synced.', { name: m.name }), t('Remove')))) {
    return shareDialog.showModal();
  }
  shareDialog.showModal();
  try {
    await invoke('unshare_collection', { id: state.collection, userId: m.user_id });
    await refresh();
    await renderShareDialog();
    toast(t('{name} removed', { name: m.name }));
  } catch (err) {
    setError(shareAdd, err);
  }
}

$('#share-collection').addEventListener('click', async () => {
  setError(shareAdd, '');
  await renderShareDialog();
  shareDialog.showModal();
});
shareAdd.addEventListener('submit', async (e) => {
  e.preventDefault();
  const { contact, role } = shareAdd.elements;
  if (!contact.value) return;
  setError(shareAdd, '');
  await share(contact.value, role.value);
  toast(t('Shared. It arrives on their devices when you are both online.'));
});
shareDialog.addEventListener('click', (e) => {
  if (e.target.dataset?.action === 'close') shareDialog.close();
});

// --- devices -------------------------------------------------------------------------------------

const devicesDialog = $('#devices-dialog');

async function renderDevices() {
  const list = await invoke('devices');
  const status = await invoke('sync_status');
  const seen = new Map(status.peers.map((p) => [p.node_id, p]));
  $('[data-devices]', devicesDialog).replaceChildren(
    ...list
      .sort((a, b) => Number(b.this_device) - Number(a.this_device) || a.name.localeCompare(b.name))
      .map((d) => {
        const peer = seen.get(d.node_id);
        const sub = t(d.this_device ? 'This device' : peer ? (peer.ok ? 'Online, in sync' : 'Offline') : 'Not seen yet');
        const name = h('div', { text: d.name });
        const who = h('div', { class: 'who' }, name, h('div', { class: 'sub', text: sub }));
        const rename = h('button', {
          text: t('Rename'),
          onclick: () => {
            const input = h('input', { value: d.name });
            const save = async () => {
              try {
                await invoke('rename_device', { nodeId: d.node_id, name: input.value });
                await renderDevices();
              } catch (err) {
                toast(String(err));
              }
            };
            input.addEventListener('keydown', (ev) => ev.key === 'Enter' && save());
            name.replaceWith(input);
            rename.replaceWith(h('button', { text: t('Save'), onclick: save }));
            input.focus();
          },
        });
        const remove = d.this_device
          ? null
          : h('button', {
              class: 'danger',
              text: t('Remove'),
              onclick: async () => {
                devicesDialog.close();
                const ok = await confirmDialog(
                  t('Remove "{name}"? It stops syncing. Its copy of the vault stays encrypted with your master password.', { name: d.name }),
                  t('Remove'),
                );
                devicesDialog.showModal();
                if (!ok) return;
                await invoke('remove_device', { nodeId: d.node_id });
                await renderDevices();
              },
            });
        return h('li', {}, who, rename, remove);
      }),
  );
}

function resetPairing() {
  $('[data-request]', devicesDialog).hidden = true;
  $('[data-pairing]', devicesDialog).hidden = true;
  $('[data-pair-start]', devicesDialog).hidden = false;
  $('[data-ticket]', devicesDialog).value = '';
  $('[data-qr]', devicesDialog).removeAttribute('src');
}

$('#open-devices').addEventListener('click', async () => {
  resetPairing();
  await renderDevices();
  devicesDialog.showModal();
});

devicesDialog.addEventListener('click', async (e) => {
  const action = e.target.dataset?.action;
  if (action === 'close') devicesDialog.close();
  if (action === 'pair') {
    await busy(e.target, async () => {
      try {
        e.target.textContent = t('Preparing…');
        const t = await invoke('start_pairing');
        $('[data-ticket]', devicesDialog).value = t.ticket;
        if (t.qr_svg) $('[data-qr]', devicesDialog).src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(t.qr_svg);
        $('[data-pair-wait]', devicesDialog).textContent = t('Waiting for the other device…');
        $('[data-pairing]', devicesDialog).hidden = false;
        $('[data-pair-start]', devicesDialog).hidden = true;
      } catch (err) {
        toast(String(err));
      } finally {
        e.target.textContent = t('Pair new device');
      }
    });
  }
  if (action === 'copy-ticket') {
    await invoke('copy_text', { text: $('[data-ticket]', devicesDialog).value });
    toast(t('Pairing code copied'));
  }
  if (action === 'cancel-pair') {
    await invoke('cancel_pairing');
    resetPairing();
  }
  if (action === 'accept-pair') await answerPairing(true);
  if (action === 'reject-pair') await answerPairing(false);
});
devicesDialog.addEventListener('close', () => {
  if (!$('[data-pairing]', devicesDialog).hidden) invoke('cancel_pairing');
});

// --- contacts ------------------------------------------------------------------------------------

const contactsDialog = $('#contacts-dialog');
const contactForm = $('[data-add-contact]', contactsDialog);
let myCard = '';
let scannedCard = false;

// A person as shown in lists: avatar, chosen name, friendly key name underneath.
function person(name, fingerprint, ...extra) {
  return h(
    'div',
    { class: 'who person' },
    avatar(name),
    h('div', {}, h('div', { text: name }), h('div', { class: 'sub', text: friendlyName(fingerprint) }), ...extra),
  );
}

function resetContactForm() {
  contactForm.reset();
  scannedCard = false;
  setError(contactForm, '');
  $('[data-preview]', contactForm).hidden = true;
  $('[data-submit]', contactForm).textContent = t('Check card');
}

async function renderContacts() {
  const me = await invoke('profile');
  myCard = me.card;
  $('[data-my-fp]', contactsDialog).textContent = me.fingerprint;
  $('[data-my-friendly]', contactsDialog).textContent = friendlyName(me.fingerprint);
  const qr = $('[data-my-qr]', contactsDialog);
  qr.hidden = !me.card_qr;
  if (me.card_qr) qr.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(me.card_qr);
  const list = await invoke('contacts');
  $('[data-contacts]', contactsDialog).replaceChildren(
    ...list.map((c) =>
      h(
        'li',
        {},
        person(c.name, c.fingerprint),
        h('button', {
          class: 'danger',
          text: t('Remove'),
          onclick: async () => {
            contactsDialog.close();
            const ok = await confirmDialog(
              t('Remove {name} from your contacts? Collections you shared stay shared until you remove them there.', { name: c.name }),
              t('Remove'),
            );
            contactsDialog.showModal();
            if (!ok) return;
            await invoke('remove_contact', { userId: c.user_id });
            await renderContacts();
          },
        }),
      ),
    ),
  );
}

$('#open-contacts').addEventListener('click', async () => {
  resetContactForm();
  await renderContacts();
  contactsDialog.showModal();
});

contactForm.elements.card.addEventListener('input', () => {
  scannedCard = false;
  $('[data-preview]', contactForm).hidden = true;
  $('[data-submit]', contactForm).textContent = t('Check card');
});

async function previewCard(card) {
  const c = await invoke('preview_contact', { card });
  $('[data-name]', contactForm).textContent = c.name;
  $('[data-friendly]', contactForm).textContent = friendlyName(c.fingerprint);
  $('[data-avatar]', contactForm).replaceChildren(avatar(c.name));
  $('[data-fp]', contactForm).textContent = c.fingerprint;
  $('[data-check-scanned]', contactForm).hidden = !scannedCard;
  $('[data-check-pasted]', contactForm).hidden = scannedCard;
  $('[data-preview]', contactForm).hidden = false;
  $('[data-submit]', contactForm).textContent = t('Add contact');
}

contactForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const card = contactForm.elements.card.value;
  setError(contactForm, '');
  try {
    if ($('[data-preview]', contactForm).hidden) {
      await previewCard(card);
    } else {
      await invoke('add_contact', { card });
      resetContactForm();
      await renderContacts();
      toast(t('Contact added'));
    }
  } catch (err) {
    setError(contactForm, err);
  }
});

contactsDialog.addEventListener('click', async (e) => {
  const action = e.target.dataset?.action;
  if (action === 'close') contactsDialog.close();
  if (action === 'details') {
    const d = $('[data-details]', contactsDialog);
    d.hidden = !d.hidden;
  }
  if (action === 'copy-card') {
    await invoke('copy_text', { text: myCard });
    toast(t('Contact card copied. Send it to the person you want to share with.'));
  }
  if (action === 'scan-card') {
    setError(contactForm, '');
    try {
      const content = await scanQr();
      if (!content?.startsWith('vaulti-contact:')) throw new Error(t("That QR code isn't a Vaulti contact card"));
      contactForm.elements.card.value = content;
      scannedCard = true;
      await previewCard(content);
    } catch (err) {
      if (String(err) !== 'cancelled') setError(contactForm, err.message || String(err));
    }
  }
});

// --- sync status & live updates ----------------------------------------------------------------

let lastStatus = null;

function renderSyncStatus(s) {
  lastStatus = s;
  const el = $('#sync-status');
  el.classList.remove('ok', 'warn');
  const text = $('[data-text]', el);
  if (!s || !s.online) return (text.textContent = s ? t('Offline') : '');
  const reachable = s.peers.filter((p) => p.ok).length;
  if (s.peers.length === 0) {
    text.textContent = t('Only this device');
  } else if (reachable > 0) {
    el.classList.add('ok');
    text.textContent = t('Synced {ago} · {online}/{total} online', { ago: s.last_sync ? timeAgo(s.last_sync) : '', online: reachable, total: s.peers.length });
  } else {
    el.classList.add('warn');
    text.textContent = t('Other devices offline');
  }
}

$('#sync-status').addEventListener('click', () => {
  invoke('sync_now');
  $('[data-text]', $('#sync-status')).textContent = t('Syncing…');
});
setInterval(() => state.unlocked && lastStatus && renderSyncStatus(lastStatus), 30_000);

listen('sync-status', async () => {
  if (state.unlocked) renderSyncStatus(await invoke('sync_status'));
});
listen('vault-changed', async () => {
  if (!state.unlocked) return;
  await refresh();
  if (shareDialog.open) await renderShareDialog();
  if (devicesDialog.open) await renderDevices();
  if (contactsDialog.open) await renderContacts();
});
listen('join-code', (e) => {
  $('[data-code]', joinForm).textContent = e.payload;
  $('[data-join-code]', joinForm).hidden = false;
  $('[data-submit]', joinForm).textContent = t('Waiting for confirmation…');
});

let pendingPair = null;
listen('pair-request', async (e) => {
  pendingPair = e.payload;
  if (!devicesDialog.open) {
    for (const d of document.querySelectorAll('dialog[open]')) d.close();
    await renderDevices();
    devicesDialog.showModal();
  }
  $('[data-pairing]', devicesDialog).hidden = false;
  $('[data-pair-start]', devicesDialog).hidden = true;
  $('[data-req-name]', devicesDialog).textContent = pendingPair.name;
  $('[data-req-code]', devicesDialog).textContent = pendingPair.code;
  $('[data-request]', devicesDialog).hidden = false;
  $('[data-pair-wait]', devicesDialog).textContent = t('Device connected, waiting for your confirmation.');
});

async function answerPairing(accept) {
  if (!pendingPair) return;
  const req = pendingPair;
  pendingPair = null;
  $('[data-request]', devicesDialog).hidden = true;
  try {
    await invoke('confirm_pairing', { nodeId: req.node_id, accept });
    if (!accept) {
      resetPairing();
      toast(t('Pairing rejected. Start again for a new code.'));
    } else {
      $('[data-pair-wait]', devicesDialog).textContent = t('Sending your vault…');
    }
  } catch (err) {
    resetPairing();
    toast(String(err));
  }
}

listen('paired', async (e) => {
  toast(t('Paired "{name}"', { name: e.payload }));
  if (devicesDialog.open) {
    resetPairing();
    await renderDevices();
  }
});

// --- language -----------------------------------------------------------------------------------

function renderLanguageSelect() {
  const sel = $('#language');
  sel.replaceChildren(
    h('option', { value: 'auto', text: t('Automatic') }),
    ...Object.entries(LANGUAGES).map(([code, name]) => h('option', { value: code, text: name })),
  );
  sel.value = langPref();
}

$('#language').addEventListener('change', async (e) => {
  setLangPref(e.target.value);
  renderLanguageSelect();
  if (state.unlocked) {
    await refresh();
    renderSyncStatus(lastStatus);
  }
});

// A new vault starts with one collection the core names in English.
async function localizeDefaultCollection() {
  const name = t('Personal');
  if (name === 'Personal') return;
  const { collections } = await invoke('overview');
  const c = collections.find((c) => c.name === 'Personal');
  if (c) await invoke('rename_collection', { id: c.id, name });
}

// --- keyboard shortcuts ------------------------------------------------------------------------

window.addEventListener('keydown', (e) => {
  if (!state.unlocked || $('#screen-main').hidden || document.querySelector('dialog[open]')) return;
  if (!(e.ctrlKey || e.metaKey)) return;
  const k = e.key.toLowerCase();
  if (k === 'f') { e.preventDefault(); $('#search').focus(); }
  if (k === 'n') { e.preventDefault(); if (!$('#new-entry').disabled) openEntryDialog(); }
  if (k === 'l') { e.preventDefault(); lock(); }
  const typing = ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName);
  if (k === 'c' && state.entry && !typing && !window.getSelection()?.toString()) { e.preventDefault(); copy(state.entry, 'password'); }
});

boot().catch((err) => {
  document.body.replaceChildren(h('p', { class: 'error', text: t('Failed to start: {err}', { err: translateError(err) }) }));
});
