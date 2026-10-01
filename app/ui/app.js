// Vaulti UI. Plain JS, no build step. All user data is rendered with
// textContent (never innerHTML) — this is a password manager.

const { invoke } = window.__TAURI__.core;
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
};

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
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 2200);
}

function setError(root, msg) {
  const el = $('[data-error]', root);
  if (el) el.textContent = msg || '';
}

async function busy(button, fn) {
  button.disabled = true;
  try {
    return await fn();
  } finally {
    button.disabled = false;
  }
}

function confirmDialog(message, okLabel = 'Delete') {
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

const collectionName = (id) => state.overview?.collections.find((c) => c.id === id)?.name ?? '';

// --- auth flows ----------------------------------------------------------------

async function boot() {
  const s = await invoke('status');
  $('#vault-path').textContent = s.path;
  if (!s.exists) show('setup');
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
  if (password.value !== repeat.value) return setError(form, 'Passwords do not match');
  setError(form, '');
  await busy(form.querySelector('[type=submit]'), async () => {
    try {
      const code = await invoke('create_vault', { password: password.value });
      form.reset();
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

$('#go-recover').addEventListener('click', () => show('recover'));
$('#back-to-lock').addEventListener('click', () => show('lock'));

$('#recover-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  const { code, password, repeat } = form.elements;
  if (password.value !== repeat.value) return setError(form, 'Passwords do not match');
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
  $('#detail').replaceChildren(h('p', { class: 'muted empty', text: 'Select an entry' }));
  $('#search').value = '';
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
          h('span', { text: c.name }),
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
  $('#list-title').textContent = state.collection ? collectionName(state.collection) : 'All items';
  $('#edit-collection').hidden = state.collection === null;
  $('#empty-list').hidden = rows.length > 0;
  $('#empty-list').textContent = state.query ? 'No matches.' : 'No entries yet.';
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
}

function clearDetail() {
  state.entry = null;
  $('#detail').replaceChildren(h('p', { class: 'muted empty', text: 'Select an entry' }));
}

async function copy(id, field, label) {
  try {
    await invoke('copy_field', { id, field });
    toast(field === 'password' ? 'Password copied, clears in 30 s' : `${label} copied`);
  } catch (err) {
    toast(String(err));
  }
}

async function renderDetail() {
  const e = await invoke('get_entry', { id: state.entry });
  let revealed = false;
  const pwText = h('span', { class: 'mono', text: MASK });
  const revealBtn = h('button', {
    text: 'Show',
    onclick: () => {
      revealed = !revealed;
      pwText.textContent = revealed ? e.password : MASK;
      revealBtn.textContent = revealed ? 'Hide' : 'Show';
    },
  });

  const field = (label, value, ...buttons) =>
    h('div', { class: 'field' }, h('div', { class: 'k', text: label }), h('div', { class: 'v' }, value, ...buttons));

  const fields = [];
  if (e.username) {
    fields.push(field('Username', h('span', { text: e.username }), h('button', { text: 'Copy', onclick: () => copy(e.id, 'username', 'Username') })));
  }
  fields.push(field('Password', pwText, revealBtn, h('button', { text: 'Copy', onclick: () => copy(e.id, 'password') })));
  if (e.url) fields.push(field('Website', h('span', { text: e.url }), h('button', { text: 'Copy', onclick: () => copy(e.id, 'url', 'Website') })));
  if (e.notes) fields.push(field('Notes', h('span', { text: e.notes })));

  $('#detail').replaceChildren(
    h('div', { class: 'detail-head' }, avatar(e.title), h('div', {}, h('h2', { text: e.title }), h('div', { class: 'muted', text: collectionName(e.collection_id) }))),
    ...fields,
    h(
      'div',
      { class: 'detail-actions' },
      h('button', { text: 'Edit', onclick: () => openEntryDialog(e) }),
      h('button', { class: 'danger', text: 'Delete', onclick: () => deleteEntry(e) }),
    ),
    h('div', { class: 'meta', text: `Updated ${new Date(e.updated_at * 1000).toLocaleString()}` }),
  );
}

async function deleteEntry(e) {
  if (!(await confirmDialog(`Delete "${e.title}"? This can't be undone.`))) return;
  try {
    await invoke('delete_entry', { id: e.id });
    state.entry = null;
    await refresh();
    toast('Entry deleted');
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
  $('[data-title]', entryForm).textContent = existing ? 'Edit entry' : 'New entry';
  f.password.type = 'password';
  $('[data-action=reveal]', entryForm).textContent = 'Show';

  f.collection.replaceChildren(
    ...state.overview.collections
      .slice()
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((c) => h('option', { value: c.id, text: c.name })),
  );
  f.collection.value = existing?.collection_id ?? state.collection ?? state.overview.collections[0]?.id;

  if (existing) {
    f.title.value = existing.title;
    f.username.value = existing.username ?? '';
    f.password.value = existing.password;
    f.url.value = existing.url ?? '';
    f.notes.value = existing.notes ?? '';
  }
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
    e.target.textContent = pw.type === 'password' ? 'Show' : 'Hide';
  }
  if (action === 'generate') {
    pw.value = await invoke('generate_password', { length: 20, symbols: true });
    pw.type = 'text';
    $('[data-action=reveal]', entryForm).textContent = 'Hide';
  }
});

entryForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = entryForm.elements;
  const entry = {
    title: f.title.value,
    username: f.username.value,
    password: f.password.value,
    url: f.url.value,
    notes: f.notes.value,
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
      toast(wasEditing ? 'Saved' : 'Entry added');
    } catch (err) {
      setError(entryForm, err);
    }
  });
});

entryDialog.addEventListener('close', () => {
  entryForm.elements.password.value = '';
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
  $('[data-title]', collectionForm).textContent = id ? 'Edit collection' : 'New collection';
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
    const msg = c.count ? `Delete "${c.name}" and its ${c.count} entries? This can't be undone.` : `Delete "${c.name}"?`;
    if (!(await confirmDialog(msg))) return;
    try {
      await invoke('delete_collection', { id: c.id });
      state.collection = null;
      await refresh();
      toast('Collection deleted');
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
$('#open-settings').addEventListener('click', () => {
  $('#password-form').reset();
  setError($('#password-form'), '');
  settingsDialog.showModal();
});
settingsDialog.addEventListener('click', (e) => {
  if (e.target.dataset?.action === 'close') settingsDialog.close();
});

$('#password-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  const { password, repeat } = form.elements;
  if (password.value !== repeat.value) return setError(form, 'Passwords do not match');
  setError(form, '');
  await busy(form.querySelector('[type=submit]'), async () => {
    try {
      await invoke('change_password', { newPassword: password.value });
      form.reset();
      toast('Master password changed');
    } catch (err) {
      setError(form, err);
    }
  });
});

$('#rotate-code').addEventListener('click', async () => {
  settingsDialog.close();
  if (!(await confirmDialog('Create a new backup code? Your current code will stop working.', 'Create new code'))) return;
  try {
    const code = await invoke('rotate_backup_code');
    showBackup(code, () => show('main'));
  } catch (err) {
    toast(String(err));
  }
});

// --- keyboard shortcuts ------------------------------------------------------------------------

window.addEventListener('keydown', (e) => {
  if (!state.unlocked || $('#screen-main').hidden || document.querySelector('dialog[open]')) return;
  if (!(e.ctrlKey || e.metaKey)) return;
  const k = e.key.toLowerCase();
  if (k === 'f') { e.preventDefault(); $('#search').focus(); }
  if (k === 'n') { e.preventDefault(); openEntryDialog(); }
  if (k === 'l') { e.preventDefault(); lock(); }
  const typing = ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName);
  if (k === 'c' && state.entry && !typing && !window.getSelection()?.toString()) { e.preventDefault(); copy(state.entry, 'password'); }
});

boot().catch((err) => {
  document.body.replaceChildren(h('p', { class: 'error', text: `Failed to start: ${err}` }));
});
