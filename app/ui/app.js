// Vaulti UI. Plain JS, no build step. All user data is rendered with
// textContent (never innerHTML) — this is a password manager.

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

const collectionById = (id) => state.overview?.collections.find((c) => c.id === id);
const collectionName = (id) => collectionById(id)?.name ?? '';
const canWrite = (c) => c && (c.my_role === 'owner' || c.my_role === 'editor');
const writableCollections = () => state.overview.collections.filter(canWrite);
const ROLE_LABEL = { owner: 'Owner', editor: 'Can edit', viewer: 'Can view' };

function timeAgo(secs) {
  const d = Math.max(0, Math.round(Date.now() / 1000 - secs));
  if (d < 60) return 'just now';
  if (d < 3600) return `${Math.floor(d / 60)} min ago`;
  return new Date(secs * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// --- auth flows ----------------------------------------------------------------

async function boot() {
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

// --- join from another device ---------------------------------------------------------

const joinForm = $('#join-form');
let joinStep = 'ticket';

function showJoinStep(step) {
  joinStep = step;
  for (const el of joinForm.querySelectorAll('[data-step]')) el.hidden = el.dataset.step !== step;
  $('[data-submit]', joinForm).textContent = step === 'ticket' ? 'Connect' : 'Unlock';
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
        $('[data-submit]', joinForm).textContent = 'Connecting…';
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
        toast('This device is now paired');
      }
    } catch (err) {
      if (joinStep === 'ticket') $('[data-submit]', joinForm).textContent = 'Connect';
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
  renderSyncStatus(null);
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
          h('span', { class: 'name' }, c.name, c.members.length > 1 ? h('span', { class: 'badge', text: 'shared' }) : null),
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
  $('#list-title').textContent = c ? c.name : 'All items';
  $('#edit-collection').hidden = c?.my_role !== 'owner';
  $('#share-collection').hidden = c?.my_role !== 'owner';
  const info = $('#collection-info');
  info.hidden = !c || c.members.length < 2;
  if (c && c.my_role !== 'owner') info.textContent = `Shared by ${c.owner_name} · ${c.my_role === 'viewer' ? 'view only' : 'you can edit'}`;
  else if (c) info.textContent = `Shared with ${c.members.filter((m) => !m.is_me).map((m) => m.name).join(', ')}`;
  $('#new-entry').disabled = c ? !canWrite(c) : writableCollections().length === 0;
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

  const writable = canWrite(collectionById(e.collection_id));
  $('#detail').replaceChildren(
    h('div', { class: 'detail-head' }, avatar(e.title), h('div', {}, h('h2', { text: e.title }), h('div', { class: 'muted', text: collectionName(e.collection_id) }))),
    ...fields,
    writable
      ? h(
          'div',
          { class: 'detail-actions' },
          h('button', { text: 'Edit', onclick: () => openEntryDialog(e) }),
          h('button', { class: 'danger', text: 'Delete', onclick: () => deleteEntry(e) }),
        )
      : h('p', { class: 'muted small', text: 'View only: this collection is shared with you read-only.' }),
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
$('#open-settings').addEventListener('click', async () => {
  $('#password-form').reset();
  setError($('#password-form'), '');
  setError($('#profile-form'), '');
  $('#profile-form').elements.name.value = (await invoke('profile')).name;
  settingsDialog.showModal();
});

$('#profile-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await invoke('set_profile_name', { name: e.target.elements.name.value });
    toast('Name saved');
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

// --- sharing -------------------------------------------------------------------------------------

const shareDialog = $('#share-dialog');
const shareAdd = $('[data-add]', shareDialog);

async function renderShareDialog() {
  const c = collectionById(state.collection);
  if (!c) return shareDialog.close();
  $('[data-title]', shareDialog).textContent = `Share "${c.name}"`;
  $('[data-members]', shareDialog).replaceChildren(
    ...c.members.map((m) => {
      const who = h('div', { class: 'who' }, h('div', { text: m.name + (m.is_me ? ' (you)' : '') }), h('div', { class: 'sub mono', text: m.fingerprint }));
      if (m.role === 'owner') return h('li', {}, who, h('span', { class: 'muted small', text: 'Owner' }));
      const role = h('select', { onchange: (e) => share(m.user_id, e.target.value) },
        h('option', { value: 'editor', text: 'Can edit' }), h('option', { value: 'viewer', text: 'Can view' }));
      role.value = m.role;
      return h('li', {}, who, role, h('button', { class: 'danger', text: 'Remove', onclick: () => unshare(m) }));
    }),
  );
  const members = new Set(c.members.map((m) => m.user_id));
  const contacts = await invoke('contacts');
  const candidates = contacts.filter((x) => !members.has(x.user_id));
  shareAdd.elements.contact.replaceChildren(...candidates.map((x) => h('option', { value: x.user_id, text: `${x.name} (${x.fingerprint})` })));
  $('[data-has-contacts]', shareDialog).hidden = candidates.length === 0;
  $('[data-no-contacts]', shareDialog).hidden = candidates.length > 0;
  $('[data-no-contacts]', shareDialog).textContent =
    contacts.length === 0
      ? 'Add people under Contacts first, then share with them here.'
      : 'Everyone in your contacts is already a member.';
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
  if (!(await confirmDialog(`Remove ${m.name} from this collection? They keep what they already synced.`, 'Remove'))) {
    return shareDialog.showModal();
  }
  shareDialog.showModal();
  try {
    await invoke('unshare_collection', { id: state.collection, userId: m.user_id });
    await refresh();
    await renderShareDialog();
    toast(`${m.name} removed`);
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
  toast('Shared. It arrives on their devices when you are both online.');
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
        const sub = d.this_device ? 'This device' : peer ? (peer.ok ? 'Online, in sync' : 'Offline') : 'Not seen yet';
        const name = h('div', { text: d.name });
        const who = h('div', { class: 'who' }, name, h('div', { class: 'sub', text: sub }));
        const rename = h('button', {
          text: 'Rename',
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
            rename.replaceWith(h('button', { text: 'Save', onclick: save }));
            input.focus();
          },
        });
        const remove = d.this_device
          ? null
          : h('button', {
              class: 'danger',
              text: 'Remove',
              onclick: async () => {
                devicesDialog.close();
                const ok = await confirmDialog(`Remove "${d.name}"? It stops syncing. Its copy of the vault stays encrypted with your master password.`, 'Remove');
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
        e.target.textContent = 'Preparing…';
        const t = await invoke('start_pairing');
        $('[data-ticket]', devicesDialog).value = t.ticket;
        if (t.qr_svg) $('[data-qr]', devicesDialog).src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(t.qr_svg);
        $('[data-pair-wait]', devicesDialog).textContent = 'Waiting for the other device…';
        $('[data-pairing]', devicesDialog).hidden = false;
        $('[data-pair-start]', devicesDialog).hidden = true;
      } catch (err) {
        toast(String(err));
      } finally {
        e.target.textContent = 'Pair new device';
      }
    });
  }
  if (action === 'copy-ticket') {
    await invoke('copy_text', { text: $('[data-ticket]', devicesDialog).value });
    toast('Pairing code copied');
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

function resetContactForm() {
  contactForm.reset();
  setError(contactForm, '');
  $('[data-preview]', contactForm).hidden = true;
  $('[data-submit]', contactForm).textContent = 'Check card';
}

async function renderContacts() {
  const me = await invoke('profile');
  myCard = me.card;
  $('[data-my-fp]', contactsDialog).textContent = me.fingerprint;
  const list = await invoke('contacts');
  $('[data-contacts]', contactsDialog).replaceChildren(
    ...list.map((c) =>
      h(
        'li',
        {},
        h('div', { class: 'who' }, h('div', { text: c.name }), h('div', { class: 'sub mono', text: c.fingerprint })),
        h('button', {
          class: 'danger',
          text: 'Remove',
          onclick: async () => {
            contactsDialog.close();
            const ok = await confirmDialog(`Remove ${c.name} from your contacts? Collections you shared stay shared until you remove them there.`, 'Remove');
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
  $('[data-preview]', contactForm).hidden = true;
  $('[data-submit]', contactForm).textContent = 'Check card';
});

contactForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const card = contactForm.elements.card.value;
  setError(contactForm, '');
  try {
    if ($('[data-preview]', contactForm).hidden) {
      const c = await invoke('preview_contact', { card });
      $('[data-name]', contactForm).textContent = c.name;
      $('[data-fp]', contactForm).textContent = c.fingerprint;
      $('[data-preview]', contactForm).hidden = false;
      $('[data-submit]', contactForm).textContent = 'Add contact';
    } else {
      await invoke('add_contact', { card });
      resetContactForm();
      await renderContacts();
      toast('Contact added');
    }
  } catch (err) {
    setError(contactForm, err);
  }
});

contactsDialog.addEventListener('click', async (e) => {
  const action = e.target.dataset?.action;
  if (action === 'close') contactsDialog.close();
  if (action === 'copy-card') {
    await invoke('copy_text', { text: myCard });
    toast('Contact card copied. Send it to the person you want to share with.');
  }
});

// --- sync status & live updates ----------------------------------------------------------------

let lastStatus = null;

function renderSyncStatus(s) {
  lastStatus = s;
  const el = $('#sync-status');
  el.classList.remove('ok', 'warn');
  const text = $('[data-text]', el);
  if (!s || !s.online) return (text.textContent = s ? 'Offline' : '');
  const reachable = s.peers.filter((p) => p.ok).length;
  if (s.peers.length === 0) {
    text.textContent = 'Only this device';
  } else if (reachable > 0) {
    el.classList.add('ok');
    text.textContent = `Synced ${s.last_sync ? timeAgo(s.last_sync) : ''} · ${reachable}/${s.peers.length} online`;
  } else {
    el.classList.add('warn');
    text.textContent = 'Other devices offline';
  }
}

$('#sync-status').addEventListener('click', () => {
  invoke('sync_now');
  $('[data-text]', $('#sync-status')).textContent = 'Syncing…';
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
  $('[data-submit]', joinForm).textContent = 'Waiting for confirmation…';
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
  $('[data-pair-wait]', devicesDialog).textContent = 'Device connected, waiting for your confirmation.';
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
      toast('Pairing rejected. Start again for a new code.');
    } else {
      $('[data-pair-wait]', devicesDialog).textContent = 'Sending your vault…';
    }
  } catch (err) {
    resetPairing();
    toast(String(err));
  }
}

listen('paired', async (e) => {
  toast(`Paired "${e.payload}"`);
  if (devicesDialog.open) {
    resetPairing();
    await renderDevices();
  }
});

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
  document.body.replaceChildren(h('p', { class: 'error', text: `Failed to start: ${err}` }));
});
