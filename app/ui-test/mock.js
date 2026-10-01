// Fake Tauri backend for app/ui-test/smoke.mjs.

const now = Date.now() / 1000;
const data = {
  platform: 'desktop',
  status: { path: '/home/me/.local/share/vaulti/vault.bin', exists: true, unlocked: true, pending_join: false },
  overview: {
    collections: [
      { id: 'c1', name: 'Persönlich', count: 2, my_role: 'owner', owner_name: 'Ich', members: [{ user_id: 'u0', name: 'Ich', is_me: true, role: 'owner', fingerprint: 'AB12' }] },
      { id: 'c2', name: 'Familie', count: 1, my_role: 'viewer', owner_name: 'Anna', members: [{ user_id: 'u1', name: 'Anna', role: 'owner', fingerprint: 'CD34' }, { user_id: 'u0', name: 'Ich', is_me: true, role: 'viewer', fingerprint: 'AB12' }] },
    ],
    entries: [
      { id: 'e1', title: 'GitHub', username: 'n3amil', collection_id: 'c1' },
      { id: 'e2', title: 'Bank', username: 'me@example.org', collection_id: 'c1' },
      { id: 'e3', title: 'Netflix', username: 'familie', collection_id: 'c2' },
    ],
    trash: [
      { id: 't1', title: 'Altes Forum', username: 'n3amil', collection_id: 'c1', trashed_at: now - 3 * 86400 },
      { id: 't2', title: 'Spotify', username: 'me', collection_id: 'c1', trashed_at: now - 29.5 * 86400 },
    ],
  },
  get_entry: { id: 'e1', title: 'GitHub', username: 'n3amil', password: 'x', url: 'https://github.com', notes: 'Notiz', totp: 'JBSWY3DPEHPK3PXP', collection_id: 'c1', updated_at: now - 3600 },
  sync_status: { online: true, last_sync: now - 120, peers: [{ node_id: 'n2', ok: true }, { node_id: 'n3', ok: false }] },
  set_aside_vault: '/home/me/.local/share/vaulti/vault.1790000000.bak',
  start_pairing: { ticket: 'vaulti-pair:abc', qr_svg: '<svg xmlns="http://www.w3.org/2000/svg"/>' },
  totp_code: { code: '123456', remaining: 17 },
  generate_password: { value: 'q7#Lp2!vXz9@Rm4&Kt8w', bits: 128 },
  profile: { name: 'Johannes', fingerprint: '3F9A 11C2 7B04 E8D1', card: 'vaulti-contact:x', card_qr: '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 29 29"><rect width="29" height="29" fill="#fff"/><path d="M2 2h7v7H2zM20 2h7v7h-7zM2 20h7v7H2zM12 4h2v2h-2zM14 12h3v3h-3zM20 20h2v2h-2zM24 14h2v4h-2zM11 22h3v2h-3z"/></svg>' },
  devices: [{ node_id: 'n1', name: 'Laptop', this_device: true }, { node_id: 'n2', name: 'Pixel', this_device: false }, { node_id: 'n3', name: 'Tablet' }],
  contacts: [{ user_id: 'u1', name: 'Anna', fingerprint: 'C4D2 9910 0000 0000' }, { user_id: 'u2', name: 'Paul', fingerprint: '07E1 5520 0000 0000' }],
};
data.entry_history = [
  { id: 'r1', changed_at: now - 7200, author_name: 'Anna', by_me: false, title: 'GitHub', username: 'n3amil', password: 'alt-pw-anna', url: 'https://github.com', notes: 'Notiz', totp: 'JBSWY3DPEHPK3PXP' },
  { id: 'r2', changed_at: now - 86400 * 5, author_name: 'Johannes', by_me: true, title: 'GitHub', username: 'johannes', password: 'x', url: 'https://github.com', notes: '', totp: 'JBSWY3DPEHPK3PXP' },
];
const fail = { unlock: 'Wrong master password', check_totp: 'malformed data: TOTP: secret is not valid base32' };
window.__TAURI__ = {
  core: { invoke: async (cmd, args) => { if (cmd === 'get_entry' && args?.id?.startsWith('t')) return { ...structuredClone(data.get_entry), id: args.id, title: 'Altes Forum', trashed_at: now - 3 * 86400 }; if (window.__fail?.includes(cmd)) throw fail[cmd]; return structuredClone(data[cmd] ?? null); } },
  event: { listen: async () => () => {} },
};
