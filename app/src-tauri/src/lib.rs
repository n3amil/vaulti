//! Tauri backend: exposes vaulti-core to the UI as commands and runs the
//! P2P sync node while the vault is unlocked.
//!
//! Passwords only leave Rust when the UI explicitly asks for one entry
//! (`get_entry`); listing returns summaries without secrets. Anything that
//! runs Argon2 is executed on a blocking thread so the window stays responsive.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tokio::sync::Notify;
use uuid::Uuid;
use vaulti_core::generator::{self, PassphraseSpec, PasswordSpec};
use vaulti_core::totp::Totp;
use vaulti_core::{backup, backup::ImportReport};
use vaulti_core::{store, BackupCode, ContactCard, Entry, EntryInput, KdfParams, Member, Role, UserId, Vault};
use vaulti_sync::{Event, Network, SharedVault, SyncNode};
use zeroize::Zeroizing;

const MIN_PASSWORD_LEN: usize = 8;
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);
const SYNC_INTERVAL: Duration = Duration::from_secs(30);
/// Wait a moment after a local change so a burst of edits syncs once.
const SYNC_DEBOUNCE: Duration = Duration::from_millis(800);

type CmdResult<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[derive(Clone, Default, Serialize)]
struct PeerStatus {
    node_id: String,
    label: String,
    ok: bool,
    error: Option<String>,
}

#[derive(Clone, Default, Serialize)]
struct SyncStatus {
    online: bool,
    last_sync: Option<u64>,
    peers: Vec<PeerStatus>,
}

struct SyncRuntime {
    node: Arc<SyncNode>,
    tasks: Vec<tauri::async_runtime::JoinHandle<()>>,
}

/// A device that fetched the vault via pairing and waits for the master password.
struct PendingJoin {
    file: vaulti_core::FileV2,
    secret: [u8; 32],
    name: String,
}

struct AppState {
    path: PathBuf,
    vault: Arc<Mutex<Option<Vault>>>,
    sync: tokio::sync::Mutex<Option<SyncRuntime>>,
    status: Arc<Mutex<SyncStatus>>,
    kick: Arc<Notify>,
    pending_join: Mutex<Option<PendingJoin>>,
}

impl AppState {
    fn read<T>(&self, f: impl FnOnce(&Vault) -> CmdResult<T>) -> CmdResult<T> {
        let guard = self.vault.lock().map_err(err)?;
        f(guard.as_ref().ok_or("vault is locked")?)
    }

    /// Runs `f` on the unlocked vault, saves, and schedules a sync.
    fn mutate<T>(&self, f: impl FnOnce(&mut Vault) -> vaulti_core::Result<T>) -> CmdResult<T> {
        let mut guard = self.vault.lock().map_err(err)?;
        let vault = guard.as_mut().ok_or("vault is locked")?;
        let out = f(vault).map_err(err)?;
        store::save(&self.path, &vault.to_file().map_err(err)?).map_err(err)?;
        self.kick.notify_one();
        Ok(out)
    }

    fn shared(&self) -> SharedVault {
        SharedVault { vault: self.vault.clone(), path: self.path.clone() }
    }
}

/// Runs a blocking (Argon2) closure off the main thread.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> CmdResult<T> + Send + 'static) -> CmdResult<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(err)?
}

fn check_new_password(pw: &str) -> CmdResult<()> {
    if pw.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!("Master password must be at least {MIN_PASSWORD_LEN} characters"));
    }
    Ok(())
}

fn hostname() -> String {
    if cfg!(target_os = "android") {
        return "Android".into();
    }
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "Linux desktop".into())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn peer_label(v: &Vault, node_id: &str) -> String {
    if let Some(d) = v.devices().into_iter().find(|d| d.node_id == node_id) {
        return d.name;
    }
    let label = v
        .contacts()
        .find(|c| c.devices.iter().any(|d| d == node_id))
        .map(|c| c.name.clone())
        .unwrap_or_else(|| node_id[..8].to_string());
    label
}

// --- sync runtime --------------------------------------------------------------

async fn start_sync(app: &AppHandle, state: &AppState) -> CmdResult<()> {
    let mut slot = state.sync.lock().await;
    if slot.is_some() {
        return Ok(());
    }
    let node = SyncNode::spawn(state.shared(), Network::Internet).await.map_err(err)?;
    state.status.lock().map_err(err)?.online = true;

    // Periodic + on-change sync with all peers.
    let loop_task = {
        let (node, kick, status, vault, app) =
            (node.clone(), state.kick.clone(), state.status.clone(), state.vault.clone(), app.clone());
        tauri::async_runtime::spawn(async move {
            loop {
                let results = node.sync_all().await;
                let mut changed = false;
                let peers = {
                    let guard = vault.lock().ok();
                    results
                        .into_iter()
                        .filter(|(id, _)| !id.is_empty())
                        .map(|(node_id, r)| {
                            let label = guard
                                .as_deref()
                                .and_then(Option::as_ref)
                                .map(|v| peer_label(v, &node_id))
                                .unwrap_or_default();
                            changed |= r.as_ref().is_ok_and(|r| r.changed);
                            PeerStatus { label, ok: r.is_ok(), error: r.err().map(|e| e.to_string()), node_id }
                        })
                        .collect()
                };
                if let Ok(mut s) = status.lock() {
                    s.peers = peers;
                    s.last_sync = Some(now_secs());
                }
                let _ = app.emit("sync-status", ());
                if changed {
                    let _ = app.emit("vault-changed", ());
                }
                tokio::select! {
                    _ = tokio::time::sleep(SYNC_INTERVAL) => {}
                    _ = kick.notified() => tokio::time::sleep(SYNC_DEBOUNCE).await,
                }
            }
        })
    };

    // Incoming syncs and pairings.
    let event_task = {
        let (mut rx, app) = (node.subscribe(), app.clone());
        tauri::async_runtime::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(Event::Synced { report, .. }) if report.changed => {
                        let _ = app.emit("vault-changed", ());
                    }
                    Ok(Event::PairRequest { node_id, name, code }) => {
                        let _ = app.emit("pair-request", PairRequestView { node_id, name, code });
                    }
                    Ok(Event::Paired { name, .. }) => {
                        let _ = app.emit("paired", name);
                        let _ = app.emit("vault-changed", ());
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(_) => break,
                }
            }
        })
    };

    *slot = Some(SyncRuntime { node, tasks: vec![loop_task, event_task] });
    Ok(())
}

async fn stop_sync(state: &AppState) {
    if let Some(rt) = state.sync.lock().await.take() {
        for t in rt.tasks {
            t.abort();
        }
        rt.node.shutdown().await;
    }
    if let Ok(mut s) = state.status.lock() {
        *s = SyncStatus::default();
    }
}

async fn node(state: &AppState) -> CmdResult<Arc<SyncNode>> {
    state.sync.lock().await.as_ref().map(|rt| rt.node.clone()).ok_or_else(|| "Sync is not running".into())
}

// --- views sent to the UI --------------------------------------------------

#[derive(Serialize)]
struct Status {
    exists: bool,
    unlocked: bool,
    pending_join: bool,
    path: String,
}

#[derive(Serialize)]
struct MemberView {
    user_id: UserId,
    name: String,
    role: Role,
    fingerprint: String,
    is_me: bool,
}

#[derive(Serialize)]
struct CollectionView {
    id: Uuid,
    name: String,
    count: usize,
    my_role: Option<Role>,
    owner_name: String,
    members: Vec<MemberView>,
}

#[derive(Serialize)]
struct EntrySummary {
    id: Uuid,
    collection_id: Uuid,
    title: String,
    username: Option<String>,
    url: Option<String>,
    updated_at: u64,
}

#[derive(Serialize)]
struct Overview {
    collections: Vec<CollectionView>,
    entries: Vec<EntrySummary>,
}

#[derive(Serialize)]
struct EntryDetail {
    #[serde(flatten)]
    entry: Entry,
    collection_id: Uuid,
}

#[derive(Serialize)]
struct ContactView {
    user_id: UserId,
    name: String,
    fingerprint: String,
    devices: usize,
}

impl From<&ContactCard> for ContactView {
    fn from(c: &ContactCard) -> Self {
        Self {
            user_id: c.identity.user_id(),
            name: c.name.clone(),
            fingerprint: c.identity.fingerprint(),
            devices: c.devices.len(),
        }
    }
}

#[derive(Serialize)]
struct Profile {
    name: String,
    fingerprint: String,
    card: String,
}

#[derive(Clone, Serialize)]
struct PairRequestView {
    node_id: String,
    name: String,
    code: String,
}

#[derive(Serialize)]
struct PairingTicket {
    ticket: String,
    qr_svg: String,
}

#[derive(Deserialize)]
struct EntryForm {
    title: String,
    username: Option<String>,
    password: String,
    url: Option<String>,
    notes: Option<String>,
    #[serde(default)]
    totp: Option<String>,
}

#[derive(Serialize)]
struct Generated {
    value: String,
    bits: f64,
}

#[derive(Serialize)]
struct TotpView {
    code: String,
    remaining: u64,
    period: u64,
    issuer: Option<String>,
}

fn blank_to_none(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

impl EntryForm {
    fn into_input(self) -> CmdResult<EntryInput> {
        let title = self.title.trim().to_string();
        if title.is_empty() {
            return Err("Title is required".into());
        }
        Ok(EntryInput {
            title,
            username: blank_to_none(self.username),
            password: self.password,
            url: blank_to_none(self.url),
            notes: blank_to_none(self.notes),
            totp: blank_to_none(self.totp),
        })
    }
}

fn parse_role(role: &str) -> CmdResult<Role> {
    match role {
        "editor" => Ok(Role::Editor),
        "viewer" => Ok(Role::Viewer),
        _ => Err(format!("unknown role {role}")),
    }
}

// --- lifecycle ---------------------------------------------------------------

#[tauri::command]
fn status(state: State<AppState>) -> CmdResult<Status> {
    Ok(Status {
        exists: state.path.exists(),
        unlocked: state.vault.lock().map_err(err)?.is_some(),
        pending_join: state.pending_join.lock().map_err(err)?.is_some(),
        path: state.path.display().to_string(),
    })
}

/// Creates the vault and returns the backup code (shown once by the UI).
#[tauri::command]
async fn create_vault(app: AppHandle, state: State<'_, AppState>, password: String) -> CmdResult<String> {
    let password = Zeroizing::new(password);
    check_new_password(&password)?;
    if state.path.exists() {
        return Err("A vault already exists".into());
    }
    let path = state.path.clone();
    let (vault, code) = blocking(move || {
        let (mut vault, code) = Vault::create(&password, KdfParams::default()).map_err(err)?;
        let me = vault.node_id();
        vault.add_device(&me, &hostname());
        store::save(&path, &vault.to_file().map_err(err)?).map_err(err)?;
        Ok((vault, code))
    })
    .await?;
    *state.vault.lock().map_err(err)? = Some(vault);
    start_sync(&app, &state).await?;
    Ok(code.display().to_string())
}

#[tauri::command]
async fn unlock(app: AppHandle, state: State<'_, AppState>, password: String) -> CmdResult<()> {
    let password = Zeroizing::new(password);
    let path = state.path.clone();
    let vault = blocking(move || {
        let file = store::load(&path).map_err(err)?;
        let vault = Vault::unlock(file, &password).map_err(|_| "Wrong master password".to_string())?;
        // Persists migrations from older formats right away.
        store::save(&path, &vault.to_file().map_err(err)?).map_err(err)?;
        Ok(vault)
    })
    .await?;
    *state.vault.lock().map_err(err)? = Some(vault);
    start_sync(&app, &state).await
}

#[tauri::command]
async fn lock(state: State<'_, AppState>) -> CmdResult<()> {
    stop_sync(&state).await;
    *state.vault.lock().map_err(err)? = None;
    Ok(())
}

/// Backup code + new master password. Returns the new backup code.
#[tauri::command]
async fn recover(app: AppHandle, state: State<'_, AppState>, code: String, new_password: String) -> CmdResult<String> {
    let code = Zeroizing::new(code);
    let new_password = Zeroizing::new(new_password);
    check_new_password(&new_password)?;
    let code = BackupCode::parse(&code).map_err(|_| "That doesn't look like a backup code".to_string())?;
    let path = state.path.clone();
    let (vault, new_code) = blocking(move || {
        let file = store::load(&path).map_err(err)?;
        let (vault, new_code) =
            Vault::recover(file, &code, &new_password).map_err(|_| "Backup code is not valid".to_string())?;
        store::save(&path, &vault.to_file().map_err(err)?).map_err(err)?;
        Ok((vault, new_code))
    })
    .await?;
    *state.vault.lock().map_err(err)? = Some(vault);
    start_sync(&app, &state).await?;
    Ok(new_code.display().to_string())
}

#[tauri::command]
async fn change_password(state: State<'_, AppState>, new_password: String) -> CmdResult<()> {
    let new_password = Zeroizing::new(new_password);
    check_new_password(&new_password)?;
    let (vault, path, kick) = (state.vault.clone(), state.path.clone(), state.kick.clone());
    blocking(move || {
        let mut guard = vault.lock().map_err(err)?;
        let v = guard.as_mut().ok_or("vault is locked")?;
        v.change_password(&new_password).map_err(err)?;
        store::save(&path, &v.to_file().map_err(err)?).map_err(err)?;
        kick.notify_one();
        Ok(())
    })
    .await
}

#[tauri::command]
async fn rotate_backup_code(state: State<'_, AppState>) -> CmdResult<String> {
    let (vault, path, kick) = (state.vault.clone(), state.path.clone(), state.kick.clone());
    blocking(move || {
        let mut guard = vault.lock().map_err(err)?;
        let v = guard.as_mut().ok_or("vault is locked")?;
        let code = v.rotate_backup_code().map_err(err)?;
        store::save(&path, &v.to_file().map_err(err)?).map_err(err)?;
        kick.notify_one();
        Ok(code.display().to_string())
    })
    .await
}

// --- joining from another device --------------------------------------------

/// Step 1 on the new device: fetch the vault copy using the ticket.
#[tauri::command]
async fn join_fetch(app: AppHandle, state: State<'_, AppState>, ticket: String, device_name: String) -> CmdResult<()> {
    if state.path.exists() {
        return Err("A vault already exists on this device".into());
    }
    let name = if device_name.trim().is_empty() { hostname() } else { device_name.trim().to_string() };
    let secret = vaulti_sync::new_device_secret().map_err(err)?;
    let file = vaulti_sync::join(&ticket, secret, &name, Network::Internet, |code| {
        let _ = app.emit("join-code", code);
    })
    .await
    .map_err(err)?;
    *state.pending_join.lock().map_err(err)? = Some(PendingJoin { file, secret, name });
    Ok(())
}

/// Step 2: unlock the received copy with the master password and save it.
#[tauri::command]
async fn join_unlock(app: AppHandle, state: State<'_, AppState>, password: String) -> CmdResult<()> {
    let password = Zeroizing::new(password);
    let (file, secret, name) = {
        let guard = state.pending_join.lock().map_err(err)?;
        let p = guard.as_ref().ok_or("Nothing to unlock; start again")?;
        (p.file.clone(), p.secret, p.name.clone())
    };
    let path = state.path.clone();
    let vault = blocking(move || {
        let v = Vault::unlock_new_device(file, &password, secret, &name)
            .map_err(|_| "Wrong master password".to_string())?;
        store::save(&path, &v.to_file().map_err(err)?).map_err(err)?;
        Ok(v)
    })
    .await?;
    *state.pending_join.lock().map_err(err)? = None;
    *state.vault.lock().map_err(err)? = Some(vault);
    start_sync(&app, &state).await
}

#[tauri::command]
fn join_cancel(state: State<AppState>) -> CmdResult<()> {
    *state.pending_join.lock().map_err(err)? = None;
    Ok(())
}

// --- data ----------------------------------------------------------------------

#[tauri::command]
fn overview(state: State<AppState>) -> CmdResult<Overview> {
    state.read(|v| {
        let me = v.user_id();
        let member_view = |m: &Member| MemberView {
            user_id: m.identity.user_id(),
            name: m.name.clone(),
            role: m.role,
            fingerprint: m.identity.fingerprint(),
            is_me: m.identity.user_id() == me,
        };
        Ok(Overview {
            collections: v
                .collections()
                .map(|c| CollectionView {
                    id: c.id,
                    name: c.name.clone(),
                    count: c.entries.len(),
                    my_role: c.my_role,
                    owner_name: c
                        .members
                        .iter()
                        .find(|m| m.identity.user_id() == c.owner)
                        .map(|m| m.name.clone())
                        .unwrap_or_default(),
                    members: c.members.iter().map(member_view).collect(),
                })
                .collect(),
            entries: v
                .entries()
                .map(|(c, e)| EntrySummary {
                    id: e.id,
                    collection_id: c.id,
                    title: e.title.clone(),
                    username: e.username.clone(),
                    url: e.url.clone(),
                    updated_at: e.updated_at,
                })
                .collect(),
        })
    })
}

#[tauri::command]
fn get_entry(state: State<AppState>, id: Uuid) -> CmdResult<EntryDetail> {
    state.read(|v| {
        let (c, e) = v.entry(id).ok_or("Entry not found")?;
        Ok(EntryDetail { entry: e.clone(), collection_id: c.id })
    })
}

#[tauri::command]
fn add_entry(state: State<AppState>, collection_id: Uuid, entry: EntryForm) -> CmdResult<Uuid> {
    let input = entry.into_input()?;
    state.mutate(|v| v.add_entry(collection_id, input))
}

/// Updates an entry; moves it if `collection_id` differs from its current one.
#[tauri::command]
fn update_entry(state: State<AppState>, id: Uuid, collection_id: Uuid, entry: EntryForm) -> CmdResult<Uuid> {
    let input = entry.into_input()?;
    state.mutate(|v| {
        let current = v.entry(id).map(|(c, _)| c.id).ok_or(vaulti_core::Error::EntryNotFound)?;
        if current == collection_id {
            v.update_entry(id, input)?;
            Ok(id)
        } else {
            // Moving between collections re-encrypts under the target's key.
            if !v.collection(collection_id).ok_or(vaulti_core::Error::CollectionNotFound)?.can_write() {
                return Err(vaulti_core::Error::NotAllowed("you can only view the target collection".into()));
            }
            let new_id = v.add_entry(collection_id, input)?;
            v.remove_entry(id)?;
            Ok(new_id)
        }
    })
}

#[tauri::command]
fn delete_entry(state: State<AppState>, id: Uuid) -> CmdResult<()> {
    state.mutate(|v| v.remove_entry(id).map(|_| ()))
}

#[tauri::command]
fn create_collection(state: State<AppState>, name: String) -> CmdResult<Uuid> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Name is required".into());
    }
    state.mutate(|v| v.create_collection(&name))
}

#[tauri::command]
fn rename_collection(state: State<AppState>, id: Uuid, name: String) -> CmdResult<()> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Name is required".into());
    }
    state.mutate(|v| v.rename_collection(id, &name))
}

#[tauri::command]
fn delete_collection(state: State<AppState>, id: Uuid) -> CmdResult<()> {
    if state.read(|v| Ok(v.collections().filter(|c| c.is_owner()).count()))? <= 1
        && state.read(|v| Ok(v.collection(id).is_some_and(|c| c.is_owner())))?
    {
        return Err("You can't delete your last collection".into());
    }
    state.mutate(|v| v.delete_collection(id).map(|_| ()))
}

#[tauri::command]
fn share_collection(state: State<AppState>, id: Uuid, user_id: UserId, role: String) -> CmdResult<()> {
    let role = parse_role(&role)?;
    state.mutate(|v| v.share_collection(id, &user_id, role))
}

#[tauri::command]
fn unshare_collection(state: State<AppState>, id: Uuid, user_id: UserId) -> CmdResult<()> {
    state.mutate(|v| v.unshare_collection(id, &user_id))
}

#[tauri::command]
fn generate_password(spec: PasswordSpec) -> CmdResult<Generated> {
    let value = generator::generate(spec).map_err(err)?.to_string();
    Ok(Generated { value, bits: generator::password_entropy(&spec) })
}

#[tauri::command]
fn generate_passphrase(spec: PassphraseSpec) -> CmdResult<Generated> {
    let value = generator::generate_passphrase(&spec).map_err(err)?.to_string();
    Ok(Generated { value, bits: generator::passphrase_entropy(&spec) })
}

/// Checks a TOTP secret/URI while the user types it.
#[tauri::command]
fn check_totp(totp: String) -> CmdResult<Option<String>> {
    let t = Totp::parse(&totp).map_err(err)?;
    Ok(t.issuer.or(t.account))
}

#[tauri::command]
fn totp_code(state: State<AppState>, id: Uuid) -> CmdResult<TotpView> {
    state.read(|v| {
        let (_, e) = v.entry(id).ok_or("Entry not found")?;
        let t = Totp::parse(e.totp.as_deref().ok_or("No TOTP for this entry")?).map_err(err)?;
        let (code, remaining) = t.now();
        Ok(TotpView { code, remaining, period: t.period, issuer: t.issuer })
    })
}

/// Encrypted backup file contents (JSON text) for the UI to save.
#[tauri::command]
async fn export_backup(state: State<'_, AppState>, password: String) -> CmdResult<String> {
    let password = Zeroizing::new(password);
    check_new_password(&password)?;
    let data = state.read(|v| Ok(v.export_backup()))?;
    blocking(move || {
        let file = backup::seal_backup(&data, &password, KdfParams::default()).map_err(err)?;
        String::from_utf8(backup::to_bytes(&file).map_err(err)?).map_err(err)
    })
    .await
}

#[tauri::command]
async fn import_backup(state: State<'_, AppState>, contents: String, password: String) -> CmdResult<ImportReport> {
    let password = Zeroizing::new(password);
    let file = backup::from_bytes(contents.as_bytes()).map_err(err)?;
    let data = blocking(move || {
        backup::open_backup(&file, &password).map_err(|_| "Wrong backup password or damaged file".to_string())
    })
    .await?;
    state.mutate(|v| v.import_backup(data))
}

/// Copies a field to the clipboard and clears it after 30s if unchanged.
#[tauri::command]
fn copy_field(app: AppHandle, state: State<AppState>, id: Uuid, field: String) -> CmdResult<()> {
    let value = Zeroizing::new(state.read(|v| {
        let (_, e) = v.entry(id).ok_or("Entry not found")?;
        let val = match field.as_str() {
            "password" => Some(e.password.clone()),
            "username" => e.username.clone(),
            "url" => e.url.clone(),
            "totp" => Some(Totp::parse(e.totp.as_deref().ok_or("No TOTP")?).map_err(err)?.now().0),
            _ => return Err(format!("unknown field {field}")),
        };
        val.ok_or_else(|| "Field is empty".to_string())
    })?);
    app.clipboard().write_text(value.to_string()).map_err(err)?;
    if field == "password" || field == "totp" {
        std::thread::spawn(move || {
            std::thread::sleep(CLIPBOARD_CLEAR_AFTER);
            if app.clipboard().read_text().ok().as_deref() == Some(value.as_str()) {
                let _ = app.clipboard().write_text(String::new());
            }
        });
    }
    Ok(())
}

/// Copies non-secret text (contact card, pairing ticket).
#[tauri::command]
fn copy_text(app: AppHandle, text: String) -> CmdResult<()> {
    app.clipboard().write_text(text).map_err(err)
}

// --- profile, contacts, devices, sync --------------------------------------------

#[tauri::command]
fn profile(state: State<AppState>) -> CmdResult<Profile> {
    state.read(|v| {
        Ok(Profile {
            name: v.profile_name().to_string(),
            fingerprint: v.identity_public().fingerprint(),
            card: v.my_card().encode(),
        })
    })
}

#[tauri::command]
fn set_profile_name(state: State<AppState>, name: String) -> CmdResult<()> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Name is required".into());
    }
    state.mutate(|v| {
        v.set_profile_name(&name);
        Ok(())
    })
}

#[tauri::command]
fn contacts(state: State<AppState>) -> CmdResult<Vec<ContactView>> {
    state.read(|v| {
        let mut list: Vec<ContactView> = v.contacts().map(ContactView::from).collect();
        list.sort_by_key(|c| c.name.to_lowercase());
        Ok(list)
    })
}

/// Parses a card without adding it, so the UI can show the fingerprint first.
#[tauri::command]
fn preview_contact(state: State<AppState>, card: String) -> CmdResult<ContactView> {
    let card = ContactCard::decode(&card).map_err(|_| "That isn't a valid contact card".to_string())?;
    if state.read(|v| Ok(card.identity.user_id() == v.user_id()))? {
        return Err("That's your own card".into());
    }
    Ok(ContactView::from(&card))
}

#[tauri::command]
fn add_contact(state: State<AppState>, card: String) -> CmdResult<()> {
    let card = ContactCard::decode(&card).map_err(|_| "That isn't a valid contact card".to_string())?;
    state.mutate(|v| v.add_contact(card).map(|_| ()))
}

#[tauri::command]
fn remove_contact(state: State<AppState>, user_id: UserId) -> CmdResult<()> {
    state.mutate(|v| v.remove_contact(&user_id))
}

#[tauri::command]
fn devices(state: State<AppState>) -> CmdResult<Vec<vaulti_core::DeviceView>> {
    state.read(|v| Ok(v.devices()))
}

#[tauri::command]
fn rename_device(state: State<AppState>, node_id: String, name: String) -> CmdResult<()> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Name is required".into());
    }
    state.mutate(|v| {
        v.add_device(&node_id, &name);
        Ok(())
    })
}

#[tauri::command]
fn remove_device(state: State<AppState>, node_id: String) -> CmdResult<()> {
    state.mutate(|v| v.remove_device(&node_id))
}

#[tauri::command]
async fn start_pairing(state: State<'_, AppState>) -> CmdResult<PairingTicket> {
    let ticket = node(&state).await?.start_pairing().await.map_err(err)?;
    let qr_svg = qrcode::QrCode::with_error_correction_level(ticket.as_bytes(), qrcode::EcLevel::L)
        .map(|q| q.render::<qrcode::render::svg::Color>().min_dimensions(260, 260).quiet_zone(true).build())
        .unwrap_or_default();
    Ok(PairingTicket { ticket, qr_svg })
}

#[tauri::command]
async fn cancel_pairing(state: State<'_, AppState>) -> CmdResult<()> {
    if let Ok(n) = node(&state).await {
        n.cancel_pairing();
    }
    Ok(())
}

#[tauri::command]
async fn confirm_pairing(state: State<'_, AppState>, node_id: String, accept: bool) -> CmdResult<()> {
    node(&state).await?.confirm_pairing(&node_id, accept).map_err(err)
}

#[tauri::command]
fn sync_now(state: State<AppState>) {
    state.kick.notify_one();
}

/// "desktop" or "android"; the UI adapts setup and layout.
#[tauri::command]
fn platform() -> &'static str {
    if cfg!(target_os = "android") {
        "android"
    } else {
        "desktop"
    }
}

#[tauri::command]
fn sync_status(state: State<AppState>) -> CmdResult<SyncStatus> {
    Ok(state.status.lock().map_err(err)?.clone())
}

/// Desktop keeps the CLI-compatible location; Android uses the app's private storage.
fn vault_path(app: &AppHandle) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if cfg!(target_os = "android") {
        return Ok(app.path().app_data_dir()?.join("vault.json"));
    }
    Ok(dirs::data_dir().ok_or("no data directory")?.join("vaulti/vault.json"))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init());
    #[cfg(mobile)]
    let builder = builder.plugin(tauri_plugin_barcode_scanner::init());
    builder
        .setup(|app| {
            let path = vault_path(app.handle())?;
            app.manage(AppState {
                path,
                vault: Arc::new(Mutex::new(None)),
                sync: tokio::sync::Mutex::new(None),
                status: Arc::new(Mutex::new(SyncStatus::default())),
                kick: Arc::new(Notify::new()),
                pending_join: Mutex::new(None),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status,
            create_vault,
            unlock,
            lock,
            recover,
            change_password,
            rotate_backup_code,
            join_fetch,
            join_unlock,
            join_cancel,
            overview,
            get_entry,
            add_entry,
            update_entry,
            delete_entry,
            create_collection,
            rename_collection,
            delete_collection,
            share_collection,
            unshare_collection,
            generate_password,
            generate_passphrase,
            check_totp,
            totp_code,
            export_backup,
            import_backup,
            copy_field,
            copy_text,
            profile,
            set_profile_name,
            contacts,
            preview_contact,
            add_contact,
            remove_contact,
            devices,
            rename_device,
            remove_device,
            start_pairing,
            cancel_pairing,
            confirm_pairing,
            sync_now,
            sync_status,
            platform,
        ])
        .run(tauri::generate_context!())
        .expect("error while running vaulti");
}
