//! Tauri backend: exposes vaulti-core to the UI as commands.
//!
//! Passwords only leave Rust when the UI explicitly asks for one entry
//! (`get_entry`); listing returns summaries without secrets. Anything that
//! runs Argon2 is executed on a blocking thread so the window stays responsive.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use uuid::Uuid;
use vaulti_core::generator::{self, PasswordSpec};
use vaulti_core::{store, BackupCode, Entry, EntryInput, KdfParams, Vault};
use zeroize::Zeroizing;

const MIN_PASSWORD_LEN: usize = 8;
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);

struct AppState {
    path: PathBuf,
    vault: Arc<Mutex<Option<Vault>>>,
}

type CmdResult<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

impl AppState {
    fn read<T>(&self, f: impl FnOnce(&Vault) -> CmdResult<T>) -> CmdResult<T> {
        let guard = self.vault.lock().map_err(err)?;
        f(guard.as_ref().ok_or("vault is locked")?)
    }

    /// Runs `f` on the unlocked vault and saves it afterwards.
    fn mutate<T>(&self, f: impl FnOnce(&mut Vault) -> vaulti_core::Result<T>) -> CmdResult<T> {
        let mut guard = self.vault.lock().map_err(err)?;
        let vault = guard.as_mut().ok_or("vault is locked")?;
        let out = f(vault).map_err(err)?;
        store::save(&self.path, &vault.to_file().map_err(err)?).map_err(err)?;
        Ok(out)
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

// --- views sent to the UI --------------------------------------------------

#[derive(Serialize)]
struct Status {
    exists: bool,
    unlocked: bool,
    path: String,
}

#[derive(Serialize)]
struct CollectionView {
    id: Uuid,
    name: String,
    count: usize,
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

#[derive(Deserialize)]
struct EntryForm {
    title: String,
    username: Option<String>,
    password: String,
    url: Option<String>,
    notes: Option<String>,
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
        })
    }
}

// --- lifecycle ---------------------------------------------------------------

#[tauri::command]
fn status(state: State<AppState>) -> CmdResult<Status> {
    Ok(Status {
        exists: state.path.exists(),
        unlocked: state.vault.lock().map_err(err)?.is_some(),
        path: state.path.display().to_string(),
    })
}

/// Creates the vault and returns the backup code (shown once by the UI).
#[tauri::command]
async fn create_vault(state: State<'_, AppState>, password: String) -> CmdResult<String> {
    let password = Zeroizing::new(password);
    check_new_password(&password)?;
    if state.path.exists() {
        return Err("A vault already exists".into());
    }
    let path = state.path.clone();
    let (vault, code) = blocking(move || {
        let (vault, code) = Vault::create(&password, KdfParams::default()).map_err(err)?;
        store::save(&path, &vault.to_file().map_err(err)?).map_err(err)?;
        Ok((vault, code))
    })
    .await?;
    *state.vault.lock().map_err(err)? = Some(vault);
    Ok(code.display().to_string())
}

#[tauri::command]
async fn unlock(state: State<'_, AppState>, password: String) -> CmdResult<()> {
    let password = Zeroizing::new(password);
    let path = state.path.clone();
    let vault = blocking(move || {
        let file = store::load(&path).map_err(err)?;
        Vault::unlock(file, &password).map_err(|_| "Wrong master password".to_string())
    })
    .await?;
    *state.vault.lock().map_err(err)? = Some(vault);
    Ok(())
}

#[tauri::command]
fn lock(state: State<AppState>) -> CmdResult<()> {
    *state.vault.lock().map_err(err)? = None;
    Ok(())
}

/// Backup code + new master password. Returns the new backup code.
#[tauri::command]
async fn recover(state: State<'_, AppState>, code: String, new_password: String) -> CmdResult<String> {
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
    Ok(new_code.display().to_string())
}

#[tauri::command]
async fn change_password(state: State<'_, AppState>, new_password: String) -> CmdResult<()> {
    let new_password = Zeroizing::new(new_password);
    check_new_password(&new_password)?;
    let (vault, path) = (state.vault.clone(), state.path.clone());
    blocking(move || {
        let mut guard = vault.lock().map_err(err)?;
        let v = guard.as_mut().ok_or("vault is locked")?;
        v.change_password(&new_password).map_err(err)?;
        store::save(&path, &v.to_file().map_err(err)?).map_err(err)
    })
    .await
}

#[tauri::command]
async fn rotate_backup_code(state: State<'_, AppState>) -> CmdResult<String> {
    let (vault, path) = (state.vault.clone(), state.path.clone());
    blocking(move || {
        let mut guard = vault.lock().map_err(err)?;
        let v = guard.as_mut().ok_or("vault is locked")?;
        let code = v.rotate_backup_code().map_err(err)?;
        store::save(&path, &v.to_file().map_err(err)?).map_err(err)?;
        Ok(code.display().to_string())
    })
    .await
}

// --- data ----------------------------------------------------------------------

#[tauri::command]
fn overview(state: State<AppState>) -> CmdResult<Overview> {
    state.read(|v| {
        Ok(Overview {
            collections: v
                .collections()
                .map(|c| CollectionView { id: c.id, name: c.name.clone(), count: c.entries.len() })
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
            v.collection(collection_id).ok_or(vaulti_core::Error::CollectionNotFound)?;
            v.remove_entry(id)?;
            v.add_entry(collection_id, input)
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
    if state.read(|v| Ok(v.collections().count()))? <= 1 {
        return Err("You can't delete the last collection".into());
    }
    state.mutate(|v| v.delete_collection(id).map(|_| ()))
}

#[tauri::command]
fn generate_password(length: usize, symbols: bool) -> CmdResult<String> {
    let p = generator::generate(PasswordSpec { length, symbols, ..Default::default() }).map_err(err)?;
    Ok(p.to_string())
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
            _ => return Err(format!("unknown field {field}")),
        };
        val.ok_or_else(|| "Field is empty".to_string())
    })?);
    app.clipboard().write_text(value.to_string()).map_err(err)?;
    if field == "password" {
        std::thread::spawn(move || {
            std::thread::sleep(CLIPBOARD_CLEAR_AFTER);
            if app.clipboard().read_text().ok().as_deref() == Some(value.as_str()) {
                let _ = app.clipboard().write_text(String::new());
            }
        });
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let path = dirs::data_dir().unwrap_or_else(|| PathBuf::from(".")).join("vaulti/vault.json");
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(AppState { path, vault: Arc::new(Mutex::new(None)) })
        .invoke_handler(tauri::generate_handler![
            status,
            create_vault,
            unlock,
            lock,
            recover,
            change_password,
            rotate_backup_code,
            overview,
            get_entry,
            add_entry,
            update_entry,
            delete_entry,
            create_collection,
            rename_collection,
            delete_collection,
            generate_password,
            copy_field,
        ])
        .run(tauri::generate_context!())
        .expect("error while running vaulti");
}
