//! The browser extension is a Vaulti device like a phone: it pairs, keeps its
//! own encrypted copy of the vault and syncs P2P (through iroh relays, since
//! browsers can't open raw UDP sockets). This crate exposes that to the
//! extension's JavaScript. Data crosses the boundary as JSON strings.

use std::sync::Arc;

use serde::Serialize;
use uuid::Uuid;
use vaulti_core::totp::Totp;
use vaulti_core::{Entry, FileV2, Vault, VaultFile};
use vaulti_sync::{Network, SharedVault, SyncNode};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

fn js_err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

/// A JS function used from Rust callbacks that require `Send`. WebAssembly in
/// the browser is single-threaded here, so it never actually crosses threads.
struct JsCallback(js_sys::Function);
unsafe impl Send for JsCallback {}
unsafe impl Sync for JsCallback {}

impl JsCallback {
    fn call(&self, arg: &str) -> Result<(), JsValue> {
        self.0.call1(&JsValue::NULL, &JsValue::from_str(arg)).map(|_| ())
    }
}

/// Received from the other device during pairing; unlock it with the master password.
#[wasm_bindgen]
pub struct Pending {
    file: FileV2,
    secret: [u8; 32],
    name: String,
}

/// Joins via a pairing ticket from another device (Devices → Pair new device).
/// `on_code` gets the 6-digit code to compare with the other device.
#[wasm_bindgen]
pub async fn join(ticket: String, device_name: String, on_code: js_sys::Function) -> Result<Pending, JsError> {
    let secret = vaulti_sync::new_device_secret().map_err(js_err)?;
    let cb = JsCallback(on_code);
    let file = vaulti_sync::join(&ticket, secret, &device_name, Network::Internet, move |code| {
        let _ = cb.call(&code);
    })
    .await
    .map_err(js_err)?;
    Ok(Pending { file, secret, name: device_name })
}

#[wasm_bindgen]
impl Pending {
    pub fn unlock(self, password: String) -> Result<Device, JsError> {
        let vault = Vault::unlock_new_device(self.file, &password, self.secret, &self.name).map_err(js_err)?;
        Ok(Device::new(vault))
    }
}

#[derive(Serialize)]
struct EntryView {
    id: Uuid,
    collection: String,
    title: String,
    username: Option<String>,
    url: Option<String>,
    has_totp: bool,
}

impl EntryView {
    fn new(collection: &str, e: &Entry) -> Self {
        Self {
            id: e.id,
            collection: collection.to_string(),
            title: e.title.clone(),
            username: e.username.clone(),
            url: e.url.clone(),
            has_totp: e.totp.is_some(),
        }
    }
}

#[derive(Serialize)]
struct Secret {
    username: Option<String>,
    password: String,
}

#[derive(Serialize)]
struct TotpView {
    code: String,
    remaining: u64,
}

/// Lowercase host without a leading `www.`; entries are often saved without a scheme.
fn host_of(url: &str) -> Option<String> {
    let url = url.trim();
    let parsed = url::Url::parse(url).or_else(|_| url::Url::parse(&format!("https://{url}"))).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    Some(host.strip_prefix("www.").map(str::to_string).unwrap_or(host))
}

/// The page is the entry's site or one of its subdomains.
/// `login.example.com` matches an entry for `example.com`; `example.com.evil.io` does not.
pub fn site_matches(entry_url: &str, page_url: &str) -> bool {
    match (host_of(entry_url), host_of(page_url)) {
        (Some(entry), Some(page)) => page == entry || page.ends_with(&format!(".{entry}")),
        _ => false,
    }
}

#[wasm_bindgen]
pub struct Device {
    vault: Arc<std::sync::Mutex<Option<Vault>>>,
    node: Option<Arc<SyncNode>>,
}

impl Device {
    fn new(vault: Vault) -> Self {
        Self { vault: Arc::new(std::sync::Mutex::new(Some(vault))), node: None }
    }

    fn with<R>(&self, f: impl FnOnce(&Vault) -> Result<R, JsError>) -> Result<R, JsError> {
        let guard = self.vault.lock().map_err(js_err)?;
        f(guard.as_ref().ok_or_else(|| js_err("vault is locked"))?)
    }
}

#[wasm_bindgen]
impl Device {
    /// Unlocks the vault file kept in browser storage.
    pub fn unlock(file_json: &str, password: &str) -> Result<Device, JsError> {
        let file: VaultFile = serde_json::from_str(file_json).map_err(js_err)?;
        Ok(Self::new(Vault::unlock(file, password).map_err(js_err)?))
    }

    /// Unlocks with a key from [`Device::session_key`] (kept in session-only browser memory).
    #[wasm_bindgen(js_name = unlockWithSessionKey)]
    pub fn unlock_with_session_key(file_json: &str, key: &[u8]) -> Result<Device, JsError> {
        let file: VaultFile = serde_json::from_str(file_json).map_err(js_err)?;
        Ok(Self::new(Vault::unlock_with_session_key(file, key).map_err(js_err)?))
    }

    #[wasm_bindgen(js_name = sessionKey)]
    pub fn session_key(&self) -> Result<Vec<u8>, JsError> {
        self.with(|v| Ok(v.session_key().to_vec()))
    }

    /// Entries for the page at `url`, best matches first (JSON).
    #[wasm_bindgen(js_name = entriesFor)]
    pub fn entries_for(&self, url: &str) -> Result<String, JsError> {
        self.with(|v| {
            let mut list: Vec<EntryView> = v
                .entries()
                .filter(|(_, e)| e.url.as_deref().is_some_and(|u| site_matches(u, url)))
                .map(|(c, e)| EntryView::new(&c.name, e))
                .collect();
            list.sort_by_key(|e| e.title.to_lowercase());
            serde_json::to_string(&list).map_err(js_err)
        })
    }

    /// Username and password of one entry (JSON), for filling or copying.
    pub fn secret(&self, id: &str) -> Result<String, JsError> {
        let id: Uuid = id.parse().map_err(js_err)?;
        self.with(|v| {
            let (_, e) = v.entry(id).ok_or_else(|| js_err("entry not found"))?;
            serde_json::to_string(&Secret { username: e.username.clone(), password: e.password.clone() })
                .map_err(js_err)
        })
    }

    /// Current TOTP code of an entry (JSON `{code, remaining}`).
    pub fn totp(&self, id: &str) -> Result<String, JsError> {
        let id: Uuid = id.parse().map_err(js_err)?;
        self.with(|v| {
            let (_, e) = v.entry(id).ok_or_else(|| js_err("entry not found"))?;
            let t = Totp::parse(e.totp.as_deref().ok_or_else(|| js_err("no TOTP for this entry"))?).map_err(js_err)?;
            let (code, remaining) = t.now();
            serde_json::to_string(&TotpView { code, remaining }).map_err(js_err)
        })
    }

    /// The encrypted vault file, to keep in browser storage.
    #[wasm_bindgen(js_name = toFile)]
    pub fn to_file(&self) -> Result<String, JsError> {
        self.with(|v| serde_json::to_string(&v.to_file().map_err(js_err)?).map_err(js_err))
    }

    /// All entries (without passwords) as JSON.
    pub fn entries(&self) -> Result<String, JsError> {
        self.with(|v| {
            let mut list: Vec<EntryView> = v.entries().map(|(c, e)| EntryView::new(&c.name, e)).collect();
            list.sort_by_key(|e| e.title.to_lowercase());
            serde_json::to_string(&list).map_err(js_err)
        })
    }

    /// Starts P2P sync; `save` is called with the vault file JSON whenever
    /// a sync changed something.
    #[wasm_bindgen(js_name = startSync)]
    pub async fn start_sync(&mut self, save: js_sys::Function) -> Result<(), JsError> {
        let cb = JsCallback(save);
        let shared = SharedVault::from_handle_with_saver(self.vault.clone(), move |file: &VaultFile| {
            let json = serde_json::to_string(file)?;
            cb.call(&json).map_err(|e| anyhow::anyhow!("saving failed: {e:?}"))
        });
        self.node = Some(SyncNode::spawn(shared, Network::Internet).await.map_err(js_err)?);
        Ok(())
    }

    /// Syncs with all reachable devices; returns how many succeeded.
    #[wasm_bindgen(js_name = syncNow)]
    pub async fn sync_now(&self) -> Result<usize, JsError> {
        let node = self.node.as_ref().ok_or_else(|| js_err("sync not started"))?;
        Ok(node.sync_all().await.into_iter().filter(|(_, r)| r.is_ok()).count())
    }
}

#[cfg(test)]
mod tests {
    use super::site_matches;

    #[test]
    fn matches_site_and_subdomains_only() {
        assert!(site_matches("https://github.com/login", "https://github.com/"));
        assert!(site_matches("github.com", "https://www.github.com/x"));
        assert!(site_matches("https://www.github.com", "https://gist.github.com/"));
        assert!(!site_matches("github.com", "https://github.com.evil.io/"));
        assert!(!site_matches("github.com", "https://notgithub.com/"));
        assert!(!site_matches("", "https://github.com/"));
    }
}
