//! P2P transport for Vaulti over [iroh](https://iroh.computer).
//!
//! Two protocols on one endpoint (the device's iroh key is stored in the vault):
//!
//! - `vaulti/pair/1`: a new device presents a one-time secret from a pairing
//!   ticket (QR code). Both devices then show the same 6-digit code derived
//!   from the secret and both device keys; only after the user confirms on
//!   the existing device does it send a copy of the (still encrypted) vault
//!   file. The user then unlocks it with the master password on the new device.
//! - `vaulti/sync/2`: three messages. The dialer sends a hash per collection;
//!   the acceptor replies with only the collections that differ (plus the
//!   small account state) and asks for the same ones back; the dialer merges
//!   and sends its merged copies of those. When nothing changed, a sync costs
//!   a few hundred bytes instead of the whole vault.
//! - `vaulti/sync/1`: the older single exchange of full [`SyncMessage`]s. Still
//!   accepted, and used when a peer runs an app version without `sync/2`.
//!
//! Only our own devices and contacts' devices are accepted; everything else
//! is refused before any data is read.
//!
//! Peers are found via n0's DNS address lookup (+ relay fallback), mDNS on
//! the local network, and addresses learned from pairing tickets. Relays only
//! ever see QUIC-encrypted traffic, and vault data is additionally encrypted.

use n0_future::time::{self, Duration, Instant};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use data_encoding::HEXLOWER;
use iroh::address_lookup::MemoryLookup;
use iroh::endpoint::{presets, Connection};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, oneshot};
use uuid::Uuid;
use vaulti_core::{store, FileV2, Peer, SyncMessage, SyncReport, Vault};

pub const SYNC_ALPN: &[u8] = b"vaulti/sync/1";
pub const SYNC2_ALPN: &[u8] = b"vaulti/sync/2";

/// `sync/2` step 1, dialer → acceptor.
#[derive(Serialize, Deserialize)]
struct Hello {
    digests: BTreeMap<Uuid, String>,
}

/// `sync/2` step 2, acceptor → dialer. Step 3 is a plain [`SyncMessage`].
#[derive(Serialize, Deserialize)]
struct Reply {
    msg: SyncMessage,
    want: Vec<Uuid>,
}
pub const PAIR_ALPN: &[u8] = b"vaulti/pair/1";
const MAX_MESSAGE: usize = 64 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(60);
pub const PAIRING_TTL: Duration = Duration::from_secs(10 * 60);
/// How long the existing device waits for the user to confirm the code.
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(3 * 60);
const TICKET_PREFIX: &str = "vaulti-pair:";

/// The unlocked vault shared between the UI/CLI and the network node.
/// Network handlers lock it briefly and save after changes.
#[derive(Clone)]
pub struct SharedVault {
    pub vault: Arc<Mutex<Option<Vault>>>,
    saver: Saver,
}

/// Where a changed vault is written: a file, or (browser extension) a callback
/// that puts the encrypted vault file into browser storage.
#[derive(Clone)]
enum Saver {
    File(PathBuf),
    Callback(Arc<SaveFn>),
}

type SaveFn = dyn Fn(&vaulti_core::VaultFile) -> Result<()> + Send + Sync;

impl SharedVault {
    pub fn new(vault: Vault, path: PathBuf) -> Self {
        Self { vault: Arc::new(Mutex::new(Some(vault))), saver: Saver::File(path) }
    }

    /// Shares an existing vault handle (the app keeps its own reference).
    pub fn from_handle(vault: Arc<Mutex<Option<Vault>>>, path: PathBuf) -> Self {
        Self { vault, saver: Saver::File(path) }
    }

    pub fn with_saver(
        vault: Vault,
        save: impl Fn(&vaulti_core::VaultFile) -> Result<()> + Send + Sync + 'static,
    ) -> Self {
        Self { vault: Arc::new(Mutex::new(Some(vault))), saver: Saver::Callback(Arc::new(save)) }
    }

    /// The vault file, if saved to disk.
    pub fn path(&self) -> Option<&PathBuf> {
        match &self.saver {
            Saver::File(p) => Some(p),
            Saver::Callback(_) => None,
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut Vault) -> Result<R>) -> Result<R> {
        let mut guard = self.vault.lock().map_err(|_| anyhow!("vault lock poisoned"))?;
        f(guard.as_mut().ok_or_else(|| anyhow!("vault is locked"))?)
    }

    fn save(&self, v: &Vault) -> Result<()> {
        let file = v.to_file()?;
        match &self.saver {
            Saver::File(path) => store::save(path, &file)?,
            Saver::Callback(save) => save(&file)?,
        }
        Ok(())
    }
}

/// How the endpoint finds peers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Network {
    /// n0 DNS lookup + relays + mDNS. Works across networks.
    #[default]
    Internet,
    /// Direct addresses only (learned from tickets / `add_addr`). For tests.
    LocalOnly,
}

#[derive(Debug, Clone)]
pub enum Event {
    Synced {
        node_id: String,
        peer: Peer,
        report: SyncReport,
    },
    /// A device presented a valid ticket. Show `code` and call
    /// [`SyncNode::confirm_pairing`]; the new device shows the same code.
    PairRequest {
        node_id: String,
        name: String,
        code: String,
    },
    Paired {
        node_id: String,
        name: String,
    },
}

/// Short code both devices display during pairing, e.g. `482 917`.
/// Bound to the ticket secret and both endpoint ids, so a device that
/// grabbed the QR code shows a different code than the user's own device.
pub fn pairing_code(secret: &[u8], host: &EndpointId, joiner: &EndpointId) -> String {
    let digest = Sha256::new()
        .chain_update(b"vaulti/pair-code/v1")
        .chain_update(secret)
        .chain_update(host.as_bytes())
        .chain_update(joiner.as_bytes())
        .finalize();
    let n = u32::from_be_bytes(digest[..4].try_into().expect("4 bytes")) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

pub fn node_id_hex(id: &EndpointId) -> String {
    HEXLOWER.encode(id.as_bytes())
}

pub fn parse_node_id(hex: &str) -> Result<EndpointId> {
    let bytes: [u8; 32] = HEXLOWER
        .decode(hex.as_bytes())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("invalid device id"))?;
    Ok(EndpointId::from_bytes(&bytes)?)
}

/// Pairing ticket shown on the existing device (as text / QR code).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairTicket {
    pub addr: EndpointAddr,
    #[serde(with = "hex_bytes")]
    pub secret: Vec<u8>,
}

impl PairTicket {
    pub fn encode(&self) -> String {
        format!("{TICKET_PREFIX}{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(self).expect("serializable")))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let raw = s.trim().strip_prefix(TICKET_PREFIX).ok_or_else(|| anyhow!("not a vaulti pairing ticket"))?;
        let bytes = URL_SAFE_NO_PAD.decode(raw.trim()).context("bad pairing ticket")?;
        serde_json::from_slice(&bytes).context("bad pairing ticket")
    }
}

mod hex_bytes {
    use data_encoding::HEXLOWER;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&HEXLOWER.encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        HEXLOWER.decode(String::deserialize(d)?.as_bytes()).map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize)]
struct PairRequest {
    #[serde(with = "hex_bytes")]
    secret: Vec<u8>,
    device_name: String,
}

#[derive(Serialize, Deserialize)]
enum PairResponse {
    Ok(Box<FileV2>),
    Refused(String),
}

struct Offer {
    secret: [u8; 16],
    expires: Instant,
}

struct Inner {
    shared: SharedVault,
    offer: Mutex<Option<Offer>>,
    /// Pairing requests waiting for the user's yes/no, by joiner node id.
    confirmations: Mutex<HashMap<String, oneshot::Sender<bool>>>,
    events: broadcast::Sender<Event>,
}

/// A running endpoint that accepts sync/pairing connections and can dial peers.
pub struct SyncNode {
    router: Router,
    memory: MemoryLookup,
    network: Network,
    inner: Arc<Inner>,
}

async fn bind(secret: [u8; 32], network: Network) -> Result<(Endpoint, MemoryLookup)> {
    let key = SecretKey::from_bytes(&secret);
    let endpoint = match network {
        Network::Internet => Endpoint::builder(presets::N0).secret_key(key).bind().await,
        Network::LocalOnly => Endpoint::builder(presets::Minimal).secret_key(key).bind().await,
    }
    .context("starting network endpoint")?;
    let memory = MemoryLookup::new();
    let lookups = endpoint.address_lookup().map_err(|e| anyhow!("{e}"))?;
    lookups.add(memory.clone());
    // Browsers can't do local-network discovery; there it's relays only.
    #[cfg(not(target_arch = "wasm32"))]
    if network == Network::Internet {
        match iroh_mdns_address_lookup::MdnsAddressLookup::builder().build(endpoint.id()) {
            Ok(mdns) => lookups.add(mdns),
            Err(e) => tracing::warn!("mDNS unavailable: {e}"),
        }
    }
    Ok((endpoint, memory))
}

/// Waits until the endpoint knows at least one address to put in a ticket.
async fn wait_for_addr(endpoint: &Endpoint, network: Network) -> EndpointAddr {
    if network == Network::Internet {
        // A relay connection gives a reachable address even behind NAT.
        let _ = time::timeout(Duration::from_secs(10), endpoint.online()).await;
    }
    for _ in 0..50 {
        let addr = endpoint.addr();
        if addr.ip_addrs().next().is_some() || addr.relay_urls().next().is_some() {
            return addr;
        }
        time::sleep(Duration::from_millis(100)).await;
    }
    endpoint.addr()
}

async fn send_json<T: Serialize>(send: &mut iroh::endpoint::SendStream, value: &T) -> Result<()> {
    send.write_all(&serde_json::to_vec(value)?).await?;
    send.finish()?;
    Ok(())
}

/// One length-prefixed JSON message, for streams that carry several.
async fn send_frame<T: Serialize>(send: &mut iroh::endpoint::SendStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    send.write_all(&u32::try_from(bytes.len())?.to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

async fn recv_frame<T: for<'de> Deserialize<'de>>(recv: &mut iroh::endpoint::RecvStream) -> Result<T> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_MESSAGE {
        bail!("sync message too large");
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

async fn recv_json<T: for<'de> Deserialize<'de>>(recv: &mut iroh::endpoint::RecvStream, limit: usize) -> Result<T> {
    let bytes = recv.read_to_end(limit).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl SyncNode {
    /// Starts the endpoint with the vault's device key and accepts connections.
    pub async fn spawn(shared: SharedVault, network: Network) -> Result<Arc<Self>> {
        Self::spawn_with(shared, network, true).await
    }

    /// `sync2: false` behaves like an app version from before `sync/2` (tests).
    async fn spawn_with(shared: SharedVault, network: Network, sync2: bool) -> Result<Arc<Self>> {
        let secret = shared.with(|v| Ok(v.device_secret()))?;
        let (endpoint, memory) = bind(secret, network).await?;
        let (events, _) = broadcast::channel(64);
        let inner =
            Arc::new(Inner { shared, offer: Mutex::new(None), confirmations: Mutex::new(HashMap::new()), events });
        let host = endpoint.id();
        let mut router = Router::builder(endpoint).accept(SYNC_ALPN, SyncHandler(inner.clone()));
        if sync2 {
            router = router.accept(SYNC2_ALPN, Sync2Handler(inner.clone()));
        }
        let router = router.accept(PAIR_ALPN, PairHandler { inner: inner.clone(), host }).spawn();
        Ok(Arc::new(Self { router, memory, network, inner }))
    }

    pub fn endpoint(&self) -> &Endpoint {
        self.router.endpoint()
    }

    pub fn node_id(&self) -> String {
        node_id_hex(&self.endpoint().id())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.events.subscribe()
    }

    /// Remembers a direct address for a peer (e.g. from a ticket).
    pub fn add_addr(&self, addr: EndpointAddr) {
        self.memory.add_endpoint_info(addr);
    }

    /// Our current address (for tickets, tests and diagnostics).
    pub async fn addr(&self) -> EndpointAddr {
        wait_for_addr(self.endpoint(), self.network).await
    }

    /// Creates a one-time pairing ticket, valid for [`PAIRING_TTL`].
    pub async fn start_pairing(&self) -> Result<String> {
        let mut secret = [0u8; 16];
        getrandom::fill(&mut secret).map_err(|e| anyhow!("{e}"))?;
        *self.inner.offer.lock().map_err(|_| anyhow!("poisoned"))? =
            Some(Offer { secret, expires: Instant::now() + PAIRING_TTL });
        let addr = self.addr().await;
        Ok(PairTicket { addr, secret: secret.to_vec() }.encode())
    }

    pub fn cancel_pairing(&self) {
        if let Ok(mut o) = self.inner.offer.lock() {
            *o = None;
        }
        if let Ok(mut c) = self.inner.confirmations.lock() {
            for (_, tx) in c.drain() {
                let _ = tx.send(false);
            }
        }
    }

    /// Answers an [`Event::PairRequest`].
    pub fn confirm_pairing(&self, node_id: &str, accept: bool) -> Result<()> {
        let tx = self
            .inner
            .confirmations
            .lock()
            .map_err(|_| anyhow!("poisoned"))?
            .remove(node_id)
            .ok_or_else(|| anyhow!("no pairing request from that device (expired?)"))?;
        let _ = tx.send(accept);
        Ok(())
    }

    /// Syncs with one peer. Errors if it's unreachable or not a known peer.
    pub async fn sync_with(&self, node_id: &str) -> Result<SyncReport> {
        let peer = self
            .inner
            .shared
            .with(|v| v.classify_peer(node_id).ok_or_else(|| anyhow!("{node_id} is not a known device")))?;
        let id = parse_node_id(node_id)?;
        let report = match self.connect(id, SYNC2_ALPN).await {
            Ok(conn) => {
                let result = time::timeout(EXCHANGE_TIMEOUT, self.exchange2(&conn, &peer)).await;
                conn.close(0u32.into(), b"done");
                result.map_err(|_| anyhow!("sync timed out"))??
            }
            // Reachable but refused sync/2: an older app version. Fall back to
            // the full exchange. (A timeout means offline; don't wait twice.)
            Err(e) if !is_timeout(&e) => {
                let conn = self.connect(id, SYNC_ALPN).await?;
                let result = time::timeout(EXCHANGE_TIMEOUT, self.exchange(&conn, &peer)).await;
                conn.close(0u32.into(), b"done");
                result.map_err(|_| anyhow!("sync timed out"))??
            }
            Err(e) => return Err(e),
        };
        let _ = self.inner.events.send(Event::Synced { node_id: node_id.to_string(), peer, report });
        Ok(report)
    }

    async fn connect(&self, id: EndpointId, alpn: &[u8]) -> Result<Connection> {
        Ok(time::timeout(CONNECT_TIMEOUT, self.endpoint().connect(id, alpn))
            .await
            .map_err(|_| anyhow!(CONNECT_TIMED_OUT))??)
    }

    async fn exchange2(&self, conn: &Connection, peer: &Peer) -> Result<SyncReport> {
        let digests = self.inner.shared.with(|v| Ok(v.sync_digests(peer)?))?;
        let (mut send, mut recv) = conn.open_bi().await?;
        send_frame(&mut send, &Hello { digests }).await?;
        let reply: Reply = recv_frame(&mut recv).await?;
        let report = self.inner.apply(peer, reply.msg)?;
        let back = self.inner.shared.with(|v| Ok(v.sync_message_with(peer, &reply.want)?))?;
        send_frame(&mut send, &back).await?;
        send.finish()?;
        let _ = recv.read_to_end(16).await; // acceptor closes its side when done
        Ok(report)
    }

    async fn exchange(&self, conn: &Connection, peer: &Peer) -> Result<SyncReport> {
        let msg = self.inner.shared.with(|v| Ok(v.sync_message(peer)?))?;
        let (mut send, mut recv) = conn.open_bi().await?;
        send_json(&mut send, &msg).await?;
        let reply: SyncMessage = recv_json(&mut recv, MAX_MESSAGE).await?;
        self.inner.apply(peer, reply)
    }

    /// Syncs with every known peer in parallel. Unreachable peers are
    /// normal (offline devices) and reported as errors per peer.
    pub async fn sync_all(self: &Arc<Self>) -> Vec<(String, Result<SyncReport>)> {
        let targets: Vec<String> = match self.inner.shared.with(|v| Ok(v.sync_targets())) {
            Ok(t) => t.into_iter().map(|(id, _)| id).collect(),
            Err(e) => return vec![(String::new(), Err(e))],
        };
        let mut set = n0_future::task::JoinSet::new();
        for id in targets {
            let node = self.clone();
            set.spawn(async move {
                let r = node.sync_with(&id).await;
                (id, r)
            });
        }
        let mut out = Vec::new();
        while let Some(r) = set.join_next().await {
            if let Ok(r) = r {
                out.push(r);
            }
        }
        out
    }

    pub async fn shutdown(&self) {
        let _ = self.router.shutdown().await;
    }
}

impl Inner {
    fn apply(&self, peer: &Peer, msg: SyncMessage) -> Result<SyncReport> {
        self.shared.with(|v| {
            let report = v.apply_sync(peer, msg)?;
            if report.changed {
                self.shared.save(v)?;
            }
            Ok(report)
        })
    }
}

fn user_err(e: anyhow::Error) -> AcceptError {
    AcceptError::from_boxed(e.into())
}

const CONNECT_TIMED_OUT: &str = "timed out connecting";

fn is_timeout(e: &anyhow::Error) -> bool {
    e.to_string() == CONNECT_TIMED_OUT
}

#[derive(Clone)]
struct Sync2Handler(Arc<Inner>);

impl std::fmt::Debug for Sync2Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sync2Handler")
    }
}

impl ProtocolHandler for Sync2Handler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let node_id = node_id_hex(&conn.remote_id());
        let Some(peer) = self.0.shared.with(|v| Ok(v.classify_peer(&node_id))).ok().flatten() else {
            conn.close(1u32.into(), b"unknown peer");
            return Ok(());
        };
        let (mut send, mut recv) = conn.accept_bi().await?;
        let hello: Hello = recv_frame(&mut recv).await.map_err(user_err)?;
        let reply = self
            .0
            .shared
            .with(|v| {
                let want = v.differing(&peer, &hello.digests)?;
                Ok(Reply { msg: v.sync_message_with(&peer, &want)?, want })
            })
            .map_err(user_err)?;
        send_frame(&mut send, &reply).await.map_err(user_err)?;
        // Step 3: the dialer's merged copies of what we asked for, plus its
        // account state (always small, merges are idempotent).
        let msg: SyncMessage = recv_frame(&mut recv).await.map_err(user_err)?;
        let report = self.0.apply(&peer, msg).map_err(user_err)?;
        send.finish().map_err(|e| user_err(e.into()))?;
        let _ = self.0.events.send(Event::Synced { node_id, peer, report });
        conn.closed().await;
        Ok(())
    }
}

#[derive(Clone)]
struct SyncHandler(Arc<Inner>);

impl std::fmt::Debug for SyncHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyncHandler")
    }
}

impl ProtocolHandler for SyncHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let node_id = node_id_hex(&conn.remote_id());
        let Some(peer) = self.0.shared.with(|v| Ok(v.classify_peer(&node_id))).ok().flatten() else {
            conn.close(1u32.into(), b"unknown peer");
            return Ok(());
        };
        let (mut send, mut recv) = conn.accept_bi().await?;
        let msg: SyncMessage = recv_json(&mut recv, MAX_MESSAGE).await.map_err(user_err)?;
        let report = self.0.apply(&peer, msg).map_err(user_err)?;
        let reply = self.0.shared.with(|v| Ok(v.sync_message(&peer)?)).map_err(user_err)?;
        send_json(&mut send, &reply).await.map_err(user_err)?;
        let _ = self.0.events.send(Event::Synced { node_id, peer, report });
        conn.closed().await;
        Ok(())
    }
}

#[derive(Clone)]
struct PairHandler {
    inner: Arc<Inner>,
    host: EndpointId,
}

impl std::fmt::Debug for PairHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairHandler")
    }
}

impl PairHandler {
    /// Checks and consumes the one-time offer (a second attempt needs a new ticket).
    fn take_offer(&self, secret: &[u8]) -> Result<bool> {
        let mut offer = self.inner.offer.lock().map_err(|_| anyhow!("poisoned"))?;
        let valid = offer.as_ref().is_some_and(|o| o.expires > Instant::now() && constant_time_eq(&o.secret, secret));
        if valid {
            *offer = None;
        }
        Ok(valid)
    }

    async fn handle(&self, joiner: EndpointId, req: PairRequest) -> Result<(PairResponse, Option<String>)> {
        let node_id = node_id_hex(&joiner);
        if !self.take_offer(&req.secret)? {
            return Ok((PairResponse::Refused("pairing code is invalid or expired".into()), None));
        }
        let name: String = req.device_name.trim().chars().take(64).collect();
        let name = if name.is_empty() { "New device".to_string() } else { name };

        let (tx, rx) = oneshot::channel();
        self.inner.confirmations.lock().map_err(|_| anyhow!("poisoned"))?.insert(node_id.clone(), tx);
        let code = pairing_code(&req.secret, &self.host, &joiner);
        let _ = self.inner.events.send(Event::PairRequest { node_id: node_id.clone(), name: name.clone(), code });
        let accepted = matches!(time::timeout(CONFIRM_TIMEOUT, rx).await, Ok(Ok(true)));
        if let Ok(mut c) = self.inner.confirmations.lock() {
            c.remove(&node_id);
        }
        if !accepted {
            return Ok((PairResponse::Refused("not confirmed on the other device".into()), None));
        }

        let file = self.inner.shared.with(|v| {
            v.add_device(&node_id, &name);
            self.inner.shared.save(v)?;
            Ok(v.file_for_new_device()?)
        })?;
        Ok((PairResponse::Ok(Box::new(file)), Some(name)))
    }
}

impl ProtocolHandler for PairHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let joiner = conn.remote_id();
        let (mut send, mut recv) = conn.accept_bi().await?;
        // A pairing request is tiny.
        let req: PairRequest = recv_json(&mut recv, 4096).await.map_err(user_err)?;
        let (resp, paired) = self.handle(joiner, req).await.map_err(user_err)?;
        send_json(&mut send, &resp).await.map_err(user_err)?;
        // Only report success once the new device has the file and hung up,
        // so callers can safely shut down on this event.
        conn.closed().await;
        if let Some(name) = paired {
            let _ = self.inner.events.send(Event::Paired { node_id: node_id_hex(&joiner), name });
        }
        Ok(())
    }
}

/// New-device side of pairing: connects with the device key this device
/// will keep, calls `on_code` with the confirmation code to display while
/// the user confirms on the other device, and returns the vault copy to
/// unlock with [`Vault::unlock_new_device`].
pub async fn join(
    ticket: &str,
    device_secret: [u8; 32],
    device_name: &str,
    network: Network,
    on_code: impl FnOnce(String) + Send,
) -> Result<FileV2> {
    let ticket = PairTicket::decode(ticket)?;
    let (endpoint, _memory) = bind(device_secret, network).await?;
    on_code(pairing_code(&ticket.secret, &ticket.addr.id, &endpoint.id()));
    let result = async {
        let conn = time::timeout(CONNECT_TIMEOUT, endpoint.connect(ticket.addr.clone(), PAIR_ALPN))
            .await
            .map_err(|_| anyhow!("timed out connecting to the other device"))??;
        let (mut send, mut recv) = conn.open_bi().await?;
        let req = PairRequest { secret: ticket.secret.clone(), device_name: device_name.to_string() };
        send_json(&mut send, &req).await?;
        let resp: PairResponse = time::timeout(CONFIRM_TIMEOUT + CONNECT_TIMEOUT, recv_json(&mut recv, MAX_MESSAGE))
            .await
            .map_err(|_| anyhow!("timed out waiting for confirmation"))??;
        conn.close(0u32.into(), b"done");
        match resp {
            PairResponse::Ok(file) => Ok(*file),
            PairResponse::Refused(why) => bail!("pairing refused: {why}"),
        }
    }
    .await;
    endpoint.close().await;
    result
}

/// Fresh random iroh key for a device that's about to join.
pub fn new_device_secret() -> Result<[u8; 32]> {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).map_err(|e| anyhow!("{e}"))?;
    Ok(s)
}

#[cfg(test)]
mod tests;
