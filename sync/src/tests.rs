//! End-to-end tests over real iroh endpoints on localhost (no relay/DNS).

use super::*;
use vaulti_core::{ContactCard, EntryInput, KdfParams, Role};

const N: Network = Network::LocalOnly;

fn entry(title: &str) -> EntryInput {
    EntryInput { title: title.into(), password: "pw".into(), ..Default::default() }
}

struct Dev {
    node: Arc<SyncNode>,
    shared: SharedVault,
    _dir: tempfile::TempDir,
}

impl Dev {
    async fn new(name: &str) -> Dev {
        let (mut v, _) = Vault::create("password", KdfParams::insecure_fast()).unwrap();
        v.set_profile_name(name);
        Self::from_vault(v).await
    }

    async fn from_vault(v: Vault) -> Dev {
        Self::from_vault_with(v, true).await
    }

    async fn from_vault_with(v: Vault, sync2: bool) -> Dev {
        let dir = tempfile::tempdir().unwrap();
        let shared = SharedVault::new(v, dir.path().join("vault.json"));
        let node = SyncNode::spawn_with(shared.clone(), N, sync2).await.unwrap();
        Dev { node, shared, _dir: dir }
    }

    fn v<R>(&self, f: impl FnOnce(&mut Vault) -> R) -> R {
        f(self.shared.vault.lock().unwrap().as_mut().unwrap())
    }

    /// Without DNS discovery, tell each node where the other one is.
    async fn introduce(&self, other: &Dev) {
        self.node.add_addr(other.node.addr().await);
        other.node.add_addr(self.node.addr().await);
    }

    fn titles(&self) -> Vec<String> {
        let mut t: Vec<String> = self.v(|v| v.entries().map(|(_, e)| e.title.clone()).collect());
        t.sort();
        t
    }
}

/// Answers the next pairing request on `dev` and returns the code it showed.
fn auto_confirm(dev: &Dev, accept: bool) -> tokio::task::JoinHandle<String> {
    let (node, mut rx) = (dev.node.clone(), dev.node.subscribe());
    tokio::spawn(async move {
        loop {
            if let Ok(Event::PairRequest { node_id, code, .. }) = rx.recv().await {
                node.confirm_pairing(&node_id, accept).unwrap();
                return code;
            }
        }
    })
}

async fn join_capturing_code(ticket: &str, secret: [u8; 32]) -> (Result<FileV2>, String) {
    let shown = Arc::new(Mutex::new(String::new()));
    let s2 = shown.clone();
    let r = join(ticket, secret, "phone", N, move |c| *s2.lock().unwrap() = c).await;
    let code = shown.lock().unwrap().clone();
    (r, code)
}

#[tokio::test]
async fn pair_then_sync_both_ways() {
    let laptop = Dev::new("Me").await;
    let pid = laptop.v(|v| v.collections().next().unwrap().id);
    laptop.v(|v| v.add_entry(pid, entry("from laptop")).unwrap());

    let ticket = laptop.node.start_pairing().await.unwrap();
    let secret = new_device_secret().unwrap();
    let confirm = auto_confirm(&laptop, true);
    let (file, phone_code) = join_capturing_code(&ticket, secret).await;
    let laptop_code = confirm.await.unwrap();
    assert_eq!(phone_code, laptop_code, "both devices show the same code");
    assert_eq!(phone_code.len(), 7);
    let phone_vault = Vault::unlock_new_device(file.unwrap(), "password", secret, "phone").unwrap();
    assert_eq!(laptop.v(|v| v.devices().len()), 2, "laptop registered the phone");

    // Ticket is single use.
    assert!(join(&ticket, new_device_secret().unwrap(), "evil", N, |_| {}).await.is_err());

    let phone = Dev::from_vault(phone_vault).await;
    assert_eq!(phone.titles(), ["from laptop"]);
    laptop.introduce(&phone).await;

    phone.v(|v| v.add_entry(pid, entry("from phone")).unwrap());
    let report = phone.node.sync_with(&laptop.node.node_id()).await.unwrap();
    assert!(report.changed || report.entries_updated == 0);
    assert_eq!(laptop.titles(), ["from laptop", "from phone"]);

    laptop.v(|v| v.add_entry(pid, entry("later")).unwrap());
    let results = laptop.node.sync_all().await;
    assert!(results.iter().all(|(_, r)| r.is_ok()), "{results:?}");
    assert_eq!(phone.titles(), ["from laptop", "from phone", "later"]);

    // Nothing changed since: the sync/2 hashes match and nothing is applied.
    let again = phone.node.sync_with(&laptop.node.node_id()).await.unwrap();
    assert!(!again.changed, "{again:?}");
    assert_eq!(
        laptop.v(|v| v.sync_digests(&vaulti_core::Peer::OwnDevice).unwrap()),
        phone.v(|v| v.sync_digests(&vaulti_core::Peer::OwnDevice).unwrap())
    );

    // Saved to disk on the receiving side.
    let reloaded = Vault::unlock(store::load(phone.shared.path().unwrap()).unwrap(), "password").unwrap();
    assert_eq!(reloaded.entries().count(), 3);
}

#[tokio::test]
async fn wrong_ticket_secret_is_refused() {
    let laptop = Dev::new("Me").await;
    let ticket = laptop.node.start_pairing().await.unwrap();
    let mut t = PairTicket::decode(&ticket).unwrap();
    t.secret[0] ^= 1;
    let err = join(&t.encode(), new_device_secret().unwrap(), "x", N, |_| {}).await.unwrap_err();
    assert!(err.to_string().contains("refused"), "{err}");
    assert_eq!(laptop.v(|v| v.devices().len()), 1);
}

#[tokio::test]
async fn rejected_confirmation_sends_nothing() {
    let laptop = Dev::new("Me").await;
    let ticket = laptop.node.start_pairing().await.unwrap();
    let reject = auto_confirm(&laptop, false);
    let (r, _) = join_capturing_code(&ticket, new_device_secret().unwrap()).await;
    reject.await.unwrap();
    let err = r.unwrap_err();
    assert!(err.to_string().contains("not confirmed"), "{err}");
    assert_eq!(laptop.v(|v| v.devices().len()), 1);
    // The ticket was used up by the attempt.
    assert!(join(&ticket, new_device_secret().unwrap(), "again", N, |_| {}).await.is_err());
}

#[test]
fn codes_differ_per_device() {
    let secret = [7u8; 16];
    let host = SecretKey::from_bytes(&[1; 32]).public();
    let a = SecretKey::from_bytes(&[2; 32]).public();
    let b = SecretKey::from_bytes(&[3; 32]).public();
    assert_eq!(pairing_code(&secret, &host, &a), pairing_code(&secret, &host, &a));
    assert_ne!(pairing_code(&secret, &host, &a), pairing_code(&secret, &host, &b));
}

#[tokio::test]
async fn share_between_users_and_refuse_strangers() {
    let alice = Dev::new("Alice").await;
    let bob = Dev::new("Bob").await;
    let mallory = Dev::new("Mallory").await;
    alice.introduce(&bob).await;
    alice.introduce(&mallory).await;

    let bob_card = ContactCard::decode(&bob.v(|v| v.my_card().encode())).unwrap();
    let alice_card = ContactCard::decode(&alice.v(|v| v.my_card().encode())).unwrap();
    let bob_id = alice.v(|v| v.add_contact(bob_card).unwrap());
    bob.v(|v| v.add_contact(alice_card.clone()).unwrap());
    mallory.v(|v| v.add_contact(alice_card).unwrap());

    let team = alice.v(|v| {
        let team = v.create_collection("Team").unwrap();
        v.add_entry(team, entry("shared")).unwrap();
        v.share_collection(team, &bob_id, Role::Editor).unwrap();
        team
    });

    alice.node.sync_with(&bob.node.node_id()).await.unwrap();
    assert_eq!(bob.v(|v| v.collection(team).map(|c| c.name.clone())), Some("Team".into()));
    assert_eq!(bob.titles(), ["shared"]);

    bob.v(|v| v.add_entry(team, entry("bob's")).unwrap());
    bob.node.sync_with(&alice.node.node_id()).await.unwrap();
    assert_eq!(alice.titles(), ["bob's", "shared"]);

    // Alice doesn't know Mallory: Mallory's connection is refused.
    assert!(mallory.node.sync_with(&alice.node.node_id()).await.is_err());
    assert_eq!(mallory.titles(), Vec::<String>::new());
}

#[tokio::test]
async fn falls_back_to_sync1_for_older_peers() {
    let laptop = Dev::new("Me").await;
    let pid = laptop.v(|v| v.collections().next().unwrap().id);
    let ticket = laptop.node.start_pairing().await.unwrap();
    let secret = new_device_secret().unwrap();
    let confirm = auto_confirm(&laptop, true);
    let (file, _) = join_capturing_code(&ticket, secret).await;
    confirm.await.unwrap();
    let old = Vault::unlock_new_device(file.unwrap(), "password", secret, "old phone").unwrap();
    let old_phone = Dev::from_vault_with(old, false).await;
    laptop.introduce(&old_phone).await;

    laptop.v(|v| v.add_entry(pid, entry("to old app")).unwrap());
    laptop.node.sync_with(&old_phone.node.node_id()).await.unwrap();
    assert_eq!(old_phone.titles(), ["to old app"]);

    old_phone.v(|v| v.add_entry(pid, entry("from old app")).unwrap());
    old_phone.node.sync_with(&laptop.node.node_id()).await.unwrap();
    assert_eq!(laptop.titles(), ["from old app", "to old app"]);
}
