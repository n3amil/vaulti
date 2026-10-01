use super::*;
use crate::crypto::KdfParams;

fn kdf() -> KdfParams {
    KdfParams::insecure_fast()
}

fn sample(title: &str) -> EntryInput {
    EntryInput {
        title: title.into(),
        username: Some("dude".into()),
        password: "hunter2".into(),
        url: Some("https://github.com".into()),
        notes: None,
    }
}

/// Simulates save + load through JSON.
fn roundtrip(v: &Vault) -> VaultFile {
    let json = serde_json::to_string(&v.to_file().unwrap()).unwrap();
    serde_json::from_str(&json).unwrap()
}

fn reload(v: &Vault, pw: &str) -> Vault {
    Vault::unlock(roundtrip(v), pw).unwrap()
}

fn personal(v: &Vault) -> Uuid {
    v.collections().find(|c| c.name == DEFAULT_COLLECTION).unwrap().id
}

fn new_user(name: &str) -> Vault {
    let (mut v, _) = Vault::create("password", kdf()).unwrap();
    v.set_profile_name(name);
    v
}

/// Pairs a second device the way the sync crate does: copy without local
/// state, new device key, register on the existing device.
fn pair(a: &mut Vault, pw: &str) -> Vault {
    let secret = *random_device_secret().unwrap();
    let file: FileV2 =
        serde_json::from_str(&serde_json::to_string(&a.file_for_new_device().unwrap()).unwrap()).unwrap();
    let b = Vault::unlock_new_device(file, pw, secret, "phone").unwrap();
    a.add_device(&b.node_id(), "phone");
    b
}

/// One sync exchange in both directions, through JSON like on the wire.
fn sync(a: &mut Vault, b: &mut Vault) -> (SyncReport, SyncReport) {
    let peer_b = a.classify_peer(&b.node_id()).expect("a knows b");
    let peer_a = b.classify_peer(&a.node_id()).expect("b knows a");
    let wire = |m: SyncMessage| -> SyncMessage { serde_json::from_slice(&serde_json::to_vec(&m).unwrap()).unwrap() };
    let to_b = wire(a.sync_message(&peer_b).unwrap());
    let rb = b.apply_sync(&peer_a, to_b).unwrap();
    let to_a = wire(b.sync_message(&peer_a).unwrap());
    let ra = a.apply_sync(&peer_b, to_a).unwrap();
    (ra, rb)
}

fn befriend(a: &mut Vault, b: &mut Vault) {
    a.add_contact(ContactCard::decode(&b.my_card().encode()).unwrap()).unwrap();
    b.add_contact(ContactCard::decode(&a.my_card().encode()).unwrap()).unwrap();
}

fn titles(v: &Vault, cid: Uuid) -> Vec<String> {
    let mut t: Vec<String> = v.collection(cid).unwrap().entries.iter().map(|e| e.title.clone()).collect();
    t.sort();
    t
}

// --- local vault -------------------------------------------------------------------

#[test]
fn create_and_unlock() {
    let (mut v, _code) = Vault::create("correct horse", kdf()).unwrap();
    let eid = v.add_entry(personal(&v), sample("GitHub")).unwrap();
    let v2 = reload(&v, "correct horse");
    let (c, e) = v2.entry(eid).unwrap();
    assert_eq!(c.name, DEFAULT_COLLECTION);
    assert_eq!(e.password, "hunter2");
    assert_eq!(v2.identity_public(), v.identity_public());
    assert_eq!(v2.node_id(), v.node_id(), "device key persists");
    assert!(c.is_owner() && !c.is_shared());
}

#[test]
fn wrong_password_fails() {
    let (v, _) = Vault::create("correct horse", kdf()).unwrap();
    assert!(matches!(Vault::unlock(roundtrip(&v), "wrong"), Err(Error::Decrypt)));
}

#[test]
fn recover_with_backup_code_rotates_code_and_password() {
    let (mut v, code) = Vault::create("old password", kdf()).unwrap();
    let eid = v.add_entry(personal(&v), sample("GitHub")).unwrap();
    let parsed = BackupCode::parse(&code.display()).unwrap();
    let (recovered, new_code) = Vault::recover(roundtrip(&v), &parsed, "new password").unwrap();
    assert_eq!(recovered.entry(eid).unwrap().1.password, "hunter2");
    let file = roundtrip(&recovered);
    assert!(Vault::unlock(file.clone(), "old password").is_err());
    assert!(Vault::unlock(file.clone(), "new password").is_ok());
    assert!(Vault::recover(file.clone(), &code, "x").is_err(), "old code must be invalid");
    assert!(Vault::recover(file, &new_code, "x").is_ok());
}

#[test]
fn change_password_keeps_backup_code() {
    let (mut v, code) = Vault::create("one", kdf()).unwrap();
    v.change_password("two").unwrap();
    let file = roundtrip(&v);
    assert!(Vault::unlock(file.clone(), "one").is_err());
    assert!(Vault::unlock(file.clone(), "two").is_ok());
    assert!(Vault::recover(file, &code, "three").is_ok());
}

#[test]
fn corrupted_collection_is_an_error_not_silent_loss() {
    let (mut v, _) = Vault::create("pw", kdf()).unwrap();
    v.create_collection("Work").unwrap();
    let VaultFile::Current(mut f) = roundtrip(&v) else { panic!() };
    let (a, b) = (f.collections[0].body.clone(), f.collections[1].body.clone());
    f.collections[0].body = b;
    f.collections[1].body = a;
    assert!(matches!(Vault::unlock(VaultFile::Current(f), "pw"), Err(Error::Decrypt)));
}

#[test]
fn entry_crud_search_and_persistence() {
    let (mut v, _) = Vault::create("pw", kdf()).unwrap();
    let work = v.create_collection("Work").unwrap();
    let id = v.add_entry(work, sample("GitHub")).unwrap();
    assert_eq!(v.search("git").len(), 1);
    assert_eq!(v.search("DUDE").len(), 1);
    v.update_entry(id, sample("GitLab")).unwrap();
    assert_eq!(v.search("gitlab").len(), 1);
    let created = v.entry(id).unwrap().1.created_at;

    let mut v = reload(&v, "pw");
    assert_eq!(v.entry(id).unwrap().1.created_at, created);
    v.remove_entry(id).unwrap();
    assert!(v.entry(id).is_none());
    assert!(matches!(v.remove_entry(id), Err(Error::EntryNotFound)));
    let v = reload(&v, "pw");
    assert!(v.entry(id).is_none(), "tombstone persists");
}

#[test]
fn delete_collection_hides_it() {
    let (mut v, _) = Vault::create("pw", kdf()).unwrap();
    let work = v.create_collection("Work").unwrap();
    v.delete_collection(work).unwrap();
    assert!(v.collection(work).is_none());
    assert!(reload(&v, "pw").collection(work).is_none());
}

#[test]
fn migrates_v1_vault() {
    let json = include_str!("../../tests/fixtures/v1-vault.json");
    let code = include_str!("../../tests/fixtures/v1-backup-code.txt").trim();
    let file: VaultFile = serde_json::from_str(json).unwrap();
    assert!(matches!(file, VaultFile::Legacy(_)));

    let v = Vault::unlock(file.clone(), "legacy password").unwrap();
    let mut names: Vec<&str> = v.collections().map(|c| c.name.as_str()).collect();
    names.sort();
    assert_eq!(names, ["Personal", "Work"]);
    assert_eq!(v.search("github")[0].1.username.as_deref(), Some("octo"));
    assert_eq!(v.search("aws")[0].0.name, "Work");

    // Saved as v2; password and the old backup code still work.
    let migrated = roundtrip(&v);
    assert!(matches!(migrated, VaultFile::Current(_)));
    assert!(Vault::unlock(migrated.clone(), "legacy password").is_ok());
    assert!(Vault::unlock_with_backup_code(migrated, &BackupCode::parse(code).unwrap()).is_ok());
    assert!(Vault::unlock_with_backup_code(file, &BackupCode::parse(code).unwrap()).is_ok());
}

// --- own devices -----------------------------------------------------------------------

#[test]
fn paired_devices_sync_entries_both_ways() {
    let (mut laptop, _) = Vault::create("pw", kdf()).unwrap();
    let pid = personal(&laptop);
    laptop.add_entry(pid, sample("before pairing")).unwrap();
    let mut phone = pair(&mut laptop, "pw");
    assert_ne!(phone.node_id(), laptop.node_id());
    assert_eq!(titles(&phone, pid), ["before pairing"]);

    // Phone doesn't know about itself as a device on the laptop until sync... it
    // registered itself; the laptop registered it too. Sync converges.
    laptop.add_entry(pid, sample("from laptop")).unwrap();
    phone.add_entry(pid, sample("from phone")).unwrap();
    sync(&mut laptop, &mut phone);
    for v in [&laptop, &phone] {
        assert_eq!(titles(v, pid), ["before pairing", "from laptop", "from phone"]);
        assert_eq!(v.devices().len(), 2);
    }

    // Second sync is a no-op.
    let (ra, rb) = sync(&mut laptop, &mut phone);
    assert!(!ra.changed && !rb.changed);
}

#[test]
fn concurrent_edit_last_writer_wins_and_delete_propagates() {
    let (mut laptop, _) = Vault::create("pw", kdf()).unwrap();
    let pid = personal(&laptop);
    let eid = laptop.add_entry(pid, sample("v0")).unwrap();
    let mut phone = pair(&mut laptop, "pw");

    laptop.update_entry(eid, sample("laptop edit")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    phone.update_entry(eid, sample("phone edit (later)")).unwrap();
    sync(&mut laptop, &mut phone);
    assert_eq!(laptop.entry(eid).unwrap().1.title, "phone edit (later)");
    assert_eq!(phone.entry(eid).unwrap().1.title, "phone edit (later)");

    laptop.remove_entry(eid).unwrap();
    sync(&mut laptop, &mut phone);
    assert!(phone.entry(eid).is_none());
}

#[test]
fn password_change_syncs_to_other_device() {
    let (mut laptop, _) = Vault::create("old", kdf()).unwrap();
    let mut phone = pair(&mut laptop, "old");
    phone.change_password("new").unwrap();
    sync(&mut laptop, &mut phone);
    let file = roundtrip(&laptop);
    assert!(Vault::unlock(file.clone(), "old").is_err());
    assert!(Vault::unlock(file, "new").is_ok());
}

#[test]
fn removed_device_is_no_longer_a_peer() {
    let (mut laptop, _) = Vault::create("pw", kdf()).unwrap();
    let phone = pair(&mut laptop, "pw");
    assert_eq!(laptop.classify_peer(&phone.node_id()), Some(Peer::OwnDevice));
    laptop.remove_device(&phone.node_id()).unwrap();
    assert_eq!(laptop.classify_peer(&phone.node_id()), None);
    assert!(laptop.remove_device(&laptop.node_id()).is_err());
}

#[test]
fn new_device_file_requires_pairing_setup() {
    let (v, _) = Vault::create("pw", kdf()).unwrap();
    let f = v.file_for_new_device().unwrap();
    assert!(matches!(Vault::unlock(VaultFile::Current(Box::new(f)), "pw"), Err(Error::NeedsDeviceSetup)));
}

// --- sharing ---------------------------------------------------------------------------

#[test]
fn share_collection_with_editor_round_trip() {
    let mut alice = new_user("Alice");
    let mut bob = new_user("Bob");
    befriend(&mut alice, &mut bob);

    let team = alice.create_collection("Team").unwrap();
    alice.add_entry(team, sample("shared db")).unwrap();
    alice.add_entry(personal(&alice), sample("alice private")).unwrap();
    alice.share_collection(team, &bob.user_id(), Role::Editor).unwrap();

    let (_, rb) = sync(&mut alice, &mut bob);
    assert_eq!(rb.new_collections, 1);
    let c = bob.collection(team).unwrap();
    assert_eq!(c.name, "Team");
    assert_eq!(c.my_role, Some(Role::Editor));
    assert_eq!(titles(&bob, team), ["shared db"]);
    assert!(bob.search("alice private").is_empty(), "personal collection not shared");

    bob.add_entry(team, sample("bob added")).unwrap();
    sync(&mut alice, &mut bob);
    assert_eq!(titles(&alice, team), ["bob added", "shared db"]);

    // Bob can't rename or reshare: owner only.
    assert!(matches!(bob.rename_collection(team, "mine"), Err(Error::NotAllowed(_))));

    // Persisted on Bob's side.
    let bob = reload(&bob, "password");
    assert_eq!(titles(&bob, team), ["bob added", "shared db"]);
}

#[test]
fn viewer_cannot_write() {
    let mut alice = new_user("Alice");
    let mut bob = new_user("Bob");
    befriend(&mut alice, &mut bob);
    let team = alice.create_collection("Team").unwrap();
    alice.share_collection(team, &bob.user_id(), Role::Viewer).unwrap();
    sync(&mut alice, &mut bob);
    assert!(!bob.collection(team).unwrap().can_write());
    assert!(matches!(bob.add_entry(team, sample("nope")), Err(Error::NotAllowed(_))));
}

#[test]
fn shared_collection_reaches_recipients_other_devices() {
    let mut alice = new_user("Alice");
    let mut bob = new_user("Bob");
    befriend(&mut alice, &mut bob);
    let mut bob_phone = pair(&mut bob, "password");

    let team = alice.create_collection("Team").unwrap();
    alice.add_entry(team, sample("x")).unwrap();
    alice.share_collection(team, &bob.user_id(), Role::Editor).unwrap();
    sync(&mut alice, &mut bob);
    sync(&mut bob, &mut bob_phone);
    assert_eq!(titles(&bob_phone, team), ["x"]);
}

#[test]
fn contact_card_updates_with_new_devices() {
    let mut alice = new_user("Alice");
    let mut bob = new_user("Bob");
    befriend(&mut alice, &mut bob);
    let bob_phone = pair(&mut bob, "password");
    assert_eq!(alice.classify_peer(&bob_phone.node_id()), None);
    sync(&mut alice, &mut bob);
    assert_eq!(alice.classify_peer(&bob_phone.node_id()), Some(Peer::Contact(bob.user_id())));
}

#[test]
fn unshare_stops_sending_and_rejects_edits() {
    let mut alice = new_user("Alice");
    let mut bob = new_user("Bob");
    befriend(&mut alice, &mut bob);
    let team = alice.create_collection("Team").unwrap();
    alice.share_collection(team, &bob.user_id(), Role::Editor).unwrap();
    sync(&mut alice, &mut bob);

    alice.unshare_collection(team, &bob.user_id()).unwrap();
    let peer_bob = alice.classify_peer(&bob.node_id()).unwrap();
    assert!(alice.sync_message(&peer_bob).unwrap().collections.is_empty());

    bob.add_entry(team, sample("after removal")).unwrap();
    let (ra, _) = sync(&mut alice, &mut bob);
    assert!(ra.rejected >= 1);
    assert!(titles(&alice, team).is_empty());
}

#[test]
fn strangers_and_impostors_are_rejected() {
    let mut alice = new_user("Alice");
    let mut mallory = new_user("Mallory");
    // Mallory knows Alice, but Alice never added Mallory.
    mallory.add_contact(alice.my_card()).unwrap();
    assert_eq!(alice.classify_peer(&mallory.node_id()), None);

    // Even if a message from Mallory arrives claiming to be a contact of Alice's
    // known friend Bob, the card must match the peer.
    let mut bob = new_user("Bob");
    befriend(&mut alice, &mut bob);
    let evil = mallory.create_collection("Free passwords").unwrap();
    mallory.share_collection(evil, &alice.user_id(), Role::Editor).unwrap();
    let msg = mallory.sync_message(&Peer::Contact(alice.user_id())).unwrap();
    assert!(alice.apply_sync(&Peer::Contact(bob.user_id()), msg.clone()).is_err());

    // And as a "contact" owner it's not trusted: collection rejected.
    mallory.add_contact(bob.my_card()).unwrap();
    let mut forwarded = bob.sync_message(&Peer::Contact(alice.user_id())).unwrap();
    forwarded.collections = msg.collections;
    let r = alice.apply_sync(&Peer::Contact(bob.user_id()), forwarded).unwrap();
    assert_eq!(r.new_collections, 0);
    assert!(alice.collection(evil).is_none());

    // Own-device state from another user is refused.
    let mut own = mallory.sync_message(&Peer::OwnDevice).unwrap();
    own.card = mallory.my_card();
    assert!(alice.apply_sync(&Peer::OwnDevice, own).is_err());
}
