//! `vaulti` CLI: a thin dev/test client over vaulti-core.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use uuid::Uuid;
use vaulti_core::generator::{self, PasswordSpec};
use vaulti_core::{store, BackupCode, Collection, ContactCard, Entry, EntryInput, KdfParams, Role, UserId, Vault};
use vaulti_sync::{Network, SharedVault, SyncNode};
use zeroize::Zeroizing;

type Secret = Zeroizing<String>;

const MIN_PASSWORD_LEN: usize = 8;

#[derive(Parser)]
#[command(name = "vaulti", version, about = "Vaulti password manager (CLI)")]
struct Cli {
    /// Vault file [default: ~/.local/share/vaulti/vault.json]
    #[arg(long, global = true, env = "VAULTI_VAULT")]
    vault: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault and print its backup code
    Init,
    /// Show vault id and public identity keys
    Info,
    /// Add an entry
    Add {
        title: String,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        /// Collection name or id [default: first collection]
        #[arg(short, long)]
        collection: Option<String>,
        /// Generate a password instead of prompting for one
        #[arg(short, long)]
        generate: bool,
        #[arg(long, default_value_t = 20)]
        length: usize,
    },
    /// List entries, optionally filtered
    List {
        query: Option<String>,
        #[arg(short, long)]
        collection: Option<String>,
    },
    /// Show an entry including its password
    Show { entry: String },
    /// Edit an entry; only given fields change
    Edit {
        entry: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        /// Prompt for a new password
        #[arg(short, long)]
        password: bool,
        /// Generate a new password
        #[arg(short, long, conflicts_with = "password")]
        generate: bool,
        #[arg(long, default_value_t = 20)]
        length: usize,
    },
    /// Remove an entry
    Rm { entry: String },
    /// Manage collections
    #[command(subcommand)]
    Collection(CollectionCmd),
    /// Change the master password
    Passwd,
    /// Unlock with the backup code, set a new password, get a new code
    Recover,
    /// Replace the backup code with a new one
    BackupCode,
    /// Show or set the name others see when you share with them
    Profile { name: Option<String> },
    /// Your devices
    #[command(subcommand)]
    Device(DeviceCmd),
    /// Pair a new device: prints a one-time ticket and waits for it to join
    Pair,
    /// Set up this device from a ticket shown by `vaulti pair` on another device
    Join {
        ticket: String,
        /// Name for this device
        #[arg(long, default_value = "CLI")]
        name: String,
    },
    /// Sync once with all reachable devices and contacts
    Sync,
    /// Stay online: accept syncs and sync with everyone every minute
    Serve,
    /// Contacts (people you can share with)
    #[command(subcommand)]
    Contact(ContactCmd),
    /// Share a collection with a contact (or change their role)
    Share {
        collection: String,
        contact: String,
        #[arg(long, value_parser = ["editor", "viewer"], default_value = "editor")]
        role: String,
    },
    /// Remove a contact from a collection
    Unshare { collection: String, contact: String },
    /// List the members of a collection
    Members { collection: String },
    /// Generate a random password (no vault needed)
    Generate {
        #[arg(long, default_value_t = 20)]
        length: usize,
        #[arg(long)]
        no_symbols: bool,
    },
}

#[derive(Subcommand)]
enum DeviceCmd {
    List,
    Rename {
        device: String,
        name: String,
    },
    /// Remove a device (it stops syncing)
    Rm {
        device: String,
    },
}

#[derive(Subcommand)]
enum ContactCmd {
    /// Print your contact card to send to someone
    Card,
    /// Add someone from their contact card
    Add {
        card: String,
    },
    List,
    Rm {
        contact: String,
    },
}

#[derive(Subcommand)]
enum CollectionCmd {
    List,
    Add {
        name: String,
    },
    Rename {
        collection: String,
        name: String,
    },
    /// Delete a collection and all its entries
    Rm {
        collection: String,
    },
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let path = match cli.vault {
        Some(p) => p,
        None => dirs::data_dir().context("no data dir")?.join("vaulti/vault.json"),
    };

    match cli.cmd {
        Cmd::Init => {
            if path.exists() {
                bail!("vault already exists at {}", path.display());
            }
            let pw = new_password("New master password")?;
            let (mut vault, code) = Vault::create(&pw, kdf_params())?;
            let me = vault.node_id();
            vault.add_device(&me, &hostname());
            store::save(&path, &vault.to_file()?)?;
            println!("Created vault at {}", path.display());
            print_backup_code(&code);
        }
        Cmd::Info => {
            let v = unlock(&path)?;
            println!("path:         {}", path.display());
            println!("profile name: {}", v.profile_name());
            println!("user id:      {}", v.user_id());
            println!("fingerprint:  {}", v.identity_public().fingerprint());
            println!("this device:  {}", v.node_id());
        }
        Cmd::Add { title, username, url, notes, collection, generate, length } => {
            let mut v = unlock(&path)?;
            let cid = resolve_collection(&v, collection.as_deref())?;
            let password =
                if generate { gen(length, false)?.to_string() } else { prompt("Entry password")?.to_string() };
            v.add_entry(cid, EntryInput { title: title.clone(), username, password, url, notes })?;
            store::save(&path, &v.to_file()?)?;
            println!("Added \"{title}\" to {}", v.collection(cid).expect("exists").name);
        }
        Cmd::List { query, collection } => {
            let v = unlock(&path)?;
            let filter = collection.as_deref().map(|c| resolve_collection(&v, Some(c))).transpose()?;
            let mut rows: Vec<(&Collection, &Entry)> = match &query {
                Some(q) => v.search(q),
                None => v.entries().collect(),
            };
            rows.retain(|(c, _)| filter.is_none_or(|f| c.id == f));
            rows.sort_by_key(|(c, e)| (c.name.to_lowercase(), e.title.to_lowercase()));
            for (c, e) in rows {
                println!("{}  {:<12} {:<24} {}", short(e.id), c.name, e.title, e.username.as_deref().unwrap_or(""));
            }
        }
        Cmd::Show { entry } => {
            let v = unlock(&path)?;
            let (c, e) = v.entry(resolve_entry(&v, &entry)?).expect("resolved");
            println!("id:         {}", e.id);
            println!("collection: {}", c.name);
            println!("title:      {}", e.title);
            println!("username:   {}", e.username.as_deref().unwrap_or(""));
            println!("password:   {}", e.password);
            println!("url:        {}", e.url.as_deref().unwrap_or(""));
            if let Some(n) = &e.notes {
                println!("notes:      {n}");
            }
        }
        Cmd::Edit { entry, title, username, url, notes, password, generate, length } => {
            let mut v = unlock(&path)?;
            let id = resolve_entry(&v, &entry)?;
            let cur = v.entry(id).expect("resolved").1.clone();
            let new_pw = if generate {
                gen(length, false)?.to_string()
            } else if password {
                prompt("New entry password")?.to_string()
            } else {
                cur.password
            };
            v.update_entry(
                id,
                EntryInput {
                    title: title.unwrap_or(cur.title),
                    username: username.or(cur.username),
                    password: new_pw,
                    url: url.or(cur.url),
                    notes: notes.or(cur.notes),
                },
            )?;
            store::save(&path, &v.to_file()?)?;
            println!("Updated {}", short(id));
        }
        Cmd::Rm { entry } => {
            let mut v = unlock(&path)?;
            let removed = v.remove_entry(resolve_entry(&v, &entry)?)?;
            store::save(&path, &v.to_file()?)?;
            println!("Removed \"{}\"", removed.title);
        }
        Cmd::Collection(cmd) => {
            let mut v = unlock(&path)?;
            match cmd {
                CollectionCmd::List => {
                    for c in v.collections() {
                        let sharing = match (c.is_owner(), c.is_shared()) {
                            (true, true) => format!("shared with {}", c.members.len() - 1),
                            (true, false) => String::new(),
                            (false, _) => format!("{} (owner: {})", role_name(c.my_role), owner_name(c)),
                        };
                        println!("{}  {:<20} {:>3} entries  {sharing}", short(c.id), c.name, c.entries.len());
                    }
                    return Ok(());
                }
                CollectionCmd::Add { name } => {
                    v.create_collection(&name)?;
                    println!("Created collection \"{name}\"");
                }
                CollectionCmd::Rename { collection, name } => {
                    let id = resolve_collection(&v, Some(&collection))?;
                    v.rename_collection(id, &name)?;
                    println!("Renamed to \"{name}\"");
                }
                CollectionCmd::Rm { collection } => {
                    let id = resolve_collection(&v, Some(&collection))?;
                    if v.collections().count() == 1 {
                        bail!("cannot delete the last collection");
                    }
                    let c = v.delete_collection(id)?;
                    println!("Deleted \"{}\" ({} entries)", c.name, c.entries.len());
                }
            }
            store::save(&path, &v.to_file()?)?;
        }
        Cmd::Passwd => {
            let mut v = unlock(&path)?;
            let pw = new_password("New master password")?;
            v.change_password(&pw)?;
            store::save(&path, &v.to_file()?)?;
            println!("Master password changed. Your backup code is unchanged.");
        }
        Cmd::Recover => {
            let file = store::load(&path).with_context(|| format!("reading {}", path.display()))?;
            let code = match std::env::var("VAULTI_BACKUP_CODE") {
                Ok(c) => Zeroizing::new(c),
                Err(_) => prompt("Backup code")?,
            };
            let code = BackupCode::parse(&code)?;
            // Unlock first so a wrong code fails before asking for a new password.
            let mut v = Vault::unlock_with_backup_code(file, &code).context("backup code rejected")?;
            let pw = new_password("New master password")?;
            v.change_password(&pw)?;
            let new_code = v.rotate_backup_code()?;
            store::save(&path, &v.to_file()?)?;
            println!("Vault recovered and master password set. Your old backup code no longer works.");
            print_backup_code(&new_code);
        }
        Cmd::BackupCode => {
            let mut v = unlock(&path)?;
            let code = v.rotate_backup_code()?;
            store::save(&path, &v.to_file()?)?;
            println!("Old backup code is now invalid.");
            print_backup_code(&code);
        }
        Cmd::Profile { name } => {
            let mut v = unlock(&path)?;
            match name {
                Some(n) => {
                    v.set_profile_name(&n);
                    store::save(&path, &v.to_file()?)?;
                    println!("Profile name set to \"{n}\"");
                }
                None => println!("{}", v.profile_name()),
            }
        }
        Cmd::Device(cmd) => {
            let mut v = unlock(&path)?;
            match cmd {
                DeviceCmd::List => {
                    for d in v.devices() {
                        let me = if d.this_device { "  (this device)" } else { "" };
                        println!("{}  {}{me}", &d.node_id[..12], d.name);
                    }
                }
                DeviceCmd::Rename { device, name } => {
                    let d = resolve_device(&v, &device)?;
                    v.add_device(&d.node_id, &name);
                    store::save(&path, &v.to_file()?)?;
                    println!("Renamed \"{}\" to \"{name}\"", d.name);
                }
                DeviceCmd::Rm { device } => {
                    let d = resolve_device(&v, &device)?;
                    v.remove_device(&d.node_id)?;
                    store::save(&path, &v.to_file()?)?;
                    println!("Removed device \"{}\"", d.name);
                }
            }
        }
        Cmd::Pair => {
            let shared = SharedVault::new(unlock(&path)?, path.clone());
            runtime()?.block_on(async {
                let node = SyncNode::spawn(shared, Network::Internet).await?;
                let mut events = node.subscribe();
                let ticket = node.start_pairing().await?;
                println!("On the new device run:\n\n  vaulti join {ticket}\n");
                println!("Waiting (10 minutes max, Ctrl+C to cancel)...");
                let wait = async {
                    loop {
                        match events.recv().await {
                            Ok(vaulti_sync::Event::PairRequest { node_id, name, code }) => {
                                println!("\n\"{name}\" wants to join. It should show the code:\n\n    {code}\n");
                                let ok = tokio::task::spawn_blocking(|| {
                                    print!("Does it match? [y/N] ");
                                    let _ = std::io::Write::flush(&mut std::io::stdout());
                                    let mut line = String::new();
                                    let _ = std::io::stdin().read_line(&mut line);
                                    line.trim().eq_ignore_ascii_case("y")
                                })
                                .await
                                .unwrap_or(false);
                                let _ = node.confirm_pairing(&node_id, ok);
                                if !ok {
                                    return None;
                                }
                            }
                            Ok(vaulti_sync::Event::Paired { name, .. }) => return Some(name),
                            _ => {}
                        }
                    }
                };
                tokio::select! {
                    name = wait => match name {
                        Some(name) => println!("Paired \"{name}\"."),
                        None => println!("Rejected. Run `vaulti pair` again for a new ticket."),
                    },
                    _ = tokio::time::sleep(vaulti_sync::PAIRING_TTL) => println!("Ticket expired."),
                    _ = tokio::signal::ctrl_c() => println!("Cancelled."),
                }
                node.shutdown().await;
                anyhow::Ok(())
            })?;
        }
        Cmd::Join { ticket, name } => {
            if path.exists() {
                bail!("a vault already exists at {} (use --vault for another path)", path.display());
            }
            let secret = vaulti_sync::new_device_secret()?;
            println!("Connecting...");
            let file = runtime()?.block_on(vaulti_sync::join(&ticket, secret, &name, Network::Internet, |code| {
                println!("\nConfirm on your other device that it shows this code:\n\n    {code}\n");
            }))?;
            println!("Received the vault. Unlock it with your master password.");
            let pw = master_password("Master password")?;
            let v = Vault::unlock_new_device(file, &pw, secret, &name)?;
            store::save(&path, &v.to_file()?)?;
            println!("This device is set up ({} entries). Run `vaulti sync` to stay up to date.", v.entries().count());
        }
        Cmd::Sync => {
            let shared = SharedVault::new(unlock(&path)?, path.clone());
            runtime()?.block_on(async {
                let node = SyncNode::spawn(shared.clone(), Network::Internet).await?;
                print_sync_results(&shared, node.sync_all().await);
                node.shutdown().await;
                anyhow::Ok(())
            })?;
        }
        Cmd::Serve => {
            let shared = SharedVault::new(unlock(&path)?, path.clone());
            runtime()?.block_on(async {
                let node = SyncNode::spawn(shared.clone(), Network::Internet).await?;
                let mut events = node.subscribe();
                println!("Online as {} (Ctrl+C to stop)", &node.node_id()[..12]);
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    tokio::select! {
                        _ = tick.tick() => print_sync_results(&shared, node.sync_all().await),
                        Ok(ev) = events.recv() => match ev {
                            vaulti_sync::Event::Synced { node_id, report, .. } if report.changed => {
                                println!("synced with {}: {} new collections, {} entries updated",
                                    peer_name(&shared, &node_id), report.new_collections, report.entries_updated);
                            }
                            vaulti_sync::Event::Paired { name, .. } => println!("paired {name}"),
                            _ => {}
                        },
                        _ = tokio::signal::ctrl_c() => break,
                    }
                }
                node.shutdown().await;
                anyhow::Ok(())
            })?;
        }
        Cmd::Contact(cmd) => {
            let mut v = unlock(&path)?;
            match cmd {
                ContactCmd::Card => {
                    println!("{}", v.my_card().encode());
                    eprintln!(
                        "\nSend this to the person you want to share with. They add it with `vaulti contact add`."
                    );
                    eprintln!("Your fingerprint (compare it with them): {}", v.identity_public().fingerprint());
                    return Ok(());
                }
                ContactCmd::Add { card } => {
                    let card = ContactCard::decode(&card)?;
                    println!("Adding \"{}\" with fingerprint {}", card.name, card.identity.fingerprint());
                    println!("Compare the fingerprint with them (e.g. by phone) before sharing anything.");
                    v.add_contact(card)?;
                }
                ContactCmd::List => {
                    for c in v.contacts() {
                        println!(
                            "{}  {:<20} {}  {} devices",
                            &c.identity.user_id().0[..8],
                            c.name,
                            c.identity.fingerprint(),
                            c.devices.len()
                        );
                    }
                    return Ok(());
                }
                ContactCmd::Rm { contact } => {
                    let uid = resolve_contact(&v, &contact)?;
                    v.remove_contact(&uid)?;
                    println!("Removed contact. Collections you shared stay shared until you `unshare` them.");
                }
            }
            store::save(&path, &v.to_file()?)?;
        }
        Cmd::Share { collection, contact, role } => {
            let mut v = unlock(&path)?;
            let cid = resolve_collection(&v, Some(&collection))?;
            let uid = resolve_contact(&v, &contact)?;
            let role = if role == "viewer" { Role::Viewer } else { Role::Editor };
            v.share_collection(cid, &uid, role)?;
            store::save(&path, &v.to_file()?)?;
            println!("Shared. It reaches them on the next sync (`vaulti sync`).");
        }
        Cmd::Unshare { collection, contact } => {
            let mut v = unlock(&path)?;
            let cid = resolve_collection(&v, Some(&collection))?;
            let uid = resolve_contact(&v, &contact)
                .or_else(|_| member_by_name(v.collection(cid).expect("resolved"), &contact))?;
            v.unshare_collection(cid, &uid)?;
            store::save(&path, &v.to_file()?)?;
            println!("Removed. They keep what they already synced; change those passwords if needed.");
        }
        Cmd::Members { collection } => {
            let v = unlock(&path)?;
            let c = v.collection(resolve_collection(&v, Some(&collection))?).expect("resolved");
            for m in &c.members {
                let me = if m.identity.user_id() == v.user_id() { " (you)" } else { "" };
                println!("{:<8} {}{me}  {}", role_name(Some(m.role)), m.name, m.identity.fingerprint());
            }
        }
        Cmd::Generate { length, no_symbols } => {
            println!("{}", *gen(length, no_symbols)?);
        }
    }
    Ok(())
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread().enable_all().build()?)
}

fn peer_name(shared: &SharedVault, node_id: &str) -> String {
    let guard = shared.vault.lock().expect("lock");
    let Some(v) = guard.as_ref() else { return node_id[..12].to_string() };
    if let Some(d) = v.devices().into_iter().find(|d| d.node_id == node_id) {
        return format!("your device \"{}\"", d.name);
    }
    let name = v
        .contacts()
        .find(|c| c.devices.iter().any(|d| d == node_id))
        .map(|c| format!("{}'s device", c.name))
        .unwrap_or_else(|| node_id[..12].to_string());
    name
}

fn print_sync_results(shared: &SharedVault, results: Vec<(String, Result<vaulti_core::SyncReport>)>) {
    if results.is_empty() {
        println!("Nothing to sync with yet: pair a device (`vaulti pair`) or add a contact.");
    }
    for (node_id, r) in results {
        match r {
            Ok(r) => println!(
                "{}: ok ({} new collections, {} entries updated{})",
                peer_name(shared, &node_id),
                r.new_collections,
                r.entries_updated,
                if r.rejected > 0 { format!(", {} rejected", r.rejected) } else { String::new() }
            ),
            Err(e) => println!("{}: unreachable ({e})", peer_name(shared, &node_id)),
        }
    }
}

fn role_name(r: Option<Role>) -> &'static str {
    match r {
        Some(Role::Owner) => "owner",
        Some(Role::Editor) => "editor",
        Some(Role::Viewer) => "viewer",
        None => "removed",
    }
}

fn owner_name(c: &Collection) -> String {
    c.members.iter().find(|m| m.identity.user_id() == c.owner).map(|m| m.name.clone()).unwrap_or_default()
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "Linux".into())
}

fn resolve_device(v: &Vault, needle: &str) -> Result<vaulti_core::DeviceView> {
    let n = needle.to_lowercase();
    v.devices()
        .into_iter()
        .find(|d| d.name.to_lowercase() == n || (n.len() >= 4 && d.node_id.starts_with(&n)))
        .ok_or_else(|| anyhow!("no device \"{needle}\" (see `vaulti device list`)"))
}

fn resolve_contact(v: &Vault, needle: &str) -> Result<UserId> {
    let n = needle.to_lowercase();
    let hits: Vec<UserId> = v
        .contacts()
        .filter(|c| c.name.to_lowercase() == n || (n.len() >= 4 && c.identity.user_id().0.starts_with(&n)))
        .map(|c| c.identity.user_id())
        .collect();
    match hits.len() {
        0 => Err(anyhow!("no contact \"{needle}\" (see `vaulti contact list`)")),
        1 => Ok(hits.into_iter().next().expect("one")),
        _ => Err(anyhow!("\"{needle}\" matches several contacts, use the id")),
    }
}

fn member_by_name(c: &Collection, needle: &str) -> Result<UserId> {
    c.members
        .iter()
        .find(|m| m.name.eq_ignore_ascii_case(needle))
        .map(|m| m.identity.user_id())
        .ok_or_else(|| anyhow!("\"{needle}\" is not a member"))
}

fn kdf_params() -> KdfParams {
    // Debug builds only: lets scripted smoke tests skip the slow KDF.
    if cfg!(debug_assertions) && std::env::var_os("VAULTI_INSECURE_KDF").is_some() {
        eprintln!("warning: using insecure KDF parameters (VAULTI_INSECURE_KDF)");
        return KdfParams::insecure_fast();
    }
    KdfParams::default()
}

fn unlock(path: &Path) -> Result<Vault> {
    let file = store::load(path).with_context(|| format!("reading {} (run `vaulti init`?)", path.display()))?;
    let pw = master_password("Master password")?;
    Ok(Vault::unlock(file, &pw)?)
}

/// Master password from `VAULTI_PASSWORD` (scripting) or an interactive prompt.
fn master_password(label: &str) -> Result<Secret> {
    if let Ok(pw) = std::env::var("VAULTI_PASSWORD") {
        return Ok(Zeroizing::new(pw));
    }
    prompt(label)
}

fn new_password(label: &str) -> Result<Secret> {
    let pw = if let Ok(pw) = std::env::var("VAULTI_NEW_PASSWORD") {
        Zeroizing::new(pw)
    } else {
        let a = prompt(label)?;
        let b = prompt("Repeat")?;
        if *a != *b {
            bail!("passwords do not match");
        }
        a
    };
    if pw.chars().count() < MIN_PASSWORD_LEN {
        bail!("master password must be at least {MIN_PASSWORD_LEN} characters");
    }
    Ok(pw)
}

fn prompt(label: &str) -> Result<Secret> {
    Ok(Zeroizing::new(rpassword::prompt_password(format!("{label}: "))?))
}

fn gen(length: usize, no_symbols: bool) -> Result<Secret> {
    let p = generator::generate(PasswordSpec { length, symbols: !no_symbols, ..Default::default() })?;
    Ok(p)
}

fn print_backup_code(code: &BackupCode) {
    println!();
    println!("  BACKUP CODE:  {}", *code.display());
    println!();
    println!("Write it down and keep it offline. It is shown only once.");
    println!("With it you can reset your master password (`vaulti recover`).");
}

fn short(id: Uuid) -> String {
    id.simple().to_string()[..8].to_string()
}

/// Matches by id prefix, then exact title, then unique search hit.
fn resolve_entry(v: &Vault, needle: &str) -> Result<Uuid> {
    let n = needle.to_lowercase();
    let by_id: Vec<Uuid> =
        v.entries().map(|(_, e)| e.id).filter(|id| id.simple().to_string().starts_with(&n)).collect();
    if n.len() >= 4 && by_id.len() == 1 {
        return Ok(by_id[0]);
    }
    let exact: Vec<Uuid> = v.entries().filter(|(_, e)| e.title.to_lowercase() == n).map(|(_, e)| e.id).collect();
    let hits = if exact.is_empty() { v.search(needle).into_iter().map(|(_, e)| e.id).collect() } else { exact };
    match hits.len() {
        0 => Err(anyhow!("no entry matches \"{needle}\"")),
        1 => Ok(hits[0]),
        n => Err(anyhow!("\"{needle}\" matches {n} entries, use the id from `vaulti list`")),
    }
}

fn resolve_collection(v: &Vault, needle: Option<&str>) -> Result<Uuid> {
    let Some(needle) = needle else {
        return v.collections().next().map(|c| c.id).ok_or_else(|| anyhow!("vault has no collections"));
    };
    let n = needle.to_lowercase();
    let hits: Vec<Uuid> = v
        .collections()
        .filter(|c| c.name.to_lowercase() == n || (n.len() >= 4 && c.id.simple().to_string().starts_with(&n)))
        .map(|c| c.id)
        .collect();
    match hits.len() {
        0 => Err(anyhow!("no collection \"{needle}\"")),
        1 => Ok(hits[0]),
        _ => Err(anyhow!("\"{needle}\" is ambiguous")),
    }
}
