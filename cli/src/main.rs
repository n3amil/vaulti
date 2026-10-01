//! `vaulti` CLI: a thin dev/test client over vaulti-core.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use uuid::Uuid;
use vaulti_core::generator::{self, PasswordSpec};
use vaulti_core::{store, BackupCode, Collection, Entry, EntryInput, KdfParams, Vault};
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
    /// Generate a random password (no vault needed)
    Generate {
        #[arg(long, default_value_t = 20)]
        length: usize,
        #[arg(long)]
        no_symbols: bool,
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
            let (vault, code) = Vault::create(&pw, kdf_params())?;
            store::save(&path, &vault.to_file()?)?;
            println!("Created vault at {}", path.display());
            print_backup_code(&code);
        }
        Cmd::Info => {
            let v = unlock(&path)?;
            let id = v.identity_public();
            println!("path:            {}", path.display());
            println!("vault id:        {}", v.vault_id());
            println!("signing key:     {}", hex(&id.signing));
            println!("encryption key:  {}", hex(&id.encryption));
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
                        println!("{}  {:<20} {} entries", short(c.id), c.name, c.entries.len());
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
        Cmd::Generate { length, no_symbols } => {
            println!("{}", *gen(length, no_symbols)?);
        }
    }
    Ok(())
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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
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
