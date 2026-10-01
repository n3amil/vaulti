# vaulti

Peer-to-peer password manager. No central server: devices sync directly,
collections can be shared with other users and organisations.

**Status:** phase 1 (local vault + CLI). Not audited — don't store real secrets yet.

## Roadmap (MVP: Linux desktop + Android)

1. ✅ Core vault, crypto, recovery, CLI
2. Device pairing (QR) + P2P sync via [iroh](https://iroh.computer), CRDT merge
3. Tauri 2 desktop UI (Linux)
4. Android build (Tauri 2)
5. Sharing collections with other users
6. Organisations: admin-signed membership log, roles

## Key hierarchy

```
root key (random 256 bit)
 ├─ wrapped by Argon2id(master password)   password slot
 └─ wrapped by Argon2id(backup code)       recovery slot
root key ─wraps─▶ identity keys (ed25519 + x25519, for sharing)
root key ─wraps─▶ collection key ─encrypts─▶ collection (name + entries)
```

- XChaCha20-Poly1305 everywhere; every ciphertext is bound (AAD) to vault id + purpose.
- Changing the master password or the backup code only rewraps the root key.
- Recovery: backup code → set new master password → new backup code issued, old one invalid.
- Losing **both** master password and backup code means the data is gone.

## CLI

```sh
cargo build --release
./target/release/vaulti init                    # prints backup code once
vaulti add GitHub -u me --url https://github.com -g
vaulti collection add Work
vaulti add "AWS prod" -u admin -c work -g --length 32
vaulti list [query] [-c work]
vaulti show github
vaulti edit github -g
vaulti passwd | recover | backup-code | info | generate
```

Vault file: `~/.local/share/vaulti/vault.json` (override with `--vault` / `VAULTI_VAULT`).
For scripting: `VAULTI_PASSWORD`, `VAULTI_NEW_PASSWORD`, `VAULTI_BACKUP_CODE`;
debug builds also honour `VAULTI_INSECURE_KDF=1`.

## Development

```sh
cargo test
cargo clippy --all-targets
cargo fmt
```
