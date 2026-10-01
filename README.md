# vaulti

Peer-to-peer password manager. No central server: devices sync directly,
collections can be shared with other users and organisations.

**Status:** local vault, CLI and Linux desktop app. No sync yet. Not audited — don't store real secrets yet.

## Roadmap (MVP: Linux desktop + Android)

1. ✅ Core vault, crypto, recovery, CLI
2. Device pairing (QR) + P2P sync via [iroh](https://iroh.computer), CRDT merge
3. ✅ Tauri 2 desktop app (Linux .deb)
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

## Desktop app (Linux)

Built in Docker, nothing needed on the host except Docker:

```sh
scripts/docker.sh deb            # -> dist/Vaulti_<version>_amd64.deb
sudo apt install ./dist/Vaulti_0.1.0_amd64.deb
```

Runtime deps: `libwebkit2gtk-4.1-0`, `libgtk-3-0`. Uses the same vault file as the CLI.
Auto-locks after 5 min idle; copied passwords are cleared from the clipboard after 30 s.
Shortcuts: Ctrl+F search, Ctrl+N new entry, Ctrl+C copy password, Ctrl+L lock.

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
scripts/docker.sh check   # fmt + clippy + tests for the whole workspace (incl. app)
scripts/docker.sh shell   # shell in the build container
cargo test                # host: core + cli only (app needs WebKitGTK, build it in Docker)
```

Layout: `core/` vault + crypto, `cli/` dev CLI, `app/` Tauri app (`ui/` plain HTML/JS, `src-tauri/` Rust commands).
