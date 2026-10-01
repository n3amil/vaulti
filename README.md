# vaulti

Peer-to-peer password manager. No central server: devices sync directly,
collections can be shared with other users and organisations.

**Status:** Linux desktop app + CLI with P2P device sync and collection sharing. Android next. Not audited — don't store real secrets yet.

## Roadmap (MVP: Linux desktop + Android)

1. ✅ Core vault, crypto, recovery, CLI
2. ✅ Device pairing (QR/ticket + confirmation code) + P2P sync via [iroh](https://iroh.computer), CRDT merge
3. ✅ Tauri 2 desktop app (Linux .deb)
4. ✅ Sharing collections with contacts (owner / editor / viewer)
5. Android app (Tauri 2): pairs with the desktop via QR code
6. Organisations: admin-signed membership log, roles
7. Collection key rotation on member removal

## Features

- Collections of entries (title, username, password, URL, notes, **TOTP**), search, copy with clipboard auto-clear
- **Generator:** passwords (length, A–Z / a–z / 0–9 / symbols, avoid look-alikes) or **passphrases**
  (EFF wordlist without hyphenated words, 3–20 words, any separator, capitalize, add a number), with strength estimate
- **TOTP (RFC 6238):** paste a secret or `otpauth://` link (scan on Android); code with countdown next to the password
- **Encrypted backups:** export everything to a `.vaulti` file protected by a backup password (Argon2id +
  XChaCha20-Poly1305); import into any vault, duplicates skipped
- P2P device sync, pairing via QR + confirmation code, sharing collections (see below)

Planned: CSV import/export (migration from Bitwarden/Vaultwarden and KeePassXC), organisations.

## Key hierarchy

```
root key (random 256 bit, same on all your devices)
 ├─ wrapped by Argon2id(master password)   password slot  ┐ synced between
 └─ wrapped by Argon2id(backup code)       recovery slot  ┘ your devices
root key ─seals─▶ identity (ed25519 signing + x25519), account (devices, contacts), device key
identity (x25519) ─opens─▶ collection key   (one KeyWrap per member)
collection key ─seals─▶ collection doc: owner-signed meta (name, members, roles)
                                         + author-signed entries
```

- XChaCha20-Poly1305 everywhere; every ciphertext is bound (AAD) to its purpose.
- Changing the master password or the backup code only rewraps the root key, and syncs to your other devices.
- Recovery: backup code → set new master password → new backup code issued, old one invalid.
- Losing **both** master password and backup code means the data is gone.

## Sync & sharing

- **Transport:** iroh (QUIC, ed25519 endpoint ids, hole punching). Peers found via n0's DNS lookup,
  mDNS on the LAN, relays as fallback. Relays only see encrypted QUIC; vault data is encrypted again.
- **Who can connect:** only your own devices and your contacts' devices; anyone else is refused before data is read.
- **Merge:** state-based CRDT. Per entry, the newest version (hybrid logical clock) with a valid
  signature from a current editor/owner wins; deletes are tombstones. Account data is last-writer-wins.
- **Pairing:** the existing device shows a one-time QR/ticket (10 min). The new device connects,
  both show a 6-digit code (bound to the ticket secret and both device keys), you confirm on the
  existing device, then it sends the encrypted vault; the new device unlocks it with your master password.
- **Sharing:** exchange contact cards, compare fingerprints, share a collection as editor or viewer.
  Members receive it the next time you're both online.
- **Limits (for now):** both sides must be online at the same time. Removing a member stops future
  updates but doesn't rotate the collection key; they keep what they already synced.
- Vault files from before sync (format v1) are migrated on first unlock.

## Desktop app (Linux)

Built in Docker, nothing needed on the host except Docker:

```sh
scripts/docker.sh deb            # -> dist/Vaulti_<version>_amd64.deb
sudo apt install ./dist/Vaulti_0.1.0_amd64.deb
```

Runtime deps: `libwebkit2gtk-4.1-0`, `libgtk-3-0`. Uses the same vault file as the CLI.

### Flatpak

`flatpak/io.github.n3amil.Vaulti.yml` repackages the binary from the .deb on the GNOME 49 runtime
(all linked libraries are in the runtime, nothing is bundled). Built in CI, see below.

```sh
flatpak install --user Vaulti.flatpak   # from a release / workflow artifact
flatpak run io.github.n3amil.Vaulti
```

Inside the Flatpak the vault lives in `~/.var/app/io.github.n3amil.Vaulti/data/vaulti/vault.json`
(separate from the CLI's `~/.local/share/vaulti/vault.json`).
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
vaulti passwd | recover | backup-code | info
vaulti generate --length 24 --no-symbols --avoid-ambiguous
vaulti generate --passphrase --words 6 --separator " " --capitalize --number
vaulti add GitHub -g --passphrase --totp "otpauth://totp/GitHub:me?secret=..."
vaulti totp github                   # current code
vaulti backup export backup.vaulti | backup import backup.vaulti

# devices
vaulti pair                          # on the existing device: prints a ticket, asks you to confirm the code
vaulti join <ticket> --name laptop   # on the new device
vaulti sync | serve                  # sync once / stay online
vaulti device list | rename | rm

# sharing
vaulti profile "Your Name"
vaulti contact card                  # send this to someone
vaulti contact add <card>            # shows their fingerprint
vaulti share work alice --role editor
vaulti members work | unshare work alice
```

Vault file: `~/.local/share/vaulti/vault.json` (override with `--vault` / `VAULTI_VAULT`).
For scripting: `VAULTI_PASSWORD`, `VAULTI_NEW_PASSWORD`, `VAULTI_BACKUP_CODE`;
debug builds also honour `VAULTI_INSECURE_KDF=1`.

## CI / releases (GitHub Actions)

- `ci.yml`: every push to `main` and every PR: fmt, clippy (`-D warnings`), all tests.
- `release.yml`: push a tag `v*` (or run it manually): builds the .deb (same Docker build as
  locally), the Flatpak, the Android APK and a universal macOS .dmg, and publishes a GitHub
  release (tags like `v0.1.0-alpha.2` become pre-releases).
- `android.yml`, `macos.yml`: also runnable on their own. APKs are signed with the key from the
  `ANDROID_KEYSTORE_B64` / `ANDROID_KEYSTORE_PASSWORD` secrets; the macOS app is unsigned for now.
- `ios.yml`: iOS simulator build on every app change (compile check, no Apple account needed).

```sh
git tag v0.1.0 && git push origin v0.1.0
```

## Development

```sh
scripts/docker.sh check   # fmt + clippy + tests for the whole workspace (incl. app)
scripts/docker.sh shell   # shell in the build container
cargo test                # host: core + cli only (app needs WebKitGTK, build it in Docker)
```

Layout: `core/` vault, crypto, CRDT merge (no networking), `sync/` iroh transport, `cli/` dev CLI, `app/` Tauri app (`ui/` plain HTML/JS, `src-tauri/` Rust commands).
