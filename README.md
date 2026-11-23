# RemoteControl

One desktop app for remote control of Windows machines (Remote Desktop / RDP) and Macs
(built-in Screen Sharing / VNC). Rust core, Tauri shell; targets macOS first, then Linux and Windows.

## Layout

| Path | What |
| --- | --- |
| `crates/rc-types` | Events and input messages shared by every backend and front end |
| `crates/rc-rdp` | RDP backend (IronRDP): TLS, certificate pinning, NLA sign-in, frames, input, text clipboard |
| `crates/rc-vnc` | VNC backend, including Apple (Mac username/password) sign-in |
| `crates/rc-tunnel` | SSH tunnel (password sign-in, pinned host key) that carries VNC to a Mac |
| `app/` | Desktop app: web UI in `app/src`, Tauri (Rust) side in `app/src-tauri` |
| `crates/rc-cli` | `rc`, a headless test client: connect, type, click, save a screenshot, verbose log |

## Build and test

```sh
cargo test --workspace      # includes end-to-end tests against in-process mock servers
cd app && npm ci && npm test && npx tauri build   # the desktop app
cargo build -p rc-cli
RC_PASSWORD='...' ./target/debug/rc rdp HOST -u USER --screenshot shot.png
```

## Releases

Actions > Release > Run workflow builds installable apps (macOS universal `.dmg` by default) and
publishes them as a pre-release. Builds are unsigned.

### Verifying downloads

Each release has a `SHA256SUMS.txt` listing the SHA-256 of every file in it. Download it next to
the installer and compare.

macOS:

```sh
shasum -a 256 -c SHA256SUMS.txt --ignore-missing
```

Linux:

```sh
sha256sum -c SHA256SUMS.txt --ignore-missing
```

Windows (PowerShell): print the hash and compare it with the installer's line in `SHA256SUMS.txt`.

```powershell
(Get-FileHash .\RemoteControl_0.1.0_x64-setup.exe -Algorithm SHA256).Hash.ToLower()
Select-String RemoteControl_0.1.0_x64-setup.exe SHA256SUMS.txt
```

A match only shows the file arrived intact from the release; the builds are still unsigned.
