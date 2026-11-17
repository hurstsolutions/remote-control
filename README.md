# RemoteControl

One desktop app for remote control of Windows machines (Remote Desktop / RDP) and Macs
(built-in Screen Sharing / VNC). Rust core, Tauri shell; targets macOS first, then Linux and Windows.

## Layout

| Path | What |
| --- | --- |
| `crates/rc-types` | Events and input messages shared by every backend and front end |
| `crates/rc-rdp` | RDP backend (IronRDP): TLS, certificate pinning, NLA sign-in, frames, input, text clipboard |
| `crates/rc-vnc` | VNC backend, including Apple (Mac username/password) sign-in |
| `crates/rc-cli` | `rc`, a headless test client: connect, type, click, save a screenshot, verbose log |

## Build and test

```sh
cargo test -p rc-rdp        # includes end-to-end tests against an in-process mock RDP server
cargo build -p rc-cli
RC_PASSWORD='...' ./target/debug/rc rdp HOST -u USER --screenshot shot.png
```
