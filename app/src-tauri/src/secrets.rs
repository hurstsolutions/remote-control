//! Passwords in the OS keychain (macOS Keychain, Windows Credential Manager, Secret Service).
//!
//! Each entry holds the password together with the machine and account it was saved for (a small
//! JSON payload), so a password can never be sent somewhere else even if the saved connection was
//! edited behind the keychain's back. Entries saved before that are plain passwords; they are taken
//! as belonging to the connection's current target and rewritten in the new form on first use.

use serde::{Deserialize, Serialize};

use crate::store::{Connection, Protocol};

const SERVICE: &str = "RemoteControl";
/// Marks an entry written in the bound form.
const FORMAT: u32 = 1;

/// The machine and account a saved password belongs to. Built normalized, so plain equality
/// matches `Connection::same_target` plus `Connection::same_account`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    protocol: Protocol,
    host: String,
    port: u16,
    ssh_tunnel: bool,
    /// 0 when the tunnel is off (the SSH port does not matter then).
    ssh_port: u16,
    username: String,
    domain: String,
}

impl Binding {
    pub fn of(connection: &Connection) -> Self {
        Self {
            protocol: connection.protocol,
            host: connection.host.to_ascii_lowercase(),
            port: connection.port,
            ssh_tunnel: connection.ssh_tunnel,
            ssh_port: if connection.ssh_tunnel { connection.ssh_port } else { 0 },
            username: connection.username.clone(),
            domain: connection.domain.to_ascii_lowercase(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Payload {
    remotecontrol_secret: u32,
    target: Binding,
    password: String,
}

/// What the keychain holds for a connection.
#[derive(Debug, PartialEq, Eq)]
pub enum Saved {
    Missing,
    Found(String),
    /// A password saved for another machine or account. Never use it.
    WrongTarget,
}

#[derive(Debug, PartialEq, Eq)]
enum Decoded {
    Bound(String),
    /// A plain password from before entries were bound.
    Legacy(String),
    WrongTarget,
}

fn decode(raw: String, binding: &Binding) -> Decoded {
    match serde_json::from_str::<Payload>(&raw) {
        Ok(payload) if payload.remotecontrol_secret == FORMAT => {
            if payload.target == *binding {
                Decoded::Bound(payload.password)
            } else {
                Decoded::WrongTarget
            }
        }
        _ => Decoded::Legacy(raw),
    }
}

fn encode(password: &str, binding: &Binding) -> Result<String, String> {
    serde_json::to_string(&Payload { remotecontrol_secret: FORMAT, target: binding.clone(), password: password.to_owned() })
        .map_err(|e| e.to_string())
}

fn entry(id: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, id).map_err(|e| format!("keychain unavailable: {e}"))
}

/// The raw entry: `Ok(None)` only when the keychain says there is none. Any other failure is an
/// error, never "no password".
fn get_raw(id: &str) -> Result<Option<String>, String> {
    match entry(id)?.get_password() {
        Ok(raw) => Ok(Some(raw)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("cannot read the keychain: {e}")),
    }
}

/// Whether an entry exists under this id (whatever it is bound to).
pub fn exists(id: &str) -> Result<bool, String> {
    get_raw(id).map(|raw| raw.is_some())
}

/// The password saved for this connection's current target.
pub fn get(id: &str, binding: &Binding) -> Result<Saved, String> {
    let Some(raw) = get_raw(id)? else { return Ok(Saved::Missing) };
    Ok(match decode(raw, binding) {
        Decoded::Bound(password) => Saved::Found(password),
        Decoded::Legacy(password) => {
            // Bind it to the target it is being used for now.
            match set(id, &password, binding) {
                Ok(()) => tracing::info!(%id, "saved password bound to its connection's address and account"),
                Err(error) => tracing::warn!(%id, %error, "cannot rewrite the saved password in the new form"),
            }
            Saved::Found(password)
        }
        Decoded::WrongTarget => Saved::WrongTarget,
    })
}

pub fn set(id: &str, password: &str, binding: &Binding) -> Result<(), String> {
    entry(id)?
        .set_password(&encode(password, binding)?)
        .map_err(|e| format!("cannot save the password in the keychain: {e}"))
}

/// Remove the saved password. `Ok(true)` when one was removed, `Ok(false)` when there was none.
pub fn delete(id: &str) -> Result<bool, String> {
    match entry(id)?.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(format!("cannot remove the password from the keychain: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection() -> Connection {
        serde_json::from_str(r#"{"id":"a","name":"Mac","protocol":"vnc","host":"Mac.local","port":5900,"username":"sam"}"#)
            .unwrap()
    }

    #[test]
    fn bound_entries_are_used_only_for_their_target() {
        let c = connection();
        let binding = Binding::of(&c);
        let raw = encode("hunter2", &binding).unwrap();
        assert!(!raw.is_empty());
        assert_eq!(decode(raw.clone(), &binding), Decoded::Bound("hunter2".into()));
        // Host and domain compare without case; the SSH port only counts with the tunnel on.
        let same = Connection { host: "MAC.LOCAL".into(), ..c.clone() };
        assert_eq!(decode(raw.clone(), &Binding::of(&same)), Decoded::Bound("hunter2".into()));
        for other in [
            Connection { host: "10.0.0.66".into(), ..c.clone() },
            Connection { port: 5901, ..c.clone() },
            Connection { protocol: Protocol::Rdp, ..c.clone() },
            Connection { ssh_tunnel: false, ..c.clone() },
            Connection { ssh_port: 2222, ..c.clone() },
            Connection { username: "admin".into(), ..c.clone() },
            Connection { domain: "CORP".into(), ..c.clone() },
        ] {
            assert_eq!(decode(raw.clone(), &Binding::of(&other)), Decoded::WrongTarget, "{other:?}");
        }
        let direct = Connection { ssh_tunnel: false, ..c.clone() };
        let direct_raw = encode("pw", &Binding::of(&direct)).unwrap();
        assert_eq!(decode(direct_raw, &Binding::of(&Connection { ssh_port: 2222, ..direct })), Decoded::Bound("pw".into()));
    }

    #[test]
    fn plain_old_entries_are_legacy() {
        let binding = Binding::of(&connection());
        for raw in ["hunter2", "", "{\"not\":\"ours\"}", "{\"remotecontrol_secret\":2}", "{"] {
            assert_eq!(decode(raw.into(), &binding), Decoded::Legacy(raw.into()), "{raw}");
        }
    }
}
