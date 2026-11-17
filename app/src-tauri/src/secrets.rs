//! Passwords in the OS keychain (macOS Keychain, Windows Credential Manager, Secret Service).

const SERVICE: &str = "RemoteControl";

fn entry(id: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, id).map_err(|e| format!("keychain unavailable: {e}"))
}

/// The saved password, or `None` when there is none (or the keychain cannot be reached).
pub fn get(id: &str) -> Option<String> {
    match entry(id).and_then(|e| e.get_password().map_err(|e| e.to_string())) {
        Ok(password) => Some(password),
        Err(error) => {
            tracing::debug!(%error, "no saved password");
            None
        }
    }
}

pub fn set(id: &str, password: &str) -> Result<(), String> {
    entry(id)?
        .set_password(password)
        .map_err(|e| format!("cannot save the password in the keychain: {e}"))
}

pub fn delete(id: &str) {
    if let Ok(entry) = entry(id) {
        let _ = entry.delete_credential();
    }
}
