//! Saved connections, kept as JSON in the app's config directory. No secrets live here.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Rdp,
    Vnc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default = "yes")]
    pub nla: bool,
    #[serde(default = "yes")]
    pub ssh_tunnel: bool,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    #[serde(default)]
    pub pinned_identity: Option<String>,
}

fn yes() -> bool {
    true
}

fn default_ssh_port() -> u16 {
    22
}

pub struct Store {
    path: PathBuf,
    connections: Vec<Connection>,
}

impl Store {
    /// Load the store; a missing file is an empty store, an unreadable one is kept aside.
    pub fn load(path: PathBuf) -> Self {
        let connections = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(list) => list,
                Err(error) => {
                    let backup = path.with_extension("json.corrupt");
                    tracing::error!(%error, backup = %backup.display(), "connections file is unreadable; keeping a copy");
                    let _ = std::fs::rename(&path, backup);
                    Vec::new()
                }
            },
            Err(_) => Vec::new(),
        };
        Self { path, connections }
    }

    pub fn list(&self) -> Vec<Connection> {
        self.connections.clone()
    }

    pub fn get(&self, id: &str) -> Option<Connection> {
        self.connections.iter().find(|c| c.id == id).cloned()
    }

    /// Insert or replace by id.
    pub fn upsert(&mut self, connection: Connection) -> Result<(), String> {
        match self.connections.iter_mut().find(|c| c.id == connection.id) {
            Some(existing) => *existing = connection,
            None => self.connections.push(connection),
        }
        self.save()
    }

    pub fn remove(&mut self, id: &str) -> Result<(), String> {
        self.connections.retain(|c| c.id != id);
        self.save()
    }

    pub fn set_pin(&mut self, id: &str, pin: Option<String>) -> Result<(), String> {
        if let Some(connection) = self.connections.iter_mut().find(|c| c.id == id) {
            connection.pinned_identity = pin;
            self.save()?;
        }
        Ok(())
    }

    fn save(&self) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(&self.connections).map_err(|e| e.to_string())?;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        }
        // Write then rename so a crash never leaves a half-written file.
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("cannot replace {}: {e}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str) -> Connection {
        Connection {
            id: id.into(),
            name: "Office PC".into(),
            protocol: Protocol::Rdp,
            host: "10.0.0.5".into(),
            port: 3389,
            username: "nick".into(),
            domain: String::new(),
            nla: true,
            ssh_tunnel: true,
            ssh_port: 22,
            pinned_identity: None,
        }
    }

    #[test]
    fn round_trips_and_pins() {
        let dir = std::env::temp_dir().join(format!("rc-store-test-{}", std::process::id()));
        let path = dir.join("connections.json");
        let _ = std::fs::remove_dir_all(&dir);

        let mut store = Store::load(path.clone());
        assert!(store.list().is_empty());
        store.upsert(sample("a")).unwrap();
        store.upsert(sample("b")).unwrap();
        store.set_pin("a", Some("abc".into())).unwrap();
        store.remove("b").unwrap();

        let reloaded = Store::load(path);
        assert_eq!(reloaded.list().len(), 1);
        assert_eq!(reloaded.get("a").unwrap().pinned_identity.as_deref(), Some("abc"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn old_files_without_new_fields_still_load() {
        let json = r#"[{"id":"x","name":"Mac","protocol":"vnc","host":"mac.local","port":5900}]"#;
        let list: Vec<Connection> = serde_json::from_str(json).unwrap();
        assert!(list[0].ssh_tunnel && list[0].nla);
        assert_eq!(list[0].ssh_port, 22);
    }
}
