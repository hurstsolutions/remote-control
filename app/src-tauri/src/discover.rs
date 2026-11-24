//! "Find computers": the saved subnets (subnets.json in the config directory) and on-demand scans
//! of them. Nothing here runs unless the user presses Scan.

use std::path::PathBuf;

use rc_discover::{CancelToken, Cidr};
use serde::{Deserialize, Serialize};

use crate::private_fs;

/// At most this many saved subnets.
pub const MAX_SUBNETS: usize = 64;
/// Labels are cut to this many characters.
pub const MAX_LABEL_CHARS: usize = 80;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subnet {
    /// Empty string when new; assigned on save.
    pub id: String,
    /// CIDR, e.g. "10.0.0.0/24". Normalized on save.
    pub cidr: String,
    #[serde(default)]
    pub label: String,
    /// The user confirmed that this public (non-private) range is their own network.
    #[serde(default)]
    pub allow_public: bool,
}

pub struct SubnetStore {
    path: PathBuf,
    subnets: Vec<Subnet>,
}

impl SubnetStore {
    /// A missing file is an empty list; an unreadable one is kept aside.
    pub fn load(path: PathBuf) -> Self {
        let subnets = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<Vec<Subnet>>(&bytes) {
                // Whatever is on disk passes the same checks as what the UI sends.
                Ok(list) => list.into_iter().filter_map(|s| validate_one(s).ok()).take(MAX_SUBNETS).collect(),
                Err(error) => {
                    let backup = path.with_extension("json.corrupt");
                    tracing::error!(%error, backup = %backup.display(), "subnets file is unreadable; keeping a copy");
                    let _ = std::fs::rename(&path, backup);
                    Vec::new()
                }
            },
            Err(_) => Vec::new(),
        };
        Self { path, subnets }
    }

    pub fn list(&self) -> Vec<Subnet> {
        self.subnets.clone()
    }

    /// Validate and replace the whole list.
    pub fn replace(&mut self, incoming: Vec<Subnet>) -> Result<Vec<Subnet>, String> {
        let list = validate(incoming)?;
        let json = serde_json::to_vec_pretty(&list).map_err(|e| e.to_string())?;
        private_fs::write_atomic(&self.path, &json)?;
        self.subnets = list.clone();
        Ok(list)
    }
}

fn clean_label(label: &str) -> String {
    let label: String = label.chars().filter(|c| !rc_discover::is_unsafe_char(*c)).take(MAX_LABEL_CHARS).collect();
    label.trim().to_owned()
}

fn valid_id(id: &str) -> bool {
    id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn validate_one(subnet: Subnet) -> Result<Subnet, String> {
    let cidr = Cidr::parse(&subnet.cidr).map_err(|e| e.to_string())?;
    let id = if subnet.id.is_empty() || !valid_id(&subnet.id) {
        uuid::Uuid::new_v4().to_string()
    } else {
        subnet.id
    };
    Ok(Subnet {
        id,
        cidr: cidr.to_string(),
        label: clean_label(&subnet.label),
        // Only meaningful for public ranges.
        allow_public: subnet.allow_public && !cidr.is_private(),
    })
}

/// The list as it will be saved, or a message naming the first problem.
pub fn validate(incoming: Vec<Subnet>) -> Result<Vec<Subnet>, String> {
    if incoming.len() > MAX_SUBNETS {
        return Err(format!("At most {MAX_SUBNETS} subnets can be saved."));
    }
    let mut out: Vec<Subnet> = Vec::with_capacity(incoming.len());
    for subnet in incoming {
        let shown = subnet.cidr.trim().chars().take(40).collect::<String>();
        let mut subnet = validate_one(subnet).map_err(|e| format!("{shown}: {e}"))?;
        if out.iter().any(|s| s.cidr == subnet.cidr) {
            return Err(format!("{} is in the list twice.", subnet.cidr));
        }
        if out.iter().any(|s| s.id == subnet.id) {
            subnet.id = uuid::Uuid::new_v4().to_string();
        }
        out.push(subnet);
    }
    Ok(out)
}

/// The networks to scan for the chosen saved subnets, after every safety check.
pub fn scan_plan(saved: &[Subnet], ids: &[String]) -> Result<Vec<Cidr>, String> {
    if ids.is_empty() {
        return Err("Choose at least one subnet to scan.".into());
    }
    let mut plan = Vec::new();
    for id in ids {
        let subnet = saved
            .iter()
            .find(|s| &s.id == id)
            .ok_or("A chosen subnet is no longer in the list. Reload and try again.")?;
        let cidr = Cidr::parse(&subnet.cidr).map_err(|e| format!("{}: {e}", subnet.cidr))?;
        if !cidr.is_private() && !subnet.allow_public {
            return Err(format!(
                "{cidr} is a public address range. Edit it and confirm it is your own network before scanning it."
            ));
        }
        if !plan.contains(&cidr) {
            plan.push(cidr);
        }
    }
    Ok(plan)
}

/// The scan that is running, if any. One at a time.
pub struct RunningScan {
    pub id: String,
    pub cancel: CancelToken,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subnet(cidr: &str) -> Subnet {
        Subnet { id: String::new(), cidr: cidr.into(), label: "Office VLAN".into(), allow_public: false }
    }

    #[test]
    fn validation_normalizes_and_refuses() {
        let list = validate(vec![subnet("10.0.0.9/24"), Subnet { label: " a\u{7}b ".into(), ..subnet("192.0.2.0/24") }]).unwrap();
        assert_eq!(list[0].cidr, "10.0.0.0/24");
        assert!(!list[0].id.is_empty());
        assert_eq!(list[1].label, "ab");
        let spoofed = validate(vec![Subnet { label: "Lab\u{202E}\u{200B}\u{2066} VLAN\u{FEFF}".into(), ..subnet("10.0.2.0/24") }]).unwrap();
        assert_eq!(spoofed[0].label, "Lab VLAN");
        assert!(validate(vec![subnet("10.0.0.0/8")]).unwrap_err().contains("/16"));
        assert!(validate(vec![subnet("10.0.0.0/24"), subnet("10.0.0.1/24")]).unwrap_err().contains("twice"));
        assert!(validate(vec![subnet("fd00::/64")]).unwrap_err().contains("IPv6"));
        assert!(validate(vec![subnet("10.0.0.0/32"); MAX_SUBNETS + 1]).is_err());
        let long = validate(vec![Subnet { label: "x".repeat(500), ..subnet("10.0.0.0/24") }]).unwrap();
        assert_eq!(long[0].label.len(), MAX_LABEL_CHARS);
        // Ids from the UI are kept only when they look like ours.
        let kept = validate(vec![Subnet { id: "abc-123".into(), ..subnet("10.0.0.0/24") }]).unwrap();
        assert_eq!(kept[0].id, "abc-123");
        let replaced = validate(vec![Subnet { id: "<script>".into(), ..subnet("10.0.0.0/24") }]).unwrap();
        assert_ne!(replaced[0].id, "<script>");
    }

    #[test]
    fn public_ranges_need_confirmation() {
        let saved = validate(vec![
            Subnet { id: "a".into(), ..subnet("10.0.0.0/24") },
            Subnet { id: "b".into(), ..subnet("192.0.2.0/24") },
            Subnet { id: "c".into(), allow_public: true, ..subnet("198.51.100.0/24") },
            Subnet { id: "d".into(), allow_public: true, ..subnet("10.1.0.0/24") },
        ])
        .unwrap();
        assert!(!saved[3].allow_public, "the flag is dropped for private ranges");
        assert_eq!(scan_plan(&saved, &["a".into()]).unwrap().len(), 1);
        assert!(scan_plan(&saved, &["a".into(), "b".into()]).unwrap_err().contains("public"));
        assert_eq!(scan_plan(&saved, &["c".into(), "a".into(), "a".into()]).unwrap().len(), 2);
        assert!(scan_plan(&saved, &["zzz".into()]).is_err());
        assert!(scan_plan(&saved, &[]).is_err());
    }

    #[test]
    fn saved_list_round_trips_privately() {
        let dir = std::env::temp_dir().join(format!("rc-subnets-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("subnets.json");
        let mut store = SubnetStore::load(path.clone());
        assert!(store.list().is_empty());
        let saved = store.replace(vec![subnet("10.0.0.0/24")]).unwrap();
        assert!(store.replace(vec![subnet("bad")]).is_err());
        assert_eq!(SubnetStore::load(path.clone()).list(), saved);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
