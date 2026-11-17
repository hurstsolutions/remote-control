//! One log file in the app's log directory. It is what the user sends back when something fails,
//! so it is verbose about protocol steps and never contains credentials or clipboard text.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;

const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
const TAIL_BYTES: u64 = 256 * 1024;

#[derive(Clone)]
struct FileWriter(Arc<Mutex<File>>);

impl std::io::Write for FileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.0.lock() {
            Ok(mut file) => file.write(buf),
            Err(_) => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.0.lock() {
            Ok(mut file) => file.flush(),
            Err(_) => Ok(()),
        }
    }
}

impl<'a> MakeWriter<'a> for FileWriter {
    type Writer = FileWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Start logging to `dir/remote-control.log` and return that path. An oversized log from earlier
/// runs is moved to `.old` first.
pub fn init(dir: &Path) -> PathBuf {
    let path = dir.join("remote-control.log");
    let _ = std::fs::create_dir_all(dir);
    if std::fs::metadata(&path).map(|m| m.len() > MAX_LOG_BYTES).unwrap_or(false) {
        let _ = std::fs::rename(&path, path.with_extension("log.old"));
    }
    let filter = tracing_subscriber::EnvFilter::try_from_env("RC_LOG").unwrap_or_else(|_| {
        "info,remote_control_lib=debug,rc_rdp=debug,rc_vnc=debug,rc_tunnel=debug,ironrdp_connector=debug".into()
    });
    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_writer(FileWriter(Arc::new(Mutex::new(file))))
                .try_init();
        }
        Err(error) => {
            let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
            tracing::error!(%error, path = %path.display(), "cannot open the log file; logging to stderr");
        }
    }
    path
}

/// The last part of the log file as text.
pub fn tail(path: &Path) -> String {
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(TAIL_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut bytes = Vec::new();
    let _ = file.read_to_end(&mut bytes);
    let text = String::from_utf8_lossy(&bytes);
    // Drop the partial first line when we started mid-file.
    match (start > 0, text.find('\n')) {
        (true, Some(i)) => text[i + 1..].to_owned(),
        _ => text.into_owned(),
    }
}
