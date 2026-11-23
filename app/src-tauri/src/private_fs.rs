//! Files only this user may read: the saved connections and the log. On Unix they are created
//! with mode 0600 inside directories with mode 0700; elsewhere the OS defaults apply (per-user
//! profile directories on Windows).

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Create `dir` (and its parents) and make `dir` itself private to this user.
pub fn create_dir(dir: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        builder.mode(0o700);
        builder.create(dir)?;
        // An existing directory keeps its old mode with `create`: tighten it.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    builder.create(dir)
}

/// Open `path` with `options`, creating it private to this user. An existing file is tightened too.
pub fn open(options: &mut OpenOptions, path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let file = options.mode(0o600).open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }
    #[cfg(not(unix))]
    options.open(path)
}

/// Replace `path` with `bytes`, private to this user: write a temporary file next to it, sync it,
/// then rename it over the old one so a crash never leaves a half-written file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    if let Some(dir) = path.parent() {
        create_dir(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    open(OpenOptions::new().write(true).create(true).truncate(true), &tmp)
        .and_then(|mut file| file.write_all(bytes).and_then(|()| file.sync_all()))
        .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot replace {}: {e}", path.display()))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn files_and_directories_are_private() {
        let root = std::env::temp_dir().join(format!("rc-private-fs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("a").join("b");
        create_dir(&dir).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);

        // A file that already exists with a loose mode is tightened as well.
        let path = dir.join("f");
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        open(OpenOptions::new().append(true), &path).unwrap();
        assert_eq!(mode(&path), 0o600);
        let fresh = dir.join("g");
        open(OpenOptions::new().create(true).write(true), &fresh).unwrap();
        assert_eq!(mode(&fresh), 0o600);
        let _ = std::fs::remove_dir_all(&root);
    }
}
