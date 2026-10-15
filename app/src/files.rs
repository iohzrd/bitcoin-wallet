//! Where PSBTs and descriptors cross the air gap: files on a card or a stick. The signer lists the
//! `.psbt` files in its directories, newest first, and writes what it signs beside the PSBT it
//! signed, as `name-signed.psbt` (the name Coldcard and Sparrow give one).

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PsbtFile {
    pub path: PathBuf,
    pub modified: SystemTime,
}

/// The home directory and every volume mounted where desktop Linux mounts removable media
/// (`/media/<user>/<volume>`, `/run/media/<user>/<volume>`) or where it is mounted by hand
/// (`/mnt/<volume>`).
pub fn default_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("HOME").map(PathBuf::from).into_iter().collect();
    for (root, depth) in [("/media", 2), ("/run/media", 2), ("/mnt", 1)] {
        dirs.extend(subdirs(Path::new(root), depth));
    }
    dirs
}

/// The directories `depth` levels below `dir`, and those above them that hold files themselves
/// (a volume mounted straight at `/media/<volume>`).
fn subdirs(dir: &Path, depth: usize) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else { return Vec::new() };
    let mut dirs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let below = if depth > 1 { subdirs(&path, depth - 1) } else { Vec::new() };
        if below.is_empty() { dirs.push(path) } else { dirs.extend(below) }
    }
    dirs.sort();
    dirs
}

/// The `.psbt` files in `dirs`, newest first.
pub fn list_psbts(dirs: &[PathBuf]) -> Vec<PsbtFile> {
    let mut files: Vec<PsbtFile> = (dirs.iter())
        .filter_map(|dir| fs::read_dir(dir).ok())
        .flatten()
        .flatten()
        .filter(|entry| {
            let path = entry.path();
            let psbt = path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("psbt"));
            psbt && path.is_file()
        })
        .filter_map(|entry| {
            let modified = entry.metadata().and_then(|meta| meta.modified()).ok()?;
            Some(PsbtFile { path: entry.path(), modified })
        })
        .collect();
    files.sort_by(|a, b| b.modified.cmp(&a.modified).then_with(|| a.path.cmp(&b.path)));
    files
}

/// Where the signed PSBT of the one at `path` goes: beside it, `name.psbt` as `name-signed.psbt`.
pub fn signed_path(path: &Path) -> PathBuf {
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!("{stem}-signed.psbt"))
}

/// Writes `data` to `path` whole or not at all, and to the card itself rather than the page
/// cache, as the card may come out the moment the screen says the file is saved.
pub fn write(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut partial = path.as_os_str().to_owned();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    let mut file = File::create(&partial)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&partial, path)?;
    if let Some(dir) = path.parent() {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("wallet-files-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_signed_psbt_goes_beside_the_one_it_was_signed_from() {
        assert_eq!(
            signed_path(Path::new("/media/sd/pay rent.psbt")),
            Path::new("/media/sd/pay rent-signed.psbt")
        );
        assert_eq!(signed_path(Path::new("/mnt/x/tx.PSBT")), Path::new("/mnt/x/tx-signed.psbt"));
    }

    #[test]
    fn psbt_files_list_newest_first_and_nothing_else_lists() {
        let dir = temp_dir("list");
        let epoch = SystemTime::UNIX_EPOCH;
        for (name, age) in [("old.psbt", 300), ("new.PSBT", 100), ("middle.psbt", 200)] {
            let file = File::create(dir.join(name)).unwrap();
            file.set_modified(epoch + Duration::from_secs(1_000 - age)).unwrap();
        }
        File::create(dir.join("notes.txt")).unwrap();
        fs::create_dir(dir.join("folder.psbt")).unwrap();
        let names: Vec<_> = (list_psbts(&[dir.clone(), dir.join("missing")]).into_iter())
            .map(|file| file.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["new.PSBT", "middle.psbt", "old.psbt"]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_write_leaves_the_whole_file_and_no_partial_one() {
        let dir = temp_dir("write");
        let path = dir.join("tx-signed.psbt");
        write(&path, b"first").unwrap();
        write(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
}
