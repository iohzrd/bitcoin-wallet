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

/// The `.txt` files in `dirs` that hold a descriptor beginning with one of `scripts`, such as
/// `wsh(` for a multisig wallet's. Files too large to be a descriptor are passed over unread.
#[cfg_attr(not(feature = "online"), allow(dead_code))]
pub fn descriptor_files(dirs: &[PathBuf], scripts: &[&str]) -> Vec<PathBuf> {
    const MAX: u64 = MAX_TEXT;
    let mut files: Vec<PathBuf> = (dirs.iter())
        .filter_map(|dir| fs::read_dir(dir).ok())
        .flatten()
        .flatten()
        .filter(|entry| entry.metadata().is_ok_and(|meta| meta.is_file() && meta.len() <= MAX))
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("txt")))
        .filter(|path| {
            let text = fs::read_to_string(path).unwrap_or_default();
            scripts.iter().any(|script| text.trim_start().starts_with(script))
        })
        .collect();
    files.sort();
    files
}

/// The `.txt` and `.bsms` files in `dirs` that hold a multisig setup a coordinator wrote: a
/// descriptor, a BSMS record or a Coldcard setup file.
pub fn setup_files(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = (dirs.iter())
        .filter_map(|dir| fs::read_dir(dir).ok())
        .flatten()
        .flatten()
        .filter(|entry| entry.metadata().is_ok_and(|meta| meta.is_file() && meta.len() <= MAX_TEXT))
        .map(|entry| entry.path())
        .filter(|path| {
            let extension = path.extension().map(|ext| ext.to_ascii_lowercase());
            extension.is_some_and(|ext| ext == "txt" || ext == "bsms")
        })
        .filter(|path| {
            wallet_airgap::setup::looks_like(&fs::read_to_string(path).unwrap_or_default())
        })
        .collect();
    files.sort();
    files
}

/// The largest text file read in looking for descriptors and setups.
const MAX_TEXT: u64 = 64 * 1024;

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

/// Where a wallet kept on the device lives: the XDG data directory's `wallet`, which the handheld
/// images keep across updates with the rest of `/home`.
pub fn default_data_dir() -> Option<PathBuf> {
    let data = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).filter(|dir| dir.is_absolute());
    let data = data.or_else(|| Some(PathBuf::from(std::env::var_os("HOME")?).join(".local/share")));
    Some(data?.join("wallet"))
}

/// Writes `data` to `path` as `write` does, readable by this user alone, in a directory only this
/// user can list.
pub fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir)?;
    }
    let mut partial = path.as_os_str().to_owned();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&partial)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&partial, path)?;
    if let Some(dir) = path.parent() {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Overwrites the file at `path` with zeros and removes it. A card's flash moves what it writes
/// as it wears, so the old blocks may outlast this until written over; what they hold is as safe
/// as the passphrase that sealed it.
pub fn erase(path: &Path) -> io::Result<()> {
    let len = fs::metadata(path)?.len();
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    file.write_all(&vec![0; len as usize])?;
    file.sync_all()?;
    drop(file);
    fs::remove_file(path)?;
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
