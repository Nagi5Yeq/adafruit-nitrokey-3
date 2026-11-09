use littlefs2::path;
use littlefs2_core::{
    Attribute, DirEntriesCallback, DirEntry, DynFilesystem, Error, FileCallback, FileOpenFlags,
    Metadata, OpenSeekFrom, Path, PathBuf, Predicate, Result,
};

pub const EXTERNAL_DIR: &Path = path!("/external");
const EXTERNAL_NAME: &str = "external";

fn is_root(path: &Path) -> bool {
    matches!(path.as_str(), "" | "/")
}

fn is_absolute(path: &Path) -> bool {
    path.as_str().starts_with('/')
}

fn is_external(path: &Path) -> bool {
    let path = path.as_str().trim_start_matches('/');
    match path.strip_prefix(EXTERNAL_NAME) {
        Some(rest) => rest.is_empty() || rest.starts_with('/'),
        None => false,
    }
}

fn to_external(path: &Path) -> Result<PathBuf> {
    let relative = path.as_str().trim_start_matches('/');
    let mut external = PathBuf::from(EXTERNAL_DIR);
    if relative.is_empty() {
        return Ok(external);
    }
    if EXTERNAL_DIR.as_str().len() + 1 + relative.len() > PathBuf::MAX_SIZE {
        return Err(Error::FILENAME_TOO_LONG);
    }
    let relative = PathBuf::try_from(relative).map_err(|_| Error::INVALID)?;
    external.push(&relative);
    Ok(external)
}

fn from_external(path: &Path, absolute: bool) -> Result<PathBuf> {
    let path = path.as_str();
    let relative = path
        .strip_prefix(EXTERNAL_DIR.as_str())
        .unwrap_or(path)
        .trim_start_matches('/');
    let mut result = if absolute {
        PathBuf::from(path!("/"))
    } else {
        PathBuf::new()
    };
    if !relative.is_empty() {
        let relative = PathBuf::try_from(relative).map_err(|_| Error::INVALID)?;
        result.push(&relative);
    }
    Ok(result)
}

fn entry_from_external(entry: DirEntry, absolute: bool) -> Result<DirEntry> {
    let path = from_external(entry.path(), absolute)?;
    Ok(DirEntry::new(
        PathBuf::from(entry.file_name()),
        entry.metadata(),
        path,
    ))
}

/// Filesystem view that hides the `/external` subtree of the shared filesystem.
pub struct InternalFs<'a> {
    fs: &'a dyn DynFilesystem,
}

impl<'a> InternalFs<'a> {
    pub fn new(fs: &'a dyn DynFilesystem) -> Self {
        Self { fs }
    }
}

impl DynFilesystem for InternalFs<'_> {
    fn total_blocks(&self) -> usize {
        self.fs.total_blocks()
    }

    fn total_space(&self) -> usize {
        self.fs.total_space()
    }

    fn available_blocks(&self) -> Result<usize> {
        self.fs.available_blocks()
    }

    fn available_space(&self) -> Result<usize> {
        self.fs.available_space()
    }

    fn remove(&self, path: &Path) -> Result<()> {
        self.fs.remove(path)
    }

    fn remove_dir(&self, path: &Path) -> Result<()> {
        self.fs.remove_dir(path)
    }

    fn remove_dir_all(&self, path: &Path) -> Result<()> {
        if is_root(path) {
            self.remove_dir_all_where(path, &|_| true).map(|_| ())
        } else {
            self.fs.remove_dir_all(path)
        }
    }

    fn remove_dir_all_where(&self, path: &Path, predicate: Predicate<'_>) -> Result<usize> {
        self.fs.remove_dir_all_where(path, &|entry: &DirEntry| {
            !is_external(entry.path()) && predicate(entry)
        })
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        self.fs.rename(from, to)
    }

    fn exists(&self, path: &Path) -> bool {
        self.fs.exists(path)
    }

    fn metadata(&self, path: &Path) -> Result<Metadata> {
        self.fs.metadata(path)
    }

    fn create_file_and_then_unit(&self, path: &Path, f: FileCallback<'_>) -> Result<()> {
        self.fs.create_file_and_then_unit(path, f)
    }

    fn open_file_and_then_unit(&self, path: &Path, f: FileCallback<'_>) -> Result<()> {
        self.fs.open_file_and_then_unit(path, f)
    }

    fn open_file_with_flags_and_then_unit(
        &self,
        flags: FileOpenFlags,
        path: &Path,
        f: FileCallback<'_>,
    ) -> Result<()> {
        self.fs.open_file_with_flags_and_then_unit(flags, path, f)
    }

    fn attribute<'b>(
        &self,
        path: &Path,
        id: u8,
        buffer: &'b mut [u8],
    ) -> Result<Option<Attribute<'b>>> {
        self.fs.attribute(path, id, buffer)
    }

    fn remove_attribute(&self, path: &Path, id: u8) -> Result<()> {
        self.fs.remove_attribute(path, id)
    }

    fn set_attribute(&self, path: &Path, id: u8, data: &[u8]) -> Result<()> {
        self.fs.set_attribute(path, id, data)
    }

    fn read_dir_and_then_unit(&self, path: &Path, f: DirEntriesCallback<'_>) -> Result<()> {
        if !is_root(path) {
            return self.fs.read_dir_and_then_unit(path, f);
        }
        self.fs.read_dir_and_then_unit(path, &mut |entries| {
            let mut entries = entries.filter(
                |entry| !matches!(entry, Ok(entry) if entry.file_name().as_str() == EXTERNAL_NAME),
            );
            f(&mut entries)
        })
    }

    fn create_dir(&self, path: &Path) -> Result<()> {
        self.fs.create_dir(path)
    }

    fn create_dir_all(&self, path: &Path) -> Result<()> {
        self.fs.create_dir_all(path)
    }

    fn write(&self, path: &Path, contents: &[u8]) -> Result<()> {
        self.fs.write(path, contents)
    }

    fn write_chunk(&self, path: &Path, contents: &[u8], pos: OpenSeekFrom) -> Result<()> {
        self.fs.write_chunk(path, contents, pos)
    }
}

/// Filesystem view rooted at `/external` of the shared filesystem.
pub struct ExternalFs<'a> {
    fs: &'a dyn DynFilesystem,
}

impl<'a> ExternalFs<'a> {
    pub fn new(fs: &'a dyn DynFilesystem) -> Self {
        Self { fs }
    }

    fn ensure_root(&self) -> Result<()> {
        if self.fs.exists(EXTERNAL_DIR) {
            Ok(())
        } else {
            self.fs.create_dir(EXTERNAL_DIR)
        }
    }
}

impl DynFilesystem for ExternalFs<'_> {
    fn total_blocks(&self) -> usize {
        self.fs.total_blocks()
    }

    fn total_space(&self) -> usize {
        self.fs.total_space()
    }

    fn available_blocks(&self) -> Result<usize> {
        self.fs.available_blocks()
    }

    fn available_space(&self) -> Result<usize> {
        self.fs.available_space()
    }

    fn remove(&self, path: &Path) -> Result<()> {
        self.fs.remove(&to_external(path)?)
    }

    fn remove_dir(&self, path: &Path) -> Result<()> {
        self.fs.remove_dir(&to_external(path)?)
    }

    fn remove_dir_all(&self, path: &Path) -> Result<()> {
        self.fs.remove_dir_all(&to_external(path)?)
    }

    fn remove_dir_all_where(&self, path: &Path, predicate: Predicate<'_>) -> Result<usize> {
        let absolute = is_absolute(path);
        self.fs
            .remove_dir_all_where(&to_external(path)?, &|entry: &DirEntry| {
                entry_from_external(entry.clone(), absolute)
                    .map(|entry| predicate(&entry))
                    .unwrap_or(false)
            })
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        self.ensure_root()?;
        self.fs.rename(&to_external(from)?, &to_external(to)?)
    }

    fn exists(&self, path: &Path) -> bool {
        to_external(path)
            .map(|path| self.fs.exists(&path))
            .unwrap_or(false)
    }

    fn metadata(&self, path: &Path) -> Result<Metadata> {
        self.fs.metadata(&to_external(path)?)
    }

    fn create_file_and_then_unit(&self, path: &Path, f: FileCallback<'_>) -> Result<()> {
        self.ensure_root()?;
        self.fs.create_file_and_then_unit(&to_external(path)?, f)
    }

    fn open_file_and_then_unit(&self, path: &Path, f: FileCallback<'_>) -> Result<()> {
        self.fs.open_file_and_then_unit(&to_external(path)?, f)
    }

    fn open_file_with_flags_and_then_unit(
        &self,
        flags: FileOpenFlags,
        path: &Path,
        f: FileCallback<'_>,
    ) -> Result<()> {
        if flags.contains(FileOpenFlags::CREATE) {
            self.ensure_root()?;
        }
        self.fs
            .open_file_with_flags_and_then_unit(flags, &to_external(path)?, f)
    }

    fn attribute<'b>(
        &self,
        path: &Path,
        id: u8,
        buffer: &'b mut [u8],
    ) -> Result<Option<Attribute<'b>>> {
        self.fs.attribute(&to_external(path)?, id, buffer)
    }

    fn remove_attribute(&self, path: &Path, id: u8) -> Result<()> {
        self.fs.remove_attribute(&to_external(path)?, id)
    }

    fn set_attribute(&self, path: &Path, id: u8, data: &[u8]) -> Result<()> {
        self.fs.set_attribute(&to_external(path)?, id, data)
    }

    fn read_dir_and_then_unit(&self, path: &Path, f: DirEntriesCallback<'_>) -> Result<()> {
        if is_root(path) {
            self.ensure_root()?;
        }
        let absolute = is_absolute(path);
        self.fs
            .read_dir_and_then_unit(&to_external(path)?, &mut |entries| {
                let mut entries =
                    entries.map(|entry| entry.and_then(|entry| entry_from_external(entry, absolute)));
                f(&mut entries)
            })
    }

    fn create_dir(&self, path: &Path) -> Result<()> {
        self.ensure_root()?;
        if is_root(path) {
            return Err(Error::ENTRY_ALREADY_EXISTED);
        }
        self.fs.create_dir(&to_external(path)?)
    }

    fn create_dir_all(&self, path: &Path) -> Result<()> {
        self.ensure_root()?;
        self.fs.create_dir_all(&to_external(path)?)
    }

    fn write(&self, path: &Path, contents: &[u8]) -> Result<()> {
        self.ensure_root()?;
        self.fs.write(&to_external(path)?, contents)
    }

    fn write_chunk(&self, path: &Path, contents: &[u8], pos: OpenSeekFrom) -> Result<()> {
        self.ensure_root()?;
        self.fs.write_chunk(&to_external(path)?, contents, pos)
    }
}
