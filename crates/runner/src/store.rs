use core::{marker::PhantomData, mem::MaybeUninit};

use apps::InitStatus;
use littlefs2::{
    const_ram_storage,
    driver::Storage,
    fs::{Allocation, Filesystem},
    io::Result,
    object_safe::DynFilesystem,
};
use trussed::store::Store;
use trussed_manage::FACTORY_RESET_MARKER_FILE;

use crate::Board;

mod view;

pub use view::{ExternalFs, InternalFs, EXTERNAL_DIR};

// 8KB of RAM
const_ram_storage!(
    name = VolatileStorage,
    erase_value = 0xff,
    read_size = 16,
    write_size = 256,
    cache_size_ty = littlefs2::consts::U256,
    // We use 256 instead of the default 512 to avoid loosing too much space to nearly empty blocks containing only folder metadata.
    block_size = 256,
    block_count = 8192 / 256,
    lookahead_size_ty = littlefs2::consts::U1,
);

pub struct StoreResources<B: Board> {
    persistent: StorageResources<B::PersistentStorage>,
    volatile: StorageResources<VolatileStorage>,
    internal: MaybeUninit<InternalFs<'static>>,
    external: MaybeUninit<ExternalFs<'static>>,
}

impl<B: Board> Default for StoreResources<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: Board> StoreResources<B> {
    pub const fn new() -> Self {
        Self {
            persistent: StorageResources::new(),
            volatile: StorageResources::new(),
            internal: MaybeUninit::uninit(),
            external: MaybeUninit::uninit(),
        }
    }
}

pub struct StorageResources<S: Storage + 'static> {
    fs: MaybeUninit<Filesystem<'static, S>>,
    alloc: MaybeUninit<Allocation<S>>,
    storage: MaybeUninit<S>,
}

impl<S: Storage + 'static> Default for StorageResources<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Storage + 'static> StorageResources<S> {
    pub const fn new() -> Self {
        Self {
            fs: MaybeUninit::uninit(),
            alloc: MaybeUninit::uninit(),
            storage: MaybeUninit::uninit(),
        }
    }
}

struct StorePointers {
    ifs: MaybeUninit<&'static dyn DynFilesystem>,
    efs: MaybeUninit<&'static dyn DynFilesystem>,
    vfs: MaybeUninit<&'static dyn DynFilesystem>,
}

impl StorePointers {
    const fn new() -> Self {
        Self {
            ifs: MaybeUninit::uninit(),
            efs: MaybeUninit::uninit(),
            vfs: MaybeUninit::uninit(),
        }
    }
}

pub struct RunnerStore<B> {
    _marker: PhantomData<*mut B>,
}

impl<B: Board> RunnerStore<B> {
    fn new(
        ifs: &'static dyn DynFilesystem,
        efs: &'static dyn DynFilesystem,
        vfs: &'static dyn DynFilesystem,
    ) -> Self {
        unsafe {
            let pointers = Self::pointers();
            pointers.ifs.write(ifs);
            pointers.efs.write(efs);
            pointers.vfs.write(vfs);
        }

        Self {
            _marker: Default::default(),
        }
    }

    unsafe fn pointers() -> &'static mut StorePointers {
        static mut POINTERS: StorePointers = StorePointers::new();
        (&raw mut POINTERS).as_mut().unwrap()
    }
}

impl<B> Clone for RunnerStore<B> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<B> Copy for RunnerStore<B> {}

unsafe impl<B> Send for RunnerStore<B> {}

impl<B: Board> Store for RunnerStore<B> {
    fn ifs(&self) -> &dyn DynFilesystem {
        unsafe { Self::pointers().ifs.assume_init() }
    }

    fn efs(&self) -> &dyn DynFilesystem {
        unsafe { Self::pointers().efs.assume_init() }
    }

    fn vfs(&self) -> &dyn DynFilesystem {
        unsafe { Self::pointers().vfs.assume_init() }
    }
}

pub fn init_store<B: Board>(
    resources: &'static mut StoreResources<B>,
    storage: B::PersistentStorage,
    status: &mut InitStatus,
) -> RunnerStore<B> {
    let storage = resources.persistent.storage.write(storage);
    let alloc = resources.persistent.alloc.write(Filesystem::allocate());
    let vfs_storage = resources.volatile.storage.write(VolatileStorage::new());
    let vfs_alloc = resources.volatile.alloc.write(Filesystem::allocate());

    let fs: &'static dyn DynFilesystem = match init_fs::<B>(storage, alloc, status) {
        Ok(fs) => resources.persistent.fs.write(fs),
        Err(_e) => {
            error!("FS Mount Error {:?}", _e);
            panic!("FS");
        }
    };

    init_external(fs, status);

    let vfs = match init_vfs(vfs_storage, vfs_alloc) {
        Ok(vfs) => resources.volatile.fs.write(vfs),
        Err(_e) => {
            error!("VFS Mount Error {:?}", _e);
            panic!("VFS");
        }
    };

    let ifs = resources.internal.write(InternalFs::new(fs));
    let efs = resources.external.write(ExternalFs::new(fs));

    RunnerStore::new(ifs, efs, vfs)
}

#[inline(always)]
fn init_fs<B: Board>(
    storage: &'static mut B::PersistentStorage,
    alloc: &'static mut Allocation<B::PersistentStorage>,
    status: &mut InitStatus,
) -> Result<Filesystem<'static, B::PersistentStorage>> {
    if cfg!(feature = "format-filesystem") {
        Filesystem::format(storage).ok();
    }

    if !Filesystem::is_mountable(storage) {
        // handle provisioner
        if cfg!(feature = "provisioner") {
            info_now!("FS mount failed - provisioner => formatting");
            Filesystem::format(storage).ok();
        } else {
            status.insert(InitStatus::INTERNAL_FLASH_ERROR);
            error_now!("FS mount-fail");
            B::recover_storage(storage).ok();
        }
    }

    B::prepare_storage(storage);

    Filesystem::mount(alloc, storage)
}

fn init_external(fs: &dyn DynFilesystem, status: &mut InitStatus) {
    if ExternalFs::new(fs).exists(FACTORY_RESET_MARKER_FILE) {
        debug_now!("Clearing external filesystem");
        if let Err(_e) = fs.remove_dir_all(EXTERNAL_DIR) {
            error_now!("EFS clear error {:?}", _e);
            status.insert(InitStatus::EXTERNAL_FLASH_ERROR);
        }
    }

    if !fs.exists(EXTERNAL_DIR) {
        if let Err(_e) = fs.create_dir(EXTERNAL_DIR) {
            error_now!("EFS create error {:?}", _e);
            status.insert(InitStatus::EXTERNAL_FLASH_ERROR);
        }
    }
}

#[inline(always)]
fn init_vfs(
    vfs_storage: &'static mut VolatileStorage,
    vfs_alloc: &'static mut Allocation<VolatileStorage>,
) -> Result<Filesystem<'static, VolatileStorage>> {
    if !Filesystem::is_mountable(vfs_storage) {
        Filesystem::format(vfs_storage).ok();
    }
    Filesystem::mount(vfs_alloc, vfs_storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use littlefs2::path;
    use littlefs2_core::{DirEntry, Path, PathBuf};

    const_ram_storage!(
        name = TestStorage,
        erase_value = 0xff,
        read_size = 4,
        write_size = 256,
        cache_size_ty = littlefs2::consts::U256,
        block_size = 256,
        block_count = 128,
        lookahead_size_ty = littlefs2::consts::U1,
    );

    fn with_fs(f: impl FnOnce(&dyn DynFilesystem)) {
        let mut storage = TestStorage::new();
        Filesystem::format(&mut storage).unwrap();
        let mut alloc = Filesystem::allocate();
        let fs = Filesystem::mount(&mut alloc, &mut storage).unwrap();
        f(&fs);
    }

    fn entries(fs: &dyn DynFilesystem, dir: &Path) -> std::vec::Vec<DirEntry> {
        fs.read_dir_and_then(dir, &mut |entries| {
            Ok(entries.skip(2).map(|entry| entry.unwrap()).collect())
        })
        .unwrap()
    }

    fn write_file(fs: &dyn DynFilesystem, dir: &Path, name: &Path) {
        fs.create_dir_all(dir).unwrap();
        fs.write(&dir.join(name), b"data").unwrap();
    }

    #[test]
    fn external_files_live_under_external_dir() {
        with_fs(|fs| {
            let efs = ExternalFs::new(fs);
            write_file(&efs, path!("piv/dat"), path!("state"));

            assert!(fs.exists(path!("/external/piv/dat/state")));
            assert!(!fs.exists(path!("/piv/dat/state")));
            assert!(efs.exists(path!("piv/dat/state")));
            assert!(efs.exists(path!("/piv/dat/state")));
        });
    }

    #[test]
    fn external_entries_keep_caller_paths() {
        with_fs(|fs| {
            let efs = ExternalFs::new(fs);
            write_file(&efs, path!("piv/dat"), path!("state"));

            let relative = entries(&efs, path!("piv/dat"));
            assert_eq!(relative.len(), 1);
            assert_eq!(relative[0].path(), path!("piv/dat/state"));
            assert_eq!(relative[0].file_name(), path!("state"));

            let absolute = entries(&efs, path!("/"));
            assert_eq!(absolute.len(), 1);
            assert_eq!(absolute[0].path(), path!("/piv"));
        });
    }

    #[test]
    fn internal_view_hides_external_dir() {
        with_fs(|fs| {
            let ifs = InternalFs::new(fs);
            let efs = ExternalFs::new(fs);
            write_file(&ifs, path!("/fido/dat"), path!("state"));
            write_file(&efs, path!("/piv/dat"), path!("state"));

            let names: std::vec::Vec<PathBuf> = entries(&ifs, path!("/"))
                .iter()
                .map(|entry| PathBuf::from(entry.file_name()))
                .collect();
            assert_eq!(names, [PathBuf::from(path!("fido"))]);
            assert!(fs.exists(path!("/external")));
        });
    }

    #[test]
    fn internal_removal_keeps_external_files() {
        with_fs(|fs| {
            let ifs = InternalFs::new(fs);
            let efs = ExternalFs::new(fs);
            write_file(&ifs, path!("/fido/dat"), path!("state"));
            write_file(&efs, path!("/piv/dat"), path!("state"));

            ifs.remove_dir_all_where(path!("/"), &|_| true).unwrap();
            assert!(!ifs.exists(path!("/fido/dat/state")));
            assert!(efs.exists(path!("/piv/dat/state")));

            ifs.remove_dir_all(path!("/")).unwrap();
            assert!(efs.exists(path!("/piv/dat/state")));
        });
    }

    #[test]
    fn external_removal_keeps_internal_files() {
        with_fs(|fs| {
            let ifs = InternalFs::new(fs);
            let efs = ExternalFs::new(fs);
            write_file(&ifs, path!("/fido/dat"), path!("state"));
            write_file(&efs, path!("/piv/dat"), path!("state"));

            efs.remove_dir_all_where(path!("/"), &|entry| {
                entry.path() == path!("/piv/dat/state")
            })
            .unwrap();
            assert!(!efs.exists(path!("/piv/dat/state")));
            assert!(ifs.exists(path!("/fido/dat/state")));

            write_file(&efs, path!("/piv/dat"), path!("state"));
            assert!(efs.exists(path!("/piv/dat/state")));
        });
    }

    #[test]
    fn factory_reset_marker_clears_only_external() {
        with_fs(|fs| {
            let ifs = InternalFs::new(fs);
            let efs = ExternalFs::new(fs);
            write_file(&ifs, path!("/fido/dat"), path!("state"));
            write_file(&efs, path!("/piv/dat"), path!("state"));
            efs.write(FACTORY_RESET_MARKER_FILE, &[]).unwrap();

            let mut status = InitStatus::empty();
            init_external(fs, &mut status);

            assert_eq!(status, InitStatus::empty());
            assert!(ifs.exists(path!("/fido/dat/state")));
            assert!(!efs.exists(path!("/piv/dat/state")));
            assert!(!efs.exists(FACTORY_RESET_MARKER_FILE));
            assert!(fs.exists(EXTERNAL_DIR));
        });
    }
}
