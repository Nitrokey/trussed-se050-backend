use littlefs2::{io::Error, object_safe::DynFilesystem, path, path::Path};

use crate::{trussed_auth_impl::AUTH_DIR, BACKEND_DIR};

// Old:
//
// ```
// /
// |- opcard
// |  |
// |  |- dat
// |  |- sec
// |  |- pub
// |  |- BACKEND_DIR
// |  |  |- CORE_DIR
// |  |  |  |- sec
// |  |  |  |- pub
// |  |  |- AUTH
// |  |  |  |- dat (`let fs = once(|resources, _| resources.raw_filestore(backend_path))`)
// |  |  |  |  |- pin.XX
// |  |  |  |  |- pin.XX
// |  |  |  |  |- application_salt
// |
// |- BACKEND_DIR (`let global_fs = once(|resources, _| resources.raw_filestore(PathBuf::from(BACKEND_DIR)))`)
// |  |- dat
// |  |  |- salt
// ```

fn migrate_single(fs: &dyn DynFilesystem, path: &Path) -> Result<(), Error> {
    let path_dat = path.join(path!("dat"));
    let dir_res = fs.read_dir_and_then(&path_dat, &mut |dir| {
        for f in dir.skip(2) {
            let f = f?;
            let new_path = path.join(f.file_name());
            fs.rename(f.path(), &new_path)?;
        }
        Ok(())
    });
    match dir_res {
        Ok(()) => fs.remove_dir(&path_dat),
        Err(Error::NoSuchEntry) => Ok(()),
        Err(_) => dir_res,
    }
}

///  Migrate the filesystem to remove the `dat` directories
///
/// `apps` must be an array of paths to the apps that make use of trussed-se050-backend
///
/// Migrate does not itself keep track of whether the migration was performed
///
/// ```rust
///# use littlefs2::{fs::Filesystem, const_ram_storage, path};
///# use trussed::types::{LfsResult, LfsStorage};
///# use trussed_se050_backend::migrate::migrate_remove_dat;
///# const_ram_storage!(Storage, 4096);
///# let mut storage = Storage::new();
///# Filesystem::format(&mut storage);
///# Filesystem::mount_and_then(&mut storage, |fs| {
/// migrate_remove_dat(fs, &[path!("secrets"), path!("opcard")])?;
///#     Ok(())
///# }).unwrap();
/// ```
pub fn migrate_remove_dat(fs: &dyn DynFilesystem, apps: &[&Path]) -> Result<(), Error> {
    migrate_single(fs, &path!("/").join(BACKEND_DIR))?;
    for p in apps {
        migrate_single(fs, &p.join(BACKEND_DIR).join(AUTH_DIR))?;
    }
    Ok(())
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use trussed_staging::manage::test_utils::{test_migration_one, FsValues};

    use super::*;

    const OPCARD_DIR: FsValues = FsValues::Dir(&[
        (path!("admin-user-pin-key.bin"), FsValues::File(40)),
        (path!("aes_key.bin"), FsValues::File(123)),
        (path!("auth_key.bin"), FsValues::File(122)),
        (path!("conf_key.bin"), FsValues::File(121)),
        (path!("persistent-state.cbor"), FsValues::File(150)),
        (path!("rc-user-pin-key.bin"), FsValues::File(40)),
        (path!("signing_key.bin"), FsValues::File(120)),
    ]);
    const OPCARD_PUB_DIR: FsValues = FsValues::Dir(&[
        (
            path!("069386c3c735689061ac51b8bca9f160"),
            FsValues::File(48),
        ),
        (
            path!("233d86bfc2f196ff7c108cf23a282bd5"),
            FsValues::File(36),
        ),
        (
            path!("2bdef14a0e18d28191162f8c1599d598"),
            FsValues::File(36),
        ),
    ]);
    const AUTH_OPCARD_DIR: FsValues = FsValues::Dir(&[
        (path!("application_salt"), FsValues::File(16)),
        (path!("pin.00"), FsValues::File(118)),
        (path!("pin.01"), FsValues::File(119)),
        (path!("pin.02"), FsValues::File(120)),
    ]);

    #[test]
    fn migration() {
        const TEST_BEFORE: FsValues = FsValues::Dir(&[
            (
                path!("opcard"),
                FsValues::Dir(&[
                    (path!("dat"), OPCARD_DIR),
                    (path!("pub"), OPCARD_PUB_DIR),
                    (
                        BACKEND_DIR,
                        FsValues::Dir(&[(
                            AUTH_DIR,
                            FsValues::Dir(&[(path!("dat"), AUTH_OPCARD_DIR)]),
                        )]),
                    ),
                ]),
            ),
            (
                BACKEND_DIR,
                FsValues::Dir(&[(
                    path!("dat"),
                    FsValues::Dir(&[(path!("salt"), FsValues::File(16))]),
                )]),
            ),
            (
                path!("trussed"),
                FsValues::Dir(&[(
                    path!("dat"),
                    FsValues::Dir(&[(path!("rng-state.bin"), FsValues::File(32))]),
                )]),
            ),
        ]);

        const TEST_AFTER: FsValues = FsValues::Dir(&[
            (
                path!("opcard"),
                FsValues::Dir(&[
                    (path!("dat"), OPCARD_DIR),
                    (path!("pub"), OPCARD_PUB_DIR),
                    (BACKEND_DIR, FsValues::Dir(&[(AUTH_DIR, AUTH_OPCARD_DIR)])),
                ]),
            ),
            (
                BACKEND_DIR,
                FsValues::Dir(&[(path!("salt"), FsValues::File(16))]),
            ),
            (
                path!("trussed"),
                FsValues::Dir(&[(
                    path!("dat"),
                    FsValues::Dir(&[(path!("rng-state.bin"), FsValues::File(32))]),
                )]),
            ),
        ]);

        test_migration_one(&TEST_BEFORE, &TEST_AFTER, |fs| {
            migrate_remove_dat(fs, &[path!("secrets"), path!("opcard")])
        });
    }
}
