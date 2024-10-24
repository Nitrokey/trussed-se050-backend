use littlefs2_core::{DynFilesystem, Error, Path};

use crate::BACKEND_DIR;

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
    match fs.remove_dir_all(path) {
        Err(Error::NO_SUCH_ENTRY) => Ok(()),
        Err(err) => Err(err),
        Ok(()) => Ok(()),
    }
}

///  Migrate the filesystem to remove the `dat` directories
///
/// `apps` must be an array of paths to the apps that make use of trussed-se050-backend
///
/// Migrate does not itself keep track of whether the migration was performed
///
/// ```rust
///# use littlefs2_core::{DynFilesystem, Error, path};
///# use trussed_se050_backend::migrate::migrate_remove_all_dat;
///# fn test(fs: &dyn DynFilesystem) -> Result<(), Error> {
/// migrate_remove_all_dat(fs, &[path!("secrets"), path!("opcard")])?;
///# Ok(())
///# }
/// ```
pub fn migrate_remove_all_dat(fs: &dyn DynFilesystem, apps: &[&Path]) -> Result<(), Error> {
    migrate_single(fs, BACKEND_DIR)?;
    for p in apps {
        migrate_single(fs, &p.join(BACKEND_DIR))?;
    }
    Ok(())
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use admin_app::migrations::test_utils::{test_migration_one, FsValues};
    use littlefs2_core::path;

    use crate::trussed_auth_impl::AUTH_DIR;

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
                FsValues::Dir(&[(path!("dat"), OPCARD_DIR), (path!("pub"), OPCARD_PUB_DIR)]),
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
            migrate_remove_all_dat(fs, &[path!("secrets"), path!("opcard")])
        });
    }

    #[test]
    fn migration_emptyt() {
        const TEST_VALUES: FsValues = FsValues::Dir(&[
            (
                path!("opcard"),
                FsValues::Dir(&[(path!("dat"), OPCARD_DIR), (path!("pub"), OPCARD_PUB_DIR)]),
            ),
            (
                path!("trussed"),
                FsValues::Dir(&[(
                    path!("dat"),
                    FsValues::Dir(&[(path!("rng-state.bin"), FsValues::File(32))]),
                )]),
            ),
        ]);

        test_migration_one(&TEST_VALUES, &TEST_VALUES, |fs| {
            migrate_remove_all_dat(fs, &[path!("secrets"), path!("opcard")])
        });
    }
}
