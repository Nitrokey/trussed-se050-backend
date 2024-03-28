# Filesystem layout resulting from the use of the backend

- The directory for the backend `BACKEND_DIR=se050-bak`
- The directory for per-client auth data: `AUTH_DIR=auth`
- The directory for the core keys `CORE_DIR=se050-core`

## Trussed auth impl:

```
/
|- opcard
|  |
|  |- dat
|  |- sec
|  |- pub
|  |- BACKEND_DIR
|  |  |- AUTH (`let fs = once(|resources, _| resources.raw_filestore(backend_path))`)
|  |  |  |- pin.XX
|  |  |  |- pin.XX
|  |  |  |- application_salt
|
|- BACKEND_DIR (`let global_fs = once(|resources, _| resources.raw_filestore(PathBuf::from(BACKEND_DIR)))`)
|  |- salt
```

## Core API impl

```
/
|- opcard
|  |- dat
|  |- sec
|  |- pub
|  |- BACKEND_DIR
|  |  |- CORE_DIR
|  |  |  |- sec
|  |  |  |- pub
```

## TOTAL:

```
/
|- opcard
|  |
|  |- dat
|  |- sec
|  |- pub
|  |- BACKEND_DIR
|  |  |- CORE_DIR
|  |  |  |- sec
|  |  |  |- pub
|  |  |- AUTH (`let fs = once(|resources, _| resources.raw_filestore(backend_path))`)
|  |  |  |- pin.XX
|  |  |  |- pin.XX
|  |  |  |- application_salt
|
|- BACKEND_DIR (`let global_fs = once(|resources, _| resources.raw_filestore(PathBuf::from(BACKEND_DIR)))`)
|  |- salt
```

