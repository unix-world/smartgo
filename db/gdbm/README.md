# go-gdbm

This package provides Go API for [GNU DBM](https://www.gnu.org.ua/software/gdbm/),
a library that implements a hashed database on a disk file.  It aims to give
a Go programmer access to all features of GDBM.  Naturally, these features
evolved over time, so special attention has been paid to supporting a wide
variety of GDBM versions.  At the time of this writing, the __go-gdbm__ package
is known to work with GDBM versions ranging from the recent 1.23 down to 1.12.

The package is written by a long-time maintainer of GDBM, Sergey Poznyakoff.
It is an official [GNU software](https://www.gnu.org).

Notice, that there exist several eponymous Go packages, with names differing
ony in _module prefix_.  This package is not based on any of them nor does it
have any code in common with them.

## Opening and Closing a Database

The simplest way to open a database is using the `Open` function:

```golang
   import "github.com/graygnuorg/go-gdbm"

   db, err := gdbm.Open("input.gdbm", gdbm.ModeReader)
   if err != nil {
       panic(err)
   }
```

The function takes two parameters: name of the database file and *opening
mode*.  The mode decides how to open the database and can have the
following values:

* `ModeReader`

    The database is opened read-only.  An error is reported if it does
    not exist.

* `ModeWriter`

    The database is opened for reading and writing.  It must exist,
    otherwise an error is reported.

* `ModeWrcreat`

    The database is open for reading and writing.  If it doesn't exist,
    it will be created.  The permission bits of the created database file
    are computed as `(0666 & ~U)`, where `U` is the current *umask*.

* `ModeNewdb`

    A new database is created.  If the database file already exists, it
    will be overwritten.  The permission bits of the newly created
    database are set as described above.

<a name="OpenConfig"></a>
If you need more control over the opening process, use the
`OpenConfig` function instead.  It takes a single argument: a
`DatabaseConfig` structure that controls how the database should be
opened or created.  The structure has the following fields:

* `FileName` __string__

    Database or dump file name.

* `Mode` __int__

    Open mode.  In addition to the values discussed above, it can be set
    to `ModeLoad`.  In this case, the `FileName` field is treated as the
    name of an existing [dump file](https://www.gnu.org.ua/software/gdbm/manual/Flat-files.html)
    in ASCII format.  The new database will be created and populated with
    the data from the dump file.  The actual file name, permissions and,
    if possible, ownership will be restored from the dump.

    The database file name can further be obtained using the database
    [FileName](#user-content-FileName) method.

* `Flags` __int__

    Additional flags.  This is a bitmask composed by ORing one or more
    of the following constants:

    * `OF_NOLOCK`
	Don't lock the database.  It is supposed that the caller will
	be responsible for locking.
    * `OF_NOMMAP`
	Disable memory mapping, use the standard I/O functions only.
    * `OF_PREREAD`
	When mapping GDBM file to memory, read its contents
	[immediately](https://www.gnu.org.ua/software/gdbm/manual/index.html#Open.index-GDBM_005fPREREAD), instead of when needed.
    * `OF_CLOEXEC`
	Close the database file descriptor on `exec`.
    * `OF_XVERIFY`
	Enable [additional consistency
	checks](https://www.gnu.org.ua/software/gdbm/manual/index.html#Open.index-GDBM_005fXVERIFY).

    The following flags are used only when creating a new database
    file:

    * `OF_BSEXACT`
	Disable adjustments of the `BlockSize`.  If the requested
	block size cannot be used without adjustment, the
	`OpenConfig` function will fail with the
	`ErrBlockSizeError` error.
    * `OF_NUMSYNC`
	Create the database in [extended format](#user-content-examining-and-changing-database-format),
	best suited for effective [crash recovery](#user-content-crash-tolerance).

* `CrashTolerance` __bool__

    When set to `true`, the database will be opened in [crash tolerance
    mode](#user-content-crash-tolerance).

The two fields below are used only when creating a new database
(i.e. when `Mode` is set to `ModeNewdb` or `ModeWrcreat`, and the database
does not exist).

* `BlockSize` __int__

    Desired block size.  If its value is less than 512, the file
    system block size is used instead.  The size is adjusted so that
    the block can hold exact number of directory entries.  As a result
    the effective block size can be slightly greater than requested.
    This adjustment can be disabled by setting the `OF_BSEXACT` flag
    (see above): in this case if the adjustment is needed, the function
    will return the `ErrBlockSizeError` error.

* `FileMode` __int__

    File mode to use when creating new database file.  This file mode
    will be further adjusted by the system `umask`.

An example of using the `OpenConfig` function:

```golang
   import "github.com/graygnuorg/go-gdbm"

   db, err := gdbm.OpenConfig(gdbm.DatabaseConfig{FileName: "file.gdbm",
						  Mode: gdbm.ModeNewdb,
						  Flags: gdbm.OF_NOMMAP,
						  FileMode: 0600})
   if err != nil {
       panic(err)
   }
```

To close a database, use the `Close` method:

```golang
   db.Close()
```

## Error Handling

Most `GDBM` function return a pair of values: an actual result and
error status.  Some functions return only error status.  The error
status is an object of type `GdbmError` - a modification
of [error](https://pkg.go.dev/errors) which, in addition to the
methods provided by the standard interface, provides the following:

* `Code()` __int__

    The `Code()` method returns a `GDBM` [error code](https://www.gnu.org.ua/software/gdbm/manual/index.html#Error-codes.index-error-codes)
    corresponding to the error condition it describes.  All `GDBM` error
    codes are exported as constants.

* `SysError()` __error__

    Some `GDBM` errors have a system error (type `syscall.error`)
    associated with them.  If such associated error exists, it is
    returned by the `SysError()` method.  Otherwise, the method
    returns nil.

* `Defined()` __bool__

    The `GDBM` library, as any other package, evolved over the time
    introducing, in particular, new error codes.  Use the
    `err.Defined` method to check if a particular `err` is defined in the
    version of `GDBM` your library is linked with.

The `gdbm` library exports errors corresponding to all `GDBM` [error
codes](https://www.gnu.org.ua/software/gdbm/manual/index.html#Error-codes.index-error-codes).
Error names are derived from the corresponding `GDBM` error constant
using the following algorithm:

1. The initial `GDBM_` prefix is removed.
2. The remaining string is split on the underscore characters into a list of strings.
3. In each obtained string, all characters except the first are converted to lower case.
4. The strings are concatenated and prefixed with `Err`.

Thus, for example, original error code `GDBM_CANNOT_REPLACE` yields
`ErrCannotReplace`.

The library defines an additional error: `ErrNotImplemented`.  This
error is returned if the called function is not supported by the
version of `libgdbm` the library is linked with.

### Error matching

Errors returned by `GDBM` functions can be matched (using the
`errors.Is` method) against `GDBM` error constants and against system
errors, if a system error is associated with the `GDBM` one.  For
example, the following code tests if opening the database failed
because the database file didn't exist:

```golang
    db, err := gdbm.Open("in.db", gdbm.ModeReader)
    if err != nil {
	if errors.Is(err, gdbm.ErrFileOpenError) && errors.Is(err, os.ErrNotExist) {
	    // Handle the error here
	}
    }
```

## Looking up a Key

Both keys and values stored in the database are represented by the Go
type `[]byte`.  To look up a key, use the `Fetch` method:

```golang
   func (db *gdbm.Database) Fetch(key []byte) (value []byte, err error)
```

On success, the method returns the value obtained from the database
and `nil` as error.  If the value is not found, the `ErrItemNotFound`
error is returned.  If an error occurred, another error code can be
returned.  In case of error return, the `value` returned is not
specified.

An example of using this function:

```golang
    value, err := db.Fetch(key)
    if err == nil {
       // Use the `value`
    } else if errors.Is(err, ErrItemNotFound) {
       fmt.Println("key not found")
    } else {
       panic(err)
    }
```

__Note__: when using string value as a key, many applications account
for the terminating `\0` character when computing its length.  When
accessing such database files from Go, it is important to include the
0 byte into the key, e.g.

```golang
    value, err := db.Fetch(append([]byte(keyString), 0))
```

## Storing a Key/Value Pair

The `Store` method stores a key/value pair into a database:

```golang
    func (db *gdbm.Database) Store(key []byte, value []byte, replace bool) error
```

On success, `nil` is returned.  When attempting to store a key that
already exists in the database, the behavior depends on the value of
`replace` parameter.  If `replace` is `false` the `ErrCannotReplace`
error is returned.  If `replace` is `true`, the new value will be stored,
replacing the old one.

Example:

```golang
    err = db.Store(key, value, false)
    if err != nil {
	panic(err)
    }
```

## Removing a Key/Value Pair

```golang
    func (db *gdbm.Database) Delete(key []byte) error
```

The `Delete` method returns `nil` on success.  If the requested key
was not found in the database, `ErrItemNotFound` is returned.
Otherwise, an error describing the failure is returned:

```golang
    err := db.Delete(key)
    if err != nil && !errors.Is(err, ErrItemNotFound) {
	panic(err)
    }
```

## Iterating Over All Keys

To iterate over all keys in the database, use the following approach:

```golang
    next := db.Iterator()
    var key []byte
    var err error
    for key, err = next(); err == nil; key, err = next() {
	// Do something with `key`
    }
    if !errors.Is(err, ErrItemNotFound) {
	panic(err)
    }
```

A usual caution regarding the body of the above loop is in order.  You
can use `key` to fetch the `value` and do any other operation that
*does not modify* the database.  Don't ever try to update the database
while iterating over it (e.g. by deleting the key or modifying its
value).  Doing so will lead to some keys being visited twice or not
visited at all.

## Inspecting the Database

<a name="FileName"></a>
```golang
    func (db *gdbm.Database) FileName() (string, error)
```

The `FileName` function returns the name of the database.  Using this
function is handy, in particular, if the database was created from an
ASCII dump file using `OpenConfig` with `ModeLoad`.

```golang
    func (db *gdbm.Database) Count() (uint, error)
```

The `Count` method returns the number of key/value pairs in the
database.

```golang
    func (db *gdbm.Database) NeedsRecovery() bool
```

The `NeedsRecovery` method returns `true` if the database is
[structurally inconsistent](https://www.gnu.org.ua/software/gdbm/manual/Database-consistency.html)
and needs recovery.  In this case, any other method invoked on that database
will return an error.  To recover the database, use the [`Recover`
method](#user-content-recovering-structural-consistency).

```golang
    func (db *gdbm.Database) LastError() error
```

Returns the last error that was detected when operating on the
database.

## Dumping a Database

`GDBM` databases can be converted to non-searchable [flat files](https://www.gnu.org.ua/software/gdbm/manual/Flat-files.html),
also known as __dumps__, and re-created from such files.  This can be
used, for example, to create back-up copies or for sending the
database over the wire.  Two dump formats are supported: `AsciiDump` and
`BinaryDump`.  The latter is a simpler format, which is
retained for backward compatibility with older versions of `GDBM`.  The
recommended format is `AsciiDump`.

To create a dump from an open database file, use the `Dump` method:

```golang
   func (db *db.Database) Dump(cfg gdbm.DumpConfig) error
```

The `DumpConfig` structure provides the necessary parameters:

* `FileName` __string__

    Name of the dump file to create.

* `Format` __int__

    Requested dump file format: `AsciiDump` or `BinaryDump`.

* `Rewrite` __bool__

    If set to `true`, the dump file will be overwritten, if it exists.
    Otherwise, if the dump file already exist, the function will
    return `ErrFileOpenError`.

* `FileMode` __int__

    File mode to use when creating dump file.

A simplified method is provided, that uses default settings:

```golang
    func (db *gdbm.Database) DumpToFile(filename string) error
```

This method dumps the database to the specified file name in
`AsciiDump` format.  If the output file exists, it will be silently
overwritten.  If the file is created, its mode is set to 0666 modified
by the system `umask`.

## Loading a Database

There are two ways to re-create a database from an existing dump file.
First, if the dump is in `AsciiDump` format, you can use
[OpenConfig](#user-content-OpenConfig) function with the `Mode` set to
`ModeLoad`.  The `FileName` field must be set to the name of the dump
file.  For example, to re-create the database from the dump file
`staff.dump`:

```golang
   db, err := gdbm.OpenConfig(gdbm.DatabaseConfig{FileName: "staff.dump", Mode: gdbm.ModeLoad})
   if err != nil {
       panic(err)
   }
```

Another approach is to use the `Load` method on an existing database:

```golang
    func (db *gdbm.Database) Load(cfg gdbm.DumpConfig) error
```

The method takes as an argument a `DumpConfig` structure, discussed above.
Its fields have the following meaning:

* `FileName`

    Name of the dump file.

* `Rewrite`

    If set to `true`, replace existing keys in the database.  If set
    to `false`, any attempt to import a key that already exists in the
    database will cause the function to fail with `ErrCannotReplace`.

The `FileMode` and `Format` fields are ignored.

A simplified interface is provided:

```golang
    func (db *gdbm.Database) LoadFromFile(filename string) error
```

It is equivalent to

```golang
    db.Load(DumpConfig{FileName: filename, Rewrite: true})
```

## Recovering Structural Consistency

Certain errors (such as write error when saving stored key) can leave
database file in [structurally inconsistent state](https://www.gnu.org.ua/software/gdbm/manual/index.html#Database-consistency).  When such a critical
error occurs, the database file is marked as needing recovery.
Subsequent calls to any `GDBM` methods on that database (except
`Recover` and `NeedRecovery`), will return immediately with the
`ErrNeedRecovery` code.

The `Recover` method attempts to recover the database into usable
state:

```golang
    func (db *gdbm.Database) Recover(cfg gdbm.RecoveryConfig) (stat *gdbm.RecoveryStat, err error)
```

The `RecoveryConfig` structure controls the recovery process:

* `Backup` __bool__

    If true, create the backup file.  The name of the file will be
    returned in the `BackupName` field of `RecoveryStat` (see below).

* `Force` __bool__

    Force recovery: don't check if the database actually needs it.

The following three fields are used when set to a non-0 value:

* `MaxFailedKeys` __uint__

    Report failure after this many failed keys.

* `MaxFailedBuckets` __uint__

    Report failure after this many failed buckets.

* `MaxFailures` __uint__

    Report failure after this many failures.

On success, the function returns a reference to a `RecoveryStat` value:

* `BackupName` __string__

    Name of the backup file (if `RecoveryConfig.Backup` was set).

* `RecoveredKeys` __uint__

    Number of recovered keys.

* `RecoveredBuckets` __uint__

    Number of recovered buckets.

* `FailedKeys` __uint__

    Number of keys that were not recovered.

* `FailedBuckets` __uint__

    Number of buckets were not recovered.

* `DuplicateKeys` __uint__

    Number of duplicated keys.

A simplified interface is provided by the `Reorganize` method:

```golang
    func (db *gdbm.Database) Reorganize() error
```

This method forces database recovery.

## Examining and Changing Database Format

In `GDBM` version 1.21 or later, databases can be stored on disk in two
distinct formats: _standard_ format, and [_extended_ (or _numsync_)](https://www.gnu.org.ua/software/gdbm/manual/Numsync.html),	format.
The extended format is recommended to use with [crash tolerance mode](#user-content-crash-tolerance).

To examine the current database format, use the `IsNumsync` method:

```golang
    numsync, err := db.IsNumsync()
    if err == nil {
	if numsync {
	    // Database is in extended format
	} else {
	    // Database is in standard format
	}
    } else {
	// An error occurred
    }
```

The format is normally determined when the database is created.  By default,
databases are created in standard format.  To create a database in extended
format, add the `OF_NUMSYNC` flag to the `DatabaseConfig.Flags` field:

```golang
    db, err := gdbm.OpenConfig(gdbm.DatabaseConfig{FileName: "file.db",
						   Mode: gdbm.ModeNewdb,
						   Flags: gdbm.OF_NUMSYNC,
						   FileMode: 0600})
```

To change the format of an existing database, use the `Convert` method.
It takes a single boolean parameter.  If the parameter is `true`, the
database will be converted to extended format.  If it is `false`, the
database will be converted to standard format.  If the database is already
in the requested format, nothing will be done.  E.g.:

```golang
   err := db.Convert(true)
   if err {
       panic(err)
   }
```

## Synchronization

The `Sync` method synchronizes the changes in `db` with its disk file:

```golang
    func (db *gdbm.Database) Sync() error
```

## Crash Tolerance

_Crash tolerance_ is a new mechanism that appeared in `GDBM` version 1.21.
This mechanism, when used correctly, guarantees that a [logically
consistent](https://www.gnu.org.ua/software/gdbm/manual/index.html#Database-consistency) recent state of application data
can be recovered following a crash. Specifically, it guarantees that
the state of the database file corresponding to the most recent
successful call to `db.Sync()` can be recovered.

The feature must be enabled at compile time, and requires appropriate
support from the OS and the filesystem.  The design rationale of the
crash tolerance mechanism is described in detail in the article,
[Crashproofing the Original NoSQL Key-Value
Store](https://queue.acm.org/DrillBits5/), by Terence Kelly,

For a database to be opened with crash tolerance support, it must
reside on a file system that supports _reflink copying_, such as
XFS, BtrFS or the like.  Crash tolerance is requested by
setting the `CrashTolerance` field of the [`DatabaseConfig`
structure](#user-content-opening-and-closing-a-database) to `true`.
It is also strongly advised to use databases in [extended database
format](https://www.gnu.org.ua/software/gdbm/manual/Numsync.html).  To
do so, when creating the database, set the `gdbm.OF_NUMSYNC` bit in the
`DatabaseConfig.Flags` field, e.g:

```golang
    db, err := gdbm.OpenConfig(gdbm.DatabaseConfig{FileName: "file.db",
						   Mode: gdbm.ModeWrcreat,
						   CrashTolerance: true,
						   Flags: gdbm.OF_NUMSYNC,
						   FileMode: 0600})
```

Once a database is opened in crash tolerance mode, two additional _snapshot
files_ are created in the directory where it resides.  The file names
are constructed by removing the suffix from the database file name and
appending suffixes `.s1` and `.s2` instead.  These files are removed when
the database is closed.  If, however, the database is not closed properly,
e.g. because of the program crash or power failure, the files will remain on
disk.  In this case, one of them will keep the state of the database at the
moment of the most recent call to `db.Sync()`.

To ensure that the snapshots keep a logically consistent state of the
database, care must be taken to call `db.Sync()` at right places.  Follow
the [discussion in GDBM manual](https://www.gnu.org.ua/software/gdbm/manual/Synchronizing-the-Database.html) to ensure the database is synchronized correctly.

When called with `DatabaseConfig.CrashTolerance` set to `true`, the
`gdbm.OpenConfig` function first checks if the snapshot files exist.
If so, it fails with the `gdbm.ErrSnapshotExist` error.  When this
happens, the caller is supposed to run the _database recovery_, by
invoking the `SnapshotRestore` function:

```golang
    func SnapshotRestore(filename string) error
```

This function takes the file name of the database file as its argument.  It
analyzes both snapshots to select the right one, and recovers the database
from it.  On success, `SnapshotRestore` returns `nil`.  On error, it returns
one of the following errors:

* `ErrSnapshotBad`

    Neither snapshot file is readable.

* `ErrSnapshotSame`

    Snapshot dates and synchronization counts are the same.

* `ErrSnapshotSuspicious`

    The snapshots are unrealiable

* Any `syscall.Errno` or `os.Errno` value, if a system error occurred in the process.

If any of these are returned, you are advised to attempt [manual crash recovery](https://www.gnu.org.ua/software/gdbm/manual/Manual-crash-recovery.html).

The following code snippet illustrates the usual sequence used when opening
a database in crash tolerance mode:

```golang
    db, err := gdbm.OpenConfig(gdbm.DatabaseConfig{FileName: filename,
						   CrashTolerance: true,
						   Mode: gdbm.ModeWrcreat,
						   FileMode: 0666,
						   Flags: gdbm.OF_NUMSYNC})

    if err != nil {
	    if errors.Is(err, gdbm.ErrSnapshotExist) {
		    // Database was not closed properly.  Attempt a crash recovery:
		    err = gdbm.SnapshotRestore(filename)
		    if err != nil {
			    fmt.Printf("Can't restore %s: %s\n", filename, err.Error())
			    fmt.Printf("Manual crash recovery is advised.\n")
			    os.Exit(1)
		    }
		    // Database was successfully recovered, now try to open it:
		    db, err = gdbm.OpenConfig(gdbm.DatabaseConfig{FileName: filename,
								  CrashTolerance: true,
								  Mode: gdbm.ModeWrcreat,
								  FileMode: 0666,
								  Flags: gdbm.OF_NUMSYNC})
		    if err != nil {
			    panic(err)
		    }
	    } else {
		    // Another error.
		    panic(err)
	    }
    }
```

## Informative Functions

```golang
    func Version() []int
```

This function returns the version of the `libgdbm` library the
package is linked with.  The returned array has 3 elements: major and
minor version numbers, and patch level number.


```golang
    func VersionString() string
```

Returns the version of the `libgdbm` library as a formatted string.
The returned string starts with words `GDBM version`, followed by
a space and the version numbers delimited by dots.  If patchlevel is
0, it is omitted.  The version number is followed by the date of
the library build,
