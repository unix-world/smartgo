# Go simple file locking

## Overview

cross platform safe, using os.O_EXCL

## Example

```
	// Try to obtain an exclusive file lock with a timeout
	lock := filelock.LockFile{
		Path: 		"example.txt", // lockfile will be: example.txt.lock
		Timeout: 	1, // seconds
	}
	err := lock.Lock()
	if(err != nil) {
		return
	}

	// Lock obtained successfully, should be released, but if it is not on the next lock will check lockfile MTime and if expired will overwrite otherwise will return error as cannot obtain lock
	defer lock.Unlock()
```

## About

(c) 2025 unix-world.org
License: BSD
