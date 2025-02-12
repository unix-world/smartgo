
// Simple File Locking
// (c) 2025 unix-world.org
// r.20250210.2358

package filelock

import (
	"log"
	"errors"
	"time"
	"strings"
	"os"
	"sync"
)

var lockFileMutex sync.Mutex
var DEBUG = false

type LockFile struct {
	Path    string 		// locked path
	Timeout uint32 		// max timeout to hold the lock

	fPath   string 		// lockfile path: Path + ".=LOCK="
	file    *os.File 	// will be locked using O_EXCL so a concurrent method cannot unlock it until lock is released manual or automated by this instance
}


func (l *LockFile) Lock() error {
	//--
	lockFileMutex.Lock() // safe concurrency handler, avoid 2 different processes to execute this method until the other one finalized a lock
	defer lockFileMutex.Unlock()
	//--
	if(l.file != nil) { // important, disallow reuse to avoid modify expiring time
		if(DEBUG) {
			log.Println("[DEBUG]", "** CANCEL: Reuse the LockFile instance is disallowed")
		} //end if
		return errors.New("reusing a lockfile is not allowed")
	} //end if
	//--
	var theTimeout int64 = int64(l.Timeout)
	//--
	if(theTimeout <= 0) {
		if(DEBUG) {
			log.Println("[DEBUG]", "** CANCEL: LockFile TimeOut is too low")
		} //end if
		return errors.New("timeout min is 1 (second)")
	} else if(theTimeout > 86400) {
		if(DEBUG) {
			log.Println("[DEBUG]", "** CANCEL: LockFile TimeOut is too high")
		} //end if
		return errors.New("timeout max is 86400 (seconds)")
	} //end if else
	//--
	l.Path = strings.TrimSpace(l.Path)
	if(l.Path == "") {
		if(DEBUG) {
			log.Println("[DEBUG]", "** CANCEL: LockFile Path is Empty")
		} //end if
		return errors.New("path is empty")
	} //end if
	//--
	l.fPath = l.Path + ".=LOCK=" // must contain single quotes which are not direct accessible in a Safe Path by SmartGo
	//--
	if(DEBUG) {
		log.Println("[DEBUG]", "Info:", "Expiration Time:", theTimeout, "seconds", "Lock Path: `" + l.Path + "`", "Lock File: `" + l.fPath + "`")
	} //end if
	//--
	fd, err := os.Stat(l.fPath)
	if(err == nil) {
		if(DEBUG) {
			log.Println("[DEBUG]", "An old LockFile detected:", l.fPath)
		} //end if
		modifTime := fd.ModTime()
		if(time.Now().Unix() < (modifTime.Unix() + theTimeout)) {
			if(DEBUG) {
				log.Println("[DEBUG]", "** CANCEL: An old LockFile detected is still locked, not yet expired:", l.fPath)
			} //end if
			return errors.New("already locked")
		} else {
			if(DEBUG) {
				log.Println("[DEBUG]", "An old, expired LockFile detected is not locked, will try to remove it:", l.fPath)
			} //end if
			errDel := os.Remove(l.fPath) // important: to achieve the below lock exclusive, file must not exists so must be deleted here, before, but only if not expired
			if(errDel != nil) {
				if(DEBUG) {
					log.Println("[DEBUG]", "** FAIL: An old, expired LockFile Failed to be removed:", l.fPath)
				} //end if
				return errors.New("clear old lock failed: " + errDel.Error())
			} //end if
		} //end if
	} //end if
	//--
	if(DEBUG) {
		log.Println("[DEBUG]", "Init the Locking File:", l.fPath)
	} //end if
	var errFOpen error = nil
	l.file, errFOpen = os.OpenFile(l.fPath, os.O_EXCL|os.O_CREATE|os.O_RDWR|os.O_APPEND, 0660)
	if(errFOpen != nil) {
		if(DEBUG) {
			log.Println("[DEBUG]", "Init of Locking File Failed:", errFOpen, l.fPath)
		} //end if
		l.file = nil
		return errors.New("lock init failed: " + errFOpen.Error())
	} //end if
	if(l.file == nil) {
		if(DEBUG) {
			log.Println("[DEBUG]", "Init of Locking File Failed: Null", l.fPath)
		} //end if
		l.Unlock()
		return errors.New("lock is null")
	} //end if
	//--
	currentTime := time.Now()
	_, errStamp := l.file.WriteString("SmartGo Lock File: `" + l.fPath + "`" + "\n" + "Path: `" + l.Path + "`" + "\n" + "Created: " + currentTime.String() + "\n")
	if(errStamp != nil) {
		if(DEBUG) {
			log.Println("[DEBUG]", "Stamp of Locking File Failed:", errStamp, l.fPath)
		} //end if
		l.Unlock() // do not track errors here, status is unknown ...
		return errors.New("lock write failed: " + errStamp.Error())
	} //end if
	//--
	go func() { // automatically release lock ; it is safe and cannot unlock other instance's lockfile because other instance should not obtain the same lock above, O_EXCL
		if(DEBUG) {
			log.Println("[DEBUG]", "INFO: LockFile safeguard monitor started for", theTimeout, "seconds")
		} //end if
		time.Sleep(time.Duration(theTimeout) * time.Second)
		if(DEBUG) {
			log.Println("[DEBUG]", "INFO: LockFile safeguard monitor will run Unlock")
		} //end if
		errUnlock := l.Unlock()
		if(errUnlock != nil) {
			log.Println("[ERROR]", "Unlock Failed:", errUnlock) // this must be error, is running async, may not return the error ...
		} //end if
		if(DEBUG) {
			log.Println("[DEBUG]", "INFO: LockFile safeguard monitor ended")
		} //end if
	}()
	//--
	if(DEBUG) {
		log.Println("[DEBUG]", "** OK: LockFile lock success")
	} //end if
	//--
	return nil
	//--
} //END FUNCTION


func (l *LockFile) Unlock() error {
	//--
	if(DEBUG) {
		log.Println("[DEBUG]", "Unlocking:", "Lock Path: `" + l.Path + "`", "Lock File: `" + l.fPath + "`")
	} //end if
	//--
	if(l.file == nil) {
		if(DEBUG) {
			log.Println("[DEBUG]", "lock file is already null, perhaps has been unlocked already by the automated monitor or unlock called twice")
		} //end if
		return nil // this is not an error, it may occur if automated unlock finalized before the manual/explicit unlock
	} //end if
	//--
	l.file.Close() // this should be no error if already closed above
	l.file = nil
	//--
	if(l.fPath == "") {
		if(DEBUG) {
			log.Println("[DEBUG]", "** FAIL: lock file path is empty")
		} //end if
		return errors.New("unlock: lock file path is empty, failed to check and clear the residual lockfile")
	} //end if
	//--
	_, errExists := os.Stat(l.fPath)
	if(errExists == nil) {
		errCleanup := os.Remove(l.fPath)
		if(errCleanup != nil) {
			if(DEBUG) {
				log.Println("[DEBUG]", "** FAIL: lock file remove (cleanup) ERR:", errCleanup)
			} //end if
			return errors.New("unlock: failed to remove the lockfile: " + errCleanup.Error())
		} //end if
	} //end if
	//--
	if(DEBUG) {
		log.Println("[DEBUG]", "** OK: LockFile unlock success")
	} //end if
	return nil
	//--
} //END FUNCTION


func (l *LockFile) GetPathOfLockFile() string {
	//--
	return l.fPath
	//--
} //END FUNCTION


// #end
