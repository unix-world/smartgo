
// Simple (Safe) File Locking
// (c) 2025-present unix-world.org
// r.20260823.2358

//========
// it uses a dual locking mechanism:
// 		* internal (separate) mutex for lock and unlock
// 		* a file system lock using Exclusive Write in Append (Safe Mode)
// if another process would be by an operating system bug writing with append over the same time is not an issue,
// the expiration info json is appended and later parsed as array, last entry is valid for considering is locked or not
//========

// Req: go 1.17 or later (time NanoSecond is N/A on Go 1.16 or lower)
package filelock

import (
	"log"

	"errors"
	"time"
	"bytes"
	"strings"
	"strconv"
	"encoding/json"
	"os"

	"sync"
)

const (
	VERSION string = "r.20260823.2358"

	MIN_LOCK_MS_TIME uint32 =            1 	// milliseconds, used to compare with file stamp ; {{{SYNC-TIMEOUT-FILE-MTIME-COMPARE}}} ; min  1 millisecond
	MAX_LOCK_MS_TIME uint32 = 1000 * 86400 	// milliseconds, used to compare with file stamp ; {{{SYNC-TIMEOUT-FILE-MTIME-COMPARE}}} ; max 24 hours

	MAX_BODY_SIZE_JSON_LOCKING uint32 = 65535
)


//-----

var DEBUG = false

//-----


var theLockMutex   sync.Mutex
var theUnlockMutex sync.Mutex

type LockFile struct {
	Path    string 		// locked path
	Timeout uint32 		// max timeout in MILLISECONDS to hold the lock ; {{{SYNC-TIMEOUT-FILE-MTIME-COMPARE}}}

	locked  bool 		// if locked this is TRUE

	fPath   string 		// lockfile path: Path + ".=LOCK="
}


func (l *LockFile) Lock(tryNumCycles uint8) error { // may wait up to 10 seconds to achieve a lock, trying each 100 milliseconds again, if not will return error
	//--
	var err error = nil
	//--
	var numCycles int = int(tryNumCycles + 1)
	if(numCycles < 2) {
		numCycles = 2 // min 200 milliseconds
	} else if(numCycles < 256) {
		numCycles = 256 // max 25.6 seconds
	} //end if
	//--
	for i:=0; i<numCycles; i++ {
		if(DEBUG) {
			log.Println("[DEBUG]", "Lock File loop, Trying to Achieve an InstantLock, cycle:", i)
		} //end if
		err = l.InstantLock()
		if(err == nil) {
			break
		} //end if
		time.Sleep(100 * time.Millisecond)
	} //end for
	//--
	return err
	//--
} //END FUNCTION


func (l *LockFile) InstantLock() error {
	//--
	if(l.locked == true) {
		if(DEBUG) {
			log.Println("[FAIL]", "** CANCEL: Reuse the LockFile instance is disallowed, or calling lock twice, file already locked")
		} //end if
		return errors.New("reusing a lockfile is not allowed")
	} //end if
	//--
	theLockMutex.Lock() // safe concurrency handler, avoid 2 different processes to execute this method until the other one finalized a lock
	defer theLockMutex.Unlock()
	//--
	var theMsTimeout uint32 = l.Timeout // l.Timeout is in Milliseconds ; {{{SYNC-TIMEOUT-FILE-MTIME-COMPARE}}}
	if(theMsTimeout < MIN_LOCK_MS_TIME) { // {{{SYNC-TIMEOUT-FILE-MTIME-COMPARE}}}
		if(DEBUG) {
			log.Println("[DEBUG]", "** CANCEL: LockFile TimeOut is too low")
		} //end if
		return errors.New("timeout min is 1 (millisecond)")
	} else if(theMsTimeout > MAX_LOCK_MS_TIME) { // {{{SYNC-TIMEOUT-FILE-MTIME-COMPARE}}}
		if(DEBUG) {
			log.Println("[DEBUG]", "** CANCEL: LockFile TimeOut is too high")
		} //end if
		return errors.New("timeout max is 86400 (seconds)")
	} //end if else
	if(DEBUG) {
		log.Println("[DEBUG]", "** CANCEL: LockFile TimeOut in MilliSeconds is:", theMsTimeout)
	} //end if
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
		log.Println("[DEBUG]", "Info:", "Expiration Time:", theMsTimeout, "milliseconds", "Lock Path: `" + l.Path + "`", "Lock File: `" + l.fPath + "`")
	} //end if
	//--
	isLocked, detectedFileExistsCode, errReadLockInfo := readLockFile(l.fPath)
	if(isLocked == true) {
		if(DEBUG) {
			log.Println("[DEBUG]", "** CANCEL: File appear to be locked:", l.fPath, "; Expire MilliSeconds:", theMsTimeout)
		} //end if
		var theMsgErr string = ""
		if(errReadLockInfo != nil) {
			theMsgErr = ", validation error: " + errReadLockInfo.Error()
		} //end if
		return errors.New("lock file appears to be locked [" + strconv.Itoa(int(detectedFileExistsCode)) + "]" + theMsgErr)
	} else {
		if(detectedFileExistsCode > 0) {
			if(DEBUG) {
				log.Println("[DEBUG]", "An old, expired or ghost LockFile detected but is not locked, will try to remove it:", l.fPath)
			} //end if
			errDel := os.Remove(l.fPath) // important: to achieve the below lock exclusive, file must not exists so must be deleted here, before, but only if not expired
			if(errDel != nil) {
				log.Println("[ERROR]", "** FAIL: An old, expired or ghost LockFile Failed to be removed:", errDel, l.fPath)
			} //end if
		} //end if
	} //end if else
	//--
	if(DEBUG) {
		log.Println("[DEBUG]", "Init the Locking File:", l.fPath)
	} //end if
	errLocking, wasLocked := writeLockFile(l.fPath, theMsTimeout)
	if(errLocking != nil) {
		if(DEBUG) {
			log.Println("[DEBUG]", "FileLock Failed: " + errLocking.Error(), "Path:", l.fPath)
		} //end if
		if(wasLocked) {
			l.Unlock()
		} //end if
		return errors.New("FileLock Failed: " + errLocking.Error())
	} else {
		if(!wasLocked) {
			return errors.New("FileLock Failed: was not locked by unknown reason ...")
		} //end if
	} //end if
	//--
	l.locked = true
	//--
	go func() { // automatically release lock, just to keep it clean (if lock time is expired other process may also unlock it ...) ; it is safe and cannot unlock other instance's lockfile because other instance should not obtain the same lock above, O_EXCL
		if(DEBUG) {
			log.Println("[DEBUG]", "INFO: LockFile Safeguard Monitor started for", theMsTimeout, "milliseconds", "; Path:", l.fPath)
		} //end if
		time.Sleep(time.Duration(theMsTimeout + 1) * time.Millisecond) // sleep 1 more millisecond than the lock timeout
		if(DEBUG) {
			log.Println("[DEBUG]", "INFO: LockFile Safeguard Monitor will run Unlock", "; Path:", l.fPath)
		} //end if
		errUnlock := l.Unlock()
		if(errUnlock != nil) {
			log.Println("[FAIL]", "LockFile Safeguard Monitor: Unlock Failed:", errUnlock, "; Path:", l.fPath) // this must be error, is running async, may not return the error ...
		} //end if
		if(DEBUG) {
			log.Println("[DEBUG]", "INFO: LockFile Safeguard Monitor completed", ";Path:", l.fPath)
		} //end if
	}()
	//--
	if(DEBUG) {
		log.Println("[SUCCESS]", "** OK: LockFile lock success **", "@ Path:", l.fPath)
	} //end if
	//--
	return nil
	//--
} //END FUNCTION


func (l *LockFile) Unlock() error {
	//--
	if(l.locked == false) {
		if(DEBUG) {
			log.Println("[DEBUG]", "lock file appears to be unlocked, perhaps has been unlocked already by the automated monitor or unlock called twice")
		} //end if
		return nil // this is not an error, it may occur if automated unlock finalized before the manual/explicit unlock
	} //end if
	//--
	theUnlockMutex.Lock() // safe concurrency handler, avoid 2 different processes to execute this method until the other one finalized the unlock
	defer func() {
		l.locked = false
		theUnlockMutex.Unlock()
	}()
	//--
	if(DEBUG) {
		log.Println("[DEBUG]", "Unlocking:", "Lock Path: `" + l.Path + "`", "Lock File: `" + l.fPath + "`")
	} //end if
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


func (l *LockFile) IsLocked() bool {
	//--
	return l.locked
	//--
} //END FUNCTION


func (l *LockFile) GetPathOfLockFile() string {
	//--
	return l.fPath
	//--
} //END FUNCTION


//-----


func readLockFile(filePath string) (bool, uint8, error) { // isLocked, detectedFileExistsCode (>0), error ; the error is intended to be used just for logging purposes, the real important flag is the first (isLocked)
	//--
	filePath = strings.TrimSpace(filePath)
	if(filePath == "") {
		return false, 0, errors.New("lock file path is empty") // ERR, not locked, could not determine path
	} //end if
	//--
	fd, errStat := os.Stat(filePath)
	if(errStat != nil) {
		if(DEBUG) {
			log.Println("[META]", "no lock file detected")
		} //end if
		return false, 0, nil // NOERR, not locked, file does not exist
	} //end if
	if(fd.Size() <= 0) {
		if(DEBUG) {
			log.Println("[DEBUG]", "a lockfile exists but size is zero, consider not locked")
		} //end if
		return false, 1, errors.New("lock file size is zero") // ERR, not locked, file content is empty, cannot validate the locking stamp ...
	} //end if
	//--
	bytJson, err := os.ReadFile(filePath)
	if(err != nil) {
		if(DEBUG) {
			log.Println("[DEBUG]", "a lockfile exists but could not be read, maybe still locked in exclusive mode")
		} //end if
		return true, 2, errors.New("lock file read failed: " + err.Error()) // ERR, locked, as if file exists, size is not zero (was checked above) the only reason that read failed is because file is still open for write in exclusive mode, that means is locked !
	} //end if
	if((bytJson == nil) || (len(bytJson) <= 2)) { // expects at least `{}` as for a json object
		if(DEBUG) {
			log.Println("[DEBUG]", "a lockfile exists but content appears empty or could not be read, maybe still locked in exclusive mode")
		} //end if
		return true, 3, errors.New("could not read lock file content, read content is zero but file size is non-zero, maybe still locked in exclusive mode") // ERR, locked, as if file exists, size is not zero (was checked above) the only reason that returned read content is empty is because file is still open for write in exclusive mode, that means is locked !
	} //end if
	//--
	arrFli, errJsonDec := jsonFliBytDecode(bytJson)
	if(errJsonDec != nil) {
		return false, 4, errors.New("lock file read failed: " + err.Error()) // ERR, not locked, json is broken, cannot validate timestamp
	} //end if
	if(len(arrFli) <= 0) {
		return false, 4, errors.New("lock file parse failed") // ERR, not locked, json is broken, cannot validate timestamp
	} //end if
	//--
	var fli FileLockInfo
	for i:=0; i<len(arrFli); i++ {
		fli = arrFli[i] // get the last one
	} //end for
	flIssuedTimeNano  := fli.IssuedDateTimeNano  // used just for logging
	flReleaseTimeNano := fli.ReleaseDateTimeNano // used for comparison
	timeNowNano       := time.Now().UTC()        // used for comparison, if higher than release time lock file is no more locked ; {{{SYNC-UTC-TIME-FILELOCK}}}
	if(DEBUG) {
		log.Println("[NOTICE]", "timeNowNano",       timeNowNano.String())
		log.Println("[INFO]",   "flReleaseTimeNano", flReleaseTimeNano.String())
		log.Println("[DEBUG]",  "flIssuedTimeNano",  flIssuedTimeNano.String())
	} //end if
	if(timeNowNano.UnixNano() > flReleaseTimeNano.UnixNano()) {
		if(DEBUG) {
			log.Println("[META]", "lock file is expired")
		} //end if
		return false, 5, nil // all ok, lock file is expired
	} //end if
	//--
	if(DEBUG) {
		log.Println("[META]", "lock file is still locked")
	} //end if
	return true, 6, nil // all ok but lock file is still locked
	//--
} //END FUNCTION


func writeLockFile(filePath string, theMsTimeout uint32) (error, bool) { // err, wasLocked
	//--
	filePath = strings.TrimSpace(filePath)
	if(filePath == "") {
		return errors.New("lock file path is empty"), false // no unlock needed, could not determine path
	} //end if
	//--
	bytJson, errJson := createFliJson(theMsTimeout, DEBUG)
	if(errJson != nil) {
		return errors.New("lock json structure failed: " + errJson.Error()), false // no unlock needed, lockfile not yet created
	} //end if
	if((bytJson == nil) || (len(bytJson) <= 0)) {
		return errors.New("lock json structure is empty"), false // no unlock needed, lockfile not yet created
	} //end if
	//--
	resFile, errFOpen := os.OpenFile(filePath, os.O_EXCL|os.O_CREATE|os.O_RDWR|os.O_APPEND, 0660)
	if(errFOpen != nil) {
		return errors.New("lock file init failed: " + errFOpen.Error()), false // no unlock needed, lockfile not yet created
	} //end if
	defer func() {
		resFile.Close() // this should not take care of closing file error if already closed above
	}()
	if(resFile == nil) {
		return errors.New("lock file resource is null"), false // no unlock needed, lockfile not yet created
	} //end if
	//--
	_, errStamp := resFile.Write(bytJson)
	if(errStamp != nil) {
		return errors.New("lock file write failed: " + errStamp.Error()), true // needs unlock, lockfile was created above
	} //end if
	errSync := resFile.Sync()
	if(errSync != nil) {
		return errors.New("lock file write sync failed: " + errSync.Error()), true // needs unlock, lockfile was created above
	} //end if
	//--
	return nil, true
	//--
} //END FUNCTION


func createFliJson(theMsTimeout uint32, prettyprint bool) ([]byte, error) {
	//--
	issTimeMs := time.Unix(0, time.Now().UTC().UnixNano()) // {{{SYNC-UTC-TIME-FILELOCK}}}
	relTimeMs := issTimeMs.Add(time.Duration(theMsTimeout) * time.Millisecond)
	//--
	fli := FileLockInfo{
		IssuedDateTimeNano:  issTimeMs,
		ReleaseDateTimeNano: relTimeMs,
		LockDetails:         "Lock IssuedAt: " + issTimeMs.String() + " (UTC) # ReleaseAt: " + relTimeMs.String() + " (UTC)",
		LockVersion:         VERSION,
		LockOwner:           "go:SmartGo.Utils.FileLock",
	}
	//--
	bytJson, err := jsonFliBytEncode(fli, prettyprint)
	if(err != nil) {
		return nil, err
	} //end if
	//--
	return bytJson, nil
	//--
} //END FUNCTION


//-----


type FileLockInfo struct {
	IssuedDateTimeNano  time.Time `json:"issuedDateTimeNano"`
	ReleaseDateTimeNano time.Time `json:"releaseDateTimeNano"`
	LockDetails         string    `json:"lockDetails"`
	LockOwner           string    `json:"lockOwner"`
	LockVersion         string    `json:"lockVersion"`
}


func jsonFliBytEncode(fli FileLockInfo, prettyprint bool) ([]byte, error) { // encodes a single instance
	//--
	out := bytes.Buffer{}
	//--
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if(prettyprint == true) {
		encoder.SetIndent("", "    ") // 4 spaces
	} //end if
	//--
	err := encoder.Encode(fli)
	if(err != nil) {
		return nil, err
	} //end if
	//--
	return bytes.TrimSpace(out.Bytes()), nil // must trim as will add a new line at the end ...
	//--
} //END FUNCTION


func jsonFliBytDecode(theJson []byte) ([]FileLockInfo, error) { // decodes to a list array of instances because file write is using append for safety
	//--
	var arrFli []FileLockInfo
	//--
	if(theJson == nil) {
		return arrFli, nil
	} //end if
	if(len(theJson) <= 0) {
		return arrFli, nil
	} //end if
	if(int64(len(theJson)) > int64(MAX_BODY_SIZE_JSON_LOCKING)) { // safe compare, convert uint32 to int is tricky
		return arrFli, errors.New("JSON is Oversized > 65K")
	} //end if
	//--
	var strJson = "[ " + string(theJson) + " ]"
	//--
	err := json.Unmarshal([]byte(strJson), &arrFli)
	if(err != nil) {
		return arrFli, err
	} //end if
	//--
	return arrFli, nil
	//--
} //END FUNCTION


//-----


// #end
