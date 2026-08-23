
// MoonGoDB :: File Storage Manager
// (c) 2026-present unix-world.org
// r.20260823.2358

// Req: go 1.17 or later (filelock req. time NanoSecond which is N/A on Go 1.16 or lower)
package moongodb

import (
	"log"

	"time"
	"sync"

	smart 		"github.com/unix-world/smartgo"
	smartcache 	"github.com/unix-world/smartgo/utils/smart-memcache"
	filelock 	"github.com/unix-world/smartgo/utils/filelock"
	uid 		"github.com/unix-world/smartgo/crypto/uuid"

	lungo 		"github.com/unix-world/smartgo/db/lungo"
)

const (
	DEBUG                      bool = false
	DEBUG_CACHE                bool = false

	LENGTH_UUID               uint8 = 17 + 1 + 13 + 1 + 10 + 1 + 10

	expiredDocsCleanInterval uint16 =   120 		// 2 minutes
	cacheCleanupIntervalMsec uint16 =     5 		// 5 milliseconds
	lockTimeOutSec           uint16 =    60 		// 1 minute

	cacheRealm string = "MoonGo.StorageManager"
	cacheName  string = "smart.db.moongo.StorageManager.inMemCache"
)

var (
	dbStoreCache      *smartcache.InMemCache = nil
	dbStoreInitMutex  sync.Mutex
	dbStoreOpenMutex  sync.Mutex
	dbStoreCloseMutex sync.Mutex
)


//-----


func memCacheExpirationHandler(cachedObj smartcache.CacheEntry) {
	//--
	defer smart.PanicHandler()
	//--
	if(DEBUG == true) {
		log.Println("[DEBUG]", smart.CurrentFunctionName(), "MoongoDB Store Manager :: Expiration Handler is running:", cacheName, cacheName)
	} //end if
	//--
	if(cachedObj.Obj == nil) {
		return
	} //end if
	cachedLockedCli, ok := cachedObj.Obj.(managerLockedClient)
	if(!ok) {
		return
	} //end if
	//--
	if(DEBUG == true) {
		log.Println("[DATA]", smart.CurrentFunctionName(), "MoongoDB Store Manager :: Expiration Handler, selected Cache Record", "Id: `" + cachedObj.Id, "` ; Realm: `" + cachedObj.Data + "`")
	} //end if
	//--
	err := SafeCloseDB(&cachedLockedCli)
	if(err != nil) {
		log.Println("[FAIL]", smart.CurrentFunctionName(), cacheRealm, cacheName, "MoongoDB Store Manager :: Expired Cache Object Handler Failed to SafeCloseDB, on selected Cache Record", "Id: `" + cachedObj.Id, "` ; Realm: `" + cachedObj.Data + "`")
	} //end if
	//--
} //END FUNCTION


func initManager() error {
	//--
	defer smart.PanicHandler()
	//--
	dbStoreInitMutex.Lock()
	defer dbStoreInitMutex.Unlock()
	//--
	if(DEBUG == true) {
		log.Println("[DEBUG]", smart.CurrentFunctionName(), "Init DB Store Cache:", cacheName, cacheName)
	} //end if
	//--
	dbStoreCache = smartcache.NewCache(cacheName, time.Duration(cacheCleanupIntervalMsec) * time.Millisecond, DEBUG_CACHE)
	if(dbStoreCache == nil) {
		return smart.NewError("Failed to Init the DB Store Manager Cache")
	} //end if
	//--
	return nil
	//--
} //END FUNCTION


type managerLockedClient struct {
	DbPath          string
	LockExpireAt 	int64
	LockFile 		*filelock.LockFile
	DbEngine 		*lungo.Engine
	DbClient 		lungo.IClient
	UUID 			string
}


func SafeOpenDB(fileBsonDBPath string) (*managerLockedClient, error) {
	//--
	defer smart.PanicHandler()
	//--
	dbStoreOpenMutex.Lock()
	defer dbStoreOpenMutex.Unlock()
	//--
	// this uses a double lock mechanism, for safety:
	// 		1. inMemoryLockCache lock 	; expires using lockTimeOutSec
	// 		2. lockFile lock 			; expires using lockTimeOutSec
	// if any of these fail to achieve a lock, return error: could not achieve a lock
	// the LockExpireAt of inMemoryLockCache object should be significant higher than the locktime of the lockFile in order to try to safe destruct it at the next execution
	//--
	fileBsonDBPath = smart.StrTrimWhitespaces(fileBsonDBPath)
	if(fileBsonDBPath == "") {
		return nil, smart.NewError("BSON File Path is Empty")
	} //end if
	fileBsonDBPath = smart.SafePathFixClean(fileBsonDBPath)
	if(!smart.StrEndsWith(fileBsonDBPath, ".bson")) {
		return nil, smart.NewError("BSON File Path have an Invalid File Name Extension")
	} //end if
	if(smart.PathIsEmptyOrRoot(fileBsonDBPath) == true) {
		return nil, smart.NewError("BSON File Path is Empty/Root")
	} //end if
	if(smart.PathIsSafeValidSafePath(fileBsonDBPath) != true) {
		return nil, smart.NewError("BSON File Path is Invalid Unsafe")
	} //end if
	if(smart.PathIsBackwardUnsafe(fileBsonDBPath) == true) {
		return nil, smart.NewError("BSON File Path is Backward Unsafe")
	} //end if
	if(smart.PathIsAbsolute(fileBsonDBPath) == true) {
		return nil, smart.NewError("BSON File Path is Absolute")
	} //end if
	if(smart.PathIsDir(fileBsonDBPath)) {
		return nil, smart.NewError("BSON File Path is a Directory not a File")
	} //end if
	//--
	errInit := initManager()
	if(errInit != nil) {
		return nil, errInit
	} //end if
	//--
	cacheExists, cachedObj, cacheExpTime := dbStoreCache.Get(fileBsonDBPath) // the cacheExpTime is used just for logging, if a cache record is expired will be removed from the cache by the cache internal loopCleanExpired mechanism
	if(cacheExists == true) { // if a cached object is found in cache and expired by checking LockExpireAt, try to safe destruct it by closing the engine ; otherwise it is still locked
		if((cachedObj.Id == fileBsonDBPath) && (cachedObj.Data == cacheRealm) && (cachedObj.Obj != nil)) { // compliant object found
			cachedLockedCli, ok := cachedObj.Obj.(managerLockedClient)
			if(ok) {
				var lockExpired bool = false
				lockExpireAtUnixTime := cachedLockedCli.LockExpireAt
				if(smart.TimeNowUnix() > lockExpireAtUnixTime) {
					lockExpired = true
				} //end if
				log.Println("[NOTICE]", smart.CurrentFunctionName(), cacheRealm, cacheName, "MoonGoDB Store Manager :: Cached Record Found: `" + fileBsonDBPath + "` ; Id: `" + cachedObj.Id, "` ; Realm: `" + cachedObj.Data + "` ; ExpireTime:", cacheExpTime, "; LockExpireAt:", smart.DateFromUnixTimeLocal(lockExpireAtUnixTime), "; LockIsExpired:", lockExpired)
				if(!lockExpired) { // not yet expired, stop here
					if(DEBUG) {
						log.Println("[DEBUG]", smart.CurrentFunctionName(), cacheRealm, cacheName, "MoonGoDB Store Manager :: Cannot Achieve Memory Lock, Unexpired Cached Record Found: `" + fileBsonDBPath + "` ; Id: `" + cachedObj.Id, "` ; Realm: `" + cachedObj.Data + "` ; ExpireTime:", cacheExpTime, "; LockExpireAt:", smart.DateFromUnixTimeLocal(lockExpireAtUnixTime), "; LockIsExpired:", lockExpired)
					} //end if
					return nil, smart.NewError("Failed to achieve DB Exclusive Memory Lock, Record is Locked and Not yet Expired")
				} //end if
				memCacheExpirationHandler(cachedObj)
			} else {
				log.Println("[WARN]", smart.CurrentFunctionName(), cacheRealm, cacheName, "MoonGoDB Store Manager :: Cached Invalid Record Found: `" + fileBsonDBPath + "` ; Id: `" + cachedObj.Id, "` ; Realm: `" + cachedObj.Data + "` ; ExpireTime:", cacheExpTime)
			} //end if else
		} else { // uncompliant object, just log ; normally this will never happend except bugs in the code, just log it if happen ...
			log.Println("[ERR]", smart.CurrentFunctionName(), cacheRealm, cacheName, "MoonGoDB Store Manager :: Cached Uncompliant Record Found: `" + fileBsonDBPath + "` ; Id: `" + cachedObj.Id, "` ; Realm: `" + cachedObj.Data + "` ; ExpireTime:", cacheExpTime)
		} //end if else
		dbStoreCache.Unset(fileBsonDBPath) // unset from cache and continue
	} //end if
	cachedObj = smartcache.CacheEntry{} // reset
	cacheExists = false // reset
	cacheExpTime = 0 // reset
	//--
	lockFile := filelock.LockFile{
		Path: 		fileBsonDBPath,  				// path that needs to be locked, not the lock file path !
		Timeout: 	uint32(lockTimeOutSec) * 1000, 	// milliseconds ; {{{SYNC-TIMEOUT-LOCKFILE}}} ; must use the exact timeout in seconds as for the lock memcached object
	}
	const tryNumCycles uint8 = 155 // each cycle is 100 ms, will result in a total to try as of 15.6 seconds
	errLock := lockFile.Lock(tryNumCycles) // fixed, OK
	if(errLock != nil) {
		return nil, smart.NewError("Failed to achieve DB Exclusive File Lock")
	} //end if
	//--
	store := lungo.NewFileStore(fileBsonDBPath, smart.CHMOD_FILES)
	if(store == nil) {
		return nil, smart.NewError("Failed to Create a New File Store")
	} //end if
	//--
	client, engine, errOpen := lungo.Open(nil, lungo.Options{
		Store: store,
		ExpireInterval: time.Duration(expiredDocsCleanInterval) * time.Second,
	})
	if(errOpen != nil) {
		return nil, smart.NewError("Failed to Open DB: " + errOpen.Error())
	} //end if
	if(client == nil) {
		return nil, smart.NewError("Failed to Open DB Client")
	} //end if
	if(engine == nil) {
		return nil, smart.NewError("Failed to Open DB Engine")
	} //end if
	//--
	var lockExpAtUnixTime int64 = smart.TimeNowUnix() + int64(lockTimeOutSec)
	mLckCli := managerLockedClient{
		DbPath: 		fileBsonDBPath,
		LockExpireAt: 	lockExpAtUnixTime, // timestamp ; {{{SYNC-TIMEOUT-LOCKFILE}}} ; must use the exact timeout in seconds as for the lock file
		LockFile: 		&lockFile,
		DbEngine: 		engine,
		DbClient: 		client,
		UUID: 			smart.StrToLower(uid.Uuid17Seq() + "-" + uid.Uuid10Num() + "-" + uid.Uuid13Str() + "-" + uid.Uuid10Str()),
	}
	cacheObj := smartcache.CacheEntry{
		Id:   fileBsonDBPath,
		Data: cacheRealm,
		Obj:  mLckCli,
		Fn:   memCacheExpirationHandler,
	}
	if(DEBUG) {
		log.Println("[DEBUG]", smart.CurrentFunctionName(), cacheRealm, cacheName, "Set In Cache DB Client Object: `" + fileBsonDBPath + "` ; Id: `" + cacheObj.Id, "` ; Realm: `" + cacheObj.Data + "; LockExpireAt:", smart.DateFromUnixTimeLocal(lockExpAtUnixTime))
	} //end if
	wasSetInCache := dbStoreCache.Set(cacheObj, int64(lockTimeOutSec))
	if(wasSetInCache != true) {
		return nil, smart.NewError("Failed to achieve DB Exclusive Memory Lock")
	} //end if
	//--
	return &mLckCli, nil
	//--
} //END FUNCTION


func SafeCloseDB(mLckCli *managerLockedClient) error {
	//--
	dbStoreCloseMutex.Lock()
	defer dbStoreCloseMutex.Unlock()
	//--
	if(mLckCli == nil) {
		return smart.NewError("Safe Client Instance is Null")
	} //end if
	//--
	var err1 error = nil
	if(mLckCli.LockFile == nil) {
		err1 = smart.NewError("Safe Client Instance LockFile is Null")
	} else {
		err1 = mLckCli.LockFile.Unlock()
	} //end if else
	//--
	var err2 error = nil
	if(mLckCli.DbEngine == nil) {
		err2 = smart.NewError("Safe Client Instance Engine is Null")
	} else {
		mLckCli.DbEngine.Close()
	} //end if
	//--
	if(err1 != nil) {
		return err1
	} else if(err2 != nil) {
		return err2
	} //end if
	//--
	return nil
	//--
} //END FUNCTION


//-----


// #end
