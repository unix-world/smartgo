
// GO Lang :: SmartGo / Simple Cache (in-Memory) :: Smart.Go.Framework
// (c) 2020-2022 unix-world.org
// r.20220410.0216 :: STABLE

// inspired from: forPelevin/go-cache/main/local.go # license: (golang, default) Apache

package simplecache

import (
	"sync"
	"time"
	"log"
)

//-----

const VERSION string = "r.20220410.0216"

//-----

type CacheEntry struct {
	Id    string `json:"id"`
	Data  string `json:"data"`
}

type cEntry struct {
	CacheEntry
	expireAtTimestamp int64
}

type InMemCache struct {
	stop chan struct{}
	wg      sync.WaitGroup
	mu      sync.RWMutex
	debug   bool
	name    string
	cInt    time.Duration
	objects map[string]cEntry
}

//-----

func NewCache(name string, cleanupInterval time.Duration, debug bool) *InMemCache {
	//--
	if(debug == true) {
		log.Println("[DEBUG] InMemCache :: NewCache: [" + name + "] / cleanupInterval:", cleanupInterval)
	} //end if
	//--
	lc := &InMemCache{
		debug:   debug,
		name:    name,
		cInt:    cleanupInterval,
		objects: make(map[string]cEntry),
		stop:    make(chan struct{}),
	}
	//--
	lc.wg.Add(1)
	go func(cleanupInterval time.Duration) {
		defer lc.wg.Done()
		lc.loopCleanExpired(cleanupInterval)
	}(cleanupInterval)
	//--
	return lc
	//--
} //END FUNCTION

//-----

func (lc *InMemCache) GetName() string {
	//--
	if(lc.debug == true) {
		log.Println("[DEBUG] InMemCache [" + lc.name + "] :: GetName")
	} //end if
	//--
	return lc.name
	//--
} //END FUNCTION

//-----

func (lc *InMemCache) GetSize() int {
	//--
	var size int = len(lc.objects)
	//--
	if(lc.debug == true) {
		log.Println("[DEBUG] InMemCache [" + lc.name + "] :: GetSize:", size)
	} //end if
	//--
	return size
	//--
} //END FUNCTION

//-----

func (lc *InMemCache) loopCleanExpired(interval time.Duration) {
	//--
	t := time.NewTicker(interval)
	defer t.Stop()
	//--
	for {
		select {
			case <-lc.stop:
				return
			case <-t.C:
				//-- do not condition this message by debug on/off
				log.Println("[DEBUG] ~~~~~~~ InMemCache [" + lc.name + "] Objects ~~~~~~~ #", len(lc.objects), "@ CleanUp Interval:", interval)
				//--
				if(len(lc.objects) > 0) {
					lc.mu.Lock()
					for uid, cu := range lc.objects {
						if((cu.expireAtTimestamp > 0) && (cu.expireAtTimestamp <= time.Now().UTC().Unix())) {
							delete(lc.objects, uid)
							if(lc.debug == true) {
								log.Println("[DEBUG] InMemCache [" + lc.name + "] :: delete UID: `" + uid + "`")
							} //end if
						} //end if
					} //end for
					lc.mu.Unlock()
				} //end if
				//--
		} //end select
	} //end for
	//--
} //END FUNCTION

//-----
/*
func (lc *InMemCache) stopCleanExpired() {
	//--
	if(lc.debug == true) {
		log.Println("[DEBUG] InMemCache [" + lc.name + "] :: stopCleanup")
	} //end if
	//--
	close(lc.stop)
	lc.wg.Wait()
	//--
} //END FUNCTION
*/
//-----

func (lc *InMemCache) Unset(id string) bool {
	//--
	lc.mu.Lock()
	defer lc.mu.Unlock()
	//--
	delete(lc.objects, id)
	//--
	if(lc.debug == true) {
		log.Println("[DEBUG] InMemCache [" + lc.name + "] :: Unset: `" + id + "`")
	} //end if
	//--
	return true
	//--
} //END FUNCTION

//-----

func (lc *InMemCache) Set(o CacheEntry, expirationInSecondsFromNow uint64) bool {
	//--
	var expTime int64 = 0
	if(expirationInSecondsFromNow > 0) {
		expTime = time.Now().UTC().Unix() + int64(expirationInSecondsFromNow)
	} //end if
	//--
	lc.mu.Lock()
	defer lc.mu.Unlock()
	//--
	lc.objects[o.Id] = cEntry{
		CacheEntry:        o,
		expireAtTimestamp: expTime,
	}
	//--
	if(lc.debug == true) {
		log.Println("[DEBUG] InMemCache [" + lc.name + "] :: Set: `" + o.Id + "`")
		log.Println("[DATA] InMemCache [" + lc.name + "] :: Set: `" + o.Id + "`: `" + o.Data + "`")
	} //end if
	//--
	return true
	//--
} //END FUNCTION

//-----

func (lc *InMemCache) Get(id string) (found bool, o CacheEntry, expTimeStamp int64) {
	//--
	lc.mu.RLock()
	defer lc.mu.RUnlock()
	//--
	cu, ok := lc.objects[id]
	if(!ok) {
		if(lc.debug == true) {
			log.Println("[DEBUG] InMemCache [" + lc.name + "] :: Get: `" + id + "` N/A")
		} //end if
		return false, CacheEntry{}, -1
	} //end if
	//--
	if(lc.debug == true) {
		log.Println("[DEBUG] InMemCache [" + lc.name + "] :: Get: `" + id + "` OK")
	} //end if
	return true, cu.CacheEntry, cu.expireAtTimestamp
	//--
} //END FUNCTION

//-----

// #END