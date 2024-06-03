
// GO Lang :: SmartGo / Simple Cache (in-Memory) :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20240117.2121 :: STABLE

// inspired from: forPelevin/go-cache/main/local.go # license: (golang, default) Apache

package simplecache

import (
	"fmt"
	"log"

	"sync"
	"time"

	"strings"
)

//-----

const (
	VERSION string = "r.20240117.2121"

	LOG_INTERVAL_SEC uint16 = 60 // log every 60 seconds
)

//-----

type CacheEntry struct {
	Id    string      `json:"id"`
	Data  string      `json:"data"`
	Obj   interface{} `json:"-"` // any ; this field should not be exported to JSON, it is intended to store internal specific Go Objects
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

func (lc *InMemCache) loopCleanExpired(interval time.Duration) {
	//--
	t := time.NewTicker(interval)
	defer t.Stop()
	//--
	a := time.NewTicker(time.Duration(LOG_INTERVAL_SEC) * time.Second)
	defer a.Stop()
	//--
	for {
		select {
			case <-lc.stop:
				return
			case <-a.C:
				now := time.Now().UTC()
				_, minutes, seconds := now.Clock()
				log.Println("[META] ±±±±±±± InMemCache [" + lc.name + "] Objects ±±±±±±± #", len(lc.objects), "@ CleanUp Interval:", interval, "# Log Frequency:", fmt.Sprintf("%ds", LOG_INTERVAL_SEC), "# mm:ss", fmt.Sprintf("%02d:%02d", minutes, seconds))
			case <-t.C:
				lc.mu.Lock() // keep above the IF as it reads ...
				if(len(lc.objects) > 0) {
					for uid, cu := range lc.objects {
						if((cu.expireAtTimestamp > 0) && (cu.expireAtTimestamp <= time.Now().UTC().Unix())) {
							delete(lc.objects, uid)
							if(lc.debug == true) {
								log.Println("[DEBUG] InMemCache [" + lc.name + "] :: delete UID: `" + uid + "`")
							} //end if
						} //end if
					} //end for
				} //end if
				lc.mu.Unlock()
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
	lc.mu.Lock()
	defer lc.mu.Unlock()
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

func (lc *InMemCache) Unset(id string) bool {
	//--
	id = strings.TrimSpace(id)
	if(id == "") {
		return false
	} //end if
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

func (lc *InMemCache) Set(o CacheEntry, expirationInSecondsFromNow int64) bool {
	//--
	o.Id = strings.TrimSpace(o.Id)
	if(o.Id == "") {
		return false
	} //end if
	//--
	var expTime int64 = 0
	if(expirationInSecondsFromNow > 0) {
		expTime = time.Now().UTC().Unix() + expirationInSecondsFromNow
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

func (lc *InMemCache) SetExpiration(id string, expirationInSecondsFromNow int64) bool {
	//--
	id = strings.TrimSpace(id)
	if(id == "") {
		return false
	} //end if
	//--
	if(expirationInSecondsFromNow < 0) {
		if(lc.debug == true) {
			log.Println("[DEBUG] InMemCache [" + lc.name + "] :: SetExpire: `" + id + "` Negative Expiration, FAIL:", expirationInSecondsFromNow)
		} //end if
		return false
	} //end if
	//--
	lc.mu.Lock()
	defer lc.mu.Unlock()
	//--
	cu, ok := lc.objects[id]
	if(!ok) {
		if(lc.debug == true) {
			log.Println("[DEBUG] InMemCache [" + lc.name + "] :: SetExpire: `" + id + "` N/A")
		} //end if
		return false
	} //end if
	//--
	var expTime int64 = 0
	if(expirationInSecondsFromNow > 0) {
		expTime = time.Now().UTC().Unix() + expirationInSecondsFromNow
	} //end if
	//--
	cu.expireAtTimestamp = expTime
	lc.objects[id] = cu
	if(lc.debug == true) {
		log.Println("[DEBUG] InMemCache [" + lc.name + "] :: SetExpire: `" + id + "` OK:", cu.expireAtTimestamp)
	} //end if
	//--
	return true
	//--
} //END FUNCTION

//-----

func (lc *InMemCache) Get(id string) (found bool, o CacheEntry, expTimeStamp int64) {
	//--
	id = strings.TrimSpace(id)
	if(id == "") {
		return false, CacheEntry{}, -1
	} //end if
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
	//--
	return true, cu.CacheEntry, cu.expireAtTimestamp
	//--
} //END FUNCTION

//-----

// #END
