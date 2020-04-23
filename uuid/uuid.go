package uuid

import (
	"sync"
)

var counterLock sync.Mutex
var counterValue int = 0

// returns an id guarenteed to be unique within the package
// currently just a simple counter
func Uuid() (id int) {
	counterLock.Lock()
	counterValue += 1
	id = counterValue
	counterLock.Unlock()
	return id
}

// taken from: https://github.com/chrisfarms/jsapi/uuid.go
