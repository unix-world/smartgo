
// GO Lang :: SmartGo/Uuid :: Smart.Go.Framework
// (c) 2020-2022 unix-world.org
// r.20220416.1958 :: STABLE

package uuid

import (
	"sync"
	"strings"
	"time"
	"math/rand"
)


var uuidSessSeqMutex sync.Mutex
var uuidSessSeqCntVal uint64 = 0
func UuidSessionSequence() uint64 { // returns an id guarenteed to be unique within the session (just a simple counter ; starts at 1) ; taken from: https://github.com/chrisfarms/jsapi/uuid.go
	//--
	uuidSessSeqMutex.Lock()
	uuidSessSeqCntVal += 1
	uuidSessSeqMutex.Unlock()
	//--
	return uuidSessSeqCntVal
	//--
} //END FUNCTION


func Uuid1013Str(uidLength uint8) string { // based on PHP Smart.Framework ; combines the: Smart/uuid_10_str() with Smart/uuid_13_str()
	//--
	if(uidLength == 13) {
		uidLength = 13
	} else {
		uidLength = 10
	} //end if else
	//--
	var chars string = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	//-- expand the chars as the randomizer have a low chance to get 1st or last character
	chars += chars // 2x
	chars += chars // 3x
	chars += chars // 4x
	chars += chars // 5x
	//--
	rSource := rand.NewSource(time.Now().UnixNano())
	rHandle := rand.New(rSource)
	//--
	var uid string = ""
	var i uint8
	var r int = 0
	var l int = len(chars)
	var m int = 0
	for i = 0; i < uidLength; i++ {
		m = l - 1
		if(m < 0) {
			m = 0
		} else if(m > l) {
			m = l
		} //end if
		if(m <= 0) {
			return "" // no chars !!
		} //end if
		r = rHandle.Intn(m - 1)
		uid += string(chars[r:(r+1)])
	} //end for
	//--
	uid = strings.TrimSpace(uid)
	//--
	if(strings.Trim(uid, "0") == "") { // disallow having all zeroes like: 0000000000..0000000000000
		uid = Uuid1013Str(uidLength)
	} //end if
	//--
	return uid
	//--
} //END FUNCTION


// #END
