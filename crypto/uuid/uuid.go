
// GO Lang (1.11 or later) :: SmartGo/Crypto/Uuid :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20241129.2358 :: STABLE

package uuid

import (
	"fmt"
	"log"

	"sync"

	"strings"
	"strconv"

	"time"
	mrand "math/rand"
	"math/big"
	crand "crypto/rand"

	"crypto/md5"
	"io"
	"encoding/hex"
)


//-----


var uuidSessSeqMutex sync.Mutex
var uuidSessSeqCntVal uint64 = 0
func UuidSessionSequence() uint64 { // returns an id guaranteed to be unique within the session (just a simple counter ; starts at 1) ; taken from: https://github.com/chrisfarms/jsapi/uuid.go
	//--
	uuidSessSeqMutex.Lock()
	uuidSessSeqCntVal += 1
	uuidSessSeqMutex.Unlock()
	//--
	return uuidSessSeqCntVal
	//--
} //END FUNCTION


//-----


func UuidUrn() string { // ex: 00000000-0000-0000-0000-000000000000
	//--
	uid := Uuid17Seq() + ":" + Uuid10Num() // safer against md5 colissions, 28 bytes only and md5 is 32 bytes !
	//--
	hash := md5.New()
	io.WriteString(hash, uid)
	//--
	uid = strings.ToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
	if(len(uid) != 32) {
		uid = strings.Repeat("0", 32)
	} //end if
	//--
	return uid[0:8] + "-" + uid[8:12] + "-" + uid[12:16] + "-" + uid[16:20] + "-" + uid[20:]
	//--
} //END FUNCTION


//-----


func Uuid10Num() string { // based on PHP Smart.Framework :: Smart/uuid_10_num()
	//--
	return uuid1013NumOrStr(10, true)
	//--
} //END FUNCTION


func Uuid10Str() string { // based on PHP Smart.Framework :: Smart/uuid_10_str()
	//--
	return uuid1013NumOrStr(10, false)
	//--
} //END FUNCTION


func Uuid13Str() string { // based on PHP Smart.Framework :: Smart/uuid_13_str()
	//--
	return uuid1013NumOrStr(13, false)
	//--
} //END FUNCTION


func Uuid10Seq() string { // based on PHP Smart.Framework :: Smart/uuid_10_str()
	//--
	return uuid1017Seq(10)
	//--
} //END FUNCTION


func Uuid17Seq() string { // based on PHP Smart.Framework :: (TODO) Smart/uuid_17_str()
	//--
	return uuid1017Seq(17)
	//--
} //END FUNCTION


//-----


func uuid1013NumOrStr(uidLength uint8, numsOnly bool) string { // based on PHP Smart.Framework ; combines the: Smart/uuid_10_str() with Smart/uuid_13_str()
	//--
	if(uidLength == 10) {
		uidLength = 10
	} else {
		uidLength = 13
	} //end if else
	//--
	var emptyRes string = strings.Repeat("0", int(uidLength)) // in case of error
	//--
	const poolNum string = "0123456789"
	const poolStr string = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	//--
	var chars string = ""
	//--
	if(numsOnly) {
		chars = strings.Repeat(poolNum, 205) // 205x ~ 2048 bytes ; expand the chars as the randomizer have a low chance to get 1st or last character
	} else {
		chars = strings.Repeat(poolStr, 57) // 57x ~ 2048 bytes ; expand the chars as the randomizer have a low chance to get 1st or last character
	} //end if else
	var l int = len(chars)
	if(l <= 0) {
		log.Println("[ERROR]", "UUID/NumOrStr", "Empty Charset Pool")
		return emptyRes
	} //end if
	//--
	var nBig *big.Int
	var err error
	rSource := mrand.NewSource(time.Now().UnixNano())
	rHandle := mrand.New(rSource)
	//--
	var uid string = ""
	var r int
	var i uint8
	for i = 0; i < uidLength; i++ {
		//-- combining crypto rand with math rand gives better dispersion
		if((i % 2) == 1) {
			nBig, err = crand.Int(crand.Reader, big.NewInt(int64(l)))
			if(err != nil) {
				log.Println("[ERROR]", "UUID/NumOrStr", "Crypto Random Generator Failed", err)
				r = 0
			} else {
				r = int(nBig.Int64())
			} //end if else
		} else {
			r = rHandle.Intn(l)
		} //end if
		//-- corrections
		if(r < 0) {
			r = 0
			log.Println("[WARNING]", "UUID/NumOrStr", "Correction (r < 0): r = 0")
		} else if(r >= l) {
			r = l - 1
			log.Println("[WARNING]", "UUID/NumOrStr", "Correction (r >= l): r = l - 1")
		} //end if
	//	log.Println("[DEBUG]", "UUID/Rand", l-1, r)
		//-- assign
		uid += string(chars[r:(r+1)])
		//--
	} //end for
	//--
	uid = strings.TrimSpace(uid)
	//--
	return uid
	//--
} //END FUNCTION


//-----


func uuid1017Seq(uidLength uint8) string { // based on PHP Smart.Framework ; combines the: Smart/uuid_10_str() with TODO:Smart/uuid_17_str()
	//--
	if(uidLength == 10) {
		uidLength = 10
	} else {
		uidLength = 17
	} //end if else
	//--
	var emptyRes string = strings.Repeat("0", int(uidLength)) // in case of error
	//--
	dateUtcNow := time.Now().UTC()
	//--
	var dayOfTheYear int = dateUtcNow.YearDay() // 0..366
	var secondOfTheDay int = (60 * 60 * dateUtcNow.Hour()) + (60 * dateUtcNow.Minute()) + dateUtcNow.Second() // 0..86400
	var secondOfTheYear string = fmt.Sprintf("%05s", strconv.FormatInt(int64(dayOfTheYear * secondOfTheDay), 36)) // 0..31622400 ; B36: 00000..ITS00
	var milisecondNow string = fmt.Sprintf("%02s", strconv.FormatInt(int64(dateUtcNow.Nanosecond() / 1e6), 36)) // 0..999 ; B36: 00..RR
	//--
	var year string = strconv.FormatInt(int64(dateUtcNow.Year()), 10)
	lY := len(year)
	if(uidLength == 10) {
		if(lY > 3) {
			year = string(year[lY-3:lY]) // 0..999 ; B36: 0..RR
		} //end if
	} else {
		if(lY > 6) {
			year = string(year[lY-6:lY]) // 0..999999 ; B36: 0..LFLR
		} //end if
	} //end if else
	iY, yErr := strconv.ParseInt(year, 10, 64)
	if(yErr != nil) {
		log.Println("[ERROR]", "UUID/Seq", "Something went wrong (year / re-parse)")
		return emptyRes
	} //end if
	var randomizer string = ""
	if(uidLength == 10) {
		year = fmt.Sprintf("%02s", strconv.FormatInt(iY, 36)) // ZZ
		randomizer = uuid1013NumOrStr(10, false) // str not num !
		randomizer = randomizer[0:1]
	} else {
		year = fmt.Sprintf("%04s", strconv.FormatInt(iY, 36)) // ZZZZ
		randomizer = uuid1013NumOrStr(13, false) // str not num !
		randomizer = randomizer[0:6]
	} //end if else
	//--
	var uid string = year + secondOfTheYear + milisecondNow + randomizer
	if(len(uid) > int(uidLength)) {
		uid = string(uid[0:uidLength])
	} //end if
	//--
	if(uidLength == 10) {
		uid = fmt.Sprintf("%010s", uid)
	} else {
		uid = fmt.Sprintf("%017s", uid)
	} //end if else
	//--
	return strings.ToUpper(strings.TrimSpace(uid))
	//--
} //END FUNCTION


// #END
