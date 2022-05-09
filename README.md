# smartgo
GO Module for Smart.Framework


# Important Notice on SmartGo/Basexx

SmartGo BaseXX encode is currently the fastest implementation available in GoLang and portable to Javascript and PHP.
It does features: Base32, Base36, Base58, Base62, Base85 and Base92. But can be easily adapted for other bases and alphabets.

The Javascript version can be found here:
https://github.com/unix-world/Smart.Framework/blob/master/lib/js/framework/src/crypt_utils.js

The PHP version can be found here:
https://github.com/unix-world/Smart.Framework/blob/master/lib/framework/lib_smart.php


## Simple Base92 Encode / Decode Test using a large text file
Just download this file and save in the same folder as the below tests:
https://www.gnu.org/licenses/gpl-3.0.txt


## Simple benchmark test ; smartgo/base92 (FASTER) ; ENCODE: 888.378397ms ; DECODE: 191.787475ms

```golang
// test-base92-unixworld.go
// unix-world/smartgo/base92 (FASTER) ; ENCODE: 888.378397ms ; DECODE: 191.787475ms

package main

import (
	"log"
	"time"

	smart "github.com/unix-world/smartgo"

	b92 "github.com/unix-world/smartgo/base92"
)

func main() {

	var timerStart time.Time

	txt, _ := smart.SafePathFileRead("gpl-3.0.txt", false)

	timerStart = time.Now()
	etxt := b92.Encode([]byte(txt))
	durationEnc := time.Since(timerStart)

	timerStart = time.Now()
	dtxt, _ := b92.Decode(etxt)
	durationDec := time.Since(timerStart)

	log.Println(dtxt, etxt, durationEnc, durationDec)

} //END FUNCTION
```

## Simple benchmark test ; teal-finance/BaseXX/base92 (SLOWER) ; ENCODE: 1.082452169s ; DECODE: 254.817341ms

```golang
// test-base92-tealfinance.go
// teal-finance/BaseXX/base92 (SLOWER) ; ENCODE: 1.082452169s ; DECODE: 254.817341ms

package main

import (
	"log"
	"time"

	smart "github.com/unix-world/smartgo"

	b92 "github.com/teal-finance/BaseXX/base92"
)

func main() {

	var timerStart time.Time

	txt, _ := smart.SafePathFileRead("gpl-3.0.txt", false)

	timerStart = time.Now()
	etxt := b92.Encode([]byte(txt))
	durationEnc := time.Since(timerStart)

	timerStart = time.Now()
	dtxt, _ := b92.Decode(etxt)
	durationDec := time.Since(timerStart)

	log.Println(dtxt, etxt, durationEnc, durationDec)

} //END FUNCTION
```

#### The tests results apearing on teal-finance/BaseXX present their version being 6x fastest but perhaps they measured in a wrong way because these two tests are identical using just one large text file and the results are clear.

##### Actually after running 100 tests every time the unix-world/smartgo/base92 was faster than teal-finance/BaseXX/base92



