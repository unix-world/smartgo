
// (c) 2024 unix-world.org
// v.20240103.1301
// license: BSD

package main

import (
	"fmt"
	"time"

	otp "github.com/unix-world/smartgo/web/2fa-totp"
	smart "github.com/unix-world/smartgo"
)

func main() {

	secret := otp.RandomSecret(16)

	fmt.Println("Random secret:", secret)

	testSecret := secret
	fmt.Println("Test secret:", testSecret)
	totp := otp.NewTOTP(testSecret, 6, 30, "sha1")

	totpNum :=  totp.Now()
	fmt.Println("current one-time password is:", totpNum, "DateTime:", smart.DateNowLocal())
	fmt.Println(totp.GenerateBarcodeUrl("user", "SmartGoOTP2FA"))

	fmt.Println(totp.Verify(totpNum, time.Now().Unix()))

} //END FUNCTION


// #end
