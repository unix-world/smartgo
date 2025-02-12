
// GO Lang :: SmartGo / Web Server / Auth-Model :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250210.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	smart "github.com/unix-world/smartgo"
)


//-----


type WebAuthGetAuthUserRecordByUserName   func(user string) (error, smart.AuthUserRecord)
type WebAuthValidateAuthUserByTokenRecord func(user string, token string) (error, smart.AuthUserToken)

type WebAuthAccountsMethods struct {
	GetAuthUserRecordByUserName   WebAuthGetAuthUserRecordByUserName
	ValidateAuthUserByTokenRecord WebAuthValidateAuthUserByTokenRecord
}


//-----


var defaultGetAuthUserRecordByUserName   WebAuthGetAuthUserRecordByUserName   = func(user string) (error, smart.AuthUserRecord) {
	//--
	noRecord := smart.AuthUserRecord{Exists:false, IsValid:false, UserName:user}
	//--
	return smart.NewError("Not Implemented"), noRecord
	//--
} //END FX


var defaultValidateAuthUserByTokenRecord WebAuthValidateAuthUserByTokenRecord = func(user string, token string) (error, smart.AuthUserToken) {
	//--
	noToken := smart.AuthUserToken{Exists:false, IsValid:false, UserName:user}
	//--
	return smart.NewError("Not Implemented"), noToken
	//--
} //END FX


var registeredWebAuthAccountsMethods WebAuthAccountsMethods = WebAuthAccountsMethods{ // by default register the dummy methods which are returning: Not Implemented / No Record
	GetAuthUserRecordByUserName:   defaultGetAuthUserRecordByUserName,
	ValidateAuthUserByTokenRecord: defaultValidateAuthUserByTokenRecord,
}


//-----


func SetWebAuthAccountsMethods(methods WebAuthAccountsMethods) error {
	//--
	if(methods.GetAuthUserRecordByUserName != nil) {
		registeredWebAuthAccountsMethods.GetAuthUserRecordByUserName = methods.GetAuthUserRecordByUserName
	} //end if
	//--
	if(methods.ValidateAuthUserByTokenRecord != nil) {
		registeredWebAuthAccountsMethods.ValidateAuthUserByTokenRecord = methods.ValidateAuthUserByTokenRecord
	} //end if
	//--
	return nil
	//--
} //END FUNCTION


func GetWebAuthAccountsMethods() WebAuthAccountsMethods {
	//--
	return registeredWebAuthAccountsMethods
	//--
} //END FUNCTION


//-----


// #END
