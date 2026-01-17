
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260116.2358 :: STABLE
// [ AUTH / MODEL ]

// REQUIRE: go 1.19 or later
package smartgo


//-----


type AuthUserRecord struct {
	Exists        bool
	IsValid       bool
	UserID        string
	UserName      string
	PassHash      string
	PassAlgo      uint8
	Totp2FASecret string
	SecurityKey   string
	PrivKey       string
	PubKey        string
	EmailAddr     string
	FullName      string
	Privileges    string
	Restrictions  string
	Quota         int64
	MetaData      map[string]string
}

type AuthUserToken struct {
	Exists        bool
	IsValid       bool
	TokenHash     string
	UserName      string
	Privileges    string
	Restrictions  string
	Expiration    string
	IsExpired     bool
}

type AuthProvider interface {
	IsInitialized() (bool, error)
	SetError(err error) bool
	Init(name string) error
	ParseAndValidateAuthUserRecord(authUserName string, arrUserRecord map[string]interface{}) (AuthUserRecord, error)
	ParseAndValidateAuthTokenRecord(authUserName string, authUserToken string, arrTokenRecord map[string]interface{}) (AuthUserToken, error)
}

type AuthDataProvider struct {
	name     string
	init     bool
	err      error
}


//-----


func (p *AuthDataProvider) IsInitialized() (bool, error) {
	//--
	return p.init, p.err
	//--
} //END FUNCTION


func (p *AuthDataProvider) SetError(err error) bool {
	//--
	if(err == nil) { // avoid set if nil to disallow clear the error by mistake
		return false
	} //end if
	//--
	p.err = err
	//--
	return true
	//--
} //END FUNCTION


func (p *AuthDataProvider) Init(name string) error {
	//--
	defer PanicHandler() // safe recovery handler
	//--
	if(p.err != nil) { // check for external pre-init error that can be set via SetEror() above
		return p.err
	} //end if
	//--
	if(p.init == true) {
		return p.err
	} //end if
	//--
	p.init = true // prevent run twice
	//--
	p.name = StrTrimWhitespaces(name)
	if(p.name == "") {
		p.err = NewError("Structure Name is Empty")
		return p.err
	} //end if
	//--
	return nil
	//--
} //END FUNCTION


func (p *AuthDataProvider) ParseAndValidateAuthUserRecord(authUserName string, arrUserRecord map[string]interface{}) (AuthUserRecord, error) {
	//--
	defer PanicHandler() // safe recovery handler
	//--
	defRecord := AuthUserRecord{Exists:false, IsValid:false, UserName:""}
	//--
	authUserName = StrTrimWhitespaces(authUserName)
	if((authUserName == "") || (AuthIsValidUserName(authUserName) != true)) {
		return defRecord, NewError("Empty or Invalid UserName")
	} //end if
	defRecord.UserName = authUserName
	//--
	if(arrUserRecord == nil) {
		return defRecord, NewError("User Record is Null")
	} //end if
	if(len(arrUserRecord) <= 0) {
		return defRecord, NewError("User Record is Empty")
	} //end if
	defRecord.Exists = true
	//--
	jsonRecord, errJson := JsonEncode(arrUserRecord, false, false)
	if(errJson != nil) {
		return defRecord, NewError("User Record JSON Encoding ERR: " + errJson.Error())
	} //end if
	jsonRecord = StrTrimWhitespaces(jsonRecord)
	if(jsonRecord == "") {
		return defRecord, NewError("JSON data record is Empty")
	} //end if
	arrRecord := JsonGetValueByKeyPath(jsonRecord, "")
	//--
	record := AuthUserRecord{}
	record.Exists 	= true
	record.UserID   = StrTrimWhitespaces(arrRecord.Get("id").String())
	if(record.UserID == "") {
		record.UserID = authUserName
	} //end if
	record.UserName = authUserName
	record.PassHash = StrTrimWhitespaces(arrRecord.Get("passhash").String())
	if(arrRecord.Get("passalgo").Exists()) {
		record.PassAlgo = uint8(arrRecord.Get("passalgo").Uint())
	} else {
		record.PassAlgo = ALGO_PASS_SMART_SAFE_SF_PASS // fallback if the `algo` field does not exists
	} //end if
	var isPassAlgoValid bool = false
	switch(record.PassAlgo) { // {{{SYNC-AUTH-PASS-ALGOS}}}
		case ALGO_PASS_NONE:
			// invalid, must have a valid pass algo
			break
		case ALGO_PASS_PLAIN:
			isPassAlgoValid = true
			break
		case ALGO_PASS_SMART_SAFE_SF_PASS:
			isPassAlgoValid = true
			break
		case ALGO_PASS_SMART_SAFE_ARGON_PASS:
			isPassAlgoValid = true
			break
		case ALGO_PASS_SMART_SAFE_BCRYPT:
			isPassAlgoValid = true
			break
		case ALGO_PASS_CUSTOM_HASH_PASS:
			isPassAlgoValid = true // valid, for custom pass hash implementations
			break
		case ALGO_PASS_SMART_SAFE_OPQ_TOKEN: fallthrough
		case ALGO_PASS_SMART_SAFE_WEB_TOKEN: fallthrough
		case ALGO_PASS_SMART_SAFE_SWT_TOKEN: fallthrough
		case ALGO_PASS_CUSTOM_TOKEN:
			// invalid, the user account can't have this kind of password hash
			break
	} //end if
	if(isPassAlgoValid != true) {
		return defRecord, NewError("Invalid Pass Algo")
	} //end if
	record.Totp2FASecret = StrTrimWhitespaces(arrRecord.Get("secret2fa").String()) // 2FA Secret Key
	record.SecurityKey = StrTrimWhitespaces(arrRecord.Get("secretkey").String()) // OAuth2 (JWT Tokens) Secret Key
	// TODO: implement encrypted private key + decrypt private key somewhere, see SF as example ...
	record.PrivKey = StrTrimWhitespaces(arrRecord.Get("privkey").String()) // Private Key used for encryption and decryption
	record.PubKey = StrTrimWhitespaces(arrRecord.Get("pubkey").String())
	record.EmailAddr = StrTrimWhitespaces(arrRecord.Get("email").String())
	record.FullName = StrTrimWhitespaces(arrRecord.Get("fullname").String())
	record.Privileges = StrTrimWhitespaces(arrRecord.Get("privileges").String())
	if(record.Privileges == "") {
		record.Privileges = HTTP_AUTH_DEFAULT_PRIV // {{{SYNC-AUTH-RECORD-FALLBACK-PRIV}}}
	} //end if
	record.Restrictions = StrTrimWhitespaces(arrRecord.Get("restrictions").String())
	if(record.Restrictions == "") {
		record.Restrictions = HTTP_AUTH_DEFAULT_RESTR // {{{SYNC-AUTH-RECORD-FALLBACK-RESTR}}}
	} //end if
	record.Quota = arrRecord.Get("quota").Int()
	record.MetaData = map[string]string{}
	metaData := arrRecord.Get("metainfo").Map()
	if(len(metaData) > 0) {
		for key, val := range metaData {
			key = StrToLower(StrTrimWhitespaces(key))
			if(key != "") {
				record.MetaData[key] = StrTrimWhitespaces(val.String())
			} //end if
		} //end for
	} //end if
	//--
	record.IsValid = true // set at the end only for safety
	//--
	return record, nil
	//--
} //END FUNCTION


func (p *AuthDataProvider) ParseAndValidateAuthTokenRecord(authUserName string, authUserToken string, arrTokenRecord map[string]interface{}) (AuthUserToken, error) {
	//--
	defer PanicHandler() // safe recovery handler
	//--
	defToken := AuthUserToken{Exists:false, IsValid:false, UserName:""}
	//--
	authUserName = StrTrimWhitespaces(authUserName)
	if((authUserName == "") || (AuthIsValidUserName(authUserName) != true)) {
		return defToken, NewError("Empty or Invalid UserName")
	} //end if
	defToken.UserName = authUserName
	//--
	authUserToken = StrTrimWhitespaces(authUserToken)
	if((authUserToken == "") || (AuthIsValidTokenOpaque(authUserToken) != true)) {
		return defToken, NewError("Empty or Invalid Token Format")
	} //end if
	//--
	if(arrTokenRecord == nil) {
		return defToken, NewError("Token Record is Null")
	} //end if
	if(len(arrTokenRecord) <= 0) {
		return defToken, NewError("Token Record is Empty")
	} //end if
	defToken.Exists = true
	//--
	jsonRecord, errJson := JsonEncode(arrTokenRecord, false, false)
	if(errJson != nil) {
		return defToken, NewError("User Token Record JSON Encoding ERR: " + errJson.Error())
	} //end if
	jsonRecord = StrTrimWhitespaces(jsonRecord)
	if(jsonRecord == "") {
		return defToken, NewError("JSON data record is Empty")
	} //end if
	arrRecord := JsonGetValueByKeyPath(jsonRecord, "")
	//--
	theToken := AuthUserToken{}
	theToken.Exists = true
	theToken.TokenHash = StrTrimWhitespaces(arrRecord.Get("id").String())
	theToken.UserName = authUserName
	theToken.Privileges = StrTrimWhitespaces(arrRecord.Get("privileges").String())
	if(theToken.Privileges == "") {
		theToken.Privileges = HTTP_AUTH_DEFAULT_PRIV // {{{SYNC-AUTH-RECORD-FALLBACK-PRIV}}}
	} //end if
	theToken.Restrictions = StrTrimWhitespaces(arrRecord.Get("restrictions").String())
	if(theToken.Restrictions == "") {
		theToken.Restrictions = HTTP_AUTH_DEFAULT_RESTR // {{{SYNC-AUTH-RECORD-FALLBACK-RESTR}}}
	} //end if
	var isExpired bool = false // by default consider it non-expired ; make it expired only if the field expiration exists and is non-empty
	var expiration string = StrToUpper(arrRecord.Get("expiration").String()) // may be as: `yyyy-mm-dd hh:ii:ss` or if not encosed in quotes ; ex: yaml will parse as `yyyy-mm-ddThh:ii:ssZ`
	expiration = StrReplaceAll(expiration, "T", " ")
	expiration = StrReplaceAll(expiration, "Z", " ")
	expiration = StrTrimWhitespaces(expiration)
	if(expiration != "") {
		dt := DateTimeStructUtc(expiration)
		if((dt.Status != "OK") || (dt.ErrMsg != "")) {
			isExpired = true // malformed
		} else if(dt.Time < TimeNowUnix()) {
			isExpired = true
		} //end if
	} //end if
	theToken.IsExpired = isExpired
	theToken.Expiration = expiration
	//--
	if(isExpired == false) {
		theToken.IsValid = true
	} //end if
	//--
	return theToken, nil
	//--
} //END FUNCTION


//-----


// #END
