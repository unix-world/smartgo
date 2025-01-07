
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250107.2358 :: STABLE
// [ AUTH / MODEL:YAML ]

// REQUIRE: go 1.19 or later
package smartgo


//-----


type AuthUserRecord struct {
	Exists        bool
	UserID        string
	UserName      string
	PassHash      string
	PassAlgo      uint8
	Totp2FASecret string
	PrivKey       string
	EmailAddr     string
	FullName      string
	Privileges    string
	Restrictions  string
	Quota         uint64
	MetaData      map[string]string
}

type AuthUserToken struct {
	IsValid       bool // exists and is valid
	TokenHash     string
	UserName      string
	Privileges    string
	Restrictions  string
	Expiration    string
	IsExpired     bool
}

type AuthProvider interface {
	Init(name string, dataYaml string) error
	GetUserRecord(authUserName string) (AuthUserRecord, error)
	VerifyUserTokenByRecord(authUserName string, authUserToken string) (AuthUserToken, error)
}

type AuthProviderYaml struct {
	name     string
	init     bool
	err      error
	yamlData string
	yamlMap  map[string]interface{}
}

func (p *AuthProviderYaml) Init(name string, dataYaml string) error {
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
	p.yamlData = StrTrimWhitespaces(dataYaml)
	if(p.yamlData == "") {
		p.err = NewError("YAML Data is Empty")
		return p.err
	} //end if
	//--
	ym, yErr := YamlDataParse(p.yamlData)
	if(yErr != nil) {
		p.err = NewError("YAML Parsed Data ERR: " + yErr.Error())
		return p.err
	} //end if
	if(ym == nil) {
		p.err = NewError("YAML Parsed Data is Empty")
		return p.err
	} //end if
	p.yamlMap = ym
	//--
	return nil
	//--
} //END FUNCTION

func (p *AuthProviderYaml) GetUserRecord(authUserName string) (AuthUserRecord, error) {
	//--
	defRecord := AuthUserRecord{Exists:false}
	//--
	//log.Println("[DEBUG] p.yamlMap", p.yamlMap, "p.yamlData", p.yamlData)
	if(p.yamlMap == nil) {
		return defRecord, NewError("No data")
	} //end if
	if(len(p.yamlMap) <= 0) {
		return defRecord, NewError("No records found")
	} //end if
	//--
	authUserName = StrTrimWhitespaces(authUserName)
	if((authUserName == "") || (AuthIsValidUserName(authUserName) != true)) {
		return defRecord, NewError("Invalid UserName")
	} //end if
	//--
	ymlRecord, ok := p.yamlMap[authUserName]
	if(!ok) {
		return defRecord, NewError("User Record Not Found")
	} //end if
	if(ymlRecord == nil) {
		return defRecord, NewError("User Record is Null")
	} //end if
	//--
	jsonRecord := JsonNoErrChkEncode(ymlRecord, false, false)
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
	record.PassAlgo = uint8(arrRecord.Get("passalgo").Uint())
	var isPassAlgoValid bool = false
	switch(record.PassAlgo) { // {{{SYNC-AUTH-PASS-ALGOS}}}
		case ALGO_PASS_NONE:
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
		case ALGO_PASS_SMART_SAFE_OPQ_TOKEN:
			// invalid, the user account can't have this kind of password hash
			break
		case ALGO_PASS_SMART_SAFE_WEB_TOKEN:
			// invalid, the user account can't have this kind of password hash
			break
		case ALGO_PASS_CUSTOM_TOKEN:
			// invalid, the user account can't have this kind of password hash
			break
		case ALGO_PASS_CUSTOM_HASH_PASS:
			isPassAlgoValid = true // valid, for custom pass hash implementations
			break
	} //end if
	if(isPassAlgoValid != true) {
		return defRecord, NewError("Invalid Pass Algo")
	} //end if
	record.Totp2FASecret = StrTrimWhitespaces(arrRecord.Get("secret2fa").String())
	record.PrivKey = StrTrimWhitespaces(arrRecord.Get("secretkey").String())
	record.EmailAddr = StrTrimWhitespaces(arrRecord.Get("email").String())
	record.FullName = StrTrimWhitespaces(arrRecord.Get("name").String())
	record.Privileges = StrTrimWhitespaces(arrRecord.Get("privileges").String())
	if(record.Privileges == "") {
		record.Privileges = HTTP_AUTH_DEFAULT_PRIV // {{{SYNC-AUTH-RECORD-FALLBACK-PRIV}}}
	} //end if
	record.Restrictions = StrTrimWhitespaces(arrRecord.Get("restrictions").String())
	if(record.Restrictions == "") {
		record.Restrictions = HTTP_AUTH_DEFAULT_RESTR // {{{SYNC-AUTH-RECORD-FALLBACK-RESTR}}}
	} //end if
	record.Quota = arrRecord.Get("quota").Uint()
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
	return record, nil
	//--
} //END FUNCTION

func (p *AuthProviderYaml) VerifyUserTokenByRecord(authUserName string, authUserToken string) (AuthUserToken, error) {
	//--
	defToken := AuthUserToken{IsValid:false, UserName:authUserName}
	//--
	if(p.yamlMap == nil) {
		return defToken, NewError("No data")
	} //end if
	if(len(p.yamlMap) <= 0) {
		return defToken, NewError("No records found")
	} //end if
	//--
	authUserName = StrTrimWhitespaces(authUserName)
	if((authUserName == "") || (AuthIsValidUserName(authUserName) != true)) {
		return defToken, NewError("Invalid UserName")
	} //end if
	//--
	authUserToken = StrTrimWhitespaces(authUserToken)
	if((authUserToken == "") || (AuthIsValidTokenOpaque(authUserToken) != true)) {
		return defToken, NewError("Invalid Token Hash")
	} //end if
	//--
	ymlRecord, ok := p.yamlMap[authUserName]
	if(!ok) {
		return defToken, NewError("User Record Not Found")
	} //end if
	if(ymlRecord == nil) {
		return defToken, NewError("User Record is Null")
	} //end if
	//--
	jsonRecord := JsonNoErrChkEncode(ymlRecord, false, false)
	//--
	theTokens := JsonGetValueByKeyPath(jsonRecord, "tokens")
	if(!theTokens.Exists()) {
		return defToken, NewError("No Tokens Defined")
	} //end if
	if(!theTokens.IsArray()) {
		return defToken, NewError("Invalid Tokens Definition")
	} //end if
	tokens := JsonGetValueByKeyPath(jsonRecord, "tokens").Array()
	if((tokens == nil) || (len(tokens) <= 0)) {
		return defToken, NewError("No Tokens Found")
	} //end if
	//--
	theToken := AuthUserToken{IsValid:false, UserName:authUserName}
	for i:=0; i<len(tokens); i++ {
		token := tokens[i]
		if(tokens[i].IsObject()) {
			var id string = StrTrimWhitespaces(token.Get("id").String())
			if((id != "") && (id == authUserToken)) {
				var isExpired bool = false
				var expiration string = StrToUpper(token.Get("expiration").String()) // may be as: `yyyy-mm-dd hh:ii:ss` or if not encosed in quotes, yaml will parse as `yyyy-mm-ddThh:ii:ssZ`
				expiration = StrReplaceAll(expiration, "T", " ")
				expiration = StrReplaceAll(expiration, "Z", " ")
				expiration = StrTrimWhitespaces(expiration)
				if(expiration != "") {
					dt := DateTimeStructUtc(expiration)
					if(dt.Time < TimeNowUtc()) {
						isExpired = true
					} //end if
				} //end if
				if(isExpired != true) {
					theToken.IsValid = true
				} //end if
				theToken.IsExpired = isExpired
				theToken.TokenHash = id
				theToken.Expiration = expiration
				theToken.Privileges = StrTrimWhitespaces(token.Get("privileges").String())
				if(theToken.Privileges == "") {
					theToken.Privileges = HTTP_AUTH_DEFAULT_PRIV // {{{SYNC-AUTH-RECORD-FALLBACK-PRIV}}}
				} //end if
				theToken.Restrictions = StrTrimWhitespaces(token.Get("restrictions").String())
				if(theToken.Restrictions == "") {
					theToken.Restrictions = HTTP_AUTH_DEFAULT_RESTR // {{{SYNC-AUTH-RECORD-FALLBACK-RESTR}}}
				} //end if
				break
			} //end if
		} //end if
	} //end for
	//--
	return theToken, nil
	//--
} //END FUNCTION


//-----


// #END
