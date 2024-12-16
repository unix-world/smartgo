
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20241216.2358 :: STABLE
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
	if((record.PassAlgo < 0) || (record.PassAlgo > 4)) {
		return defRecord, NewError("Invalid Pass Algo")
	} //end if
	record.Totp2FASecret = StrTrimWhitespaces(arrRecord.Get("secret2fa").String())
	record.PrivKey = StrTrimWhitespaces(arrRecord.Get("secretkey").String())
	record.EmailAddr = StrTrimWhitespaces(arrRecord.Get("email").String())
	record.FullName = StrTrimWhitespaces(arrRecord.Get("name").String())
	record.Privileges = StrTrimWhitespaces(arrRecord.Get("privileges").String())
	record.Restrictions = StrTrimWhitespaces(arrRecord.Get("restrictions").String())
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
	var token string = StrTrimWhitespaces(JsonGetValueByKeyPath(jsonRecord, "token").String())
	if((token == "") || (token != authUserToken)) { // check if is valid
		return defToken, NewError("No Valid Token Found")
	} //end if
	//--
	theToken := AuthUserToken{IsValid:true, TokenHash:token, UserName:authUserName}
	//--
	return theToken, nil
	//--
} //END FUNCTION


//-----


// #END
