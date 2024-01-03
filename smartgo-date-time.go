
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20240103.1301 :: STABLE
// [ DATE / TIME ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"
	"errors"

	"time"
	mrand "math/rand"
)

const (
	//-- FIXED DATE CONSTANTS REFERENCE VALUES ... SYNCED WITH GO DATE STANDARDS !
	DATE_TIME_DEFAULT_LOCAL_TIMEZONE  string = "UTC"
	DATE_TIME_FMT_ISO_NOTIME_GO_EPOCH string = "2006-01-02" 					// GO EPOCH:   NO TIME,   NO TZ OFFSET
	DATE_TIME_FMT_ISO_STD_GO_EPOCH    string = "2006-01-02 15:04:05" 			// GO EPOCH: WITH TIME,   NO TZ OFFSET
	DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH  string = "2006-01-02 15:04:05 -0700" 		// GO EPOCH: WITH TIME, WITH TZ OFFSET
	DATE_TIME_FMT_RFC1123_GO_EPOCH    string = "Mon, 02 Jan 2006 15:04:05" 		// GO EPOCH: RFC1123
	//-- #
)

var (
	ini_SMART_FRAMEWORK_TIMEZONE string = DATE_TIME_DEFAULT_LOCAL_TIMEZONE // set via DateTimeSetLocation
)

//-----


// PRIVATE
type uxmDateTimeStruct struct {
	Status        string  `json:"status"` 			// OK | ERROR
	ErrMsg        string  `json:"errMsg"` 			// error message (if any if date/time conversion was used)
	Time          int64   `json:"time"` 			// 1607230987 as unix epoch (seconds since unix epoch 1970-01-01 00:00:00), 64-bit integer !!
	DayOfWeekName string  `json:"dayOfWeekName"` 	// "Sunday" .. "Wednesday" .. "Saturday"
	DayOfWeek     int     `json:"dayOfWeek"` 		// 1        .. 4           .. 7
	DayOfYear     int     `json:"dayOfYear"` 		// 1 .. 365(366)
	Year          int     `json:"year"` 			// 2020
	Years         string  `json:"years"` 			// "2020"
	Month         int     `json:"month"` 			// 5
	Months        string  `json:"months"` 			// "05"
	MonthName     string  `json:"monthName"` 		// "May"
	Day           int     `json:"day"` 				// 7
	Days          string  `json:"days"` 			// "07"
	Hour          int     `json:"hour"` 			// 9
	Hours         string  `json:"hours"` 			// "09"
	Minute        int     `json:"minute"` 			// 8
	Minutes       string  `json:"minutes"` 			// "08"
	Second        int     `json:"second"` 			// 1
	Seconds       string  `json:"seconds"` 			// "01"
	NanoSec       int     `json:"nanoSec"` 			// Ex: 709122707
	TzOffset      string  `json:"tzOffset"` 		// "+0000" / "+0300" / ... / "-0700" / ...
	TzName        string  `json:"tzName"` 			// "UTC" | "LOCAL"
}


func DateTimeSetLocation(loc string) bool {
	//--
	loc = StrTrimWhitespaces(loc)
	if(loc != "") {
		ini_SMART_FRAMEWORK_TIMEZONE = loc
	} //end if
	//--
	tzLocation, tzLocErr := time.LoadLocation(ini_SMART_FRAMEWORK_TIMEZONE)
	if(tzLocErr != nil) {
		ini_SMART_FRAMEWORK_TIMEZONE = DATE_TIME_DEFAULT_LOCAL_TIMEZONE // restore
		log.Println("[ERROR]", CurrentFunctionName(), "SmartGo Date/Time Location FAILED to be Set to: `" + ini_SMART_FRAMEWORK_TIMEZONE + "`")
		return false
	} //end if
	//--
	time.Local = tzLocation // set the global timezone
	//--
	log.Println("[INFO]", CurrentFunctionName(), "SmartGo Date/Time Location was Set to `" + ini_SMART_FRAMEWORK_TIMEZONE + "`: Success")
	//--
	return true
	//--
} //END FUNCTION


func DateTimeGetLocation() string {
	//--
	return ini_SMART_FRAMEWORK_TIMEZONE
	//--
} //END FUNCTION


// PRIVATE
func parseDateTimeAsStruct(mode string, dateIsoStr string) uxmDateTimeStruct { // mode = UTC | LOCAL
	//--
	dateIsoStr = StrTrimWhitespaces(dateIsoStr)
	if((dateIsoStr == "") || (StrIContains(dateIsoStr, "NOW"))) {
		dateIsoStr = ""
	} //end if
	//--
	var currentTime time.Time = time.Now()
	var theError error = nil
	if(dateIsoStr != "") {
		dateIsoArr := Explode(" ", dateIsoStr)
		var dtFormat string = DATE_TIME_FMT_ISO_NOTIME_GO_EPOCH // YYYY-MM-DD
		var isWellFormatedDate bool = true
		if(len(dateIsoArr) == 3) { // YYYY-MM-DD HH:II:SS +ZZZZ
			dtFormat = DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH
		} else if(len(dateIsoArr) == 2) { // YYYY-MM-DD HH:II:SS
			dtFormat = DATE_TIME_FMT_ISO_STD_GO_EPOCH
		} else if(len(dateIsoArr) == 1) { // YYYY-MM-DD
			// OK
		} else {
			isWellFormatedDate = false
		} //end if else
		if(isWellFormatedDate == true) {
			parseTime, err := time.Parse(dtFormat, dateIsoStr)
			if(err != nil) {
				theError = err
			} else {
				currentTime = parseTime
			} //end if
		} else { // error
			theError = errors.New(`Invalid Format for the Input Date/Time: "` + dateIsoStr + `" # Using Now()`)
		} //end if else
	} //end if else
	//--
	if(mode == "UTC") {
		currentTime = currentTime.UTC()
	} else if(mode == "LOCAL") {
		// leave as is
	} else {
		if(theError == nil) { // avoid overwrite if previous error registered
			theError = errors.New("Invalid Parsing Mode `" + mode + "` for Date/Time ... Using `LOCAL`")
		} //end if
	} //end if else
	//--
	var crrYear int = currentTime.Year() // type int
	var crrStrYear string = ConvertIntToStr(crrYear)
	//--
	var crrDofY int = currentTime.YearDay()
	//--
	crrDofW := currentTime.Weekday() // type time.Weekday
	var crrDofWInt int = int(crrDofW) // using yota
	var crrDofWName string = crrDofW.String()
	//--
	crrMonth := currentTime.Month() // type time.Month
	crrIntMonth := int(crrMonth)
	var crrStrMonth string = ""
	if(crrIntMonth <= 9) {
		crrStrMonth = "0" + ConvertIntToStr(crrIntMonth)
	} else {
		crrStrMonth = ""  + ConvertIntToStr(crrIntMonth)
	} //end if else
	var crrNameOfMonth string = crrMonth.String()
	//--
	var crrDay int = currentTime.Day()
	var crrStrDay string = ""
	if(crrDay <= 9) {
		crrStrDay = "0" + ConvertIntToStr(crrDay)
	} else {
		crrStrDay = ""  + ConvertIntToStr(crrDay)
	} //end if else
	//--
	var crrHour int = int(currentTime.Hour())
	var crrStrHour string = ""
	if(crrHour <= 9) {
		crrStrHour = "0" + ConvertIntToStr(crrHour)
	} else {
		crrStrHour = ""  + ConvertIntToStr(crrHour)
	} //end if else
	//--
	var crrMinute int = int(currentTime.Minute())
	var crrStrMinute = ""
	if(crrMinute <= 9) {
		crrStrMinute = "0" + ConvertIntToStr(crrMinute)
	} else {
		crrStrMinute = ""  + ConvertIntToStr(crrMinute)
	} //end if else
	//--
	var crrSecond int = int(currentTime.Second())
	var crrStrSecond string = ""
	if(crrSecond <= 9) {
		crrStrSecond = "0" + ConvertIntToStr(crrSecond)
	} else {
		crrStrSecond = ""  + ConvertIntToStr(crrSecond)
	} //end if
	//--
	var crrDTimeFmt string = currentTime.Format(DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH)
	arrDTimeFmt := Explode(" ", crrDTimeFmt)
	var crrStrTzOffs string = StrTrimWhitespaces(arrDTimeFmt[2])
	//--
	var unixTimeStamp64 int64 = int64(currentTime.Unix())
	var nanoSec int = int(currentTime.Nanosecond())
	//--
	var theStatus string = "OK"
	var theErrMsg string = ""
	if(theError != nil) {
		theErrMsg = string(theError.Error())
	} //end if
	if(theErrMsg != "") {
		theStatus = "ERROR"
		theErrMsg = StrReplaceAll(theErrMsg, `"`, "`")
	} //end if
	//--
	uxmDTStruct := uxmDateTimeStruct {
		Status        : theStatus,
		ErrMsg        : theErrMsg,
		Time          : unixTimeStamp64, // int64
		DayOfWeekName : crrDofWName,
		DayOfWeek     : (crrDofWInt + 1), // 1..7 (instead of 0..6)
		DayOfYear     : crrDofY,
		Year          : crrYear,
		Years         : crrStrYear,
		Month         : crrIntMonth,
		Months        : crrStrMonth,
		MonthName     : crrNameOfMonth,
		Day           : crrDay,
		Days          : crrStrDay,
		Hour          : crrHour,
		Hours         : crrStrHour,
		Minute        : crrMinute,
		Minutes       : crrStrMinute,
		Second        : crrSecond,
		Seconds       : crrStrSecond,
		NanoSec       : nanoSec,
		TzOffset      : crrStrTzOffs,
		TzName        : mode,
	}
	//--
	return uxmDTStruct
	//--
} //END FUNCTION


func DateTimeStructUtc(dateIsoStr string) uxmDateTimeStruct {
	//--
	return parseDateTimeAsStruct("UTC", dateIsoStr)
	//--
} //END FUNCTION


func DateTimeStructLocal(dateIsoStr string) uxmDateTimeStruct {
	//--
	return parseDateTimeAsStruct("LOCAL", dateIsoStr)
	//--
} //END FUNCTION


func DateNowIsoUtc() string { // YYYY-MM-DD HH:II:SS
	//--
	return time.Now().UTC().Format(DATE_TIME_FMT_ISO_STD_GO_EPOCH)
	//--
} //END FUNCTION


func DateNowIsoLocal() string { // YYYY-MM-DD HH:II:SS
	//--
	return time.Now().Format(DATE_TIME_FMT_ISO_STD_GO_EPOCH)
	//--
} //END FUNCTION


func DateNowUtc() string { // YYYY-MM-DD HH:II:SS +ZZZZ
	//--
	return time.Now().UTC().Format(DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH)
	//--
} //END FUNCTION


func DateNowLocal() string { // YYYY-MM-DD HH:II:SS +ZZZZ
	//--
	return time.Now().Format(DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH)
	//--
} //END FUNCTION


//-----


func TimeNowUtc() int64 { // unix timestamp UTC
	//--
	return time.Now().UTC().Unix()
	//--
} //END FUNCTION


func TimeNowLocal() int64 { // unix timestamp UTC
	//--
	return time.Now().Unix()
	//--
} //END FUNCTION


//-----


func TimeUnixNanoMathRandHandler() *mrand.Rand {
	//--
	rSource := mrand.NewSource(time.Now().UnixNano())
	rHandle := mrand.New(rSource)
	//--
	return rHandle
	//--
} //END FUNCTION


//-----


// #END
