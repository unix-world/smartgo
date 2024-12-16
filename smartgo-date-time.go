
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20241216.2358 :: STABLE
// [ DATE / TIME ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"

	"time"
	"math"
	mrand "math/rand"
)

const (
	//-- Time Zones
	TIME_ZONE_UTC                     string = "UTC"                            // UTC Time Zone Code
	//-- Time Zone Modes
	TZ_MODE_UTC                       string = TIME_ZONE_UTC                    // Time Zone Mode UTC
	TZ_MODE_LOCAL                     string = "LOCAL"                          // Time Zone Mode LOCAL
	//-- FIXED DATE CONSTANTS REFERENCE VALUES ... SYNCED WITH GO DATE STANDARDS !
	DATE_TIME_DEFAULT_LOCAL_TIMEZONE  string = TIME_ZONE_UTC 					// Default Local Time Zone: UTC
	DATE_TIME_FMT_ISO_NOTIME_GO_EPOCH string = "2006-01-02" 					// GO EPOCH:   NO TIME,   NO TZ OFFSET
	DATE_TIME_FMT_ISO_STD_GO_EPOCH    string = "2006-01-02 15:04:05" 			// GO EPOCH: WITH TIME,   NO TZ OFFSET
	DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH  string = "2006-01-02 15:04:05 -0700" 		// GO EPOCH: WITH TIME, WITH TZ OFFSET
	DATE_TIME_FMT_RFC1123_GO_EPOCH    string = "Mon, 02 Jan 2006 15:04:05" 		// GO EPOCH: RFC1123
	DATE_TIME_FMT_CONDENSED           string = "20060102150405" 				// GO EPOCH: WITH TIME,   NO TZ OFFSET, CONDENSED
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
	Times         string  `json:"times"` 			// "1607230987" as unix epoch (seconds since unix epoch 1970-01-01 00:00:00), 64-bit integer as string !!
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
	MiliSec       int     `json:"miliSec"` 			// Ex: 709
	MiliSecs      string  `json:"miliSecs"` 		// Ex: "709"
	NanoSec       int     `json:"nanoSec"` 			// Ex: 709122707
	NanoSecs      string  `json:"nanoSecs"` 		// Ex: "709122707"
	TzOffset      string  `json:"tzOffset"` 		// "+0000" / "+0300" / ... / "-0700" / ...
	TzName        string  `json:"tzName"` 			// TZ_MODE_UTC | TZ_MODE_LOCAL
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
	//-- if dateIsoStr is empty will use Now()
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
			theError = NewError(`Invalid Format for the Input Date/Time: "` + dateIsoStr + `" # Using Now()`)
		} //end if else
	} //end if else
	//--
	if(mode == TZ_MODE_UTC) {
		currentTime = currentTime.UTC()
	} else if(mode == TZ_MODE_LOCAL) {
		// leave as is: LOCAL
	} else {
		if(theError == nil) { // avoid overwrite if previous error registered
			theError = NewError("Invalid Parsing Mode `" + mode + "` for Date/Time ... Using `" + TZ_MODE_LOCAL + "`")
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
	//--
	var nanoSec int = int(currentTime.Nanosecond())
	var nanoSecs string = ConvertIntToStr(nanoSec)
	//--
	var miliSec int = int(math.Round(float64(nanoSec / 1000 / 1000)))
	var miliSecs string = ConvertIntToStr(miliSec)
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
		Times         : ConvertInt64ToStr(unixTimeStamp64),
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
		MiliSec       : miliSec,
		MiliSecs      : miliSecs,
		NanoSec       : nanoSec,
		NanoSecs      : nanoSecs,
		TzOffset      : crrStrTzOffs,
		TzName        : mode,
	}
	//--
	return uxmDTStruct
	//--
} //END FUNCTION


func DateTimeStructUtc(dateIsoStr string) uxmDateTimeStruct {
	//-- if dateIsoStr is empty will use Now()
	return parseDateTimeAsStruct(TZ_MODE_UTC, dateIsoStr)
	//--
} //END FUNCTION


func DateTimeStructLocal(dateIsoStr string) uxmDateTimeStruct {
	//-- if dateIsoStr is empty will use Now()
	return parseDateTimeAsStruct(TZ_MODE_LOCAL, dateIsoStr)
	//--
} //END FUNCTION


func DateFromStr(dateIsoStr string, withTime bool, withTzOffset bool, isUTC bool) string {
	//-- if dateIsoStr is empty will return empty string
	dateIsoStr = StrTrimWhitespaces(dateIsoStr)
	if(dateIsoStr == "") {
		return ""
	} //end if
	//--
	var dts uxmDateTimeStruct
	if(isUTC) {
		dts = parseDateTimeAsStruct(TZ_MODE_UTC, dateIsoStr)
	} else {
		dts = parseDateTimeAsStruct(TZ_MODE_LOCAL, dateIsoStr)
	} //end if else
	//--
	var dt string = dts.Years + "-" + dts.Months + "-" + dts.Days // YYYY-MM-DD
	if(withTime) {
		dt += " " + dts.Hours + ":" + dts.Minutes + ":" + dts.Seconds // YYYY-MM-DD HH:II:SS
		if(withTzOffset == true) {
			dt += " " + dts.TzOffset // YYYY-MM-DD HH:II:SS +0200
		} //end if
	} else if(withTzOffset == true) {
		return "" // cannot use TZ Offset just with date, needs also time
	} //end if
	//--
	return dt
	//--
} //END FUNCTION


//-----


func DateNowNoTimeUtc() string { // YYYY-MM-DD
	//--
	return time.Now().UTC().Format(DATE_TIME_FMT_ISO_NOTIME_GO_EPOCH)
	//--
} //END FUNCTION


func DateNowNoTimeLocal() string { // YYYY-MM-DD
	//--
	return time.Now().Format(DATE_TIME_FMT_ISO_NOTIME_GO_EPOCH)
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


func DateNoTimeFromUnixTimeUtc(timestamp int64) string { // YYYY-MM-DD
	//--
	t := time.Unix(timestamp, 0)
	//--
	return t.UTC().Format(DATE_TIME_FMT_ISO_NOTIME_GO_EPOCH)
	//--
} //END FUNCTION


func DateNoTimeFromUnixTimeLocal(timestamp int64) string { // YYYY-MM-DD
	//--
	t := time.Unix(timestamp, 0)
	//--
	return t.Format(DATE_TIME_FMT_ISO_NOTIME_GO_EPOCH)
	//--
} //END FUNCTION


func DateIsoFromUnixTimeUtc(timestamp int64) string { // YYYY-MM-DD HH:II:SS
	//--
	t := time.Unix(timestamp, 0)
	//--
	return t.UTC().Format(DATE_TIME_FMT_ISO_STD_GO_EPOCH)
	//--
} //END FUNCTION


func DateIsoFromUnixTimeLocal(timestamp int64) string { // YYYY-MM-DD HH:II:SS
	//--
	t := time.Unix(timestamp, 0)
	//--
	return t.Format(DATE_TIME_FMT_ISO_STD_GO_EPOCH)
	//--
} //END FUNCTION


func DateFromUnixTimeUtc(timestamp int64) string { // YYYY-MM-DD HH:II:SS +ZZZZ
	//--
	t := time.Unix(timestamp, 0)
	//--
	return t.UTC().Format(DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH)
	//--
} //END FUNCTION


func DateFromUnixTimeLocal(timestamp int64) string { // YYYY-MM-DD HH:II:SS +ZZZZ
	//--
	t := time.Unix(timestamp, 0)
	//--
	return t.Format(DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH)
	//--
} //END FUNCTION


//-----


func DateNoTimeFromTime(t time.Time) string { // YYYY-MM-DD
	//--
	return t.Format(DATE_TIME_FMT_ISO_NOTIME_GO_EPOCH)
	//--
} //END FUNCTION


func DateIsoFromTime(t time.Time) string { // YYYY-MM-DD HH:II:SS
	//--
	return t.Format(DATE_TIME_FMT_ISO_STD_GO_EPOCH)
	//--
} //END FUNCTION


func DateFromTime(t time.Time) string { // YYYY-MM-DD HH:II:SS +ZZZZ
	//--
	return t.Format(DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH)
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


func NanoTimeRandIntN(min int, max int) uint {
	//--
	if(min < 0) {
		min = 0 // avoid panic, if negative
	} //end if
	if(max < 0) {
		max = math.MaxInt32 // avoid panic, if negative use max
	} //end if
	if(max < math.MaxInt32) { // avoid overflow
		max = max + 1 // correction
	} //end if
	if(min == max) {
		return uint(min)
	} //end if
	if(min > max) {
		return uint(max)
	} //end if
	//--
	rnd := TimeUnixNanoMathRandHandler()
	//--
	return uint(rnd.Intn(max-min) + min)
	//--
} //END FUNCTION


func NanoTimeRandInt63N(min int64, max int64) uint64 {
	//--
	if(min < 0) {
		min = 0 // avoid panic, if negative
	} //end if
	if(max < 0) {
		max = math.MaxInt64 // avoid panic, if negative use max
	} //end if
	if(max < math.MaxInt64) { // avoid overflow
		max = max + 1 // correction
	} //end if
	if(min == max) {
		return uint64(min)
	} //end if
	if(min > max) {
		return uint64(max)
	} //end if
	//--
	rnd := TimeUnixNanoMathRandHandler()
	//--
	return uint64(rnd.Int63n(max-min) + min)
	//--
} //END FUNCTION


//-----


// #END
