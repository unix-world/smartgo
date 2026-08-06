
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260806.2358 :: STABLE
// [ FS (FILESYSTEM) ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"

	"os"
	"path/filepath"
	"embed"

	"io"

	"strings"
	"encoding/hex"

	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/unix-world/smartgo/crypto/sha3" // {{{SYNC-SMARTGO-SHA3}}} ; this is a better version than golang.org/x/crypto/sha3, works without amd64 ASM - non hardware optimized on amd64 version ; from cloudflare: github.com/cloudflare/circl/internal/sha3
)

const (
	CHMOD_DIRS  os.FileMode = 0755
	CHMOD_FILES os.FileMode = 0644

	//-- Cross Platform Safe Paths ; The following are disallowed in Windows paths: `< > : " / \ | ? *` ; also disallow `=` (lock file reserved) and SPACE because of the web context
	REGEX_NEGATIVE_SAFE_PATH_NAME string 	= `[^_a-zA-Z0-9\-\.@#\/`+"`"+`~\!\$%&\(\)\^\{\}'`+`\[\],;\+`+`]+` 	// SAFETY: MATCH ALL CHARACTERS NOT IN THE BELOW SET, USED FOR CLEANUP
	//--
	REGEX_SAFE_PATH_NAME string 			= `^[_a-zA-Z0-9\-\.@#\/`+"`"+`~\!\$%&\(\)\^\{\}'`+`\[\],;\+`+`]+$` 	// SAFETY: SAFE Cross Platform Character Set for FileSystems: Smart + MsDOS + Linux/Unix + Windows (intersect)
	REGEX_SAFE_FILE_NAME string 			= `^[_a-zA-Z0-9\-\.@#`+"`"+`~\!\$%&\(\)\^\{\}'`+`\[\],;\+`+`]+$` 	// SAFETY: SAFE Cross Platform Character Set for FileSystems: Smart + MsDOS + Linux/Unix + Windows (intersect) ; like above, just missing slash /
	//-- allow just: "_ a-z A-Z 0-9 - . @ # ` ~ ! $ % & ( ) ^ { } ' [ ] , ; +" ; for dir paths also allow "/"

	//-- Web Ultra-Safe Paths (Smart)
	REGEX_NEGATIVE_SMART_SAFE_PATH string 	= `[^_a-zA-Z0-9\-\.@#\/]+` 			// SAFETY: MATCH ALL CHARACTERS NOT IN THE BELOW SET, USED FOR CLEANUP
	//--
	REGEX_SMART_SAFE_PATH_NAME string 		= `^[_a-zA-Z0-9\-\.@#\/]+$` 		// SAFETY: SUPPORT ONLY THESE CHARACTERS IN FILE SYSTEM PATHS ...
	REGEX_SMART_SAFE_FILE_NAME string 		= `^[_a-zA-Z0-9\-\.@#]+$` 			// SAFETY: SUPPORT ONLY THESE CHARACTERS IN FILE SYSTEM FILE AND DIR NAMES ... ; like above, just missing slash /
	//-- allow just: "_ a-z A-Z 0-9 - . @ #" ; for dir paths also allow "/"

	MAX_PATH_LENGTH int     = 1024 // path can be up to 4096 characters, safe is 1024 to be cross platform
	MAX_FILENAME_LENGTH int =  255 // file can be up to  512 characters, safe is  255 to be cross platform

	FILE_WRITE_MODE_DEFAULT string = "w" // write
	FILE_WRITE_MODE_APPEND  string = "a" // append

	INVALID_ABSOLUTE_PATH string = "/tmp/go-invalid-path/err-absolute-path/"
	INVALID_HOMEDIR_PATH  string = "/tmp/go-invalid-path/err-user-home-dir/"
)


// IMPORTANT:
// 		filepath.Clean() 		DO NOT USE ; USE INSTEAD: SafePathFixClean() ; is OS Aware ; ex: will remove `./` as prefix or `/` as suffix from paths ; will convert `` (empty path) into `.`
// 		filepath.ToSlash() 		DO NOT USE ; USE INSTEAD: SafePathFixSeparator() ; only works on Windows (OS Aware) ; just on Windows will convert all non-slash separators into slash


//-----


func PathDirName(filePath string) string { // returns: `a/path/to` from `a/path/to/lastDirInPath|file.extension` | `/a/path/to` from `/a/path/to/lastDirInPath|file.extension`
	//--
	if(filePath == "") {
		return ""
	} //end if
	//--
	filePath = SafePathFixClean(filePath)
	//--
	return SafePathFixSeparator(filepath.Dir(filePath))
	//--
} //END FUNCTION


func PathBaseName(filePath string) string { // returns: `file.extension` | `lastDirInPath` from `(/)a/path/to/lastDirInPath|file.extension`
	//--
	if(filePath == "") {
		return ""
	} //end if
	//--
	filePath = SafePathFixClean(filePath)
	//--
	return SafePathFixSeparator(filepath.Base(filePath))
	//--
} //END FUNCTION


func PathBaseNoExtName(filePath string) string { // returns: `file` (without extension) | `lastDirInPath` from `(/)a/path/to/lastDirInPath|file.extension`
	//--
	if(filePath == "") {
		return ""
	} //end if
	//--
	filePath = SafePathFixClean(filePath)
	//--
	var fWithExt string = PathBaseName(filePath)
	var fExt string = PathBaseExtension(fWithExt)
	//--
	return strings.TrimSuffix(fWithExt, fExt)
	//--
} //END FUNCTION


func PathBaseExtension(filePath string) string { // returns: file `.extension` (includding dot) from `(/)a/path/to/lastDirInPath|file.extension`
	//--
	if(filePath == "") {
		return ""
	} //end if
	//--
	filePath = SafePathFixClean(filePath)
	//--
	return SafePathFixSeparator(filepath.Ext(filePath))
	//--
} //END FUNCTION


func PathIsSafeValidFileName(fileName string) bool {
	//--
	if(StrTrimWhitespaces(fileName) == "") {
		return false
	} //end if
	//--
	if(len(fileName) > MAX_FILENAME_LENGTH) {
		return false
	} //end if
	//--
	if(StrRegexMatch(REGEX_SAFE_FILE_NAME, fileName) != true) {
		return false
	} //end if
	//--
	if(StrContains(fileName, "/")) {
		return false
	} //end if
	//--
	if(IsPathAlikeWithSafeFixedPath(fileName, false) != true) { // no need to fix trailing slashes, regex above does not allow them, it should be a filename not a dir path
		return false
	} //end if
	//--
	fileName = StrTrimWhitespaces(fileName)
	fileName = StrReplaceAll(fileName, ".", "")
	if(fileName == "") {
		return false // must not be composed only of dots, especially: . or ..
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func PathIsSafeValidSafeFileName(fileName string) bool {
	//--
	if(PathIsSafeValidFileName(fileName)) {
		if(StrRegexMatch(REGEX_SMART_SAFE_FILE_NAME, fileName)) {
			return true
		} //end if
	} //end if
	//--
	return false
	//--
} //END FUNCTION


func PathIsSafeValidSafePath(filePath string) bool {
	//--
	if(PathIsSafeValidPath(filePath)) {
		if(StrRegexMatch(REGEX_SMART_SAFE_PATH_NAME, filePath)) {
			return true
		} //end if
	} //end if
	//--
	return false
	//--
} //END FUNCTION


func PathIsSafeValidPath(filePath string) bool {
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return false
	} //end if
	//--
	if(len(filePath) > MAX_PATH_LENGTH) {
		return false
	} //end if
	//--
	if(StrRegexMatch(REGEX_SAFE_PATH_NAME, filePath) != true) {
		return false
	} //end if
	//--
	if(filePath == "./") { // {{{SYNC-SMARTGO-SAMEDIR-MIN-PATH}}}
		return true
	} //end if
	//--
	if(IsPathAlikeWithSafeFixedPath(filePath, true) != true) { // allow just unix style paths ; need to fix trailing slashes, it can be a dir
		return false
	} //end if
	//--
	filePath = SafePathFixSeparator(filePath) // req. for below
	filePath = StrTrimWhitespaces(filePath)
	filePath = StrReplaceAll(filePath, ".", "")
	filePath = StrReplaceAll(filePath, "/", "")
	if(filePath == "") {
		return false // must not be composed only of dots, especially: . or .. ; and/or: /
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func PathIsEmptyOrRoot(filePath string) bool { // dissalow a path under 3 characters
	//--
	if(filePath == "./") { // {{{SYNC-SMARTGO-SAMEDIR-MIN-PATH}}}
		return false
	} //end if
	//--
	filePath = StrReplaceAll(filePath, "/", "")  // test for linux/unix file system
	filePath = StrReplaceAll(filePath, "\\", "") // test for network shares or windows style path separator
	filePath = StrReplaceAll(filePath, ":", "")  // test for windows file system
	//--
	filePath = StrTrimWhitespaces(filePath)
	//--
	if((filePath == "") || (filePath == ".") || (filePath == "..")) {
		return true
	} //end if
	//--
	// do not test for length > 1 because can be a simple file or dir name like `a`
	//--
	return false
	//--
} //END FUNCTION


func PathIsAbsolute(filePath string) bool {
	//--
	filePath = StrTrimWhitespaces(filePath)
	//--
	//filePath = SafePathFixClean(filePath) // this fails on windows ; actually path does not need to be fixed, just test first part
	//--
	if(
		(StrSubstr(filePath, 0, 1) == "/") || // unix / linux
		(StrSubstr(filePath, 0, 1) == ":") || // windows
		(StrSubstr(filePath, 1, 2) == ":")) { // windows
		return true
	} //end if
	//--
	return false
	//--
} //END FUNCTION


func PathIsBackwardUnsafe(filePath string) bool {
	//--
	filePath = StrTrimWhitespaces(filePath)
	//--
	filePath = SafePathFixSeparator(filePath) // DO NOT USE Clean, path here must be un-cleaned to correct detect backward sequences, only need to normalize slashes ...
	//--
	if(
		(len(filePath) > MAX_PATH_LENGTH) || // check max path length !
		StrContains(filePath, "\\") ||
		StrContains(filePath, "/../") ||
		StrContains(filePath, "/./")  ||
		StrContains(filePath, "/..")  || // also covers a path that must not end with /..
		StrContains(filePath, "../")  ||
		StrEndsWith(filePath, "/.")   || // must not end with /.
		(filePath == ".") || (filePath == "..")) { // must not be one or two dots
		return true
	} //end if
	//--
	return false
	//--
} //END FUNCTION


func PathIsDir(thePath string) bool {
	//--
	if(StrTrimWhitespaces(thePath) == "") {
		return false
	} //end if
	//--
	thePath = SafePathFixClean(thePath)
	//--
	fd, err := os.Stat(thePath)
	if(err != nil) {
		if(os.IsNotExist(err)) {
			return false
		} //end if
	} //end if
	//--
	fm := fd.Mode()
	//--
	return fm.IsDir()
	//--
} //END FUNCTION


func PathIsFile(thePath string) bool {
	//--
	if(StrTrimWhitespaces(thePath) == "") {
		return false
	} //end if
	//--
	thePath = SafePathFixClean(thePath)
	//--
	fd, err := os.Stat(thePath)
	if(err != nil) {
		if(os.IsNotExist(err)) {
			return false
		} //end if
	} //end if
	//--
	fm := fd.Mode()
	//--
	return ! fm.IsDir()
	//--
} //END FUNCTION


func PathExists(thePath string) bool {
	//--
	if(StrTrimWhitespaces(thePath) == "") {
		return false
	} //end if
	//--
	thePath = SafePathFixClean(thePath)
	//--
	_, err := os.Stat(thePath)
	if(err != nil) {
		if(os.IsNotExist(err)) {
			return false
		} //end if
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func PathGetAbsoluteFromRelative(thePath string) string {
	//--
	absPath, err := filepath.Abs("./")
	if(err != nil) {
		return INVALID_ABSOLUTE_PATH
	} //end if
	//--
	if(StrContains(absPath, ":")) {
		arr := ExplodeWithLimit(":", absPath, 2)
		if(len(arr) != 2) {
			return INVALID_ABSOLUTE_PATH
		} //end if
		absPath = arr[1]
	} //end if
	//--
	absPath = StrTrimWhitespaces(absPath)
	if(absPath == "") {
		return INVALID_ABSOLUTE_PATH
	} //end if
	//--
	absPath = SafePathFixClean(absPath)
	//--
	if((StrTrimWhitespaces(absPath) == "") || (absPath == "/") || (absPath == ":") || (absPath == ".") || (absPath == "..")) {
		return INVALID_ABSOLUTE_PATH
	} //end if
	//--
	absPath = PathAddDirLastSlash(PathAddDirLastSlash(absPath) + SafePathFixClean(StrTrimLeft(thePath, "./")))
	if((StrTrimWhitespaces(absPath) == "") || (absPath == "/") || (absPath == ":") || (absPath == ".") || (absPath == "..")) {
		return INVALID_ABSOLUTE_PATH
	} //end if
	//--
	if(PathIsSafeValidPath(absPath) != true) {
		return INVALID_ABSOLUTE_PATH
	} //end if
	//--
	return absPath
	//--
} //END FUNCTION


func PathGetCurrentExecutableName() string {
	//--
	defer PanicHandler()
	//--
	currentExecutableAbsolutePath, err := os.Executable()
	if(err != nil) {
		return ""
	} //end if
	if(currentExecutableAbsolutePath == "") {
		return ""
	} //end if
	//--
	return PathBaseName(currentExecutableAbsolutePath)
	//--
} //END FUNCTION


func PathGetCurrentExecutableDir() string {
	//--
	defer PanicHandler()
	//--
	currentExecutableAbsolutePath, err := os.Executable()
	if(err != nil) {
		return ""
	} //end if
	if(currentExecutableAbsolutePath == "") {
		return ""
	} //end if
	//--
	return PathDirName(currentExecutableAbsolutePath)
	//--
} //END FUNCTION


func PathGetCurrentExecutablePathAndName() string {
	//--
	return PathAddDirLastSlash(PathGetCurrentExecutableDir()) + PathGetCurrentExecutableName()
	//--
} //END FUNCTION


//-----


func PathAddDirLastSlash(dirPath string) string {
	//--
	dirPath = StrTrimWhitespaces(dirPath)
	if(dirPath == "") { // must be detected before filepath Clean, which transforms empty path in `.`
		return "./"
	} //end if
	//--
	dirPath = SafePathFixClean(dirPath)
	//--
	if((dirPath == "") || (dirPath == ".") || (dirPath == "..") || (dirPath == "/")) {
		return "./"
	} //end if
	//--
	dirPath = StrTrimRightWhitespaces(StrTrimRight(dirPath, " /"))
	if((dirPath == "") || (dirPath == ".") || (dirPath == "..") || (dirPath == "/")) {
		return "./"
	} //end if
	//--
	return dirPath + "/"
	//--
} //END FUNCTION


//-----


// this is a safer replacement for filepath.ToSlash(p), because is not OS Context Aware
func SafePathFixSeparator(p string) string {
	//--
	if(StrTrimWhitespaces(p) == "") {
		return p
	} //end if
	//-- do not apply path Clean !
	return StrReplaceAll(p, "\\", "/")
	//--
} //END FUNCTION


func SafePathFixClean(p string) string {
	//--
	if(StrTrimWhitespaces(p) == "") {
		return p
	} //end if
	//--
	p = filepath.Clean(p) // this is OS dependent, on Windows will replace / slash with backslashes in paths, so fix below !
	p = SafePathFixSeparator(p) // this is mandatory after clean above because clean is OS Aware and on Windows will transform / slash with backslash for paths !
	//--
	return p
	//--
} //END FUNCTION


func SafePathCleanInvalidChars(path string, isFilePath bool, allowPathSlash bool, allowAbsolute bool, smartSafe bool) string {
	//--
	// isFilePath must be set to TRUE if path is a file path, must not end with a slash
	// allowPathSlash must be set to FALSE for file names ; for paths must be set to TRUE
	//--
	defer PanicHandler()
	//--
	path = StrTrimWhitespaces(path)
	if(path == "") {
		return ""
	} //end if
	//--
	var doesPathEndsWithSlash bool = false
	if(StrEndsWith(path, "/") == true) {
		doesPathEndsWithSlash = true
	} //end if
	path = StrTrimWhitespaces(SafePathFixClean(path))
	if(path == "") {
		return ""
	} //end if
	if(doesPathEndsWithSlash == true) { // if any trailing slash it was removed by SafePathFixClean ; restore it
		path = PathAddDirLastSlash(path)
	} //end if
	//--
	var rx string = REGEX_NEGATIVE_SAFE_PATH_NAME
	if(smartSafe == true) {
		rx = REGEX_NEGATIVE_SMART_SAFE_PATH
	} //end if
	//--
	path = StrTrimWhitespaces(StrRegexReplaceAll(rx, path, ""))
	if(path == "") {
		return ""
	} //end if
	//--
	if(allowAbsolute != true) {
		path = StrTrimLeftWhitespaces(StrTrimLeft(path, "/"))
	} //end if
	if(isFilePath == true) {
		path = StrTrimRightWhitespaces(StrTrimRight(path, "/"))
	} //end if
	path = StrReplaceAll(path, "..", ".")
	//--
	if(smartSafe == true) {
		if(PathIsSafeValidSafePath(path) != true) {
			return ""
		} //end if
	} else {
		if(PathIsSafeValidPath(path) != true) {
			return ""
		} //end if
	} //end if else
	//--
	if(allowPathSlash != true) {
		//--
		path = StrReplaceAll(path, "/", "")
		//--
		if(smartSafe == true) {
			if(PathIsSafeValidSafeFileName(path) != true) {
				return ""
			} //end if
		} else {
			if(PathIsSafeValidFileName(path) != true) {
				return ""
			} //end if
		} //end if else
		//--
	} //end if
	//--
	if(PathIsBackwardUnsafe(path) == true) {
		return ""
	} //end if
	//--
	if(allowAbsolute != true) {
		if(PathIsAbsolute(path) == true) {
			return ""
		} //end if
	} //end if
	//--
	if((path == ".") || (path == "..") || (path == "/")) {
		return ""
	} //end if
	//--
	return path
	//--
} //END FUNCTION


func IsPathAlikeWithSafeFixedPath(path string, fixTrailingSlashes bool) bool {
	//--
	comparePath := StrTrimWhitespaces(path)
	//--
	if(fixTrailingSlashes) { // this is only for paths that can be dirs, which end with a trailing slash ; ex: `/path/to/` to become `/path/to` for comparation
		comparePath = StrTrimRight(comparePath, "/") // trim trailing slashes for comparing with CleanPath+Fix
	} //end if
	//--
	if(StrStartsWith(path, "./")) { //  this is for both: file names and dir paths
		if(len(comparePath) > 2) {
			comparePath = StrSubstr(comparePath, 2, -1)  // trim suffix ./ only if starts with ./, otherwise don't apply may trim / on an absolute path
		} //end if
	} //end if
	//--
	if(SafePathFixClean(path) != comparePath) { // when apply Fix Path, ex: `./test/` will become `test`
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


//-----


func SafePathDirCreate(dirPath string, allowRecursive bool, allowAbsolutePath bool) (isSuccess bool, errMsg error) {
	//--
	defer PanicHandler()
	//--
	if(StrTrimWhitespaces(dirPath) == "") {
		return false, NewError("WARNING: Dir Path is Empty")
	} //end if
	//--
	dirPath = SafePathFixClean(dirPath)
	//--
	if(PathIsEmptyOrRoot(dirPath) == true) {
		return false, NewError("WARNING: Dir Path is Empty/Root")
	} //end if
	//--
	if(PathIsSafeValidPath(dirPath) != true) {
		return false, NewError("WARNING: Dir Path is Invalid Unsafe")
	} //end if
	//--
	if(PathIsBackwardUnsafe(dirPath) == true) {
		return false, NewError("WARNING: Dir Path is Backward Unsafe")
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(dirPath) == true) {
			return false, NewError("NOTICE: Dir Path is Absolute but not allowed to be absolute by the calling parameters")
		} //end if
	} //end if
	//--
	if(PathExists(dirPath)) {
		//--
		if(PathIsFile(dirPath)) {
			return false, NewError("WARNING: Dir Path is a File not a Directory")
		} //end if
		if(!PathIsDir(dirPath)) {
			return false, NewError("WARNING: Dir Path is Not a Directory")
		} //end if
		//--
	} else {
		//--
		var err error = nil
		if(allowRecursive == true) {
			err = os.MkdirAll(dirPath, CHMOD_DIRS)
		} else {
			err = os.Mkdir(dirPath, CHMOD_DIRS)
		} //end if else
		if(err != nil) {
			return false, err
		} //end if
		//--
	} //end if
	//--
	return true, nil
	//--
} //END FUNCTION


func SafePathDirDelete(dirPath string, allowAbsolutePath bool) (isSuccess bool, errMsg error) { // will delete the dir with all it's (recursive) content
	//--
	defer PanicHandler()
	//--
	if(StrTrimWhitespaces(dirPath) == "") {
		return false, NewError("WARNING: Dir Path is Empty")
	} //end if
	//--
	dirPath = SafePathFixClean(dirPath)
	//--
	if(PathIsEmptyOrRoot(dirPath) == true) {
		return false, NewError("WARNING: Dir Path is Empty/Root")
	} //end if
	//--
	if(PathIsSafeValidPath(dirPath) != true) {
		return false, NewError("WARNING: Dir Path is Invalid Unsafe")
	} //end if
	//--
	if(PathIsBackwardUnsafe(dirPath) == true) {
		return false, NewError("WARNING: Dir Path is Backward Unsafe")
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(dirPath) == true) {
			return false, NewError("NOTICE: Dir Path is Absolute but not allowed to be absolute by the calling parameters")
		} //end if
	} //end if
	//--
	if(PathExists(dirPath)) {
		//--
		if(PathIsFile(dirPath)) {
			return false, NewError("WARNING: Dir Path is a File not a Directory")
		} //end if
		if(!PathIsDir(dirPath)) {
			return false, NewError("WARNING: Dir Path is Not a Directory")
		} //end if
		//--
		err := os.RemoveAll(dirPath)
		if(err != nil) {
			return false, err
		} //end if
		//--
	} //end if
	//--
	return true, nil
	//--
} //END FUNCTION


func SafePathDirRename(dirPath string, dirNewPath string, allowAbsolutePath bool) (isSuccess bool, errMsg error) {
	//--
	defer PanicHandler()
	//--
	if(StrTrimWhitespaces(dirPath) == "") {
		return false, NewError("WARNING: Dir Path is Empty")
	} //end if
	if(StrTrimWhitespaces(dirNewPath) == "") {
		return false, NewError("WARNING: New Dir Path is Empty")
	} //end if
	//--
	dirPath = SafePathFixClean(dirPath)
	//--
	if(PathIsEmptyOrRoot(dirPath) == true) {
		return false, NewError("WARNING: Dir Path is Empty/Root")
	} //end if
	//--
	if(PathIsSafeValidPath(dirPath) != true) {
		return false, NewError("WARNING: Dir Path is Invalid Unsafe")
	} //end if
	//--
	if(PathIsBackwardUnsafe(dirPath) == true) {
		return false, NewError("WARNING: Dir Path is Backward Unsafe")
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(dirPath) == true) {
			return false, NewError("NOTICE: Dir Path is Absolute but not allowed to be absolute by the calling parameters")
		} //end if
	} //end if
	//--
	dirNewPath = SafePathFixClean(dirNewPath)
	//--
	if(PathIsEmptyOrRoot(dirNewPath) == true) {
		return false, NewError("WARNING: New Dir Path is Empty/Root")
	} //end if
	//--
	if(PathIsSafeValidPath(dirNewPath) != true) {
		return false, NewError("WARNING: New Dir Path is Invalid Unsafe")
	} //end if
	//--
	if(PathIsBackwardUnsafe(dirNewPath) == true) {
		return false, NewError("WARNING: New Dir Path is Backward Unsafe")
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(dirNewPath) == true) {
			return false, NewError("NOTICE: New Dir Path is Absolute but not allowed to be absolute by the calling parameters")
		} //end if
	} //end if
	//--
	if(dirPath == dirNewPath) {
		return false, NewError("WARNING: New Dir Path is the same as the Original Dir Path")
	} //end if
	//--
	if(!PathExists(dirPath)) {
		return false, NewError("WARNING: Dir Path does not exist")
	} //end if
	if(!PathIsDir(dirPath)) {
		return false, NewError("WARNING: Dir Path is Not a Dir")
	} //end if
	//--
	if(PathIsFile(dirPath)) {
		return false, NewError("WARNING: Dir Path is a File not a Directory")
	} //end if
	if(PathIsFile(dirNewPath)) {
		return false, NewError("WARNING: New Dir Path is a File not a Directory")
	} //end if
	//--
	if(PathExists(dirNewPath)) {
		return false, NewError("WARNING: New Dir Path already exist")
	} //end if
	//--
	err := os.Rename(dirPath, dirNewPath)
	if(err != nil) {
		return false, err
	} //end if
	//--
	return true, nil
	//--
} //END FUNCTION


func SafePathDirScan(dirPath string, recursive bool, allowAbsolutePath bool) (isSuccess bool, errMsg error, arrDirs []string, arrFiles []string) {
	//--
	defer PanicHandler()
	//--
	var dirs  []string
	var files []string
	//--
	if(StrTrimWhitespaces(dirPath) == "") {
		return false, NewError("WARNING: Dir Path is Empty"), dirs, files
	} //end if
	//--
	dirPath = SafePathFixClean(dirPath)
	//--
	if(PathIsEmptyOrRoot(dirPath) == true) {
		return false, NewError("WARNING: Dir Path is Empty/Root"), dirs, files
	} //end if
	//--
	dirPath = PathAddDirLastSlash(dirPath)
	//--
	if(PathIsSafeValidPath(dirPath) != true) {
		return false, NewError("WARNING: Dir Path is Invalid Unsafe"), dirs, files
	} //end if
	//--
	if(PathIsBackwardUnsafe(dirPath) == true) {
		return false, NewError("WARNING: Dir Path is Backward Unsafe"), dirs, files
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(dirPath) == true) {
			return false, NewError("NOTICE: Dir Path is Absolute but not allowed to be absolute by the calling parameters"), dirs, files
		} //end if
	} //end if
	//--
	if(!PathExists(dirPath)) {
		return false, NewError("WARNING: Path does not exists"), dirs, files
	} //end if
	if(PathIsFile(dirPath)) {
		return false, NewError("WARNING: Dir Path is a File not a Directory"), dirs, files
	} //end if
	if(!PathIsDir(dirPath)) {
		return false, NewError("WARNING: Dir Path is Not a Directory"), dirs, files
	} //end if
	//--
	if(recursive) {
		//--
		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			path = SafePathFixSeparator(path)
			if((StrTrimWhitespaces(path) != "") && (StrTrim(path, "/ ") != "") && (path != ".") && (path != "..") && (path != "/") && (StrTrimRight(path, "/") != StrTrimRight(dirPath, "/"))) {
				if(PathIsDir(path)) {
					dirs = append(dirs, path)
				} else {
					files = append(files, path)
				} //end if else
			} //end if
			return nil
		})
		if(err != nil) {
			return false, err, dirs, files
		} //end if
		//--
	} else {
		//--
		dir, derr := os.Open(dirPath)
		if(derr != nil) {
			return false, derr, dirs, files
		} //end if
		defer dir.Close()
		paths, err := dir.Readdir(0)
		if(err != nil) {
			return false, err, dirs, files
		} //end if
		for _, p := range paths {
			if((StrTrimWhitespaces(p.Name()) != "") && (StrTrim(p.Name(), "/ ") != "") && (p.Name() != ".") && (p.Name() != "..") && (p.Name() != "/")) {
				path   := dirPath + p.Name()
				isDir  := p.IsDir()
				if(isDir) {
					dirs = append(dirs, path)
				} else {
					files = append(files, path)
				} //end if else
			} //end if
		} //end for
		//--
	} //end if else
	//--
	return true, nil, dirs, files
	//--
} //END FUNCTION


// ex call (req. go ambed fs assets): SafePathEmbedDirScan(&assets, "assets/", true)
func SafePathEmbedDirScan(efs *embed.FS, dirPath string, recursive bool) (isSuccess bool, err error, arrDirs []string, arrFiles []string) {
	//--
	defer PanicHandler()
	//--
	if(dirPath == "") {
		return false, nil, nil, nil
	} //end if
	dirPath = StrTrimWhitespaces(dirPath)
	dirPath = SafePathFixClean(dirPath) // embed paths are supposed to use unix type separators only
	dirPath = StrTrimRight(dirPath, "/")
	dirPath = StrTrimWhitespaces(dirPath)
	if(dirPath == "") {
		return false, nil, nil, nil
	} //end if
	//--
	entries, err := efs.ReadDir(dirPath)
	if(err != nil) {
		return false, err, nil, nil
	} //end if
	//--
	for _, entry := range entries {
	//	fp := path.Join(dirPath, entry.Name()) // works better on windows but is unsafe
		fp := filepath.Join(dirPath, SafePathFixSeparator(entry.Name()))
		if(entry.IsDir()) {
			arrDirs = append(arrDirs, fp)
			if(recursive) {
				rIsSuccess, rErr, rArrDirs, rArrFiles := SafePathEmbedDirScan(efs, fp, recursive)
				if(!rIsSuccess || rErr != nil) {
					return false, rErr, nil, nil
				} //end if
				arrDirs  = append(arrDirs,  rArrDirs...)
				arrFiles = append(arrFiles, rArrFiles...)
				continue
			} //end if
		} else {
			arrFiles = append(arrFiles, fp)
		} //end if else
	} //end for
	//--
	return true, nil, arrDirs, arrFiles
	//--
} //END FUNCTION


//-----


func SafePathFileCrc(mode string, filePath string, allowAbsolutePath bool) (hashSum string, errMsg error) {
	//--
	defer PanicHandler()
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return "", NewError("WARNING: File Path is Empty")
	} //end if
	//--
	filePath = SafePathFixClean(filePath)
	//--
	if(PathIsEmptyOrRoot(filePath) == true) {
		return "", NewError("WARNING: File Path is Empty/Root")
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return "", NewError("WARNING: File Path is Invalid Unsafe")
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return "", NewError("WARNING: File Path is Backward Unsafe")
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return "", NewError("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters")
		} //end if
	} //end if
	//--
	if(PathIsDir(filePath)) {
		return "", NewError("WARNING: File Path is a Directory not a File")
	} //end if
	//--
	var isSupported bool = false
	if(mode == "crc64e") {
		isSupported = true
	} else if(mode == "crc32b") {
		isSupported = true
	} else if(mode == "adler32") {
		isSupported = true
	} //end if else
	if(isSupported != true) {
		return "", NewError("WARNING: Invalid Mode: `" + mode + "`")
	} //end if
	//--
	f, errO := os.Open(filePath)
	if(errO != nil) {
		return "", NewError("ERROR: Failed to Open File: " + errO.Error())
	} //end if
	defer f.Close()
	//--
	if(mode == "crc64e") {
		//--
		h := crc64.New(crc64TableECMA)
		//--
		if _, errC := io.Copy(h, f); errC != nil {
			return "", NewError("ERROR: Failed to Read File: " + errC.Error())
		} //end if
		//--
		hexCrc := StrToLower(hex.EncodeToString(h.Sum(nil)))
		//--
		return hexCrc, nil
		//--
	} else if(mode == "crc32b") {
		//--
		h := crc32.NewIEEE()
		//--
		if _, errC := io.Copy(h, f); errC != nil {
			return "", NewError("ERROR: Failed to Read File: " + errC.Error())
		} //end if
		//--
		hexCrc := StrToLower(hex.EncodeToString(h.Sum(nil)))
		//--
		return hexCrc, nil
		//--
	} else if(mode == "adler32") {
		//--
		h := adler32.New()
		//--
		if _, errC := io.Copy(h, f); errC != nil {
			return "", NewError("ERROR: Failed to Read File: " + errC.Error())
		} //end if
		//--
		hexCrc := StrToLower(hex.EncodeToString(h.Sum(nil)))
		//--
		return hexCrc, nil
		//--
	} //end if else
	//--
	return "", NewError("ERROR: Invalid Mode: `" + mode + "`")
	//--
} //END FUNCTION


func SafePathFileMd5(filePath string, allowAbsolutePath bool) (hashSum string, errMsg error) {
	//--
	defer PanicHandler()
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return "", NewError("WARNING: File Path is Empty")
	} //end if
	//--
	filePath = SafePathFixClean(filePath)
	//--
	if(PathIsEmptyOrRoot(filePath) == true) {
		return "", NewError("WARNING: File Path is Empty/Root")
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return "", NewError("WARNING: File Path is Invalid Unsafe")
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return "", NewError("WARNING: File Path is Backward Unsafe")
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return "", NewError("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters")
		} //end if
	} //end if
	//--
	if(PathIsDir(filePath)) {
		return "", NewError("WARNING: File Path is a Directory not a File")
	} //end if
	//--
	f, errO := os.Open(filePath)
	if(errO != nil) {
		return "", NewError("ERROR: Failed to Open File: " + errO.Error())
	} //end if
	defer f.Close()
	h := md5.New()
	if _, errC := io.Copy(h, f); errC != nil {
		return "", NewError("ERROR: Failed to Read File: " + errC.Error())
	} //end if
	//--
	hexMd5 := StrToLower(hex.EncodeToString(h.Sum(nil)))
	//--
	return hexMd5, nil
	//--
} //END FUNCTION


func SafePathFileSha(mode string, filePath string, allowAbsolutePath bool) (hashSum string, errMsg error) {
	//--
	defer PanicHandler()
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return "", NewError("WARNING: File Path is Empty")
	} //end if
	//--
	filePath = SafePathFixClean(filePath)
	//--
	if(PathIsEmptyOrRoot(filePath) == true) {
		return "", NewError("WARNING: File Path is Empty/Root")
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return "", NewError("WARNING: File Path is Invalid Unsafe")
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return "", NewError("WARNING: File Path is Backward Unsafe")
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return "", NewError("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters")
		} //end if
	} //end if
	//--
	if(PathIsDir(filePath)) {
		return "", NewError("WARNING: File Path is a Directory not a File")
	} //end if
	//--
	var h hash.Hash = nil
	if(mode == "sha3-512") {
		h = sha3.New512()
	} else if(mode == "sha3-384") {
		h = sha3.New384()
	} else if(mode == "sha3-256") {
		h = sha3.New256()
	} else if(mode == "sha3-224") {
		h = sha3.New224()
	} else if(mode == "sha512") {
		h = sha512.New()
	} else if(mode == "sha384") {
		h = sha512.New384()
	} else if(mode == "sha256") {
		h = sha256.New()
	} else if(mode == "sha224") {
		h = sha256.New224()
	} else if(mode == "sha1") {
		h = sha1.New()
	} //end if else
	if(h == nil) {
		return "", NewError("WARNING: Invalid Mode: `" + mode + "`")
	} //end if
	//--
	f, errO := os.Open(filePath)
	if(errO != nil) {
		return "", NewError("ERROR: Failed to Open File: " + errO.Error())
	} //end if
	defer f.Close()
	if _, errC := io.Copy(h, f); errC != nil {
		return "", NewError("ERROR: Failed to Read File: " + errC.Error())
	} //end if
	//--
	hexSha := StrToLower(hex.EncodeToString(h.Sum(nil)))
	//--
	return hexSha, nil
	//--
} //END FUNCTION


//-----


func SafePathFileBytRead(filePath string, allowAbsolutePath bool) ([]byte, error) {
	//--
	defer PanicHandler()
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return nil, NewError("WARNING: File Path is Empty")
	} //end if
	//--
	filePath = SafePathFixClean(filePath)
	//--
	if(PathIsEmptyOrRoot(filePath) == true) {
		return nil, NewError("WARNING: File Path is Empty/Root")
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return nil, NewError("WARNING: File Path is Invalid Unsafe")
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return nil, NewError("WARNING: File Path is Backward Unsafe")
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return nil, NewError("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters")
		} //end if
	} //end if
	//--
	if(PathIsDir(filePath)) {
		return nil, NewError("WARNING: File Path is a Directory not a File")
	} //end if
	//--
	content, err := os.ReadFile(filePath)
	if(err != nil) {
		return nil, NewError("ERROR: File Read: " + err.Error())
	} //end if
	//--
	return content, nil
	//--
} //END FUNCTION


func SafePathFileRead(filePath string, allowAbsolutePath bool) (string, error) {
	//--
	defer PanicHandler()
	//--
	content, err := SafePathFileBytRead(filePath, allowAbsolutePath)
	if(err != nil) {
		return "", err
	} //end if
	//--
	return string(content), nil
	//--
} //END FUNCTION


func SafePathFileBytWrite(filePath string, wrMode string, allowAbsolutePath bool, fileContent []byte) (bool, error) {
	//--
	defer PanicHandler()
	//--
	// wrMode : "w" for write (FILE_WRITE_MODE_DEFAULT) | "a" for append (FILE_WRITE_MODE_APPEND)
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return false, NewError("WARNING: File Path is Empty")
	} //end if
	//--
	filePath = SafePathFixClean(filePath)
	//--
	if(PathIsEmptyOrRoot(filePath) == true) {
		return false, NewError("WARNING: File Path is Empty/Root")
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return false, NewError("WARNING: File Path is Invalid Unsafe")
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return false, NewError("WARNING: File Path is Backward Unsafe")
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return false, NewError("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters")
		} //end if
	} //end if
	//--
	if(PathIsDir(filePath)) {
		return false, NewError("WARNING: File Path is a Directory not a File")
	} //end if
	//--
	if(wrMode == FILE_WRITE_MODE_APPEND) { // append mode
		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, CHMOD_FILES)
		if(err != nil) {
			return false, err
		} //end if
		defer f.Close()
		if _, err := f.Write(fileContent); err != nil {
			return false, err
		} //end if
		return true, nil // must return here to avoid defered f to be out of scope
	} else if(wrMode == FILE_WRITE_MODE_DEFAULT) { // write (default) mode
		err := os.WriteFile(filePath, fileContent, CHMOD_FILES)
		if(err != nil) {
			return false, err
		} //end if
		return true, nil // return here, keep the same logic as above
	} //end if else
	//--
	return false, NewError("WARNING: Invalid File Write Mode: `" + wrMode + "`")
	//--
} //END FUNCTION


func SafePathFileWrite(filePath string, wrMode string, allowAbsolutePath bool, fileContent string) (bool, error) {
	//--
	defer PanicHandler()
	//--
	// wrMode : "w" for write (FILE_WRITE_MODE_DEFAULT) | "a" for append (FILE_WRITE_MODE_APPEND)
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return false, NewError("WARNING: File Path is Empty")
	} //end if
	//--
	filePath = SafePathFixClean(filePath)
	//--
	if(PathIsEmptyOrRoot(filePath) == true) {
		return false, NewError("WARNING: File Path is Empty/Root")
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return false, NewError("WARNING: File Path is Invalid Unsafe")
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return false, NewError("WARNING: File Path is Backward Unsafe")
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return false, NewError("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters")
		} //end if
	} //end if
	//--
	if(PathIsDir(filePath)) {
		return false, NewError("WARNING: File Path is a Directory not a File")
	} //end if
	//--
	fFlags := os.O_CREATE|os.O_WRONLY
	if(wrMode == FILE_WRITE_MODE_APPEND) { // append mode
		fFlags |= os.O_APPEND
	} else if(wrMode == FILE_WRITE_MODE_DEFAULT) {
		fFlags |= os.O_TRUNC // required, without this will not write the file if is not empty !
	} else {
		return false, NewError("WARNING: Invalid File Write Mode: `" + wrMode + "`")
	} //end if
	//--
	f, err := os.OpenFile(filePath, fFlags, CHMOD_FILES)
	if(err != nil) {
		return false, err
	} //end if
	defer f.Close()
	if _, err := f.WriteString(fileContent); err != nil {
		return false, err
	} //end if
	return true, nil // must return here to avoid defered f to be out of scope
	//--
} //END FUNCTION


func SafePathFileDelete(filePath string, allowAbsolutePath bool) (isSuccess bool, errMsg error) {
	//--
	defer PanicHandler()
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return false, NewError("WARNING: File Path is Empty")
	} //end if
	//--
	filePath = SafePathFixClean(filePath)
	//--
	if(PathIsEmptyOrRoot(filePath) == true) {
		return false, NewError("WARNING: File Path is Empty/Root")
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return false, NewError("WARNING: File Path is Invalid Unsafe")
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return false, NewError("WARNING: File Path is Backward Unsafe")
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return false, NewError("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters")
		} //end if
	} //end if
	//--
	if(PathExists(filePath)) {
		//--
		if(PathIsDir(filePath)) {
			return false, NewError("WARNING: File Path is a Directory not a File")
		} //end if
		if(!PathIsFile(filePath)) {
			return false, NewError("WARNING: File Path is Not a File")
		} //end if
		//--
		err := os.Remove(filePath)
		if(err != nil) {
			return false, err
		} //end if
		//--
	} //end if
	//--
	return true, nil
	//--
} //END FUNCTION


func SafePathFileRename(filePath string, fileNewPath string, allowAbsolutePath bool) (isSuccess bool, errMsg error) {
	//--
	defer PanicHandler()
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return false, NewError("WARNING: File Path is Empty")
	} //end if
	if(StrTrimWhitespaces(fileNewPath) == "") {
		return false, NewError("WARNING: New File Path is Empty")
	} //end if
	//--
	filePath = SafePathFixClean(filePath)
	//--
	if(PathIsEmptyOrRoot(filePath) == true) {
		return false, NewError("WARNING: File Path is Empty/Root")
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return false, NewError("WARNING: File Path is Invalid Unsafe")
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return false, NewError("WARNING: File Path is Backward Unsafe")
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return false, NewError("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters")
		} //end if
	} //end if
	//--
	fileNewPath = SafePathFixClean(fileNewPath)
	//--
	if(PathIsEmptyOrRoot(fileNewPath) == true) {
		return false, NewError("WARNING: New File Path is Empty/Root")
	} //end if
	//--
	if(PathIsSafeValidPath(fileNewPath) != true) {
		return false, NewError("WARNING: New File Path is Invalid Unsafe")
	} //end if
	//--
	if(PathIsBackwardUnsafe(fileNewPath) == true) {
		return false, NewError("WARNING: New File Path is Backward Unsafe")
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(fileNewPath) == true) {
			return false, NewError("NOTICE: New File Path is Absolute but not allowed to be absolute by the calling parameters")
		} //end if
	} //end if
	//--
	if(filePath == fileNewPath) {
		return false, NewError("WARNING: New File Path is the same as the Original File Path")
	} //end if
	//--
	if(!PathExists(filePath)) {
		return false, NewError("WARNING: File Path does not exist")
	} //end if
	if(!PathIsFile(filePath)) {
		return false, NewError("WARNING: File Path is Not a File")
	} //end if
	//--
	if(PathIsDir(filePath)) {
		return false, NewError("WARNING: File Path is a Directory not a File")
	} //end if
	if(PathIsDir(fileNewPath)) {
		return false, NewError("WARNING: New File Path is a Directory not a File")
	} //end if
	//--
	if(PathExists(fileNewPath)) {
		return false, NewError("WARNING: New File Path already exist")
	} //end if
	//--
	err := os.Rename(filePath, fileNewPath)
	if(err != nil) {
		return false, err
	} //end if
	//--
	return true, nil
	//--
} //END FUNCTION


func SafePathFileCopy(filePath string, fileNewPath string, allowAbsolutePath bool) (isSuccess bool, errMsg error) {
	//--
	defer PanicHandler()
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return false, NewError("WARNING: File Path is Empty")
	} //end if
	if(StrTrimWhitespaces(fileNewPath) == "") {
		return false, NewError("WARNING: New File Path is Empty")
	} //end if
	//--
	filePath = SafePathFixClean(filePath)
	//--
	if(PathIsEmptyOrRoot(filePath) == true) {
		return false, NewError("WARNING: File Path is Empty/Root")
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return false, NewError("WARNING: File Path is Invalid Unsafe")
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return false, NewError("WARNING: File Path is Backward Unsafe")
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return false, NewError("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters")
		} //end if
	} //end if
	//--
	fileNewPath = SafePathFixClean(fileNewPath)
	//--
	if(PathIsEmptyOrRoot(fileNewPath) == true) {
		return false, NewError("WARNING: New File Path is Empty/Root")
	} //end if
	//--
	if(PathIsSafeValidPath(fileNewPath) != true) {
		return false, NewError("WARNING: New File Path is Invalid Unsafe")
	} //end if
	//--
	if(PathIsBackwardUnsafe(fileNewPath) == true) {
		return false, NewError("WARNING: New File Path is Backward Unsafe")
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(fileNewPath) == true) {
			return false, NewError("NOTICE: New File Path is Absolute but not allowed to be absolute by the calling parameters")
		} //end if
	} //end if
	//--
	if(filePath == fileNewPath) {
		return false, NewError("WARNING: New File Path is the same as the Original File Path")
	} //end if
	//--
	if(!PathExists(filePath)) {
		return false, NewError("WARNING: File Path does not exist")
	} //end if
	if(!PathIsFile(filePath)) {
		return false, NewError("WARNING: File Path is Not a File")
	} //end if
	//--
	if(PathIsDir(filePath)) {
		return false, NewError("WARNING: File Path is a Directory not a File")
	} //end if
	if(PathIsDir(fileNewPath)) {
		return false, NewError("WARNING: New File Path is a Directory not a File")
	} //end if
	if(PathIsFile(fileNewPath)) {
		testDelOldFile, errDelO := SafePathFileDelete(fileNewPath, allowAbsolutePath)
		if(errDelO != nil) {
			return false, NewError("ERROR: Cannot Remove existing Destination File: " + errDelO.Error())
		} //end if
		if(testDelOldFile != true) {
			return false, NewError("WARNING: Cannot Remove existing Destination File")
		} //end if
	} //end if
	//-- revised copy file, using pipe
	sourceFileStat, err := os.Stat(filePath)
	if(err != nil) {
		return false, err
	} //end if
	if(!sourceFileStat.Mode().IsRegular()) {
		return false, NewError("WARNING: Source File is not a regular file")
	} //end if
	source, err := os.Open(filePath)
	if(err != nil) {
		return false, err
	} //end if
	defer source.Close()
	destination, err := os.Create(fileNewPath)
	if(err != nil) {
		return false, err
	} //end if
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	if(err != nil) {
		return false, err
	} //end if
	//--
	if(!PathIsFile(fileNewPath)) {
		return false, NewError("WARNING: New File Path cannot be found after copy")
	} //end if
	errChmod := os.Chmod(fileNewPath, CHMOD_FILES)
	if(err != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Failed to CHMOD the Destination File after copy", fileNewPath, errChmod)
	} //end if
	//--
	fSizeOrigin, fszErrO := SafePathFileGetSize(filePath, allowAbsolutePath)
	if(fszErrO != nil) {
		SafePathFileDelete(fileNewPath, allowAbsolutePath)
		return false, NewError("WARNING: Failed to Compare After Copy File Sizes (origin)")
	} //end if
	fSizeDest, fszErrD := SafePathFileGetSize(fileNewPath, allowAbsolutePath)
	if(fszErrD != nil) {
		SafePathFileDelete(fileNewPath, allowAbsolutePath)
		return false, NewError("WARNING: Failed to Compare After Copy File Sizes (destination)")
	} //end if
	//--
	if(fSizeOrigin != fSizeDest) {
		SafePathFileDelete(fileNewPath, allowAbsolutePath)
		return false, NewError("WARNING: Compare After Copy File Sizes: File Sizes are Different: OriginSize=" + ConvertInt64ToStr(fSizeOrigin) + " / DestinationSize=" + ConvertInt64ToStr(fSizeDest))
	} //end if
	if(fSizeOrigin != nBytes) {
		SafePathFileDelete(fileNewPath, allowAbsolutePath)
		return false, NewError("WARNING: Compare After Copy File Sizes: Bytes Copied Size is Different than Original Size: OriginSize=" + ConvertInt64ToStr(fSizeOrigin) + " / BytesCopied=" + ConvertInt64ToStr(nBytes))
	} //end if
	//--
	return true, nil
	//--
} //END FUNCTION


func SafePathFileGetSize(filePath string, allowAbsolutePath bool) (fileSize int64, errMsg error) {
	//--
	defer PanicHandler()
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return 0, NewError("WARNING: File Path is Empty")
	} //end if
	//--
	filePath = SafePathFixClean(filePath)
	//--
	if(PathIsEmptyOrRoot(filePath) == true) {
		return 0, NewError("WARNING: File Path is Empty/Root")
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return 0, NewError("WARNING: File Path is Invalid Unsafe")
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return 0, NewError("WARNING: File Path is Backward Unsafe")
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return 0, NewError("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters")
		} //end if
	} //end if
	//--
	if(!PathExists(filePath)) {
		return 0, NewError("WARNING: File Path does not exist")
	} //end if
	if(!PathIsFile(filePath)) {
		return 0, NewError("WARNING: File Path is not a file")
	} //end if
	//--
	fd, err := os.Stat(filePath)
	if(err != nil) {
		if(os.IsNotExist(err)) {
			return 0, err
		} //end if
	} //end if
	var size int64 = fd.Size()
	//--
	return size, nil
	//--
} //END FUNCTION


func SafePathGetMTime(thePath string, allowAbsolutePath bool) (mTime int64, errMsg error) {
	//--
	defer PanicHandler()
	//--
	if(StrTrimWhitespaces(thePath) == "") {
		return 0, NewError("WARNING: The Path is Empty")
	} //end if
	//--
	thePath = SafePathFixClean(thePath)
	//--
	if(PathIsEmptyOrRoot(thePath) == true) {
		return 0, NewError("WARNING: The Path is Empty/Root")
	} //end if
	//--
	if(PathIsSafeValidPath(thePath) != true) {
		return 0, NewError("WARNING: The Path is Invalid Unsafe")
	} //end if
	//--
	if(PathIsBackwardUnsafe(thePath) == true) {
		return 0, NewError("WARNING: The Path is Backward Unsafe")
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(thePath) == true) {
			return 0, NewError("NOTICE: The Path is Absolute but not allowed to be absolute by the calling parameters")
		} //end if
	} //end if
	//--
	if(!PathExists(thePath)) {
		return 0, NewError("WARNING: The Path does not exist")
	} //end if
	//--
	fd, err := os.Stat(thePath)
	if(err != nil) {
		if(os.IsNotExist(err)) {
			return 0, err
		} //end if
	} //end if
	modifTime := fd.ModTime()
	//--
	return int64(modifTime.Unix()), nil
	//--
} //END FUNCTION


//-----


func PathIsWebSafeValidPath(path string) bool { // must work for dir or file ; used for web srv
	//--
	defer PanicHandler()
	//--
	path = StrTrimWhitespaces(path)
	if(path == "") {
		return false
	} //end if
	//--
	if((path == ".") || (path == "./") || (path == "..") || StrContains(path, "..") || StrContains(path, " ") || StrContains(path, "\\") || StrContains(path, ":")) {
		return false
	} //end if
	//--
	if(StrStartsWith(path, "/") == true) { // safety: dissalow start with / ; will be later checked for absolute path, but this is much clear to have also
		return false
	} //end if
	//--
	if(IsPathAlikeWithSafeFixedPath(path, true) != true) { // need to fix trailing slashes, it can be a dir path
		return false
	} //end if
	//--
	if((PathIsEmptyOrRoot(path) == true) || (PathIsSafeValidPath(path) != true) || (PathIsBackwardUnsafe(path) == true)) {
		return false
	} //end if
	//--
	if(PathIsAbsolute(path) == true) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func PathIsWebSafeValidSafePath(path string) bool { // must work for dir or file ; used for web srv
	//--
	if(PathIsWebSafeValidPath(path) != true) {
		return false
	} //end if
	//--
	if(PathIsSafeValidSafePath(path) != true) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


//-----


func GetCurrentUserHomeDir() (string, error) {
	//--
	userDirHome, errHomeDir := os.UserHomeDir()
	if(errHomeDir != nil) {
		return INVALID_HOMEDIR_PATH, NewError("ERR: Failed to get the Current User Home Dir: " + errHomeDir.Error())
	} //end if
	//--
	userDirHome = StrTrimWhitespaces(userDirHome)
	if(userDirHome == "") {
		return INVALID_HOMEDIR_PATH, NewError("ERR: Current User Home Dir is Empty")
	} //end if
	//--
	if(PathIsEmptyOrRoot(userDirHome) == true) {
		return INVALID_HOMEDIR_PATH, NewError("ERR: Current User Home Dir is Empty/Root")
	} //end if
	if(PathIsSafeValidPath(userDirHome) != true) {
		return INVALID_HOMEDIR_PATH, NewError("ERR: Current User Home Dir is Invalid Unsafe")
	} //end if
	if(PathIsBackwardUnsafe(userDirHome) == true) {
		return INVALID_HOMEDIR_PATH, NewError("ERR: Current User Home Dir is Backward Unsafe")
	} //end if
	if(PathIsAbsolute(userDirHome) != true) {
		return INVALID_HOMEDIR_PATH, NewError("ERR: Current User Home Dir is Not an Absolute Path")
	} //end if
	//--
	userDirHome = PathAddDirLastSlash(userDirHome)
	if(PathIsDir(userDirHome) != true) {
		return INVALID_HOMEDIR_PATH, NewError("ERR: Current User Home Dir does Not Exists")
	} //end if
	//--
	return userDirHome, nil
	//--
} //END FUNCTION


//-----


// #END
