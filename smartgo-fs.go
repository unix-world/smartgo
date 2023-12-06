
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2023 unix-world.org
// r.20231206.2358 :: STABLE
// [ FS (FILESYSTEM) ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"os"
	"errors"
	"log"

	"io"
	"path/filepath"
	"embed"

	"strings"
	"encoding/hex"

	"hash"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
)

const (
	CHOWN_DIRS  os.FileMode = 0755
	CHOWN_FILES os.FileMode = 0644

	REGEX_SMART_SAFE_PATH_NAME string 		= `^[_a-zA-Z0-9\-\.@#\/]+$` 		// SAFETY: SUPPORT ONLY THESE CHARACTERS IN FILE SYSTEM PATHS ...
	REGEX_SMART_SAFE_FILE_NAME string 		= `^[_a-zA-Z0-9\-\.@#]+$` 			// SAFETY: SUPPORT ONLY THESE CHARACTERS IN FILE SYSTEM FILE AND DIR NAMES ...
)


func PathDirName(filePath string) string { // returns: `a/path/to` from `a/path/to/lastDirInPath|file.extension` | `/a/path/to` from `/a/path/to/lastDirInPath|file.extension`
	//--
	if(filePath == "") {
		return ""
	} //end if
	//--
	return filepath.Dir(filePath)
	//--
} //END FUNCTION


func PathBaseName(filePath string) string { // returns: `file.extenstion` | `lastDirInPath` from `(/)a/path/to/lastDirInPath|file.extension`
	//--
	if(filePath == "") {
		return ""
	} //end if
	//--
	return filepath.Base(filePath)
	//--
} //END FUNCTION


func PathBaseNoExtName(filePath string) string { // returns: `file` (without extension) | `lastDirInPath` from `(/)a/path/to/lastDirInPath|file.extension`
	//--
	var fWithExt string = PathBaseName(filePath)
	var fExt string = PathBaseExtension(fWithExt)
	//--
	return strings.TrimSuffix(fWithExt, fExt)
	//--
} //END FUNCTION


func PathBaseExtension(filePath string) string { // returns: file .extension (includding dot) from `(/)a/path/to/lastDirInPath|file.extension`
	//--
	if(filePath == "") {
		return ""
	} //end if
	//--
	return filepath.Ext(filePath)
	//--
} //END FUNCTION


func PathIsSafeValidFileName(fileName string) bool { // fileName must not contain: / or : spaces and must not be only spaces ; it detects and convert to spaces all characters handled by StrNormalizeSpaces(), includding NULL byte
	//--
	fileName = StrNormalizeSpaces(fileName) // normalize all kind of spaces to detect below ; spaces of any kind or NULL byte are not allowed in filenames or paths ...
	//--
	if((StrTrimWhitespaces(fileName) == "") || StrContains(fileName, " ") || StrContains(fileName, "/") || StrContains(fileName, "\\") || StrContains(fileName, ":")) {
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


func PathIsSafeValidPath(filePath string) bool { // path must not contain spaces and must not be only spaces ; it detects and convert to spaces all characters handled by StrNormalizeSpaces(), includding NULL byte
	//--
	if(filePath == "./") { // {{{SYNC-SMARTGO-SAMEDIR-MIN-PATH}}}
		return true
	} //end if
	//--
	filePath = StrNormalizeSpaces(filePath) // normalize all kind of spaces to detect below ; spaces of any kind or NULL byte are not allowed in filenames or paths ...
	//--
	if((StrTrimWhitespaces(filePath) == "") || StrContains(filePath, " ")) {
		return false
	} //end if
	//--
	filePath = StrTrimWhitespaces(filePath)
	filePath = StrReplaceAll(filePath, ".", "")
	filePath = StrReplaceAll(filePath, "/", "")
	filePath = StrReplaceAll(filePath, "\\", "")
	filePath = StrReplaceAll(filePath, ":", "")
	if(filePath == "") {
		return false // must not be composed only of dots, especially: . or .. ; and/or: / ; and/or \ ; and or: :
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
	filePath = StrReplaceAll(filePath, "\\", "") // test for network shares
	filePath = StrReplaceAll(filePath, ":", "")  // test for windows file system
	//--
	filePath = StrTrimWhitespaces(filePath)
	//--
	if(filePath == "") {
		return true
	} //end if
	if(len(filePath) < 3) {
		return true
	} //end if
	//--
	return false
	//--
} //END FUNCTION


func PathIsAbsolute(filePath string) bool {
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
	if(
		(len(filePath) > 1024) || // check max path length !
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
	//--
	if(err != nil) {
		return "/tmp/err-absolute-path/invalid-path/"
	} //end if
	//--
	if((StrTrimWhitespaces(absPath) == "") || (absPath == "/") || (absPath == ".") || (absPath == "..")) {
		return "/tmp/err-absolute-path/empty-or-root-path/"
	} //end if
	//--
	return PathAddDirLastSlash(absPath) + StrTrimLeft(thePath, "./")
	//--
} //END FUNCTION


func PathGetCurrentExecutableName() string {
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


func PathAddDirLastSlash(dirPath string) string {
	//--
	dirPath = StrTrimWhitespaces(dirPath)
	if((dirPath == "") || (dirPath == ".") || (dirPath == "..") || (dirPath == "/")) {
		return "./"
	} //end if
	//--
	dirPath = StrTrimRightWhitespaces(StrTrimRight(dirPath, "/"))
	if((dirPath == "") || (dirPath == ".") || (dirPath == "..") || (dirPath == "/")) {
		return "./"
	} //end if
	//--
	return dirPath + "/"
	//--
} //END FUNCTION


//-----


func SafePathFixSeparator(p string) string {
	//--
	if(p == "") {
		return ""
	} //end if
	//--
	return StrReplaceAll(p, "\\", "/")
	//--
} //END FUNCTION


//-----


func SafePathDirCreate(dirPath string, allowRecursive bool, allowAbsolutePath bool) (isSuccess bool, errMsg string) {
	//--
	if(StrTrimWhitespaces(dirPath) == "") {
		return false, errors.New("WARNING: Dir Path is Empty").Error()
	} //end if
	//--
	if(PathIsSafeValidPath(dirPath) != true) {
		return false, errors.New("WARNING: Dir Path is Invalid Unsafe").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(dirPath) == true) {
		return false, errors.New("WARNING: Dir Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(dirPath) == true) {
			return false, errors.New("NOTICE: Dir Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(PathExists(dirPath)) {
		//--
		if(PathIsFile(dirPath)) {
			return false, errors.New("WARNING: Dir Path is a File not a Directory").Error()
		} //end if
		if(!PathIsDir(dirPath)) {
			return false, errors.New("WARNING: Dir Path is Not a Directory").Error()
		} //end if
		//--
	} else {
		//--
		var err error = nil
		if(allowRecursive == true) {
			err = os.MkdirAll(dirPath, CHOWN_DIRS)
		} else {
			err = os.Mkdir(dirPath, CHOWN_DIRS)
		} //end if else
		if(err != nil) {
			return false, err.Error()
		} //end if
		//--
	} //end if
	//--
	return true, ""
	//--
} //END FUNCTION


func SafePathDirDelete(dirPath string, allowAbsolutePath bool) (isSuccess bool, errMsg string) { // will delete the dir with all it's (recursive) content
	//--
	if(StrTrimWhitespaces(dirPath) == "") {
		return false, errors.New("WARNING: Dir Path is Empty").Error()
	} //end if
	//--
	if(PathIsSafeValidPath(dirPath) != true) {
		return false, errors.New("WARNING: Dir Path is Invalid Unsafe").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(dirPath) == true) {
		return false, errors.New("WARNING: Dir Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(dirPath) == true) {
			return false, errors.New("NOTICE: Dir Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(PathExists(dirPath)) {
		//--
		if(PathIsFile(dirPath)) {
			return false, errors.New("WARNING: Dir Path is a File not a Directory").Error()
		} //end if
		if(!PathIsDir(dirPath)) {
			return false, errors.New("WARNING: Dir Path is Not a Directory").Error()
		} //end if
		//--
		err := os.RemoveAll(dirPath)
		if(err != nil) {
			return false, err.Error()
		} //end if
		//--
	} //end if
	//--
	return true, ""
	//--
} //END FUNCTION


func SafePathDirRename(dirPath string, dirNewPath string, allowAbsolutePath bool) (isSuccess bool, errMsg string) {
	//--
	if(StrTrimWhitespaces(dirPath) == "") {
		return false, errors.New("WARNING: Dir Path is Empty").Error()
	} //end if
	//--
	if(PathIsSafeValidPath(dirPath) != true) {
		return false, errors.New("WARNING: Dir Path is Invalid Unsafe").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(dirPath) == true) {
		return false, errors.New("WARNING: Dir Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(dirPath) == true) {
			return false, errors.New("NOTICE: Dir Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(StrTrimWhitespaces(dirNewPath) == "") {
		return false, errors.New("WARNING: New Dir Path is Empty").Error()
	} //end if
	//--
	if(PathIsSafeValidPath(dirNewPath) != true) {
		return false, errors.New("WARNING: New Dir Path is Invalid Unsafe").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(dirNewPath) == true) {
		return false, errors.New("WARNING: New Dir Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(dirNewPath) == true) {
			return false, errors.New("NOTICE: New Dir Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(dirPath == dirNewPath) {
		return false, errors.New("WARNING: New Dir Path is the same as the Original Dir Path").Error()
	} //end if
	//--
	if(!PathExists(dirPath)) {
		return false, errors.New("WARNING: Dir Path does not exist").Error()
	} //end if
	if(!PathIsDir(dirPath)) {
		return false, errors.New("WARNING: Dir Path is Not a Dir").Error()
	} //end if
	//--
	if(PathIsFile(dirPath)) {
		return false, errors.New("WARNING: Dir Path is a File not a Directory").Error()
	} //end if
	if(PathIsFile(dirNewPath)) {
		return false, errors.New("WARNING: New Dir Path is a File not a Directory").Error()
	} //end if
	//--
	if(PathExists(dirNewPath)) {
		return false, errors.New("WARNING: New Dir Path already exist").Error()
	} //end if
	//--
	err := os.Rename(dirPath, dirNewPath)
	if(err != nil) {
		return false, err.Error()
	} //end if
	//--
	return true, ""
	//--
} //END FUNCTION


func SafePathDirScan(dirPath string, recursive bool, allowAbsolutePath bool) (isSuccess bool, errMsg string, arrDirs []string, arrFiles []string) {
	//--
	var dirs  []string
	var files []string
	//--
	if(StrTrimWhitespaces(dirPath) == "") {
		return false, errors.New("WARNING: Dir Path is Empty").Error(), dirs, files
	} //end if
	//--
	dirPath = PathAddDirLastSlash(dirPath)
	//--
	if(PathIsSafeValidPath(dirPath) != true) {
		return false, errors.New("WARNING: Dir Path is Invalid Unsafe").Error(), dirs, files
	} //end if
	//--
	if(PathIsBackwardUnsafe(dirPath) == true) {
		return false, errors.New("WARNING: Dir Path is Backward Unsafe").Error(), dirs, files
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(dirPath) == true) {
			return false, errors.New("NOTICE: Dir Path is Absolute but not allowed to be absolute by the calling parameters").Error(), dirs, files
		} //end if
	} //end if
	//--
	if(!PathExists(dirPath)) {
		return false, errors.New("WARNING: Path does not exists").Error(), dirs, files
	} //end if
	if(PathIsFile(dirPath)) {
		return false, errors.New("WARNING: Dir Path is a File not a Directory").Error(), dirs, files
	} //end if
	if(!PathIsDir(dirPath)) {
		return false, errors.New("WARNING: Dir Path is Not a Directory").Error(), dirs, files
	} //end if
	//--
	if(recursive) {
		//--
		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
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
			return false, err.Error(), dirs, files
		} //end if
		//--
	} else {
		//--
		dir, derr := os.Open(dirPath)
		if(derr != nil) {
			return false, derr.Error(), dirs, files
		} //end if
		paths, err := dir.Readdir(0)
		if(err != nil) {
			return false, err.Error(), dirs, files
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
	return true, "", dirs, files
	//--
} //END FUNCTION


// ex call (req. go ambed fs assets): SafePathEmbedDirScan(&assets, "assets/", true)
func SafePathEmbedDirScan(efs *embed.FS, dirPath string, recursive bool) (isSuccess bool, err error, arrDirs []string, arrFiles []string) {
	//--
	if(dirPath == "") {
		return false, nil, nil, nil
	} //end if
	dirPath = SafePathFixSeparator(dirPath)
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
		fp := filepath.Join(dirPath, entry.Name())
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


func SafePathFileMd5(filePath string, allowAbsolutePath bool) (hashSum string, errMsg string) {
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return "", errors.New("WARNING: File Path is Empty").Error()
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return "", errors.New("WARNING: File Path is Invalid Unsafe").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return "", errors.New("WARNING: File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return "", errors.New("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(PathIsDir(filePath)) {
		return "", errors.New("WARNING: File Path is a Directory not a File").Error()
	} //end if
	//--
	f, err := os.Open(filePath)
	if(err != nil) {
		return "", err.Error()
	} //end if
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err.Error()
	} //end if
	//--
//	hexMd5 := StrToLower(fmt.Sprintf("%x", h.Sum(nil)))
	hexMd5 := StrToLower(hex.EncodeToString(h.Sum(nil)))
	//--
	return hexMd5, ""
	//--
} //END FUNCTION


func SafePathFileSha(mode string, filePath string, allowAbsolutePath bool) (hashSum string, errMsg string) {
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return "", errors.New("WARNING: File Path is Empty").Error()
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return "", errors.New("WARNING: File Path is Invalid Unsafe").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return "", errors.New("WARNING: File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return "", errors.New("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(PathIsDir(filePath)) {
		return "", errors.New("WARNING: File Path is a Directory not a File").Error()
	} //end if
	//--
	var h hash.Hash
	if(mode == "sha512") {
		h = sha512.New()
	} else if(mode == "sha256") {
		h = sha256.New()
	} else if(mode == "sha1") {
		h = sha1.New()
	} //end if else
	if(h == nil) {
		return "", errors.New("WARNING: Invalid Mode: `" + mode + "`").Error()
	} //end if
	//--
	f, err := os.Open(filePath)
	if(err != nil) {
		return "", err.Error()
	} //end if
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return "", err.Error()
	} //end if
	//--
//	hexSha := StrToLower(fmt.Sprintf("%x", h.Sum(nil)))
	hexSha := StrToLower(hex.EncodeToString(h.Sum(nil)))
	//--
	return hexSha, ""
	//--
} //END FUNCTION


//-----


func SafePathIniFileReadAndParse(iniFilePath string, allowAbsolutePath bool, iniKeys []string) (iniMap map[string]string, errMsg string) {
	//--
	iniContent, iniFileErr := SafePathFileRead(iniFilePath, true)
	if(iniFileErr != "") {
		return nil, "INI Settings # Read Failed `" + iniFilePath + "`: " + iniFileErr
	} //end if
	if(StrTrimWhitespaces(iniContent) == "") {
		return nil, "INI Settings # Content is Empty `" + iniFilePath + "`"
	} //end if
	//--
	settings, err := IniContentParse(iniContent, iniKeys)
	if(err != "") {
		return nil, err + " # `" + iniFilePath + "`"
	} //end if
	//--
	return settings, ""
	//--
} //END FUNCTION


//-----


func SafePathFileRead(filePath string, allowAbsolutePath bool) (fileContent string, errMsg string) {
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return "", errors.New("WARNING: File Path is Empty").Error()
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return "", errors.New("WARNING: File Path is Invalid Unsafe").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return "", errors.New("WARNING: File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return "", errors.New("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(PathIsDir(filePath)) {
		return "", errors.New("WARNING: File Path is a Directory not a File").Error()
	} //end if
	//--
	content, err := os.ReadFile(filePath)
	if(err != nil) {
		return "", err.Error()
	} //end if
	//--
	return string(content), ""
	//--
} //END FUNCTION


func SafePathFileWrite(filePath string, wrMode string, allowAbsolutePath bool, fileContent string) (isSuccess bool, errMsg string) {
	//--
	// wrMode : "a" for append | "w" for write
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return false, errors.New("WARNING: File Path is Empty").Error()
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return false, errors.New("WARNING: File Path is Invalid Unsafe").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return false, errors.New("WARNING: File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return false, errors.New("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(PathIsDir(filePath)) {
		return false, errors.New("WARNING: File Path is a Directory not a File").Error()
	} //end if
	//--
	if(wrMode == "a") { // append mode
		f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, CHOWN_FILES)
		if(err != nil) {
			return false, err.Error()
		} //end if
	//	defer f.Close() // changes as below to log if not closing a file the issue with 'too many open files'
		fClose := func() { // because this method in append mode is used for writing also the log files make defer a bit more safe, from above
			if err := f.Close(); err != nil {
				log.Println("[ERROR] " + CurrentFunctionName() + ":", "FAILED to explicit Close an Opened File (write:append mode): `" + filePath + "` # Errors:", err)
			} else {
				if(DEBUG == true) { // !!! need this because actually this method will write also to log files so this will repeat on each logged message !!!
					log.Println("[DEBUG] " + CurrentFunctionName() + ":", "An Opened File (write:append mode) was explicit Closed: `" + filePath) // this is important, as all logs that write to files must be able to watch this ... to monitor (debug) if the past issue with too many opened files persists after new fixes ...
				} //end if
			} //end if
		} //end function
		if _, err := f.WriteString(fileContent); err != nil {
			fClose()
			return false, err.Error()
		} //end if
		fClose()
		return true, "" // must return here to avoid defered f to be out of scope
	} else if(wrMode == "w") { // write mode
		err := os.WriteFile(filePath, []byte(fileContent), CHOWN_FILES)
		if(err != nil) {
			return false, err.Error()
		} //end if
		return true, "" // return here, keep the same logic as above
	} //end if else
	//--
	return false, errors.New("WARNING: Invalid File Write Mode: `" + wrMode + "`").Error()
	//--
} //END FUNCTION


func SafePathFileDelete(filePath string, allowAbsolutePath bool) (isSuccess bool, errMsg string) {
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return false, errors.New("WARNING: File Path is Empty").Error()
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return false, errors.New("WARNING: File Path is Invalid Unsafe").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return false, errors.New("WARNING: File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return false, errors.New("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(PathExists(filePath)) {
		//--
		if(PathIsDir(filePath)) {
			return false, errors.New("WARNING: File Path is a Directory not a File").Error()
		} //end if
		if(!PathIsFile(filePath)) {
			return false, errors.New("WARNING: File Path is Not a File").Error()
		} //end if
		//--
		err := os.Remove(filePath)
		if(err != nil) {
			return false, err.Error()
		} //end if
		//--
	} //end if
	//--
	return true, ""
	//--
} //END FUNCTION


func SafePathFileRename(filePath string, fileNewPath string, allowAbsolutePath bool) (isSuccess bool, errMsg string) {
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return false, errors.New("WARNING: File Path is Empty").Error()
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return false, errors.New("WARNING: File Path is Invalid Unsafe").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return false, errors.New("WARNING: File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return false, errors.New("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(StrTrimWhitespaces(fileNewPath) == "") {
		return false, errors.New("WARNING: New File Path is Empty").Error()
	} //end if
	//--
	if(PathIsSafeValidPath(fileNewPath) != true) {
		return false, errors.New("WARNING: New File Path is Invalid Unsafe").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(fileNewPath) == true) {
		return false, errors.New("WARNING: New File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(fileNewPath) == true) {
			return false, errors.New("NOTICE: New File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(filePath == fileNewPath) {
		return false, errors.New("WARNING: New File Path is the same as the Original File Path").Error()
	} //end if
	//--
	if(!PathExists(filePath)) {
		return false, errors.New("WARNING: File Path does not exist").Error()
	} //end if
	if(!PathIsFile(filePath)) {
		return false, errors.New("WARNING: File Path is Not a File").Error()
	} //end if
	//--
	if(PathIsDir(filePath)) {
		return false, errors.New("WARNING: File Path is a Directory not a File").Error()
	} //end if
	if(PathIsDir(fileNewPath)) {
		return false, errors.New("WARNING: New File Path is a Directory not a File").Error()
	} //end if
	//--
	if(PathExists(fileNewPath)) {
		return false, errors.New("WARNING: New File Path already exist").Error()
	} //end if
	//--
	err := os.Rename(filePath, fileNewPath)
	if(err != nil) {
		return false, err.Error()
	} //end if
	//--
	return true, ""
	//--
} //END FUNCTION


func SafePathFileCopy(filePath string, fileNewPath string, allowAbsolutePath bool) (isSuccess bool, errMsg string) {
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return false, errors.New("WARNING: File Path is Empty").Error()
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return false, errors.New("WARNING: File Path is Invalid Unsafe").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return false, errors.New("WARNING: File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return false, errors.New("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(StrTrimWhitespaces(fileNewPath) == "") {
		return false, errors.New("WARNING: New File Path is Empty").Error()
	} //end if
	//--
	if(PathIsSafeValidPath(fileNewPath) != true) {
		return false, errors.New("WARNING: New File Path is Invalid Unsafe").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(fileNewPath) == true) {
		return false, errors.New("WARNING: New File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(fileNewPath) == true) {
			return false, errors.New("NOTICE: New File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(filePath == fileNewPath) {
		return false, errors.New("WARNING: New File Path is the same as the Original File Path").Error()
	} //end if
	//--
	if(!PathExists(filePath)) {
		return false, errors.New("WARNING: File Path does not exist").Error()
	} //end if
	if(!PathIsFile(filePath)) {
		return false, errors.New("WARNING: File Path is Not a File").Error()
	} //end if
	//--
	if(PathIsDir(filePath)) {
		return false, errors.New("WARNING: File Path is a Directory not a File").Error()
	} //end if
	if(PathIsDir(fileNewPath)) {
		return false, errors.New("WARNING: New File Path is a Directory not a File").Error()
	} //end if
	if(PathIsFile(fileNewPath)) {
		testDelOldFile, errMsg := SafePathFileDelete(fileNewPath, allowAbsolutePath)
		if((testDelOldFile != true) || (errMsg != "")) {
			return false, errors.New("WARNING: Cannot Remove existing Destination File: " + errMsg).Error()
		} //end if
	} //end if
	//-- revised copy file, using pipe
	sourceFileStat, err := os.Stat(filePath)
	if(err != nil) {
		return false, err.Error()
	} //end if
	if(!sourceFileStat.Mode().IsRegular()) {
		return false, errors.New("WARNING: Source File is not a regular file").Error()
	} //end if
	source, err := os.Open(filePath)
	if(err != nil) {
		return false, err.Error()
	} //end if
	defer source.Close()
	destination, err := os.Create(fileNewPath)
	if(err != nil) {
		return false, err.Error()
	} //end if
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	if(err != nil) {
		return false, err.Error()
	} //end if
	//--
	if(!PathIsFile(fileNewPath)) {
		return false, errors.New("WARNING: New File Path cannot be found after copy").Error()
	} //end if
	errChmod := os.Chmod(fileNewPath, CHOWN_FILES)
	if(err != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Failed to CHMOD the Destination File after copy", fileNewPath, errChmod)
	} //end if
	//--
	fSizeOrigin, errMsg := SafePathFileGetSize(filePath, allowAbsolutePath)
	if(errMsg != "") {
		SafePathFileDelete(fileNewPath, allowAbsolutePath)
		return false, errors.New("WARNING: Failed to Compare After Copy File Sizes (origin)").Error()
	} //end if
	fSizeDest, errMsg := SafePathFileGetSize(fileNewPath, allowAbsolutePath)
	if(errMsg != "") {
		SafePathFileDelete(fileNewPath, allowAbsolutePath)
		return false, errors.New("WARNING: Failed to Compare After Copy File Sizes (destination)").Error()
	} //end if
	//--
	if(fSizeOrigin != fSizeDest) {
		SafePathFileDelete(fileNewPath, allowAbsolutePath)
		return false, errors.New("WARNING: Compare After Copy File Sizes: File Sizes are Different: OriginSize=" + ConvertInt64ToStr(fSizeOrigin) + " / DestinationSize=" + ConvertInt64ToStr(fSizeDest)).Error()
	} //end if
	if(fSizeOrigin != nBytes) {
		SafePathFileDelete(fileNewPath, allowAbsolutePath)
		return false, errors.New("WARNING: Compare After Copy File Sizes: Bytes Copied Size is Different than Original Size: OriginSize=" + ConvertInt64ToStr(fSizeOrigin) + " / BytesCopied=" + ConvertInt64ToStr(nBytes)).Error()
	} //end if
	//--
	return true, ""
	//--
} //END FUNCTION


func SafePathFileGetSize(filePath string, allowAbsolutePath bool) (fileSize int64, errMsg string) {
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return 0, errors.New("WARNING: File Path is Empty").Error()
	} //end if
	//--
	if(PathIsSafeValidPath(filePath) != true) {
		return 0, errors.New("WARNING: File Path is Invalid Unsafe").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return 0, errors.New("WARNING: File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return 0, errors.New("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(!PathExists(filePath)) {
		return 0, errors.New("WARNING: File Path does not exist").Error()
	} //end if
	if(!PathIsFile(filePath)) {
		return 0, errors.New("WARNING: File Path is not a file").Error()
	} //end if
	//--
	fd, err := os.Stat(filePath)
	if(err != nil) {
		if(os.IsNotExist(err)) {
			return 0, err.Error()
		} //end if
	} //end if
	var size int64 = fd.Size()
	//--
	return size, ""
	//--
} //END FUNCTION


func SafePathGetMTime(thePath string, allowAbsolutePath bool) (mTime int64, errMsg string) {
	//--
	if(StrTrimWhitespaces(thePath) == "") {
		return 0, errors.New("WARNING: The Path is Empty").Error()
	} //end if
	//--
	if(PathIsSafeValidPath(thePath) != true) {
		return 0, errors.New("WARNING: The Path is Invalid Unsafe").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(thePath) == true) {
		return 0, errors.New("WARNING: The Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(thePath) == true) {
			return 0, errors.New("NOTICE: The Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(!PathExists(thePath)) {
		return 0, errors.New("WARNING: The Path does not exist").Error()
	} //end if
	//--
	fd, err := os.Stat(thePath)
	if(err != nil) {
		if(os.IsNotExist(err)) {
			return 0, err.Error()
		} //end if
	} //end if
	modifTime := fd.ModTime()
	//--
	return int64(modifTime.Unix()), ""
	//--
} //END FUNCTION


//-----


// #END
