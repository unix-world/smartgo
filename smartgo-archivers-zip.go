
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2021-present, unix-world.org
// r.20260823.2358 :: STABLE
// [ ARCHIVERS / ZIP ]

// REQUIRE: go 1.22 or later
package smartgo

import (
	"log"
	"fmt"

	"io"
	"bytes"
	"time"

	"github.com/unix-world/smartgo/compress/zip"
)


//-----


func ZipArchive(files map[string][]byte, verifyCompressed bool) ([]byte, error) { // compress zip ; file extension: .zip (zip)
	//--
	// compatible with PHP
	//--
	defer PanicHandler()
	//--
	if((files == nil) || (len(files) <= 0)) {
		return nil, NewError("Zip: No files to add")
	} //end if
	//--
	var buf bytes.Buffer
	//--
	w := zip.NewWriter(&buf)
	//--
	var idx uint64 = 0
	for k, v := range files {
		//--
		k = StrTrimWhitespaces(k) // do trim, spaces are not supported ...
		if(k == "") { // path must not be empty
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + " # empty file path")
		} //end if
		var isDirectory bool = false
		if(StrEndsWith(k, "/") == true) { // must be test before SafePathFixClean
			if(BytesEqual(v, []byte("/")) == true) { // a directory must end with a slash and content must be a slash
				isDirectory = true
			} else { // file cannot end with a slash
				return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + " # unsupported dir path for File: `" + k + "`")
			} //end if else
		} //end if
		k = SafePathFixClean(k) // this removes the trailing slash if any
		if(isDirectory == true) { // add trailing slash back, if dir
			k = PathAddDirLastSlash(k)
		} //end if
		if(PathIsEmptyOrRoot(k) == true) { // should not be root o empty path
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + " # empty or root path for File: `" + k + "`")
		} //end if
		if(PathIsSafeValidPath(k) != true) { // can be: a/b/c.txt
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + " # invalid path for File: `" + k + "`")
		} //end if
		if(PathIsBackwardUnsafe(k) == true) { // must not be backward unsafe path
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + " # unsafe backward path for File: `" + k + "`")
		} //end if
		if(PathIsAbsolute(k) == true) { // path must not be absolute
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + " # unsafe absolute path for File: `" + k + "`")
		} //end if
		if((k == ".") || (k == "..") || (k == "/")) { // disallowed
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + " # disallowed dir path for File: `" + k + "`")
		} //end if
		//-- create with header (better than simple, can set metadata)
		var theComment string = ""
		if(isDirectory == true) {
			theComment = "#" + ConvertUInt64ToStr(idx+1) + " Dir: `" + k + "`"
		} else { // file
			theComment = "#" + ConvertUInt64ToStr(idx+1) + " File: `" + k + "` # Size: " + ConvertIntToStr(len(v)) + " bytes # Checksum SHA3-512/B64: " + string(Sh3aByt512B64(v)) // b64, better for compression
		} //end if
		if(uint64(len(theComment)) > SIZE_BYTES_65K) {
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + ", FileName: `" + k + "` # entry comment is too long")
		} //end if
		zHdr := zip.FileHeader{
			Name: k, // must be a relative path
			Comment: theComment, // must be shorter than 64KiB
			Modified: time.Now(),
		}
		if(isDirectory == true) {
			zHdr.Method = zip.Store
			zHdr.SetDirMode(0755) // required to set the archive in unix mode (do not want msdos mode ...)
		} else {
			zHdr.Method = zip.Deflate
			zHdr.SetMode(0644) // required to set the archive in unix mode (do not want msdos mode ...)
		} //end if else
		f, errHCreate := w.CreateHeader(&zHdr)
		if(errHCreate != nil) {
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + ", FileName: `" + k + "` # Create (with Header) entry Failed: " + errHCreate.Error())
		} //end if
		//--
		var errWrite error
		if(isDirectory == true) { // file only
		//	log.Println("isDirectory:", isDirectory, "; name:", k)
			errWrite = nil // no need to write, dirs only ned to be created as entry
		} else {
			_, errWrite = f.Write(v)
		} //end if
		if(errWrite != nil) {
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + ", FileName: `" + k + "` # Write entry Failed: " + errWrite.Error())
		} //end if
		//--
		idx++
		//--
	} //end for
	//--
	var zipComment string = NAME + " " + VERSION + " Zip.Archiver"
	if(uint64(len(zipComment)) > SIZE_BYTES_65K) {
		return nil, NewError("Zip: archive comment is too long")
	} //end if
	//--
	errComment := w.SetComment(zipComment) // sets the end-of-central-directory comment field, it can only be called before Writer.Close
	if(errComment != nil) {
		return nil, NewError("Zip: archive comment error: " + errComment.Error())
	} //end if
	//--
	errClose := w.Close()
	if(errClose != nil) {
		return nil, NewError("Zip: archive close error: " + errClose.Error())
	} //end if
	//--
	byts := buf.Bytes()
	if(byts == nil) {
		return nil, NewError("Zip: archived data is Null")
	} //end if
	//--
	if(verifyCompressed == true) {
		arrUncompressed, errUncompress := ZipUnarchive(byts, false) // non-permissive
		if(errUncompress != nil) {
			return nil, NewError("Compressed Data Verification Failed: " + errUncompress.Error())
		} //end if
		if(arrUncompressed == nil) {
			return nil, NewError("Compressed Data Verification Failed, Null")
		} //end if
		if(len(arrUncompressed) <= 0) {
			return nil, NewError("Compressed Data Verification Failed, Empty")
		} //end if
		if(len(arrUncompressed) != len(files)) {
			return nil, NewError("Compressed Data Verification Failed, Mismatch")
		} //end if
		var ix uint64 = 0
		for k, v := range files {
			vv, ok := arrUncompressed[k]
			if(ok != true) {
				return nil, NewError("Compressed Data Verification Failed, Missing entry at position #" + ConvertUInt64ToStr(ix) + " / Path `" + k + "`")
			} //end if
			if(vv == nil) {
				return nil, NewError("Compressed Data Verification Failed, Content is Null entry at position #" + ConvertUInt64ToStr(ix) + " / Path `" + k + "`")
			} //end if
			if(len(vv) != len(v)) {
				return nil, NewError("Compressed Data Verification Failed, Content Length does Not Match at position #" + ConvertUInt64ToStr(ix) + " / Path `" + k + "`")
			} //end if
			var isDirectory bool = false
			if(StrEndsWith(k, "/") == true) {
				isDirectory = true
			} //end if
			if(isDirectory == true) { // dir only
				if(BytesEqual(vv, []byte("/")) != true) { // trick by unixman, a dir must have the content set as "/"
					return nil, NewError("Compressed Data Verification Failed, Content Dir as Slash does Not Match at position #" + ConvertUInt64ToStr(ix) + " / Dir `" + k + "`")
				} //end if
			} else { // file only
				if(string(Sh3aByt512B64(v)) != string(Sh3aByt512B64(vv))) {
					return nil, NewError("Compressed Data Verification Failed, Content Checksum does Not Match at position #" + ConvertUInt64ToStr(ix) + " / File `" + k + "`")
				} //end if
			} //end if
			if(BytesEqual(vv, v) != true) {
				return nil, NewError("Compressed Data Verification Failed, Content does Not Match at position #" + ConvertUInt64ToStr(ix) + " / Path `" + k + "`")
			} //end if
			ix++
		} //end for
	} //end if
	//--
	return byts, nil
	//--
} //END FUNCTION


//-----


func ZipUnarchive(zipData []byte, permissive bool) (map[string][]byte, error) { // uncompress zip ; file extension: .zip (zip)
	//--
	// compatible with PHP
	//--
	// if permissive is set to TRUE will allow partial extraction if some other file extraction failed ; otherwise will stop and raise error on any failure
	//--
	defer PanicHandler()
	//--
	var noFiles map[string][]byte = map[string][]byte{}
	//--
	if(zipData == nil) {
		return noFiles, NewError("Zip Archive: Content is Empty")
	} //end if
	//--
	zipReader, errReader := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if(errReader != nil) {
		return noFiles, NewError("Zip Archive: Reader ERR: " + errReader.Error())
	} //end if
	if(len(zipReader.File) <= 0) {
		return noFiles, NewError("Zip Archive: Contains No Readable Files")
	} //end if
	//-- read all the files from zip archive
	files := noFiles
	var fName string = ""
	for key, zipFile := range zipReader.File {
		//--
		fName = StrTrimWhitespaces(zipFile.Name)
		if(fName == "") {
			var msg string = "Zip Archive: a File has an Empty Name, at Key: #" + ConvertIntToStr(key)
			if(permissive == true) { // not fatal, let it continue
				log.Println("[NOTICE]", CurrentFunctionName(), msg)
				fName = "#EMPTY#" // fix path
			} else {
				return noFiles, NewError(msg)
			} //end if else
		} //end if
		//--
		if(DEBUG) {
			log.Println("[DEBUG]", CurrentFunctionName(), "Entry #", key, zipFile.Name, zipFile.Flags, zipFile.CRC32, string(zipFile.Extra), zipFile.ExternalAttrs)
		} //end if
		//--
		var isDirectory bool = false
		if(((StrEndsWith(fName, "/") == true) || ((zipFile.CRC32 <= 0) && (zipFile.Flags == 0))) && ((zipFile.UncompressedSize <= 0) && (zipFile.UncompressedSize64 <= 0))) { // a directory ending with a slash is optional, but the rule is that a dir must have flags 0 and crc 0 and no content
			isDirectory = true
		} //end if
		//--
		var hexCrc32 string = StrToLower(StrPad2LenLeft(fmt.Sprintf("%x", zipFile.CRC32), "0", 8))
		//--
		var fOriginalName string = fName
		fName = StrTrimWhitespaces(SafePathCleanInvalidChars(fName, true, true, false, false)) // is file ; allow path slash ; disallow absolute path ; not smart safe
		if(isDirectory == true) { // dir
			fName = PathAddDirLastSlash(fName)
		} else { // file
			if(StrEndsWith(fName, "/") == true) { // cannot end with a slash
				fName = StrTrimRightWhitespaces(StrTrimRight(fName, "/")) // fix
			} //end if
		} //end if
		var isFNameOk bool = true
		if(fName == "") {
			isFNameOk = false
		} //end if
		if(PathIsEmptyOrRoot(fName) == true) { // should not be root o empty path
			isFNameOk = false
		} //end if
		if(PathIsSafeValidPath(fName) != true) { // can be: a/b/c.txt
			isFNameOk = false
		} //end if
		if(PathIsBackwardUnsafe(fName) == true) { // must not be backward unsafe path
			isFNameOk = false
		} //end if
		if(PathIsAbsolute(fName) == true) { // path must not be absolute
			isFNameOk = false
		} //end if
		if(isDirectory == true) { // dir
			if(StrEndsWith(fName, "/") != true) { // must end with a slash
				isFNameOk = false
			} //end if
		} else { // file
			if(StrEndsWith(fName, "/") == true) { // cannot end with a slash
				isFNameOk = false
			} //end if
		} //end if
		if((fName == ".") || (fName == "..") || (fName == "/")) { // disallowed
			isFNameOk = false
		} //end if
		//--
		if(isFNameOk != true) {
			var msg string = "Zip Archive: a File has an Invalid Path or Name, at Key: #" + ConvertIntToStr(key) + ", as: `" + fOriginalName + "`"
			if(permissive == true) { // not fatal, let it continue
				log.Println("[NOTICE]", CurrentFunctionName(), msg)
				fName = "#INVALID#" + Sha224(fOriginalName) // fix path, hash
				var fExt string = StrToLower(StrTrimWhitespaces(PathBaseExtension(fOriginalName))) // extract file extension
				if((fExt != "") && (PathIsSafeValidSafeFileName(fExt) == true)) { // add file extension
					fName += fExt
				} //end if
			} else {
				return noFiles, NewError(msg)
			} //end if else
		} //end if
		//--
		if(isDirectory == true) { // dir
			//--
			files[fName] = []byte("/") // mandatory for verify
			//--
		} else {
			//--
			unzippedBytes, errUnzip := zipArchReadFileFromMemory(zipFile)
			if(errUnzip != nil) {
				var msg string = "Zip Archive: the File: `" + fName + "` at Key: #" + ConvertIntToStr(key) + " # Unzip Failed: " + errUnzip.Error()
				if(permissive == true) { // not fatal, let it continue
					log.Println("[NOTICE]", CurrentFunctionName(), msg)
				} else {
					return noFiles, NewError(msg)
				} //end if else
			} else if(unzippedBytes == nil) {
				var msg string = "Zip Archive: the File: `" + fName + "` at Key: #" + ConvertIntToStr(key) + " # Unzip Content is Empty"
				if(permissive == true) { // not fatal, let it continue
					log.Println("[NOTICE]", CurrentFunctionName(), msg)
				} else {
					return noFiles, NewError(msg)
				} //end if else
			} else if(string(CrcByt32b(unzippedBytes)) != hexCrc32) {
				var msg string = "Zip Archive: the File: `" + fName + "` at Key: #" + ConvertIntToStr(key) + " # Unzip Content CRC32 failed"
				return noFiles, NewError(msg)
				// no permissive on broken content CRC32 !
			} else {
				files[fName] = unzippedBytes // all ok, append the file name and the unzipped file bytes
			} //end if
			//--
		} //end if else
		//--
	} //end for
	//--
	return files, nil
	//--
} //END FUNCTION


func zipArchReadFileFromMemory(zf *zip.File) ([]byte, error) {
	//--
	// internal only
	//--
	defer PanicHandler()
	//--
	if(zf == nil) {
		return nil, NewError("File Resource is Null")
	} //end if
	//--
	f, errOpen := zf.Open()
	if(errOpen != nil) {
		return nil, errOpen
	} //end if
	//--
	defer f.Close()
	//--
	data, errRd := io.ReadAll(f)
	if(errRd != nil) {
		return nil, errRd
	} //end if
	//--
	return data, nil
	//--
} //END FUNCTION


//-----


// #END
