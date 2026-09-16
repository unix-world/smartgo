
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2021-present, unix-world.org
// r.20260915.2358 :: STABLE
// [ ARCHIVERS / GZIP ]

// REQUIRE: go 1.24 or later
package smartgo

import (
	"io"
	"bytes"

	"github.com/unix-world/smartgo/compress/gzip"
	"github.com/unix-world/smartgo/utils/iox"
)


//-----


func GzPak(data string, verifyCompressed bool) (string, error) { // compress gzip style smart archive ; file extension: .smart-gz
	//--
	// compatible PHP
	//--
	defer PanicHandler()
	//--
	if(data == "") {
		return "", nil // should be no error
	} //end if
	//--
	if(uint64(len(data)) > SIZE_BYTES_16M) { // max 16MB ; sync with PHP
		return "", NewError("Data is too large to be Archived by this method")
	} //end if
	//--
	gzData, err := GzCompress([]byte(data), -1, verifyCompressed) // compress
	if(err != nil) {
		return "", err
	} //end if
	if(gzData == nil) {
		return "", NewError("Empty Data after Compress")
	} //end if
	//--
	return SIGNATURE_GZIP_PACK_v1 + "#" + string(Base64BytEncode(gzData)) + "#" + Crc64eB36(data + NULL_BYTE + ConvertIntToStr(len(data)) + VERTICAL_TAB + Sh3a512B64(data)), nil // this have to be fast and url safe, use B64s, intended for Web
	//--
} //END FUNCTION


func GzUnpak(data string) (string, error) { // uncompress gzip style smart archive ; file extension: .smart-gz
	//--
	// compatible PHP
	//--
	defer PanicHandler()
	//--
	data = StrTrimWhitespaces(data)
	if(data == "") {
		return "", nil // should be no error
	} //end if
	//--
	if(uint64(len(data)) > SIZE_BYTES_16M) { // max 16MB ; sync with PHP
		return "", NewError("Data is too large to be UnArchived by this method")
	} //end if
	//--
	if(StrStartsWith(data, SIGNATURE_GZIP_PACK_v1 + "#") != true) {
		return "", NewError("Invalid Package Prefix")
	} //end if
	//--
	arr := ExplodeWithLimit("#", data, 3)
	if(len(arr) != 3) {
		return "", NewError("Invalid Package Format")
	} //end if
	if(StrTrimWhitespaces(arr[0]) != SIGNATURE_GZIP_PACK_v1) {
		return "", NewError("Invalid Package Signature")
	} //end if
	arr[1] = StrTrimWhitespaces(arr[1])
	if(arr[1] == "") {
		return "", NewError("Empty B64 Data")
	} //end if
	var crc string = StrTrimWhitespaces(arr[2])
	if(crc == "") {
		return "", NewError("Empty Checksum")
	} //end if
	data = Base64Decode(arr[1])
	arr = nil // free mem
	if(data == "") {
		return "", NewError("Empty Data after B64 decode")
	} //end if
	//--
	unGzData, errUnGzip := GzUncompress([]byte(data)) // uncompress
	if(errUnGzip != nil) {
		return "", errUnGzip
	} //end if
	if(unGzData == nil) {
		return "", NewError("Empty Data after Uncompress")
	} //end if
	//--
	data = string(unGzData)
	unGzData = nil // free mem
	//--
	if(Crc64eB36(data + NULL_BYTE + ConvertIntToStr(len(data)) + VERTICAL_TAB + Sh3a512B64(data)) != crc) {
		return "", NewError("Data Checksum does Not Match")
	} //end if
	//--
	return data, nil
	//--
} //END FUNCTION


func GzCompress(data []byte, level int, verifyCompressed bool) ([]byte, error) { // compress gzip compatible ; file extension: .gz (gunzip)
	//--
	// compatible with PHP
	//--
	defer PanicHandler() // req. by gz encode panic handler with malformed data
	//--
	if(data == nil) {
		return nil, NewError("Input Data is Empty")
	} //end if
	//--
	if((level < 1) || (level > 9)) {
		level = -1 // zlib default compression
	} //end if
	//--
	var b bytes.Buffer
	//--
	w, errInit := gzip.NewWriterLevel(&b, level) // RFC 1952 (gzip compatible)
	if(errInit != nil) {
		return nil, NewError("Compress Init Failed: " + errInit.Error())
	} //end if
	//--
	_, errWr := w.Write(data)
	if(errWr != nil) {
		return nil, NewError("Compress Write Failed: " + errWr.Error())
	} //end if
	//--
	errClose := w.Close()
	if(errClose != nil) {
		return nil, NewError("Compress Close Failed: " + errClose.Error())
	} //end if
	//--
	byts := b.Bytes()
	if(byts == nil) {
		return nil, NewError("Compressed Data is Empty")
	} //end if
	//--
	if(verifyCompressed == true) {
		unarchData, unarchErr := GzUncompress(byts)
		if(unarchErr != nil) {
			return nil, NewError("Compressed Data Verification Failed: " + unarchErr.Error())
		} //end if
		if(unarchData == nil) {
			return nil, NewError("Compressed Data Verification Failed, Empty")
		} //end if
		if(len(unarchData) != len(data)) {
			return nil, NewError("Compressed Data Verification Failed, Length")
		} //end if
		if(string(ShaByt512B64(unarchData)) != string(ShaByt512B64(data))) {
			return nil, NewError("Compressed Data Verification Failed, Checksum")
		} //end if
		if(BytesEqual(unarchData, data) != true) {
			return nil, NewError("Compressed Data Verification Failed, Data")
		} //end if
	} //end if
	//--
	return byts, nil
	//--
} //END FUNCTION


func GzUncompress(data []byte) ([]byte, error) { // uncompress gzip compatible ; file extension: .gz (gunzip)
	//--
	// compatible with PHP
	//--
	defer PanicHandler() // req. by gz decode panic handler with malformed data
	//--
	if(data == nil) {
		return nil, NewError("Input Data is Empty")
	} //end if
	//--
	b := bytes.NewReader(data)
	r, errInit := gzip.NewReader(b) // RFC 1952 (gzip compatible)
	if(errInit != nil) {
		return nil, NewError("Uncompress Init Failed: " + errInit.Error())
	} //end if
	//--
	byts, errRd := io.ReadAll(r)
	if(errRd != nil) {
		return nil, NewError("Uncompress Read Failed: " + errRd.Error())
	} //end if
	//--
	errClose := r.Close()
	if(errClose != nil) {
		return nil, NewError("Uncompress Close Failed: " + errClose.Error())
	} //end if
	//--
	if(byts == nil) {
		return nil, NewError("Uncompressed Data is Empty")
	} //end if
	//--
	return byts, nil
	//--
} //END FUNCTION


func GzStreamCompress(rdStream io.ReadCloser, level int, wrStreams ...io.WriteCloser) error { // compress gzip compatible ; file extension: .gz (gunzip)
	//--
	// compatible with PHP
	//--
	// the purpose for accepting multiple writers is to allow for multiple outputs (for example a file and a hash)
	//--
	defer PanicHandler() // req. by gz encode panic handler with malformed data
	//--
	if(rdStream == nil) {
		return NewError("Input Stream is Null")
	} //end if
	if(wrStreams == nil) {
		return NewError("Output Stream is Null")
	} //end if
	if(len(wrStreams) < 1) {
		return NewError("Output Streams is Empty")
	} //end if
	//--
	for i:=0; i<len(wrStreams); i++ {
		if(wrStreams[i] == nil) {
			return NewError("Output Stream[" + ConvertIntToStr(i) + "] is Null")
		} //end if
	} //end for
	mw := iox.MultiWriteCloser(wrStreams...)
	defer mw.Close()
	//--
	defer rdStream.Close()
	//--
	if((level < 1) || (level > 9)) {
		level = -1 // zlib default compression
	} //end if
	//--
	w, errInit := gzip.NewWriterLevel(mw, level) // RFC 1952 (gzip compatible)
	if(errInit != nil) {
		return NewError("Compress Init Failed: " + errInit.Error())
	} //end if
	//--
	_, errWr := io.Copy(w, rdStream)
	if(errWr != nil) {
		return NewError("Compress Write Failed: " + errWr.Error())
	} //end if
	//--
	errClose := w.Close()
	if(errClose != nil) {
		return NewError("Compress Close Failed: " + errClose.Error())
	} //end if
	//--
	return nil
	//--
} //END FUNCTION


func GzStreamUncompress(rdStream io.ReadCloser, wrStreams ...io.WriteCloser) error { // uncompress gzip compatible ; file extension: .gz (gunzip)
	//--
	// compatible with PHP
	//--
	// the purpose for accepting multiple writers is to allow for multiple outputs (for example a file and a hash)
	//--
	defer PanicHandler() // req. by gz decode panic handler with malformed data
	//--
	if(rdStream == nil) {
		return NewError("Input Stream is Null")
	} //end if
	if(wrStreams == nil) {
		return NewError("Output Streams are Null")
	} //end if
	if(len(wrStreams) < 1) {
		return NewError("Output Streams are Empty")
	} //end if
	//--
	for i:=0; i<len(wrStreams); i++ {
		if(wrStreams[i] == nil) {
			return NewError("Output Stream[" + ConvertIntToStr(i) + "] is Null")
		} //end if
	} //end for
	mw := iox.MultiWriteCloser(wrStreams...)
	defer mw.Close()
	//--
	defer rdStream.Close()
	//--
	r, errInit := gzip.NewReader(rdStream) // RFC 1952 (gzip compatible)
	if(errInit != nil) {
		return NewError("Uncompress Init Failed: " + errInit.Error())
	} //end if
	//--
	_, errWr := io.Copy(mw, r)
	if(errWr != nil) {
		return NewError("Uncompress Write Failed: " + errWr.Error())
	} //end if
	//--
	return nil
	//--
} //END FUNCTION


//-----


func TarGzStreamCompressDir(srcDir string, allowAbsolutePath bool, level int, wrStreams ...io.WriteCloser) error {
	//--
	// the purpose for accepting multiple writers is to allow for multiple outputs (for example a file and a hash)
	//--
	defer PanicHandler()
	//--
	// use a buffered channel below, maybe there are cases when the sender and receiver are not ready simultaneously, to avoid fatal error as: `fatal error: all goroutines are asleep - deadlock!`
	// it works with boths on tests (buffered or unbuffered), but perhaps in other situations with different readers/writeres there are lags ...
	// if a Go channel is created without the second parameter, it is an unbuffered channel (zero capacity)
	// unbuffered channels require both the sender and the receiver to be ready simultaneously
	// for buffered channels the capacity should be set to the number of workers ; when capacity is full the channel will block, being fatal error
//	errChan := make(chan error)    // unbuffered channel, synchronous
	errChan := make(chan error, 1) // buffered channel, asynchronous with capacity=1 (capacity should be set to number of expected messages from workers, only have 1 async go routine below, with 1 message)
	defer close(errChan)
	//--
	pipeR, pipeW := io.Pipe()
	//--
	go func() {
		errTar := TarStreamCompressDir(srcDir, allowAbsolutePath, pipeW)
		if(errTar != nil) {
			errChan <- NewError("Tar Stream Compress Dir Failed: " + errTar.Error()) // #1
			return
		} //end if
		errChan <- nil // #1
		return
	}()
	//--
	errGz := GzStreamCompress(pipeR, level, wrStreams...)
	if(errGz != nil) {
		return NewError("Gz Stream Compress Failed: " + errGz.Error())
	} //end if
	//--
	for i:=0; i<len(errChan)+1; i++ { // needs len(errChan) + 1, unstandard situation ; this is because also an unbuffered channel (having capacity=0) have to be avle to read ...
		if err := <-errChan; err != nil {
			return err
		} //end if
	} //end for
	//--
	return nil
	//--
} //END FUNCTION


func TarGzStreamUncompressDir(dstDir string, allowAbsolutePath bool, rdStream io.ReadCloser, preserveFileChmod bool) error {
	//--
	defer PanicHandler()
	//--
	// use a buffered channel below, maybe there are cases when the sender and receiver are not ready simultaneously, to avoid fatal error as: `fatal error: all goroutines are asleep - deadlock!`
	// it works with boths on tests (buffered or unbuffered), but perhaps in other situations with different readers/writeres there are lags ...
	// if a Go channel is created without the second parameter, it is an unbuffered channel (zero capacity)
	// unbuffered channels require both the sender and the receiver to be ready simultaneously
	// for buffered channels the capacity should be set to the number of workers ; when capacity is full the channel will block, being fatal error
//	errChan := make(chan error)    // unbuffered channel, synchronous
	errChan := make(chan error, 1) // buffered channel, asynchronous with capacity=1 (capacity should be set to number of expected messages from workers, only have 1 async go routine below, with 1 message)
	defer close(errChan)
	//--
	pipeR, pipeW := io.Pipe()
	//--
	go func() {
		errGz := GzStreamUncompress(rdStream, pipeW)
		if(errGz != nil) {
			errChan <- NewError("Gz Stream Uncompress Failed: " + errGz.Error()) // #1
			return
		} //end if
		errChan <- nil // #1
		return
	}()
	//--
	errTar := TarStreamUncompressDir(dstDir, allowAbsolutePath, pipeR, preserveFileChmod)
	if(errTar != nil) {
		return NewError("Tar Stream Uncompress Dir Failed: " + errTar.Error())
	} //end if
	//--
	for i:=0; i<len(errChan)+1; i++ { // needs len(errChan) + 1, unstandard situation ; this is because also an unbuffered channel (having capacity=0) have to be avle to read ...
		if err := <-errChan; err != nil {
			return err
		} //end if
	} //end for
	//--
	return nil
	//--
} //END FUNCTION


//-----


// #END
