
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2021-present, unix-world.org
// r.20260915.2358 :: STABLE
// [ ARCHIVERS / ZSTD ]

// REQUIRE: go 1.24 or later
package smartgo

import (
	"bytes"
	"io"
	"runtime"

	"github.com/unix-world/smartgo/utils/iox"

	"github.com/unix-world/smartgo/compress/zstd"
)


//----- IMPORTANT: Zstd is the best in the area with both (small strings or large data, almost comparable with xz) ; extremely fast speed (almost comparable in speed with Lz4) ; for checksums is using XxHash


func ZstdCompress(data []byte, concurrency int, level int, verifyCompressed bool) ([]byte, error) { // compress zstd compatible ; file extension: .zst
	//--
	defer PanicHandler()
	//--
	if(data == nil) {
		return nil, NewError("Input Data is Empty")
	} //end if
	//--
	if((concurrency < 0) || (concurrency > runtime.GOMAXPROCS(0))) {
		concurrency = 0 // 0 = all CPUs ; 1..n=num of cpus
	} //end if
	//--
	if((level < -1) || (level > 3)) {
		level = -1 // force fallback to default compression
	} //end if
	var lvl zstd.EncoderLevel = zstd.SpeedDefault // ZSTD default level is 1 (zstd.SpeedDefault)
	switch level {
		case 0:
			lvl = zstd.SpeedFastest // fastest
			break
		case 1:
			lvl = zstd.SpeedDefault // default
			break
		case 2:
			lvl = zstd.SpeedBetterCompression // better compression
			break
		case 3:
			lvl = zstd.SpeedBestCompression // best compression
			break
		default:
			// use default
	} //end switch
	//--
	var buf bytes.Buffer
	//--
	w, errInit := zstd.NewWriter(&buf, zstd.WithEncoderCRC(true), zstd.WithEncoderConcurrency(concurrency), zstd.WithEncoderLevel(lvl))
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
	byts := buf.Bytes()
	if(byts == nil) {
		return nil, NewError("Compressed Data is Empty")
	} //end if
	//--
	if(verifyCompressed == true) {
		unarchData, unarchErr := ZstdUncompress(byts, concurrency)
		if(unarchErr != nil) {
			return nil, NewError("Compressed Data Verification Failed: " + unarchErr.Error())
		} //end if
		if(unarchData == nil) {
			return nil, NewError("Compressed Data Verification Failed, Empty")
		} //end if
		if(len(unarchData) != len(data)) {
			return nil, NewError("Compressed Data Verification Failed, Length")
		} //end if
		if(string(Sh3aByt512B64(unarchData)) != string(Sh3aByt512B64(data))) {
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


func ZstdUncompress(data []byte, concurrency int) ([]byte, error) { // uncompress zstd compatible ; file extension: .zst
	//--
	defer PanicHandler()
	//--
	if(data == nil) {
		return nil, NewError("Input Data is Empty")
	} //end if
	//--
	if((concurrency < 0) || (concurrency > runtime.GOMAXPROCS(0))) {
		concurrency = 0 // 0 = all CPUs ; 1..n=num of cpus
	} //end if
	//--
	b := bytes.NewReader(data)
	//--
	r, errInit := zstd.NewReader(b, zstd.IgnoreChecksum(false), zstd.WithDecoderConcurrency(concurrency))
	if(errInit != nil) {
		return nil, NewError("Uncompress Init Failed: " + errInit.Error())
	} //end if
	//--
	byts, errRd := io.ReadAll(r)
	if(errRd != nil) {
		return nil, NewError("Uncompress Read Failed: " + errRd.Error())
	} //end if
	//--
	if(byts == nil) {
		return nil, NewError("Uncompress Data is Empty")
	} //end if
	//--
	return byts, nil
	//--
} //END FUNCTION


func ZstdStreamCompress(rdStream io.ReadCloser, concurrency int, level int, wrStreams ...io.WriteCloser) error { // compress zstd compatible ; file extension: .zst
	//--
	// the purpose for accepting multiple writers is to allow for multiple outputs (for example a file and a hash)
	//--
	defer PanicHandler()
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
	if((concurrency < 0) || (concurrency > runtime.GOMAXPROCS(0))) {
		concurrency = 0 // 0 = all CPUs ; 1..n=num of cpus
	} //end if
	//--
	if((level < -1) || (level > 3)) {
		level = -1 // force fallback to default compression
	} //end if
	var lvl zstd.EncoderLevel = zstd.SpeedDefault // ZSTD default level is 1 (zstd.SpeedDefault)
	switch level {
		case 0:
			lvl = zstd.SpeedFastest // fastest
			break
		case 1:
			lvl = zstd.SpeedDefault // default
			break
		case 2:
			lvl = zstd.SpeedBetterCompression // better compression
			break
		case 3:
			lvl = zstd.SpeedBestCompression // best compression
			break
		default:
			// use default
	} //end switch
	//--
	w, errInit := zstd.NewWriter(mw, zstd.WithEncoderCRC(true), zstd.WithEncoderConcurrency(concurrency), zstd.WithEncoderLevel(lvl))
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


func ZstdStreamUncompress(rdStream io.ReadCloser, concurrency int, wrStreams ...io.WriteCloser) error { // uncompress zstd compatible ; file extension: .zst
	//--
	// the purpose for accepting multiple writers is to allow for multiple outputs (for example a file and a hash)
	//--
	defer PanicHandler()
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
	if((concurrency < 0) || (concurrency > runtime.GOMAXPROCS(0))) {
		concurrency = 0 // 0 = all CPUs ; 1..n=num of cpus
	} //end if
	//--
	r, errInit := zstd.NewReader(rdStream, zstd.IgnoreChecksum(false), zstd.WithDecoderConcurrency(concurrency))
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


func TarZstdStreamCompressDir(srcDir string, allowAbsolutePath bool, concurrency int, level int, wrStreams ...io.WriteCloser) error {
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
	errZstd := ZstdStreamCompress(pipeR, concurrency, level, wrStreams...)
	if(errZstd != nil) {
		return NewError("Zstd Stream Compress Failed: " + errZstd.Error())
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


func TarZstdStreamUncompressDir(dstDir string, allowAbsolutePath bool, rdStream io.ReadCloser, concurrency int, preserveFileChmod bool) error {
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
		errZstd := ZstdStreamUncompress(rdStream, concurrency, pipeW)
		if(errZstd != nil) {
			errChan <- NewError("Zstd Stream Uncompress Failed: " + errZstd.Error()) // #1
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
