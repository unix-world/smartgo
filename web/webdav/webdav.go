
// SmartGo :: WebDAV
// r.20241125.2358 :: STABLE
// (c) 2024 unix-world.org

// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package webdav provides a WebDAV server implementation.
package webdav

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"strconv"
	"time"

	"log" // unixman

	smart "github.com/unix-world/smartgo" // unixman
)

const (
	VERSION string = "v.20241125.2358"
)

var (
	DEBUG bool = smart.DEBUG
)

type Handler struct {
	// Prefix is the URL path prefix to strip from WebDAV resource paths.
	Prefix string
	// FileSystem is the virtual file system.
	FileSystem FileSystem
	// LockSystem is the lock management system.
	LockSys *LockSys
	// Logger is an optional error logger. If non-nil, it will be called for all HTTP requests.
	Logger func(*http.Request, error)
}

func (h *Handler) stripPrefix(p string) (string, int, error) {
	if h.Prefix == "" {
		return p, http.StatusOK, nil
	} //end if
	if r := strings.TrimPrefix(p, h.Prefix); len(r) < len(p) {
		return r, http.StatusOK, nil
	} //end if
	return p, http.StatusNotFound, errPrefixMismatch
} //END FUNCTION

//---- from: lock.go
// Condition can match a WebDAV resource, based on a token or ETag.
// Exactly one of Token and ETag should be non-empty.
type Condition struct {
	Not   bool
	Token string
	ETag  string
}
//----

//-- unixman
type loggedResponse struct {
	http.ResponseWriter
	status int
}
func (l *loggedResponse) WriteHeader(status int) { // capture write status header
	l.status = status
	l.ResponseWriter.WriteHeader(status)
} //END FUNCTION
var useSmartSafeValidPaths bool = false
//func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
func (h *Handler) ServeHTTP(ww http.ResponseWriter, r *http.Request, smartSafeValidPaths bool) {
	w := &loggedResponse{ResponseWriter: ww, status:200}
	useSmartSafeValidPaths = smartSafeValidPaths
//-- #unixman
	status, err := http.StatusBadRequest, errUnsupportedMethod
	if(h.LockSys != nil) {
		log.Println("[META]", "SmartGo::WebDAV", VERSION, "LockSys: ON")
	} else {
		log.Println("[META]", "SmartGo::WebDAV", VERSION, "LockSys: N/A")
	} //end if else
	if h.FileSystem == nil {
		status, err = http.StatusInternalServerError, errNoFileSystem
	} else {
		switch r.Method {
			case "OPTIONS":
				status, err = h.handleOptions(w, r)
				break
			case "GET", "HEAD", "POST":
				status, err = h.handleGetHeadPost(w, r)
				break
			case "DELETE":
				status, err = h.handleDelete(w, r)
				break
			case "PUT":
				status, err = h.handlePut(w, r)
				break
			case "MKCOL":
				status, err = h.handleMkcol(w, r)
				break
			case "COPY", "MOVE":
				status, err = h.handleCopyMove(w, r)
				break
			case "PROPFIND":
				status, err = h.handlePropfind(w, r)
				break
			case "PROPPATCH":
				status, err = h.handleProppatch(w, r)
				break
			//-- unixman: LOCK/UNLOCK fake support only ; implemented for compatibility with MacOS ; locking is made using flock mechanism provided by filelock package (custom implementation)
			case "LOCK":
				status, err = h.handleLock(w, r)
				break
			case "UNLOCK":
				status, err = h.handleUnlock(w, r)
				break
			//-- #unixman
		} //end switch
	} //end if

	if status != 0 {
		w.WriteHeader(status)
		if status != http.StatusNoContent {
			w.Write([]byte(StatusText(status)))
		} //end if
	} //end if
	if(DEBUG) {
		errStr := ""
		if(err != nil) {
			errStr = "Error: " + err.Error()
		} //end if
		log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "Status:", w.status, "Method:", r.Method, "Path:", r.URL.Path, errStr)
	} //end if
	if h.Logger != nil {
		h.Logger(r, err)
	} //end if
} //END FUNCTION


func (h *Handler) handleLock(w http.ResponseWriter, r *http.Request) (retStatus int, retErr error) { // fake
	if(r.Header == nil) {
		return http.StatusBadRequest, errUxmNoHeaders
	}
	duration, err := parseTimeout(r.Header.Get("Timeout"))
	if err != nil {
		return http.StatusBadRequest, err
	} //end if
	li, status, err := readLockInfo(r.Body)
	if err != nil {
		return status, err
	} //end if

	var token string = "" // as in PHP
	var created bool = false
	ld := LockDetails{}

	if li == (lockInfo{}) {
		if(DEBUG) {
			log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "LockInfo")
		} //end if
		// An empty lockInfo means to refresh the lock.
		ih, ok := parseIfHeader(r.Header.Get("If"))
		if !ok {
			return http.StatusBadRequest, errInvalidIfHeader
		} //end if
		if len(ih.lists) == 1 && len(ih.lists[0].conditions) == 1 {
			token = smart.StrTrimWhitespaces(ih.lists[0].conditions[0].Token)
		} //end if
		if token == "" {
			return http.StatusBadRequest, errInvalidLockToken
		} //end if
		if(h.LockSys != nil) {
			if(!h.LockSys.Exists(false, token)) { // external lock
				return http.StatusPreconditionFailed, nil
			} //end if
		} //end if
	} else {
		if(DEBUG) {
			log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "Lock")
		} //end if
		// Section 9.10.3 says that "If no Depth header is submitted on a LOCK request,
		// then the request MUST act as if a "Depth:infinity" had been submitted."
		depth := infiniteDepth
		reqPath, status, err := h.stripPrefix(r.URL.Path)
		if err != nil {
			return status, err
		} //end if
	//	if(li.Owner.InnerXML == "") {
	//		li.Owner.InnerXML = "default" // TODO: use the auth real user name ? or leave as is ...
	//	} //end if
		ld = LockDetails{
			Root:      reqPath,
			Duration:  duration,
			OwnerXML:  li.Owner.InnerXML,
			ZeroDepth: depth == 0,
		} //end if
		if(h.LockSys != nil) {
			ctx := r.Context()
			//-- unixman
			realPath, errRealPath := h.FileSystem.GetRealPath(ctx, reqPath)
			if(errRealPath != nil) {
				if(errRealPath == os.ErrInvalid) {
					errRealPath = nil // fix: avoid logging this kind of path validation errors
				} //end if
				return http.StatusUnsupportedMediaType, errRealPath
			} //end if
			if(realPath == "") {
				return http.StatusUnsupportedMediaType, errUxmEmptyRealPath
			} //end if
			//--
			t, err := h.LockSys.Lock(false, realPath) // external lock
			if(err != nil) {
				return http.StatusPreconditionFailed, err
			} //end if
			if(t == "") {
				return http.StatusInternalServerError, nil
			} //end if
			token = t
		} else {
			token = FakeLockToken // as in PHP
		} //end if else
		created = true
		// http://www.webdav.org/specs/rfc4918.html#HEADER_Lock-Token says that the
		// Lock-Token value is a Coded-URL. We add angle brackets.
		w.Header().Set("Lock-Token", "<"+lockTokenScheme+token+">")
	} //end if

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	if created {
		// This is "w.WriteHeader(http.StatusCreated)" and not "return
		// http.StatusCreated, nil" because we write our own (XML) response to w
		// and Handler.ServeHTTP would otherwise write "Created".
		w.WriteHeader(http.StatusCreated)
	} else { // fix by unixman, as in PHP
		w.WriteHeader(http.StatusOK)
	} //end if else
	writeLockInfo(w, lockTokenScheme+token, ld)
	return 0, nil // must return zero, status code is written above
} //END FUNCTION


func (h *Handler) handleUnlock(w http.ResponseWriter, r *http.Request) (status int, err error) { // fake
	if(r.Header == nil) {
		return http.StatusBadRequest, errUxmNoHeaders
	}
	// http://www.webdav.org/specs/rfc4918.html#HEADER_Lock-Token says that the
	// Lock-Token value is a Coded-URL. We strip its angle brackets.
	t := r.Header.Get("Lock-Token")
	if len(t) < 2 || t[0] != '<' || t[len(t)-1] != '>' {
		if(DEBUG) {
			log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "Invalid Lock Token", t)
		} //end if
		return http.StatusBadRequest, errInvalidLockToken
	} //end if
	t = t[1 : len(t)-1]
	t = smart.StrTrimWhitespaces(t)
	if(t == "") {
		if(DEBUG) {
			log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "Empty Lock Token", t)
		} //end if
		return http.StatusBadRequest, errInvalidLockToken
	} //end if
	if(h.LockSys != nil) {
		if(!h.LockSys.Exists(false, t)) { // external lock
			if(DEBUG) {
				log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "Lock Token Does Not Exists", t)
			} //end if
			return http.StatusConflict, errInvalidLockToken
		} //end if
		success, err := h.LockSys.Unlock(false, t) // external lock
		if(err != nil) {
			return http.StatusPreconditionFailed, err
		} //end if
		if(!success) {
			return http.StatusLocked, nil
		} //end if
	} else {
		if(t != FakeLockToken) {
			if(DEBUG) {
				log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "Lock Token is N/A", t)
			} //end if
			return http.StatusConflict, errInvalidLockToken
		} //end if
	} //end if else
	return http.StatusNoContent, nil
} //END FUNCTION

func (h *Handler) confirmLocks(r *http.Request, src, dst string) (release func(), status int, err error) {
	//--
	defer smart.PanicHandler()
	//--
	if(DEBUG) {
		log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "Source:", src, "Destination:", dst)
	} //end if
	//--
	release = func(){}
	//--
	if(r.Header == nil) {
		return release, http.StatusBadRequest, errUxmNoHeaders
	}
	//--
	hdr := r.Header.Get("If") // this is used here just to validate request, for nothing else ...
	if(hdr != "") {
		_, ok := parseIfHeader(hdr)
		if(!ok) {
			return release, http.StatusBadRequest, errInvalidIfHeader
		} //end if
	} //end if
	//-- unixman
	if((src == "") && (dst == "")) {
		return release, http.StatusInternalServerError, errUxmNothingToLock
	} //end if
	if(h.LockSys == nil) {
		return release, 0, nil
	} //end if
	//--
	var tokenSrc string = ""
	var errSrc error = nil
	if(src != "") {
		tokenSrc, errSrc = h.LockSys.Lock(true, src) // internal lock
		if(errSrc != nil) {
			return release, http.StatusInternalServerError, errSrc
		} //end if
		if(tokenSrc == "") {
			return release, http.StatusLocked, ErrLocked
		} //end if
	} //end if
	var tokenDst string = ""
	var errDst error = nil
	if(dst != "") {
		release = func(){
			defer smart.PanicHandler()
			if(tokenSrc != "") {
				h.LockSys.Unlock(true, tokenSrc) // internal unlock
			} //end if
		} //end func
		tokenDst, errDst = h.LockSys.Lock(true, dst) // internal lock
		if(errDst != nil) {
			return release, http.StatusInternalServerError, errSrc
		} //end if
		if(tokenDst == "") {
			return release, http.StatusLocked, ErrConfirmationFailed
		} //end if
	}
	//--
	release = func(){
		defer smart.PanicHandler()
		if(tokenSrc != "") {
			h.LockSys.Unlock(true, tokenSrc) // internal unlock
		} //end if
		if(tokenDst != "") {
			h.LockSys.Unlock(true, tokenDst) // internal unlock
		} //end if
	} //end func
	//--
	return release, 0, nil
	//--
} //END FUNCTION

func (h *Handler) handleOptions(w http.ResponseWriter, r *http.Request) (status int, err error) {
	reqPath, status, err := h.stripPrefix(r.URL.Path)
	if err != nil {
		return status, err
	} //end if
	ctx := r.Context()
	//-- unixman
//	allow := "OPTIONS, LOCK, PUT, MKCOL"
	allow := "OPTIONS, PROPFIND" // unixman: default
	if fi, err := h.FileSystem.Stat(ctx, reqPath); err == nil {
		if fi.IsDir() {
//			allow = "OPTIONS, LOCK, DELETE, PROPPATCH, COPY, MOVE, UNLOCK, PROPFIND"
			allow = "OPTIONS, DELETE, PROPPATCH, COPY, MOVE, PROPFIND, PUT, MKCOL" // unixman: Dir
		} else {
//			allow = "OPTIONS, LOCK, GET, HEAD, POST, DELETE, PROPPATCH, COPY, MOVE, UNLOCK, PROPFIND, PUT"
			allow = "OPTIONS, DELETE, PROPPATCH, COPY, MOVE, PROPFIND, PUT, GET, HEAD, POST, LOCK, UNLOCK" // unixman: File
		} //end if else
	} //end if
	//-- #unixman
	w.Header().Set("Allow", allow)
	// http://www.webdav.org/specs/rfc4918.html#dav.compliance.classes
	w.Header().Set("DAV", "1, 2")
	// http://msdn.microsoft.com/en-au/library/cc250217.aspx
	w.Header().Set("MS-Author-Via", "DAV")
//	return 0, nil
	return http.StatusOK, nil // fix by unixman, as in PHP
} //END FUNCTION

func (h *Handler) handleGetHeadPost(w http.ResponseWriter, r *http.Request) (status int, err error) {
	reqPath, status, err := h.stripPrefix(r.URL.Path)
	if err != nil {
		return status, err
	} //end if
	// TODO: check locks for read-only access??
	ctx := r.Context()
	f, err := h.FileSystem.OpenFile(ctx, reqPath, os.O_RDONLY, 0)
	if err != nil {
		return http.StatusNotFound, err
	} //end if
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return http.StatusNotFound, err
	} //end if
	if fi.IsDir() {
		return http.StatusMethodNotAllowed, nil
	} //end if
	lks := false // unixman
	etag, err := findETag(ctx, h.FileSystem, lks, reqPath, fi)
	if err != nil {
		return http.StatusInternalServerError, err
	} //end if
	w.Header().Set("ETag", etag)
	// Let ServeContent determine the Content-Type header.
	http.ServeContent(w, r, reqPath, fi.ModTime(), f)
	return 0, nil // must return zero ; httpStatusCode is managed by the above method
} //END FUNCTION

func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request) (status int, err error) {
	reqPath, status, err := h.stripPrefix(r.URL.Path)
	if err != nil {
		return status, err
	} //end if

	ctx := r.Context()

	//-- unixman
	realPath, errRealPath := h.FileSystem.GetRealPath(ctx, reqPath)
	if(errRealPath != nil) {
		if(DEBUG) {
			log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "Invalid or Unsafe Path: `" + reqPath + "`", "RealPath: `" + realPath + "`")
		} //end if
		if(errRealPath == os.ErrInvalid) {
			errRealPath = nil // fix: avoid logging this kind of path validation errors
		} //end if
		return http.StatusUnsupportedMediaType, errRealPath
	} //end if
	if(realPath == "") {
		return http.StatusUnsupportedMediaType, errUxmEmptyRealPath
	} //end if
	if(DEBUG) {
		log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "Request Path: `" + reqPath + "`", "RealPath: `" + realPath + "`")
	} //end if
	//-- #unixman

	release, status, err := h.confirmLocks(r, realPath, "") // real path
	if err != nil {
		return status, err
	} //end if
	defer release()

	// TODO: return MultiStatus where appropriate.

	// "godoc os RemoveAll" says that "If the path does not exist, RemoveAll
	// returns nil (no error)." WebDAV semantics are that it should return a
	// "404 Not Found". We therefore have to Stat before we RemoveAll.
	if _, err := h.FileSystem.Stat(ctx, reqPath); err != nil {
		if os.IsNotExist(err) {
			return http.StatusNotFound, err
		} //end if
		return http.StatusMethodNotAllowed, err
	} //end if
	if err := h.FileSystem.RemoveAll(ctx, reqPath); err != nil {
		return http.StatusMethodNotAllowed, err
	} //end if
	return http.StatusNoContent, nil
} //END FUNCTION

func (h *Handler) handlePut(w http.ResponseWriter, r *http.Request) (status int, err error) {
	reqPath, status, err := h.stripPrefix(r.URL.Path)
	if err != nil {
		return status, err
	} //end if

	//-- unixman: disallow except some extensions ; ex: vcf ; ics
//	if(!smart.StrEndsWith(reqPath, ".ics")) {
//		return http.StatusUnsupportedMediaType, err
//	} //end if
	//-- #unixman

	ctx := r.Context()

	//-- unixman
	realPath, errRealPath := h.FileSystem.GetRealPath(ctx, reqPath)
	if(errRealPath != nil) {
		if(DEBUG) {
			log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "Invalid or Unsafe File Path: `" + reqPath + "`", "RealPath: `" + realPath + "`")
		} //end if
		if(errRealPath == os.ErrInvalid) {
			errRealPath = nil // fix: avoid logging this kind of path validation errors
		} //end if
		return http.StatusUnsupportedMediaType, errRealPath
	} //end if
	if(smart.StrTrimWhitespaces(realPath) == "") {
		return http.StatusUnsupportedMediaType, errUxmEmptyRealPath
	} //end if
	if(DEBUG) {
		log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "Request File Path: `" + reqPath + "`", "RealPath: `" + realPath + "`")
	} //end if
	//-- #unixman

	release, status, err := h.confirmLocks(r, realPath, "") // real path
	if err != nil {
		return status, err
	} //end if
	defer release()

	// TODO(rost): Support the If-Match, If-None-Match headers? See bradfitz'
	// comments in http.checkEtag.

	f, err := h.FileSystem.OpenFile(ctx, reqPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		//-- unixman
	//	return http.StatusNotFound, err
		return http.StatusUnsupportedMediaType, err
		//--
	} //end if
	_, copyErr := io.Copy(f, r.Body)
	fi, statErr := f.Stat()
	closeErr := f.Close()
	// TODO(rost): Returning 405 Method Not Allowed might not be appropriate.
	if copyErr != nil {
		return http.StatusMethodNotAllowed, copyErr
	} //end if
	if statErr != nil {
		return http.StatusMethodNotAllowed, statErr
	} //end if
	if closeErr != nil {
		return http.StatusMethodNotAllowed, closeErr
	} //end if
	lks := false // unixman
	etag, err := findETag(ctx, h.FileSystem, lks, reqPath, fi)
	if err != nil {
		return http.StatusInternalServerError, err
	} //end if
	w.Header().Set("ETag", etag)
	return http.StatusCreated, nil
} //END FUNCTION

func (h *Handler) handleMkcol(w http.ResponseWriter, r *http.Request) (status int, err error) {
	reqPath, status, err := h.stripPrefix(r.URL.Path)
	if err != nil {
		return status, err
	} //end if
	if r.ContentLength > 0 {
		return http.StatusUnsupportedMediaType, nil // should be no body for MkCol
	} //end if

	ctx := r.Context()

	//-- unixman
	realPath, errRealPath := h.FileSystem.GetRealPath(ctx, reqPath)
	if(errRealPath != nil) {
		if(DEBUG) {
			log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "Invalid or Unsafe Dir Path: `" + reqPath + "`", "RealPath: `" + realPath + "`")
		} //end if
		if(errRealPath == os.ErrInvalid) {
			errRealPath = nil // fix: avoid logging this kind of path validation errors
		} //end if
		return http.StatusUnsupportedMediaType, errRealPath
	} //end if
	if(realPath == "") {
		return http.StatusUnsupportedMediaType, errUxmEmptyRealPath
	} //end if
	if(DEBUG) {
		log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "Request Dir Path: `" + reqPath + "`", "RealPath: `" + realPath + "`")
	} //end if
	//-- #unixman

	release, status, err := h.confirmLocks(r, realPath, "") // real path
	if err != nil {
		return status, err
	} //end if
	defer release()

	if err := h.FileSystem.Mkdir(ctx, reqPath, 0777); err != nil {
		if os.IsNotExist(err) {
			//-- unixman
		//	return http.StatusConflict, err
			return http.StatusUnsupportedMediaType, err
			//--
		} //end if
		return http.StatusMethodNotAllowed, err
	} //end if

	return http.StatusCreated, nil
} //END FUNCTION

func (h *Handler) handleCopyMove(w http.ResponseWriter, r *http.Request) (status int, err error) {
	hdr := r.Header.Get("Destination")
	if hdr == "" {
		return http.StatusBadRequest, errInvalidDestination
	} //end if
	u, err := url.Parse(hdr)
	if err != nil {
		return http.StatusBadRequest, errInvalidDestination
	} //end if
	if u.Host != "" && u.Host != r.Host {
		return http.StatusBadGateway, errInvalidDestination
	} //end if

	src, status, err := h.stripPrefix(r.URL.Path)
	if err != nil {
		return status, err
	} //end if

	dst, status, err := h.stripPrefix(u.Path)
	if err != nil {
		return status, err
	} //end if

	if dst == "" {
		return http.StatusBadGateway, errInvalidDestination
	} //end if
	if dst == src {
		return http.StatusForbidden, errDestinationEqualsSource
	} //end if
	//-- unixman
	if(src == "") {
		return http.StatusForbidden, errUxmInvalidSource
	} //end if
	if(smart.StrTrimRight(dst, " /") == smart.StrTrimRight(src, " /")) {
		return http.StatusForbidden, errDestinationEqualsSource
	} //end if
	//-- #unixman

	ctx := r.Context()

	//-- unixman
	var overWrite bool = false
	if(r.Header.Get("Overwrite") == "T") {
		overWrite = true
	} //end if
	if(overWrite != true) {
		_, err := h.FileSystem.Stat(ctx, dst)
		if err == nil {
			return http.StatusPreconditionFailed, nil
		} //end if
	} //end if
	//-- #unixman

	//-- unixman
	realSrcPath, errRealSrcPath := h.FileSystem.GetRealPath(ctx, src)
	if(errRealSrcPath != nil) {
		if(DEBUG) {
			log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), r.Method, "Invalid or Unsafe Src Path: `" + src + "`", "RealPath: `" + realSrcPath + "`")
		} //end if
		if(errRealSrcPath == os.ErrInvalid) {
			errRealSrcPath = nil // fix: avoid logging this kind of path validation errors
		} //end if
		return http.StatusUnsupportedMediaType, errRealSrcPath
	} //end if
	if(realSrcPath == "") {
		return http.StatusUnsupportedMediaType, errUxmEmptyRealPath
	} //end if
	if(DEBUG) {
		log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), r.Method, "Request Src Path: `" + src + "`", "RealPath: `" + realSrcPath + "`")
	} //end if
	//--
	realDstPath, errRealDstPath := h.FileSystem.GetRealPath(ctx, dst)
	if(errRealDstPath != nil) {
		if(DEBUG) {
			log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), r.Method, "Invalid or Unsafe Dst Path: `" + dst + "`", "RealPath: `" + realDstPath + "`")
		} //end if
		if(errRealDstPath == os.ErrInvalid) {
			errRealDstPath = nil // fix: avoid logging this kind of path validation errors
		} //end if
		return http.StatusUnsupportedMediaType, errRealDstPath
	} //end if
	if(realDstPath == "") {
		return http.StatusUnsupportedMediaType, errUxmEmptyRealPath
	} //end if
	if(DEBUG) {
		log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), r.Method, "Request Dst Path: `" + dst + "`", "RealPath: `" + realDstPath + "`")
	} //end if
	//-- #unixman

	// unixman: lock both: source and destination also for COPY not only for MOVE
	release, status, err := h.confirmLocks(r, realSrcPath, realDstPath) // real paths
	if err != nil {
		return status, err
	} //end if
	defer release()

	if r.Method == "COPY" {
		// Section 9.8.3 says that "The COPY method on a collection without a Depth
		// header must act as if a Depth header with value "infinity" was included".
		depth := infiniteDepth
		if hdr := r.Header.Get("Depth"); hdr != "" {
			depth = parseDepth(hdr)
			if depth != 0 && depth != infiniteDepth {
				// Section 9.8.3 says that "A client may submit a Depth header on a
				// COPY on a collection with a value of "0" or "infinity"."
				return http.StatusBadRequest, errInvalidDepth
			} //end if
		} //end if
	//	return copyFiles(ctx, h.FileSystem, src, dst, r.Header.Get("Overwrite") != "F", depth, 0)
		return copyFiles(ctx, h.FileSystem, src, dst, overWrite, depth, 0) // fix by unixman
	} //end if

	// Section 9.9.2 says that "The MOVE method on a collection must act as if
	// a "Depth: infinity" header was used on it. A client must not submit a
	// Depth header on a MOVE on a collection with any value but "infinity"."
	if hdr := r.Header.Get("Depth"); hdr != "" {
		if parseDepth(hdr) != infiniteDepth {
			return http.StatusBadRequest, errInvalidDepth
		} //end if
	} //end if
	return moveFiles(ctx, h.FileSystem, src, dst, r.Header.Get("Overwrite") == "T")
} //END FUNCTION

func (h *Handler) handlePropfind(w http.ResponseWriter, r *http.Request) (status int, err error) {
	reqPath, status, err := h.stripPrefix(r.URL.Path)
	if err != nil {
		return status, err
	} //end if
	ctx := r.Context()
	fi, err := h.FileSystem.Stat(ctx, reqPath)
	if err != nil {
		if os.IsNotExist(err) {
			return http.StatusNotFound, err
		} //end if
		return http.StatusMethodNotAllowed, err
	} //end if
	depth := infiniteDepth
	if hdr := r.Header.Get("Depth"); hdr != "" {
		depth = parseDepth(hdr)
		if depth == invalidDepth {
			return http.StatusBadRequest, errInvalidDepth
		} //end if
	} //end if
	pf, status, err := readPropfind(r.Body)
	if err != nil {
		return status, err
	} //end if

	mw := multistatusWriter{w: w}

	walkFn := func(reqPath string, info os.FileInfo, err error) error {
		if err != nil {
			return handlePropfindError(err, info)
		} //end if

		var pstats []Propstat
		lks := false // unixman
		if pf.Propname != nil {
			lks := false // unixman
			pnames, err := propnames(ctx, h.FileSystem, lks, reqPath)
			if err != nil {
				return handlePropfindError(err, info)
			} //end if
			pstat := Propstat{Status: http.StatusOK}
			for _, xmlname := range pnames {
				pstat.Props = append(pstat.Props, Property{XMLName: xmlname})
			} //end for
			pstats = append(pstats, pstat)
		} else if pf.Allprop != nil {
			pstats, err = allprop(ctx, h.FileSystem, lks, reqPath, pf.Prop)
		} else {
			pstats, err = props(ctx, h.FileSystem, lks, reqPath, pf.Prop)
		} //end if else
		if err != nil {
			return handlePropfindError(err, info)
		} //end if
		href := path.Join(h.Prefix, reqPath)
		if href != "/" && info.IsDir() {
			href += "/"
		} //end if
		return mw.write(makePropstatResponse(href, pstats))
	} //end func

	walkErr := walkFS(ctx, h.FileSystem, depth, reqPath, fi, walkFn)
	closeErr := mw.close()
	if walkErr != nil {
		return http.StatusInternalServerError, walkErr
	} //end if
	if closeErr != nil {
		return http.StatusInternalServerError, closeErr
	} //end if
	return 0, nil // must return zero ; httpStatusCode is managed by the above methods
} //END FUNCTION

func (h *Handler) handleProppatch(w http.ResponseWriter, r *http.Request) (status int, err error) {
	reqPath, status, err := h.stripPrefix(r.URL.Path)
	if err != nil {
		return status, err
	} //end if

	ctx := r.Context()

	//-- unixman
	realPath, errRealPath := h.FileSystem.GetRealPath(ctx, reqPath)
	if(errRealPath != nil) {
		if(DEBUG) {
			log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "Invalid or Unsafe Path: `" + reqPath + "`", "RealPath: `" + realPath + "`")
		} //end if
		if(errRealPath == os.ErrInvalid) {
			errRealPath = nil // fix: avoid logging this kind of path validation errors
		} //end if
		return http.StatusUnsupportedMediaType, errRealPath
	} //end if
	if(realPath == "") {
		return http.StatusUnsupportedMediaType, errUxmEmptyRealPath
	} //end if
	if(DEBUG) {
		log.Println("[DEBUG]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "Request Path: `" + reqPath + "`", "RealPath: `" + realPath + "`")
	} //end if
	//-- #unixman

	release, status, err := h.confirmLocks(r, realPath, "") // real path
	if err != nil {
		return status, err
	} //end if
	defer release()

	if _, err := h.FileSystem.Stat(ctx, reqPath); err != nil {
		if os.IsNotExist(err) {
			return http.StatusNotFound, err
		} //end if
		return http.StatusMethodNotAllowed, err
	} //end if
	patches, status, err := readProppatch(r.Body)
	if err != nil {
		return status, err
	} //end if
	lks := false // unixman
	pstats, err := patch(ctx, h.FileSystem, lks, reqPath, patches)
	if err != nil {
		return http.StatusInternalServerError, err
	} //end if
	mw := multistatusWriter{w: w}
	writeErr := mw.write(makePropstatResponse(r.URL.Path, pstats))
	closeErr := mw.close()
	if writeErr != nil {
		return http.StatusInternalServerError, writeErr
	} //end if
	if closeErr != nil {
		return http.StatusInternalServerError, closeErr
	} //end if
	return 0, nil // must return zero ; httpStatusCode is managed by the above methods
} //END FUNCTION

func makePropstatResponse(href string, pstats []Propstat) *response {
	resp := response{
		Href:     []string{(&url.URL{Path: href}).EscapedPath()},
		Propstat: make([]propstat, 0, len(pstats)),
	}
	for _, p := range pstats {
		var xmlErr *xmlError
		if p.XMLError != "" {
			xmlErr = &xmlError{InnerXML: []byte(p.XMLError)}
		} //end if
		resp.Propstat = append(resp.Propstat, propstat{
			Status:              fmt.Sprintf("HTTP/1.1 %d %s", p.Status, StatusText(p.Status)),
			Prop:                p.Props,
			ResponseDescription: p.ResponseDescription,
			Error:               xmlErr,
		})
	} //end if
	return &resp
} //END FUNCTION

func handlePropfindError(err error, info os.FileInfo) error {
	var skipResp error = nil
	if info != nil && info.IsDir() {
		skipResp = filepath.SkipDir
	} //end if

	if errors.Is(err, os.ErrPermission) {
		// If the server cannot recurse into a directory because it is not allowed,
		// then there is nothing more to say about it. Just skip sending anything.
		return skipResp
	} //end if

	if _, ok := err.(*os.PathError); ok {
		// If the file is just bad, it couldn't be a proper WebDAV resource. Skip it.
		return skipResp
	} //end if

	// We need to be careful with other errors: there is no way to abort the xml stream
	// part way through while returning a valid PROPFIND response. Returning only half
	// the data would be misleading, but so would be returning results tainted by errors.
	// The current behaviour by returning an error here leads to the stream being aborted,
	// and the parent http server complaining about writing a spurious header. We should
	// consider further enhancing this error handling to more gracefully fail, or perhaps
	// buffer the entire response until we've walked the tree.
	return err
} //END FUNCTION

const (
	infiniteDepth = -1
	invalidDepth  = -2
)

// parseDepth maps the strings "0", "1" and "infinity" to 0, 1 and
// infiniteDepth. Parsing any other string returns invalidDepth.
//
// Different WebDAV methods have further constraints on valid depths:
//   - PROPFIND has no further restrictions, as per section 9.1.
//   - COPY accepts only "0" or "infinity", as per section 9.8.3.
//   - MOVE accepts only "infinity", as per section 9.9.2.
//   - LOCK accepts only "0" or "infinity", as per section 9.10.3.
//
// These constraints are enforced by the handleXxx methods.
func parseDepth(s string) int {
	switch s {
		case "0":
			return 0
		case "1":
			return 1
		case "infinity":
			return infiniteDepth
	} //end switch
	return invalidDepth
} //END FUNCTION

// http://www.webdav.org/specs/rfc4918.html#status.code.extensions.to.http11
const (
	StatusMulti               = 207
	StatusUnprocessableEntity = 422
	StatusLocked              = 423
	StatusFailedDependency    = 424
	StatusInsufficientStorage = 507
)

func StatusText(code int) string {
	switch code {
		case StatusMulti:
			return "Multi-Status"
		case StatusUnprocessableEntity:
			return "Unprocessable Entity"
		case StatusLocked:
			return "Locked"
		case StatusFailedDependency:
			return "Failed Dependency"
		case StatusInsufficientStorage:
			return "Insufficient Storage"
	} //end switch
	return http.StatusText(code)
} //END FUNCTION

var (
	errUxmEmptyRealPath        = errors.New("webdav: real path is empty")
	errUxmInvalidSource        = errors.New("webdav: invalid source")
	errUxmNothingToLock        = errors.New("webdav: nothing to lock (confirm)")
	errUxmNoHeaders            = errors.New("webdav: http headers are missing")

	errDestinationEqualsSource = errors.New("webdav: destination equals source")
	errDirectoryNotEmpty       = errors.New("webdav: directory not empty")
	errInvalidDepth            = errors.New("webdav: invalid depth")
	errInvalidDestination      = errors.New("webdav: invalid destination")
	errInvalidIfHeader         = errors.New("webdav: invalid If header")
	errInvalidLockInfo         = errors.New("webdav: invalid lock info")
	errInvalidLockToken        = errors.New("webdav: invalid lock token")
	errInvalidPropfind         = errors.New("webdav: invalid propfind")
	errInvalidProppatch        = errors.New("webdav: invalid proppatch")
	errInvalidResponse         = errors.New("webdav: invalid response")
	errInvalidTimeout          = errors.New("webdav: invalid timeout")
	errNoFileSystem            = errors.New("webdav: no file system")
	errNoLockSystem            = errors.New("webdav: no lock system")
	errNotADirectory           = errors.New("webdav: not a directory")
	errPrefixMismatch          = errors.New("webdav: prefix mismatch")
	errRecursionTooDeep        = errors.New("webdav: recursion too deep")
	errUnsupportedLockInfo     = errors.New("webdav: unsupported lock info")
	errUnsupportedMethod       = errors.New("webdav: unsupported method")
)

const infiniteTimeout = -1

// parseTimeout parses the Timeout HTTP header, as per section 10.7. If s is
// empty, an infiniteTimeout is returned.
func parseTimeout(s string) (time.Duration, error) {
	s = smart.StrTrimWhitespaces(s)
	if s == "" {
		return infiniteTimeout, nil
	} //end if
	if i := strings.IndexByte(s, ','); i >= 0 {
		s = s[:i]
	} //end if
	s = smart.StrTrimWhitespaces(s)
	if s == "Infinite" {
		return infiniteTimeout, nil
	} //end if
	const pre = "Second-"
	if !strings.HasPrefix(s, pre) {
		return 0, errInvalidTimeout
	} //end if
	s = s[len(pre):]
	if s == "" || s[0] < '0' || '9' < s[0] {
		return 0, errInvalidTimeout
	} //end if
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || 1<<32-1 < n {
		return 0, errInvalidTimeout
	} //end if
	return time.Duration(n) * time.Second, nil
} //END FUNCTION

// #end
