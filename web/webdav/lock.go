
// SmartGo :: WebDAV :: Lock
// r.20241125.2358 :: STABLE
// (c) 2024 unix-world.org

// custom locking system (unixman)
// this is intended to run over SimpleCache or similar AutoManaged cleanup expiring entries !

package webdav

import (
	"time"
	"errors"
)


const (
//	lockTokenScheme string = "opaquelocktoken:"
	lockTokenScheme string = "urn:uuid:"

	FakeLockToken string = "00000000-0000-0000-0000-000000000000"
)


type LockSys struct { // internal locks should not be allowed to be unlocked from outside ; they only can be unlocked from inside or garbage collected
	Lock     func(internal bool, path string) (token string, err error)
	Exists   func(internal bool, token string) bool
	Unlock   func(internal bool, token string) (success bool, err error)
}


// LockDetails are a lock's metadata.
type LockDetails struct {
	// Root is the root resource name being locked. For a zero-depth lock, the
	// root is the only resource being locked.
	Root string
	// Duration is the lock timeout. A negative duration means infinite.
	Duration time.Duration
	// OwnerXML is the verbatim <owner> XML given in a LOCK HTTP request.
	//
	// TODO: does the "verbatim" nature play well with XML namespaces?
	// Does the OwnerXML field need to have more structure? See
	// https://codereview.appspot.com/175140043/#msg2
	OwnerXML string
	// ZeroDepth is whether the lock has zero depth. If it does not have zero
	// depth, it has infinite depth.
	ZeroDepth bool
}

var (
	// ErrConfirmationFailed is returned by a LockSystem's Confirm method.
	ErrConfirmationFailed = errors.New("webdav: confirmation failed")
	// ErrForbidden is returned by a LockSystem's Unlock method.
	ErrForbidden = errors.New("webdav: forbidden")
	// ErrLocked is returned by a LockSystem's Create, Refresh and Unlock methods.
	ErrLocked = errors.New("webdav: locked")
	// ErrNoSuchLock is returned by a LockSystem's Refresh and Unlock methods.
	ErrNoSuchLock = errors.New("webdav: no such lock")
)

// #end
