
// SmartGo :: WebDAV :: File
// r.20250207.2358 :: STABLE
// (c) 2024-present unix-world.org

// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package webdav

import (
	"context"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"log" // unixman

	smart "github.com/unix-world/smartgo" // unixman
)

// slashClean is equivalent to but slightly more efficient than
// path.Clean("/" + name).
func slashClean(name string) string {
	//-- unixman
	name = smart.StrTrimWhitespaces(name)
	name = smart.SafePathFixClean(name) // fix prior to below tests ; avoid use OS context dir separator, have them all unix style (safety) !
	//-- #unixman
	if name == "" || name[0] != '/' {
		name = "/" + name
	}
	//-- unixman
//	return path.Clean(name)
	return name // no need to fix again, was fixed above
	//-- #unixman
} //END FUNCTION

// A FileSystem implements access to a collection of named files. The elements
// in a file path are separated by slash ('/', U+002F) characters, regardless
// of host operating system convention.
//
// Each method has the same semantics as the os package's function of the same
// name.
//
// Note that the os.Rename documentation says that "OS-specific restrictions
// might apply". In particular, whether or not renaming a file or directory
// overwriting another existing file or directory is an error is OS-dependent.
type FileSystem interface {
	GetRealPath(ctx context.Context, name string) (string, error) // unixman
	Mkdir(ctx context.Context, name string, perm os.FileMode) error
	OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (File, error)
	RemoveAll(ctx context.Context, name string) error
	Rename(ctx context.Context, oldName, newName string) error
	Stat(ctx context.Context, name string) (os.FileInfo, error)
}

// A File is returned by a FileSystem's OpenFile method and can be served by a
// Handler.
//
// A File may optionally implement the DeadPropsHolder interface, if it can
// load and save dead properties.
type File interface {
	http.File
	io.Writer
}

// A Dir implements FileSystem using the native file system restricted to a
// specific directory tree.
//
// While the FileSystem.OpenFile method takes '/'-separated paths, a Dir's
// string value is a filename on the native file system, not a URL, so it is
// separated by filepath.Separator, which isn't necessarily '/'.
//
// An empty Dir is treated as ".".
type Dir string

func (d Dir) resolve(name string) string {
	//-- unixman
	if((name != "") && (name != "/")) {
		if(useSmartSafeValidPaths) {
			if(smart.PathIsSafeValidSafePath(name) != true) {
				log.Println("[NOTICE]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "Unsafe SmartValid Path Name (Rejected): `" + name + "`")
				return ""
			} //end if
		} else {
			if(smart.PathIsSafeValidPath(name) != true) {
				log.Println("[NOTICE]", "SmartGo::WebDAV", smart.CurrentFunctionName(), "Unsafe Valid Path Name (Rejected): `" + name + "`")
				return ""
			} //end if
		} //end if
	} //end if
	//-- #unixman
	// This implementation is based on Dir.Open's code in the standard net/http package.
	if filepath.Separator != '/' && strings.IndexRune(name, filepath.Separator) >= 0 || strings.Contains(name, "\x00") {
		return ""
	}
	dir := string(d)
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, filepath.FromSlash(slashClean(name)))
} //END FUNCTION

//-- unixman
func (d Dir) GetRealPath(ctx context.Context, name string) (string, error) {
	if name = d.resolve(name); name == "" {
		return "", os.ErrInvalid
	}
	return name, nil
} //END FUNCTION
//-- #unixman

func (d Dir) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	if name = d.resolve(name); name == "" {
		return os.ErrNotExist
	}
	return os.Mkdir(name, perm)
} //END FUNCTION

func (d Dir) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (File, error) {
	//--
	defer smart.PanicHandler()
	//--
	if name = d.resolve(name); name == "" {
		return nil, os.ErrNotExist
	}
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return f, nil
} //END FUNCTION

func (d Dir) RemoveAll(ctx context.Context, name string) error {
	if name = d.resolve(name); name == "" {
		return os.ErrNotExist
	}
	//-- unixman: fix: test all 3 cases ; filepath.Clean is OS dependent
//	if name == filepath.Clean(string(d)) {
	if((name == string(d)) || (name == filepath.Clean(string(d))) || (name == smart.SafePathFixClean(string(d)))) {
	//-- # unixman
		// Prohibit removing the virtual root directory.
		return os.ErrInvalid
	}
	return os.RemoveAll(name)
} //END FUNCTION

func (d Dir) Rename(ctx context.Context, oldName, newName string) error {
	if oldName = d.resolve(oldName); oldName == "" {
		return os.ErrNotExist
	}
	if newName = d.resolve(newName); newName == "" {
		return os.ErrNotExist
	}
	//-- unixman: fix: test all 3 cases ; filepath.Clean is OS dependent
//	if root := filepath.Clean(string(d)); root == oldName || root == newName {
	root1 := filepath.Clean(string(d));
	root2 := smart.SafePathFixClean(string(d));
	if((string(d) == oldName) || (string(d) == newName) ||
		(root1 == oldName) || (root1 == newName) ||
		(root2 == smart.SafePathFixClean(oldName)) || (root2 == smart.SafePathFixClean(newName))) {
	//-- # unixman
		// Prohibit renaming from or to the virtual root directory.
		return os.ErrInvalid
	}
	return os.Rename(oldName, newName)
} //END FUNCTION

func (d Dir) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	if name = d.resolve(name); name == "" {
		return nil, os.ErrNotExist
	}
	return os.Stat(name)
} //END FUNCTION


// moveFiles moves files and/or directories from src to dst.
//
// See section 9.9.4 for when various HTTP status codes apply.
func moveFiles(ctx context.Context, fs FileSystem, src, dst string, overwrite bool) (status int, err error) {
	created := false
	if _, err := fs.Stat(ctx, dst); err != nil {
		if !os.IsNotExist(err) {
			return http.StatusForbidden, err
		}
		created = true
	} else if overwrite {
		// Section 9.9.3 says that "If a resource exists at the destination
		// and the Overwrite header is "T", then prior to performing the move,
		// the server must perform a DELETE with "Depth: infinity" on the
		// destination resource.
		if err := fs.RemoveAll(ctx, dst); err != nil {
			return http.StatusForbidden, err
		}
	} else {
		return http.StatusPreconditionFailed, os.ErrExist
	}
	if err := fs.Rename(ctx, src, dst); err != nil {
		return http.StatusForbidden, err
	}
	if created {
		return http.StatusCreated, nil
	}
	return http.StatusNoContent, nil
} //END FUNCTION

func copyProps(dst, src File) error {
	d, ok := dst.(DeadPropsHolder)
	if !ok {
		return nil
	}
	s, ok := src.(DeadPropsHolder)
	if !ok {
		return nil
	}
	m, err := s.DeadProps()
	if err != nil {
		return err
	}
	props := make([]Property, 0, len(m))
	for _, prop := range m {
		props = append(props, prop)
	}
	_, err = d.Patch([]Proppatch{{Props: props}})
	return err
} //END FUNCTION

// copyFiles copies files and/or directories from src to dst.
//
// See section 9.8.5 for when various HTTP status codes apply.
func copyFiles(ctx context.Context, fs FileSystem, src, dst string, overwrite bool, depth int, recursion int) (status int, err error) {
	if recursion == 1000 {
		return http.StatusInternalServerError, errRecursionTooDeep
	}
	recursion++

	// TODO: section 9.8.3 says that "Note that an infinite-depth COPY of /A/
	// into /A/B/ could lead to infinite recursion if not handled correctly."

	srcFile, err := fs.OpenFile(ctx, src, os.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return http.StatusNotFound, err
		}
		return http.StatusInternalServerError, err
	}
	defer srcFile.Close()
	srcStat, err := srcFile.Stat()
	if err != nil {
		if os.IsNotExist(err) {
			return http.StatusNotFound, err
		}
		return http.StatusInternalServerError, err
	}
	srcPerm := srcStat.Mode() & os.ModePerm

	created := false
	if _, err := fs.Stat(ctx, dst); err != nil {
		if os.IsNotExist(err) {
			created = true
		} else {
			return http.StatusForbidden, err
		}
	} else {
		if !overwrite {
			return http.StatusPreconditionFailed, os.ErrExist
		}
		if err := fs.RemoveAll(ctx, dst); err != nil && !os.IsNotExist(err) {
			return http.StatusForbidden, err
		}
	}

	if srcStat.IsDir() {
		if err := fs.Mkdir(ctx, dst, srcPerm); err != nil {
			return http.StatusForbidden, err
		}
		if depth == infiniteDepth {
			children, err := srcFile.Readdir(-1)
			if err != nil {
				return http.StatusForbidden, err
			}
			for _, c := range children {
				name := c.Name()
				s := path.Join(src, name)
				d := path.Join(dst, name)
				cStatus, cErr := copyFiles(ctx, fs, s, d, overwrite, depth, recursion)
				if cErr != nil {
					// TODO: MultiStatus.
					return cStatus, cErr
				}
			}
		}

	} else {
		dstFile, err := fs.OpenFile(ctx, dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, srcPerm)
		if err != nil {
			if os.IsNotExist(err) {
				return http.StatusConflict, err
			}
			return http.StatusForbidden, err

		}
		_, copyErr := io.Copy(dstFile, srcFile)
		propsErr := copyProps(dstFile, srcFile)
		closeErr := dstFile.Close()
		if copyErr != nil {
			return http.StatusInternalServerError, copyErr
		}
		if propsErr != nil {
			return http.StatusInternalServerError, propsErr
		}
		if closeErr != nil {
			return http.StatusInternalServerError, closeErr
		}
	}

	if created {
		return http.StatusCreated, nil
	}
	return http.StatusNoContent, nil
} //END FUNCTION

// walkFS traverses filesystem fs starting at name up to depth levels.
//
// Allowed values for depth are 0, 1 or infiniteDepth. For each visited node,
// walkFS calls walkFn. If a visited file system node is a directory and
// walkFn returns filepath.SkipDir, walkFS will skip traversal of this node.
func walkFS(ctx context.Context, fs FileSystem, depth int, name string, info os.FileInfo, walkFn filepath.WalkFunc) error {
	// This implementation is based on Walk's code in the standard path/filepath package.
	err := walkFn(name, info, nil)
	if err != nil {
		if info.IsDir() && err == filepath.SkipDir {
			return nil
		}
		return err
	}
	if !info.IsDir() || depth == 0 {
		return nil
	}
	if depth == 1 {
		depth = 0
	}

	// Read directory names.
	f, err := fs.OpenFile(ctx, name, os.O_RDONLY, 0)
	if err != nil {
		return walkFn(name, info, err)
	}
	fileInfos, err := f.Readdir(0)
	f.Close()
	if err != nil {
		return walkFn(name, info, err)
	}

	for _, fileInfo := range fileInfos {
		filename := path.Join(name, fileInfo.Name())
		fileInfo, err := fs.Stat(ctx, filename)
		if err != nil {
			if err := walkFn(filename, fileInfo, err); err != nil && err != filepath.SkipDir {
				return err
			}
		} else {
			//--
		//	isDir := fileInfo.Mode().IsDir()
		//	modifTime := fileInfo.ModTime()
			//--
			// TODO: vcf / ics:
		//	if((!isDir) && smart.StrEndsWith(fileInfo.Name(), ".ics")) {
		//		// ...
		//	} else {
		//		// ...
		//	} //end if else
			//--
			err = walkFS(ctx, fs, depth, filename, fileInfo, walkFn)
			if err != nil {
				if !fileInfo.IsDir() || err != filepath.SkipDir {
					return err
				}
			}
			//--
		}
	}
	return nil
} //END FUNCTION

// #end
