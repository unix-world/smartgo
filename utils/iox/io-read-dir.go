
// Go IO Extend
// (c) 2026-present, unix-world.org
// r.20260821.2358

package iox

// supplied from go source: src/ioutil.go which is deprecated

import (
	"os"
	"io/fs"

	"strings"
	"slices"
)


//-----


// ReadDir reads the directory named by dirname and returns
// a list of fs.FileInfo for the directory's contents,
// sorted by filename. If an error occurs reading the directory,
// ReadDir returns no directory entries along with the error.
//
// The method below, ioutil.ReadDir, was Deprecated as of Go 1.16 in ioutil,
// but a copy of it is below for maintaining compatibility with old code
//
// As an alternative to this method to obtain a list of [fs.FileInfo], you can:
//	entries, err := os.ReadDir(dirname)
//	if err != nil { ... }
//	infos := make([]fs.FileInfo, 0, len(entries))
//	for _, entry := range entries {
//		info, err := entry.Info()
//		if err != nil { ... }
//		infos = append(infos, info)
//	}
func ReadDir(dirname string) ([]fs.FileInfo, error) {
	f, err := os.Open(dirname)
	if err != nil {
		return nil, err
	}
	list, err := f.Readdir(-1)
	f.Close()
	if err != nil {
		return nil, err
	}
	slices.SortFunc(list, func(a, b os.FileInfo) int {
		return strings.Compare(a.Name(), b.Name())
	})
	return list, nil
}


//-----


// #END
