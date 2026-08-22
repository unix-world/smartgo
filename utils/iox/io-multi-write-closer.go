
// Go IO Extend
// (c) 2026-present, unix-world.org
// r.20260821.2358

package iox

// adapted from go source: src/io/multi.go

import (
	"errors"
	"io"
)


//-----

type multiWriteCloser struct {
	writers []io.WriteCloser
}

//-----


func (t *multiWriteCloser) WriteString(s string) (n int, err error) {
//	var _ io.StringWriter = (*multiWriteCloser)(nil)
	var p []byte // lazily initialized if/when needed
	for _, w := range t.writers {
		if sw, ok := w.(io.StringWriter); ok {
			n, err = sw.WriteString(s)
		} else {
			if p == nil {
				p = []byte(s)
			}
			n, err = w.Write(p)
		}
		if err != nil {
			return
		}
		if n != len(s) {
			err = errors.New("short write")
			return
		}
	}
	return len(s), nil
}



// Write implements the Writer interface.
func (t *multiWriteCloser) Write(p []byte) (int, error) {
	for _, w := range t.writers {
		n, err := w.Write(p)
		if err != nil {
			return n, err
		}
		if n != len(p) {
			err = io.ErrShortWrite
			return n, err
		}
	}
	return len(p), nil
}


// Close implements the Closer interface.
func (t *multiWriteCloser) Close() error {
	for _, wc := range t.writers {
		err := wc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}


// MultiWriteCloser creates a WriteCloser that duplicates its writes to all the
// provided writers, similar to the Unix tee(1) command.
//
// Each write is written to each listed writer, one at a time.
// If a listed writer returns an error, that overall write operation
// stops and returns the error; it does not continue down the list.
func MultiWriteCloser(writers ...io.WriteCloser) io.WriteCloser {
	allWriters := make([]io.WriteCloser, 0, len(writers))
	for _, w := range writers {
		if mw, ok := w.(*multiWriteCloser); ok {
			allWriters = append(allWriters, mw.writers...)
		} else {
			allWriters = append(allWriters, w)
		}
	}
	return &multiWriteCloser{allWriters}
}


//-----


// #END
