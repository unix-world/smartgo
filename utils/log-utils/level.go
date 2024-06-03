
// GO Lang :: SmartGo/LogUtils :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20240117.2121 :: STABLE

// original source: github.com/hashicorp/logutils # (c) 2018 hashicorp

// Package logutils augments the standard log package with levels
package logutils


import (
	"bytes"
	"io"
	"sync"
)


type LogLevel string


// LevelFilter is an io.Writer that can be used with a logger that will
// filter out log messages that aren't at least a certain level.
// Once the filter is in use somewhere, it is not safe to modify the structure.
type LevelFilter struct {
	// Levels is the list of log levels, in increasing order of severity.
	Levels []LogLevel // Example: {"DEBUG", "WARN", "ERROR"}

	// MinLevel is the minimum level allowed through
	MinLevel LogLevel

	// The underlying io.Writer where log messages that pass the filter will be set.
	Writer io.Writer

	// Other, unhandled levels
	otherLevels map[LogLevel]struct{}

	// Synchro
	once sync.Once
}


// Check will check a given line if it would be included in the level filter.
func (f *LevelFilter) Check(line []byte) bool {
	//--
	f.once.Do(f.init)
	//-- Check for a log level
	var level LogLevel
	x := bytes.IndexByte(line, '[')
	if x >= 0 {
		y := bytes.IndexByte(line[x:], ']')
		if y >= 0 {
			level = LogLevel(line[x+1 : x+y])
		} //end if
	} //end if
	//--
	_, ok := f.otherLevels[level]
	//--
	return !ok
	//--
} //END FUNCTION


func (f *LevelFilter) Write(p []byte) (n int, err error) {
	//--
	// Note in general that io.Writer can receive any byte sequence
	// to write, but the "log" package always guarantees that we only
	// get a single line. We use that as a slight optimization within
	// this method, assuming we're dealing with a single, complete line
	// of log data.
	if !f.Check(p) {
		return len(p), nil
	} //end if
	//--
	return f.Writer.Write(p)
	//--
} //END FUNCTION


// SetMinLevel is used to update the minimum log level
func (f *LevelFilter) SetMinLevel(min LogLevel) {
	//--
	f.MinLevel = min
	f.init()
	//--
} //END FUNCTION


func (f *LevelFilter) init() {
	//--
	otherLevels := make(map[LogLevel]struct{})
	//--
	for _, level := range f.Levels {
		if level == f.MinLevel {
			break
		} //end if
		otherLevels[level] = struct{}{}
	} //end for
	//--
	f.otherLevels = otherLevels
	//--
} //END FUNCTION


// #end
