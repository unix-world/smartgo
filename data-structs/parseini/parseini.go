
// Go :: parse INI configuration files
// modified by unixman
// (c) 2022 unix-world.org
// r.20220410.0712

package parseini

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
	"strconv"
)

var (
	sectionRegex = regexp.MustCompile(`^\[(.*)\]$`)
	assignRegex  = regexp.MustCompile(`^([^=]+)=(.*)$`)
)


// A Data represents a parsed INI file.
type Data map[string]Section

// A Section represents a single section of an INI file.
type Section map[string]string

// ErrSyntax is returned when there is a syntax error in an INI file.
type ErrSyntax struct {
	Line   int64
	Source string // The contents of the erroneous line, without leading or trailing whitespace
}


func (e ErrSyntax) Error() string {
	return fmt.Sprintf("invalid INI syntax on line %d: %s", e.Line, e.Source)
} //END FUNCTION


// Returns a named Section. A Section will be created if one does not already exist for the given name.
func (f Data) Section(name string) Section {
	section := f[name]
	if(section == nil) {
		section = make(Section)
		f[name] = section
	} //end if
	return section
} //END FUNCTION


// Looks up a value for a key in a section and returns that value, along with a boolean result similar to a map lookup.
func (f Data) Get(section, key string) (value string, ok bool) {
	if s := f[section]; s != nil {
		value, ok = s[key]
	} //end if
	return
} //END FUNCTION


// Loads INI data from a reader and stores the data in the Data.
func (f Data) Load(in io.Reader) (err error) {
	bufin, ok := in.(*bufio.Reader)
	if(!ok) {
		bufin = bufio.NewReader(in)
	} //end if
	return parseData(bufin, f)
} //END FUNCTION


// Parse the INI Data
func parseData(in *bufio.Reader, dat Data) (err error) {
	section := ""
	lineNum := 0
	for done := false; !done; {
		var line string
		if line, err = in.ReadString('\n'); err != nil {
			if(err == io.EOF) {
				done = true
			} else {
				return
			} //end if else
		} //end if
		lineNum++
		line = strings.TrimSpace(line)
		if(len(line) == 0) {
			// Skip blank lines
			continue
		} //end if
		if line[0] == ';' || line[0] == '#' {
			// Skip comments
			continue
		} //end if
		if groups := assignRegex.FindStringSubmatch(line); groups != nil {
			key, val := groups[1], groups[2]
			key, val = strings.TrimSpace(key), strings.TrimSpace(val)
			dat.Section(section)[key] = val
		} else if groups := sectionRegex.FindStringSubmatch(line); groups != nil {
			name := strings.TrimSpace(groups[1])
			section = name
			// Create the section if it does not exist
			dat.Section(section)
		} else {
			return ErrSyntax{int64(lineNum), line}
		} //end if else
	} //end for
	return nil
} //END FUNCTION


// Loads and returns a Data from a string.
func Load(src string) (Data, error) {
	dat := make(Data)
	in := strings.NewReader(src)
	err := dat.Load(in)
	return dat, err
} //END FUNCTION


func GetIniStrVal(dat Data, section string, key string) string {
	//--
	str, ok := dat.Get(section, key)
	if(!ok) {
		str = ""
	} //end if
	//--
	return str
	//--
} //END FUNCTION


func GetIniIntVal(dat Data, section string, key string) int {
	//--
	str, ok := dat.Get(section, key)
	if(!ok) {
		str = ""
	} //end if
	//--
	i, err := strconv.Atoi(str)
	if(err != nil) {
		i = 0
	} //end if
	//--
	return i
	//--
} //END FUNCTION


// #END
