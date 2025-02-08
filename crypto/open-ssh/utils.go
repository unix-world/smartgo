
package openssh

import (
	"fmt"
	"reflect"

	"bytes"
	"strings"
	"strconv"

	"encoding/binary"
)


func contains(list []string, e string) bool {
	for _, s := range list {
		if s == e {
			return true
		}
	}
	return false
}


func parseString(in []byte) (out, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	in = in[4:]
	if uint32(len(in)) < length {
		return
	}
	out = in[:length]
	rest = in[length:]
	ok = true
	return
}


func parseNameList(in []byte) (out []string, rest []byte, ok bool) {
	contents, rest, ok := parseString(in)
	if !ok {
		return
	}
	if len(contents) == 0 {
		out = emptyNameList
		return
	}
	parts := bytes.Split(contents, comma)
	out = make([]string, len(parts))
	for i, part := range parts {
		out[i] = string(part)
	}
	return
}


// typeTags returns the possible type bytes for the given reflect.Type, which
// should be a struct. The possible values are separated by a '|' character.
func typeTags(structType reflect.Type) (tags []byte) {
	tagStr := structType.Field(0).Tag.Get("sshtype")

	for _, tag := range strings.Split(tagStr, "|") {
		i, err := strconv.Atoi(tag)
		if err == nil {
			tags = append(tags, byte(i))
		}
	}

	return tags
}


// parseError results from a malformed SSH message.
func parseError(tag uint8) error {
	return fmt.Errorf("ssh: parse error in message type %d", tag)
}


func fieldError(t reflect.Type, field int, problem string) error {
	if problem != "" {
		problem = ": " + problem
	}
	return fmt.Errorf("ssh: unmarshal error for field %s of type %s%s", t.Field(field).Name, t.Name(), problem)
}


//#end
