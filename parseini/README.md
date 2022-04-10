go-ini
======

INI parsing library for Go (golang)
This is a modified version of the original package at: github.com/vaughan0/go-ini

Usage
-----

Parse an INI file:

```go
package main

import (
	ini "github.com/unix-world/smartgo/parseini"
)

func main() {
	content, err := ioutil.ReadFile("myfile.ini")
	if(err == nil) {
		dat, err := ini.Load(string(content))
		if(err == nil) {
			log.Println(ini.GetIniStrVal(dat, "apples", "colour"))
			log.Println(ini.GetIniIntVal(dat, "numbers", "one")
		}
	}
}

```

File Format
-----------

INI files are parsed by go-ini line-by-line. Each line may be one of the following:

  * A section definition: [section-name]
  * A property: key = value
  * A comment: #blahblah _or_ ;blahblah
  * Blank. The line will be ignored.

Properties defined before any section headers are placed in the default section, which has
the empty string as it's key.

Example:

```ini
# I am a comment
; So am I!

[apples]
colour = red or green
shape = applish

[oranges]
shape = square
colour = blue

[numbers]
one = 1
two = 2
```
