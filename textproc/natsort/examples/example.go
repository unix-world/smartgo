// Copyright 2018 Marc-Antoine Ruel. All rights reserved.
// Use of this source code is governed under the Apache License, Version 2.0
// that can be found in the LICENSE file.

package main

import (
	"fmt"
	"sort"
	"strings"

	natsort "github.com/unix-world/smartgo/textproc/natsort"
)

func main() {
	items := []string{
		"gpio10",
		"gpio1",
		"gpio20",
	}
	sort.Sort(natsort.StringSlice(items))
	fmt.Println(strings.Join(items, "\n"))
	// Output:
	// gpio1
	// gpio10
	// gpio20
}
