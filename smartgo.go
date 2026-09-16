
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260915.2358 :: STABLE

// REQUIRE: go 1.24 or later (depends on Go generics, available since go 1.18 but stable only since go 1.19)
package smartgo

//-----

const (
	VERSION string = "v.20260915.2358"
	NAME string = "SmartGo"

	DESCRIPTION string = "Smart.Framework.Go"
	COPYRIGHT string = "(c) 2021-present, unix-world.org"
)

var (
	DEBUG bool = false
)

//-----


func init() {
	//--
	registerMimeTypes()
	//--
} //END FUNCTION


//-----


// #END
