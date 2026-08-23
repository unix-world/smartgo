package mongokit

import (
	"github.com/unix-world/smartgo/db/mongo-driver/bson"

	"github.com/unix-world/smartgo/db/lungo/bsonkit"
)

// Distinct will perform a MongoDB distinct value search on the list of documents
// and return an array with the results.
func Distinct(list bsonkit.List, path string) bson.A {
	return bsonkit.Collect(list, path, true, true, true, true)
}
