
// GO Lang :: SmartGo DB :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20240117.2121 :: STABLE

// REQUIRE: go 1.19 or later
package smartdb

import (
	"fmt"
	"log"
	"strings"

	"database/sql"
	sqlite3 "github.com/unix-world/smartgo/db/sqlite3"
	pgsql   "github.com/unix-world/smartgo/db/lib-pq"
	mysql   "github.com/unix-world/smartgo/db/mysql"

	smart   "github.com/unix-world/smartgo"
)


//-----


const (
	DB_SQL_TYPE_SQLITE string = "sqlite3"
	DB_SQL_TYPE_PGSQL  string = "postgres"
	DB_SQL_TYPE_MYSQL  string = "mysql"

	HARD_LIMIT_ROWS    uint64 = 1000000 // get max 1 million rows
)

const SQLITE_INIT_META_TABLE string = `
BEGIN;
CREATE TABLE IF NOT EXISTS _smartframework_metadata (
	id VARCHAR(255) PRIMARY KEY UNIQUE, description TEXT
);
INSERT OR IGNORE INTO _smartframework_metadata VALUES('db-type-version',$1);
INSERT OR IGNORE INTO _smartframework_metadata VALUES('smartframework-version',$2);
INSERT OR IGNORE INTO _smartframework_metadata VALUES('creation-date-and-time',$3);
INSERT OR IGNORE INTO _smartframework_metadata VALUES('database-name',$4);
INSERT OR IGNORE INTO _smartframework_metadata VALUES('domain-realm-id',$5);
COMMIT;
`

const PGSQL_INIT_META_TABLE string = `
BEGIN;
CREATE SCHEMA IF NOT EXISTS smartframework;
COMMENT ON SCHEMA smartframework IS 'Smart.Framework Schema (do not delete)';
CREATE TABLE IF NOT EXISTS smartframework._metadata (
	id VARCHAR(255) PRIMARY KEY UNIQUE, description TEXT
);
COMMENT ON TABLE smartframework._metadata IS 'Smart.Framework Table MetaData (do not delete)';
INSERT INTO smartframework._metadata VALUES('db-type-version',$1) ON CONFLICT DO NOTHING;
INSERT INTO smartframework._metadata VALUES('smartframework-version',$2) ON CONFLICT DO NOTHING;
INSERT INTO smartframework._metadata VALUES('creation-date-and-time',$3) ON CONFLICT DO NOTHING;
INSERT INTO smartframework._metadata VALUES('database-name',$4) ON CONFLICT DO NOTHING;
INSERT INTO smartframework._metadata VALUES('domain-realm-id',$5) ON CONFLICT DO NOTHING;
COMMIT;
`

const MYSQL_INIT_META_TABLE string = `
-- BEGIN; // no DDL support
CREATE TABLE IF NOT EXISTS _smartframework_metadata (
	id VARCHAR(255) PRIMARY KEY UNIQUE, description TEXT
);
INSERT IGNORE INTO _smartframework_metadata VALUES('db-type-version',?1);
INSERT IGNORE INTO _smartframework_metadata VALUES('smartframework-version',?2);
INSERT IGNORE INTO _smartframework_metadata VALUES('creation-date-and-time',?3);
INSERT IGNORE INTO _smartframework_metadata VALUES('database-name',?4);
INSERT IGNORE INTO _smartframework_metadata VALUES('domain-realm-id',?5);
-- COMMIT; // no DDL support
`

//-----


type DbSqlConnector struct {
	dbType string
	dbUrl  string
	dbConn *sql.DB
	dbErr  error
	debug  bool
}


//-----

// TODO: sqlite3:
// 		* RegisterFunc()
// 		* support DSN: file:test.db?cache=shared&mode=memory ; file::memory: ; :memory:

func NewSqlDb(dbType string, dbUrl string, debug bool) (DbSqlConnector, error) {
	//--
	defer smart.PanicHandler()
	//--
	// Ex: dbType = "sqlite3"  ; dbUrl = "#db/sample.sqlite" |  dbUrl = "/path/to/#db/sample.sqlite"
	// Ex: dbType = "postgres" ; dbUrl = "postgres://user:pass@host:port/db_name?sslmode=disable"
	// Ex: dbType = "mysql"    ; dbUrl = "user:pass@tcp(127.0.0.1:3306)/db_name?collation_connection=utf8mb4_bin&multiStatements=true&tls=false"
	//--
	dbUrl = smart.StrTrimWhitespaces(dbUrl)
	//--
	emtyDbConn := DbSqlConnector{}
	//--
	switch(dbType) {
		case DB_SQL_TYPE_SQLITE: // showld allow absolute paths, ex: desktop apps with a path from config
			if(dbUrl == "") {
				return emtyDbConn, smart.NewError("Empty DB Connection String. Must be as `dir/db.sqlite` (relative path) or as `/dir/db.sqlite` (absolute path)")
			} //end if
			if(smart.StrStartsWith(dbUrl, ".")) {
				return emtyDbConn, smart.NewError("Invalid DB Connection URL Path Prefix (Must NOT start with a dot): " + dbUrl)
			} //end if
			if(smart.StrContains(dbUrl, "://")) {
				return emtyDbConn, smart.NewError("Invalid DB Connection URL Path Prefix (Must NOT start with ://): " + dbUrl)
			} //end if
			if(len(dbUrl) > 255) {
				return emtyDbConn, smart.NewError("Invalid DB Connection URL Suffix (Must have max 255 characters): " + dbUrl)
			} //end if
			testPath := strings.NewReplacer("/", "", "\\", "", ":", "")
			if(len(smart.StrTrimWhitespaces(testPath.Replace(dbUrl))) < 10) { // {{{SYNC-DB-SQLITE-FNAME-MIN-LEN}}} ; expected: extension + 3 letters prefix
				return emtyDbConn, smart.NewError("Invalid DB Connection URL Path (Must have at least 8 characters, ex: `abc.sqlite`): " + dbUrl)
			} //end if
			if(smart.PathIsEmptyOrRoot(dbUrl)) {
				return emtyDbConn, smart.NewError("Invalid DB Connection URL Path (Empty or Root): " + dbUrl)
			} //end if
			if(smart.PathIsBackwardUnsafe(dbUrl)) {
				return emtyDbConn, smart.NewError("Invalid DB Connection URL Path (Backward Unsafe): " + dbUrl)
			} //end if
			if(!smart.PathIsSafeValidSafePath(dbUrl)) {
				return emtyDbConn, smart.NewError("Invalid DB Connection URL Path (Must contain only SafePath/Restricted Characters): " + dbUrl)
			} //end if
			dir  := smart.StrTrimWhitespaces(smart.PathDirName(dbUrl))
			file := smart.StrTrimLeft(smart.StrTrimWhitespaces(smart.PathBaseName(dbUrl)), ".")
			if(
				(dir == "./") || // this is a special case, disallow being in the same dir as the executable
				smart.PathIsEmptyOrRoot(dir) ||
				smart.PathIsBackwardUnsafe(dir) ||
				(!smart.PathIsSafeValidSafePath(dir))) {
					return emtyDbConn, smart.NewError("Invalid DB Connection URL Path Dir: " + dir)
			} //end if
			if(smart.PathIsFile(dir)) {
				return emtyDbConn, smart.NewError("Invalid DB Connection URL Path: It points to an existing File: " + dir)
			} //end if
			dir = smart.PathAddDirLastSlash(dir)
			if(
				(dir == "./") || // this is a special case, disallow being in the same dir as the executable
				smart.PathIsEmptyOrRoot(dir) ||
				smart.PathIsBackwardUnsafe(dir) ||
				(!smart.PathIsSafeValidSafePath(dir))) {
					return emtyDbConn, smart.NewError("Invalid DB Connection URL Path with Trailing Slash: " + dir)
			} //end if
			if(len(file) < 10) { // {{{SYNC-DB-SQLITE-FNAME-MIN-LEN}}}
				return emtyDbConn, smart.NewError("Invalid DB Connection URL File Name Length (must be at least 10 characters): " + file)
			} //end if
			if(smart.StrStartsWith(file, ".")) {
				return emtyDbConn, smart.NewError("Invalid DB Connection URL File Name Prefix (Must NOT start with a dot): " + file)
			} //end if
			if(!smart.StrEndsWith(file, ".sqlite")) {
				return emtyDbConn, smart.NewError("Invalid DB Connection URL File Name Extension (Must end with .sqlite): " + file)
			} //end if
			if(!smart.PathIsSafeValidSafeFileName(file)) {
				return emtyDbConn, smart.NewError("Invalid DB Connection URL File Name Extension (Must end with .sqlite): " + file)
			} //end if
			safePath := dir + file
			if(!smart.PathIsSafeValidSafePath(safePath)) {
				return emtyDbConn, smart.NewError("Invalid DB Connection URL Canonicalized Path: " + safePath)
			} //end if
			if(smart.PathIsDir(safePath)) {
				return emtyDbConn, smart.NewError("Invalid DB Connection URL Path: It points to an existing Directory: " + safePath)
			} //end if
			if(!smart.PathExists(dir)) {
				log.Println("[NOTICE]", NAME, smart.CurrentFunctionName(), "DB Dir does not exists, will try to create it:", dir)
				okDir, errDir := smart.SafePathDirCreate(dir, true, true) // recursive, allow absolute
				if((okDir != true) || (errDir != nil)) {
					return emtyDbConn, smart.NewError("Failed to Create the DB Directory: " + dir)
				} //end if
				if(smart.PathExists(dir)) {
					log.Println("[INFO]", NAME, smart.CurrentFunctionName(), "DB Dir created:", dir)
				} else {
					log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Failed to create DB Dir:", dir)
				} //end if
			} //end if
			if(!smart.PathExists(dir)) {
				return emtyDbConn, smart.NewError("The DB Directory cannot be found: " + dir)
			} //end if
			dbUrl = safePath
			if(smart.PathIsDir(dbUrl)) {
				return emtyDbConn, smart.NewError("The DB Safe File points to an existing Directory: " + dbUrl)
			} //end if
			if(!smart.PathExists(dbUrl)) {
				log.Println("[NOTICE]", NAME, smart.CurrentFunctionName(), "DB File does not exists, will be initialized on first connection:", dbUrl)
			} //end if
			log.Println("[INFO]", NAME, smart.CurrentFunctionName(), "Driver is ready, using SQlite DB:", dbUrl)
			break
		case DB_SQL_TYPE_PGSQL:
			if((dbUrl == "") || (!smart.StrStartsWith(dbUrl, "postgres://"))) {
				return emtyDbConn, smart.NewError("PostgreSQL Connection String is empty or invalid, must be such as (example): `postgres://user:pass@host:port/db_name?sslmode=disable` and is: `" + dbUrl + "")
			} //end if
			break
		case DB_SQL_TYPE_MYSQL:
			if((dbUrl == "") || (!smart.StrContains(dbUrl, "multiStatements=true"))) {
				return emtyDbConn, smart.NewError("MySQL Connection String is empty or invalid, must be such as (example): `user:pass@tcp(127.0.0.1:3306)/db_name?collation_connection=utf8mb4_bin&multiStatements=true&tls=false` and is: `" + dbUrl + "")
			} //end if
			break
		default:
			return emtyDbConn, smart.NewError("Invalid DB Type: `" + dbType + "`")
	} //end switch
	//--
	conn := DbSqlConnector{
		dbType: dbType,
		dbUrl:  dbUrl,
		dbConn: nil,
		dbErr:  nil,
		debug:  debug,
	}
	//--
	return conn, nil
	//--
} //END FUNCTION


//-----


func (conn *DbSqlConnector) GetConnectionInfo() string {
	//--
	safeConnUrl := conn.dbUrl
	if(conn.dbType != DB_SQL_TYPE_SQLITE) {
		safeConnUrl = smart.StrRegexReplaceAll(`\:(.*)@`, safeConnUrl, `:*******@`) // mask password
	} //end if
	//--
	return "@ Connection: [" + conn.dbType + ":`" + safeConnUrl + "`]"
	//--
} //END FUNCTION


func (conn *DbSqlConnector) CheckConnection() bool {
	//--
	defer smart.PanicHandler()
	//--
	connDescr := conn.GetConnectionInfo()
	//--
	if(conn.dbConn == nil) {
		return false
	} //end if
	//--
	if(conn.dbConn.Ping() != nil) {
		log.Println("[WARNING]", NAME, smart.CurrentFunctionName(), "Ping Failed", connDescr)
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func (conn *DbSqlConnector) OpenConnection() (*sql.DB, error) {
	//--
	defer smart.PanicHandler()
	//--
	connDescr := conn.GetConnectionInfo()
	//--
	if(conn.CheckConnection() == true) {
		log.Println("[WARNING]", NAME, smart.CurrentFunctionName(), "Already Connected", connDescr)
		conn.dbErr = nil
		return conn.dbConn, nil
	} //end if
	//--
	if(conn.debug) {
		log.Println("[DEBUG]", NAME, smart.CurrentFunctionName(), connDescr)
	} //end if
	//--
	conn.dbConn, conn.dbErr = sql.Open(conn.dbType, conn.dbUrl)
	if(conn.dbErr != nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), connDescr)
		conn.dbConn = nil // reset
		return nil, conn.dbErr
	} //end if
	//--
	var initDbSQL string = ""
	var infoDbName string = ""
	if(conn.dbType == DB_SQL_TYPE_SQLITE) {
		infoDbName = conn.dbUrl // on SQLite is OK, it is the path to the file
		initDbSQL = smart.StrTrimWhitespaces(SQLITE_INIT_META_TABLE)
	} else if(conn.dbType == DB_SQL_TYPE_PGSQL) {
		infoDbName = "[smart:db:postgresql]" // {{{SYNC-SAVE-METAINFO-DB-NAME}}} ; IMPORTANT: on PostgreSQL SKIP this, is the connection string which contains sensitive data such as user/pass !
		initDbSQL = smart.StrTrimWhitespaces(PGSQL_INIT_META_TABLE)
	} else if(conn.dbType == DB_SQL_TYPE_MYSQL) {
		infoDbName = "[smart:db:mariadb]" // {{{SYNC-SAVE-METAINFO-DB-NAME}}} ; IMPORTANT: on MySQL SKIP this, is the connection string which contains sensitive data such as user/pass !
		initDbSQL = smart.StrTrimWhitespaces(MYSQL_INIT_META_TABLE)
	} //end if
	if(initDbSQL != "") {
		var errI error
		var params []any
		params = []any{
			conn.dbType,
			NAME + "." + VERSION,
			smart.DateNowUtc(),
			infoDbName, // {{{SYNC-SAVE-METAINFO-DB-NAME}}}
			"smart.framework.go",
		}
		if(conn.dbType == DB_SQL_TYPE_SQLITE) {
			_, errI = conn.dbConn.Exec(initDbSQL + "\n", params...)
		} else if(conn.dbType == DB_SQL_TYPE_PGSQL) { // postgresql does not support prepared statements within a single transaction
			for i := 0; i < len(params); i++ {
				initDbSQL = smart.StrReplaceAll(initDbSQL, fmt.Sprintf("$%d", (i+1)), pgsql.QuoteLiteral(fmt.Sprintf("%s", params[i])))
			} //end for
			_, errI = conn.dbConn.Exec(initDbSQL + "\n")
		} else if(conn.dbType == DB_SQL_TYPE_MYSQL) { // in MySQL package there is no support for quote ; however a simplistic (unsafe, safe just for ASCII) has been added by unixman
			for i := 0; i < len(params); i++ {
				initDbSQL = smart.StrReplaceAll(initDbSQL, fmt.Sprintf("?%d", (i+1)), mysql.QuoteAsciiStr(fmt.Sprintf("%s", params[i]))) // this is pretty unsafe for other scenarios, don't use with unknown strings !!!
			} //end for
			_, errI = conn.dbConn.Exec(initDbSQL + "\n")
		}
		if(errI != nil) {
			log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Failed to Initialize DB MetaData Table", connDescr, initDbSQL)
			conn.dbConn = nil // reset
			conn.dbErr = errI
			return nil, conn.dbErr
		} //end if
	} else {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "DB Initialization MetaData SQL is Empty", connDescr)
		conn.dbConn = nil // reset
		conn.dbErr = smart.NewError("DB Initialization MetaData Failed: `" + conn.dbUrl + "`")
		return nil, conn.dbErr
	} //end if
	//--
	if(conn.dbType == DB_SQL_TYPE_SQLITE) { // for SQLite check if DB file exists ; by example if dir write privileges prevent the file creation, this is an error
		if((!smart.PathExists(conn.dbUrl)) || (!smart.PathIsFile(conn.dbUrl))) { // file must exists
			log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "DB File Creation Error", connDescr)
			conn.dbConn = nil // reset
			conn.dbErr = smart.NewError("DB File Creation Failed: `" + conn.dbUrl + "`")
			return nil, conn.dbErr
		} //end if
		fSize, fSzMsgErr := smart.SafePathFileGetSize(conn.dbUrl, true)
		if((fSize <= 0) || (fSzMsgErr != nil)) { // file size must be greater than zero
			log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "DB File Creation Invalid Size (zero)", fSize, "Error:", fSzMsgErr, connDescr)
			conn.dbConn = nil // reset
			conn.dbErr = smart.NewError("DB File Creation Invalid Size (zero): `" + conn.dbUrl + "`")
			return nil, conn.dbErr
		} //end if
		libVersion, _, _ := sqlite3.Version()
		log.Println("SQLite3 Version:", libVersion, connDescr)
	} else if(conn.dbType == DB_SQL_TYPE_PGSQL) {
		var pgVersion string = ""
		var pgEncoding string = ""
		var pgTimeZone string = ""
		errVer := conn.dbConn.QueryRow("SHOW SERVER_VERSION").Scan(&pgVersion)
		if(errVer != nil) {
			log.Println("[WARNING]", NAME, smart.CurrentFunctionName(), "Failed to Get PostgreSQL Server Version", errVer)
		} //end if else
		errEnc := conn.dbConn.QueryRow("SHOW SERVER_ENCODING").Scan(&pgEncoding)
		if(errEnc != nil) {
			log.Println("[WARNING]", NAME, smart.CurrentFunctionName(), "Failed to Get PostgreSQL Server Encoding", errEnc)
		} //end if else
		_, errSetTz := conn.dbConn.Exec("SET TIMEZONE TO " + pgsql.QuoteLiteral(smart.DateTimeGetLocation()))
		if(errSetTz != nil) {
			log.Println("[WARNING]", NAME, smart.CurrentFunctionName(), "Failed to Set PostgreSQL Server TimeZone to: `" + smart.DateTimeGetLocation() + "`", errSetTz)
		} //end if
		errTz := conn.dbConn.QueryRow("SHOW TIMEZONE").Scan(&pgTimeZone)
		if(errTz != nil) {
			log.Println("[WARNING]", NAME, smart.CurrentFunctionName(), "Failed to Get PostgreSQL Server TimeZone", errTz)
		} //end if else
		log.Println("PostgreSQL Server", "Version: " + pgVersion + " ; Encoding: " + pgEncoding + " ; TimeZone: " + pgTimeZone, connDescr)
		if(smart.StrToUpper(smart.StrTrimWhitespaces(pgTimeZone)) != smart.StrToUpper(smart.DateTimeGetLocation())) {
			log.Println("[WARNING]", NAME, smart.CurrentFunctionName(), "Failed to Set PostgreSQL Server TimeZone to: `" + smart.DateTimeGetLocation() + "`", "Server=`" + pgTimeZone + "`", "Client=`" + smart.DateTimeGetLocation() + "`")
		} //end if
		if(smart.StrToUpper(smart.StrTrimWhitespaces(pgEncoding)) != ENCODING) {
			log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "PostgreSQL Server/Database Encoding is not `" + ENCODING + "` !", connDescr)
			conn.dbConn = nil // reset
			conn.dbErr = smart.NewError("PostgreSQL Server/Database Encoding must be `" + ENCODING + "` ! `" + conn.dbUrl + "`")
			return nil, conn.dbErr
		} //end if
	} else if(conn.dbType == DB_SQL_TYPE_MYSQL) {
		_, errSetCl := conn.dbConn.Exec("SET CHARACTER SET 'utf8mb4'; SET COLLATION_CONNECTION = 'utf8mb4_bin';")
		if(errSetCl != nil) {
			log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Failed to Set MySQL Server Connection Collation to: `UTF8.MB4`", errSetCl)
			conn.dbConn = nil // reset
			conn.dbErr = smart.NewError("MySQL Server Connection Collation cannot be set to `UTF8.MB4` ! `" + conn.dbUrl + "`")
			return nil, conn.dbErr
		} //end if
		var myVersion string = ""
		var myTimeZone string = ""
		errVer := conn.dbConn.QueryRow("SELECT VERSION()").Scan(&myVersion)
		if(errVer != nil) {
			log.Println("[WARNING]", NAME, smart.CurrentFunctionName(), "Failed to Get MySQL Server Version", errVer)
		} //end if else
		_, errSetTz := conn.dbConn.Exec("SET time_zone = ?", smart.DateTimeGetLocation())
		if(errSetTz != nil) {
			log.Println("[WARNING]", NAME, smart.CurrentFunctionName(), "Failed to Set MySQL Server TimeZone to: `" + smart.DateTimeGetLocation() + "`", errSetTz)
		} //end if
		errTz := conn.dbConn.QueryRow("SELECT @@SESSION.time_zone").Scan(&myTimeZone)
		if(errTz != nil) {
			log.Println("[WARNING]", NAME, smart.CurrentFunctionName(), "Failed to Get MySQL Server TimeZone", errTz)
		} //end if else
		log.Println("MySQL Server", "Version: " + myVersion + " ; Connection Collation: UTF8.MB4 ; TimeZone: " + myTimeZone, connDescr)
		if(smart.StrToUpper(smart.StrTrimWhitespaces(myTimeZone)) != smart.StrToUpper(smart.DateTimeGetLocation())) {
			log.Println("[WARNING]", NAME, smart.CurrentFunctionName(), "Failed to Set MySQL Server TimeZone to: `" + smart.DateTimeGetLocation() + "`", "Server=`" + myTimeZone + "`", "Client=`" + smart.DateTimeGetLocation() + "`")
		} //end if
	} //end if else
	//--
	return conn.dbConn, nil
	//--
} //END FUNCTION


func (conn *DbSqlConnector) CloseConnection() error {
	//--
	defer smart.PanicHandler()
	//--
	connDescr := conn.GetConnectionInfo()
	//--
	if(conn.debug) {
		log.Println("[DEBUG]", NAME, smart.CurrentFunctionName(), connDescr)
	} //end if
	//--
	if(conn.CheckConnection() != true) {
		log.Println("[WARNING]", NAME, smart.CurrentFunctionName(), "Not Connected", connDescr)
		conn.dbConn = nil // reset
		return nil
	} //end if
	//--
	conn.dbErr = conn.dbConn.Close()
	conn.dbConn = nil // reset
	//--
	if(conn.dbErr != nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), connDescr)
	} //end of
	//--
	return conn.dbErr
	//--
} //END FUNCTION


//-----


// In GoLang opposite to PHP, there is only one connection with possible asynchronous writes.
// Because of this, should NEVER use direct SQL: BEGIN / TOLLBACK / COMMIT on the connection, they should always be isolated insite a TX transaction !
func (conn *DbSqlConnector) TransactionStart() (*sql.Tx, error) {
	//--
	defer smart.PanicHandler()
	//--
	connDescr := conn.GetConnectionInfo()
	//--
	if(conn.debug) {
		log.Println("[DEBUG]", NAME, smart.CurrentFunctionName(), "TRANSACTION Start", connDescr)
	} //end if
	//--
	if(conn.CheckConnection() != true) {
		_, errC := conn.OpenConnection()
		if(errC != nil) {
			log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Connection Error", errC, connDescr)
			return nil, errC
		} //end if
	} //end if
	if(conn.dbConn == nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "No Connection", connDescr)
		return nil, smart.NewError("No Connection")
	} //end if
	//--
	tx, err := conn.dbConn.Begin()
	if(err != nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Begin", err, connDescr)
		return nil, err
	} //end if
	if(tx == nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Failed to Initiate Transaction", connDescr)
		return nil, smart.NewError("Failed to Initiate Transaction")
	} //end if
	//--
	return tx, nil
	//--
} //END FUNCTION


func (conn *DbSqlConnector) TransactionRollback(tx *sql.Tx) error {
	//--
	defer smart.PanicHandler()
	//--
	connDescr := conn.GetConnectionInfo()
	if(tx != nil) {
		connDescr += " # {Tx}"
	} //end if
	//--
	if(conn.debug) {
		log.Println("[DEBUG]", NAME, smart.CurrentFunctionName(), "TRANSACTION Rollback", connDescr)
	} //end if
	//--
	if(tx == nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Transaction is N/A", connDescr)
		return smart.NewError("Transaction is N/A")
	} //end if
	//--
	err := tx.Rollback()
	if(err != nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Rollback", err, connDescr)
	} //end if
	//--
	return err
	//--
} //END FUNCTION


func (conn *DbSqlConnector) TransactionCommit(tx *sql.Tx) error {
	//--
	defer smart.PanicHandler()
	//--
	connDescr := conn.GetConnectionInfo()
	if(tx != nil) {
		connDescr += " # {Tx}"
	} //end if
	//--
	if(conn.debug) {
		log.Println("[DEBUG]", NAME, smart.CurrentFunctionName(), "TRANSACTION Commit", connDescr)
	} //end if
	//--
	if(tx == nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Transaction is N/A", connDescr)
		return smart.NewError("Transaction is N/A")
	} //end if
	//--
	err := tx.Commit()
	if(err != nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Commit", err, connDescr)
	} //end if
	//--
	return err
	//--
} //END FUNCTION


//-----


func (conn *DbSqlConnector) WriteData(query string, params ...any) (int64, error) {
	//--
	defer smart.PanicHandler()
	//--
	return conn.writeExec(nil, query, params...)
	//--
} //END FUNCTION


func (conn *DbSqlConnector) WriteTxData(tx *sql.Tx, query string, params ...any) (int64, error) {
	//--
	defer smart.PanicHandler()
	//--
	if(tx == nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Transaction cannot be NULL", conn.GetConnectionInfo())
		return 0, smart.NewError("Transaction cannot be NULL")
	} //end if
	//--
	return conn.writeExec(tx, query, params...)
	//--
} //END FUNCTION


func (conn *DbSqlConnector) writeExec(tx *sql.Tx, query string, params ...any) (int64, error) {
	//--
	// return: affectedRows, err ; lastID is unsupported on PostgreSQL ; on SQLite is not important, so don't handle
	//--
	defer smart.PanicHandler()
	//--
	connDescr := conn.GetConnectionInfo()
	if(tx != nil) {
		connDescr += " # {Tx}"
	} //end if
	//--
	if(conn.debug) {
		log.Println("[DEBUG]", NAME, smart.CurrentFunctionName(), "Query Params:", params, connDescr)
		log.Println("[DATA]",  NAME, smart.CurrentFunctionName(), "Query String:", "\n" + smart.StrTrimWhitespaces(query) + "\n", connDescr)
	} //end if
	//--
	if(conn.CheckConnection() != true) {
		_, errC := conn.OpenConnection()
		if(errC != nil) {
			log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Connection Error", errC, connDescr)
			return 0, errC
		} //end if
	} //end if
	if(conn.dbConn == nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "No Connection", connDescr)
		return 0, smart.NewError("No Connection")
	} //end if
	//--
	var result sql.Result
	var errQ error
	if(tx != nil) {
		result, errQ = tx.Exec(query, params...)
	} else {
		result, errQ = conn.dbConn.Exec(query, params...)
	} //end if else
	if(errQ != nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Exec", errQ, connDescr, "::", query, params)
		return 0, errQ
	} //end if
	var affected int64 = 0
	var err error
	if(result != nil) {
		affected, err = result.RowsAffected()
		if(err != nil) {
			log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "RowsAffected", affected, err, connDescr)
			affected = 0
		} //end if
	} //end if
	result = nil // free mem
	//--
	return affected, nil
	//--
} //END FUNCTION


//-----


func (conn *DbSqlConnector) CountData(query string, params ...any) (int64, error) {
	//--
	defer smart.PanicHandler()
	//--
	return conn.countQueryRow(nil, query, params...)
	//--
} //END FUNCTION


func (conn *DbSqlConnector) CountTxData(tx *sql.Tx, query string, params ...any) (int64, error) {
	//--
	defer smart.PanicHandler()
	//--
	if(tx == nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Transaction cannot be NULL", conn.GetConnectionInfo())
		return 0, smart.NewError("Transaction cannot be NULL")
	} //end if
	//--
	return conn.countQueryRow(tx, query, params...)
	//--
} //END FUNCTION


func (conn *DbSqlConnector) countQueryRow(tx *sql.Tx, query string, params ...any) (int64, error) {
	//--
	defer smart.PanicHandler()
	//--
	connDescr := conn.GetConnectionInfo()
	if(tx != nil) {
		connDescr += " # {Tx}"
	} //end if
	//--
	if(conn.debug) {
		log.Println("[DEBUG]", NAME, smart.CurrentFunctionName(), "Query Params:", params, connDescr)
		log.Println("[DATA]",  NAME, smart.CurrentFunctionName(), "Query String:", "\n" + smart.StrTrimWhitespaces(query) + "\n", connDescr)
	} //end if
	//--
	if(conn.CheckConnection() != true) {
		_, errC := conn.OpenConnection()
		if(errC != nil) {
			log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Connection Error", errC, connDescr)
			return 0, errC
		} //end if
	} //end if
	if(conn.dbConn == nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "No Connection", connDescr)
		return 0, smart.NewError("No Connection")
	} //end if
	//--
	var count int64
	var errQ error
	if(tx != nil) {
		errQ = tx.QueryRow(query, params...).Scan(&count)
	} else {
		errQ = conn.dbConn.QueryRow(query, params...).Scan(&count)
	} //end if else
	if(errQ != nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "QueryRow", errQ, connDescr, "::", query, params)
		return 0, errQ
	} //end if
	//--
	return count, nil
	//--
} //END FUNCTION


//-----


func (conn *DbSqlConnector) ReadData(query string, params ...any) ([]map[string]string, error) {
	//--
	defer smart.PanicHandler()
	//--
	return conn.readQuery(nil, query, params...)
	//--
} //END FUNCTION


func (conn *DbSqlConnector) ReadTxData(tx *sql.Tx, query string, params ...any) ([]map[string]string, error) {
	//--
	defer smart.PanicHandler()
	//--
	if(tx == nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Transaction cannot be NULL", conn.GetConnectionInfo())
		return []map[string]string{}, smart.NewError("Transaction cannot be NULL")
	} //end if
	//--
	return conn.readQuery(tx, query, params...)
	//--
} //END FUNCTION


func (conn *DbSqlConnector) readQuery(tx *sql.Tx, query string, params ...any) ([]map[string]string, error) {
	//--
	defer smart.PanicHandler()
	//--
	connDescr := conn.GetConnectionInfo()
	if(tx != nil) {
		connDescr += " # {Tx}"
	} //end if
	//--
	emptyArr := []map[string]string{} // instead of return nil, return this as default
	//--
	if(conn.debug) {
		log.Println("[DEBUG]", NAME, smart.CurrentFunctionName(), "Query Params:", params, connDescr)
		log.Println("[DATA]",  NAME, smart.CurrentFunctionName(), "Query String:", "\n" + smart.StrTrimWhitespaces(query) + "\n", connDescr)
	} //end if
	//--
	if(conn.CheckConnection() != true) {
		_, errC := conn.OpenConnection()
		if(errC != nil) {
			log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Connection Error", errC, connDescr)
			return emptyArr, errC
		} //end if
	} //end if
	if(conn.dbConn == nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "No Connection", connDescr)
		return emptyArr, smart.NewError("No Connection")
	} //end if
	//--
	var rows *sql.Rows
	var errQ error
	if(tx != nil) {
		rows, errQ = tx.Query(query, params...)
	} else {
		rows, errQ = conn.dbConn.Query(query, params...)
	} //end if else
	if(errQ != nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Query", errQ, connDescr, "::", query, params)
		return emptyArr, errQ
	} //end if
	defer rows.Close()
	//--
	arr, errA := getArrDataFromSQLRows(rows, HARD_LIMIT_ROWS)
	if(errA != nil) { // no need to log again here, the above method will log
		return emptyArr, errA
	} //end if
	if(arr == nil) {
		arr = emptyArr
	} //end if
	//--
	return arr, nil
	//--
} //END FUNCTION


//-----


func (conn *DbSqlConnector) ReadOneData(query string, params ...any) (map[string]string, error) {
	//--
	// this method query should always use: LIMIT 1 ; if more than 1 rows returned will hit error
	//--
	defer smart.PanicHandler()
	//--
	return conn.readOneQuery(nil, query, params...)
	//--
} //END FUNCTION


func (conn *DbSqlConnector) ReadTxOneData(tx *sql.Tx, query string, params ...any) (map[string]string, error) {
	//--
	// this method query should always use: LIMIT 1 ; if more than 1 rows returned will hit error
	//--
	defer smart.PanicHandler()
	//--
	if(tx == nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Transaction cannot be NULL", conn.GetConnectionInfo())
		return map[string]string{}, smart.NewError("Transaction cannot be NULL")
	} //end if
	//--
	return conn.readOneQuery(tx, query, params...)
	//--
} //END FUNCTION


func (conn *DbSqlConnector) readOneQuery(tx *sql.Tx, query string, params ...any) (map[string]string, error) {
	//--
	// this method query should always use: LIMIT 1 ; if more than 1 rows returned will hit error
	//--
	defer smart.PanicHandler()
	//--
	connDescr := conn.GetConnectionInfo()
	if(tx != nil) {
		connDescr += " # {Tx}"
	} //end if
	//--
	emptyArr := map[string]string{} // instead of return nil, return this as default
	//--
	if(conn.debug) {
		log.Println("[DEBUG]", NAME, smart.CurrentFunctionName(), "Query Params:", params, connDescr)
		log.Println("[DATA]",  NAME, smart.CurrentFunctionName(), "Query String:", "\n" + smart.StrTrimWhitespaces(query) + "\n", connDescr)
	} //end if
	//--
	if(conn.CheckConnection() != true) {
		_, errC := conn.OpenConnection()
		if(errC != nil) {
			log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Connection Error", errC, connDescr)
			return emptyArr, errC
		} //end if
	} //end if
	if(conn.dbConn == nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "No Connection", connDescr)
		return emptyArr, smart.NewError("No Connection")
	} //end if
	//--
	var rows *sql.Rows
	var errQ error
	if(tx != nil) {
		rows, errQ = tx.Query(query, params...)
	} else {
		rows, errQ = conn.dbConn.Query(query, params...)
	} //end if else
	if(errQ != nil) {
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Query", errQ, connDescr, "::", query, params)
		return emptyArr, errQ
	} //end if
	defer rows.Close()
	//--
	arr, errA := getArrDataFromSQLRows(rows, 1)
	if(errA != nil) { // no need to log again here, the above method will log
		return emptyArr, errA
	} //end if
	oneArr := map[string]string{}
	if(arr != nil) {
		if(len(arr) == 1) {
			oneArr = arr[0]
		} //end if
	} //end if
	//--
	return oneArr, nil
	//--
} //END FUNCTION


//-----


func GetArrFromSQLRows(rows *sql.Rows) (arr []map[string]string, err error) {
	//--
	return getArrDataFromSQLRows(rows, HARD_LIMIT_ROWS)
	//--
} //END FUNCTION


func getArrDataFromSQLRows(rows *sql.Rows, hLimit uint64) (arr []map[string]string, err error) {
	//--
	defer smart.PanicHandler()
	//--
	emptyArr := []map[string]string{} // instead of return nil, return this as default
	//--
	arr = emptyArr
	err = nil
	//--
	if(rows == nil) {
		return
	} //end if
	//--
	cols, errCl := rows.Columns()
	if(errCl != nil) {
		arr = emptyArr // reset
		err = errCl
		log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Get Columns", err)
		return
	} //end if
	//--
	var rNum uint64 = 0
	for rows.Next() {
		rNum++
		if(rNum > hLimit) {
			err = smart.NewError("Hard Limit: Current Query returned more rows than the Allowed Limit")
			log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Scan Row #", rNum, "@", "Allowed Limit", hLimit, "::", err)
			return
		} //end if
		columns := make([]string, len(cols))
		columnPointers := make([]interface{}, len(cols))
		for i, _ := range columns {
			columnPointers[i] = &columns[i]
		} //end for
		errScn := rows.Scan(columnPointers...)
		if(errScn != nil) {
			arr = emptyArr // reset
			err = errScn
			log.Println("[ERROR]", NAME, smart.CurrentFunctionName(), "Scan Row #", rNum, "::", err)
			return
		} //end if
		data := make(map[string]string)
		for i, colName := range cols {
			data[colName] = columns[i]
		} //end for
		arr = append(arr, data)
	} //end for
	//--
	return
	//--
} //END FUNCTION


//-----


// #END
