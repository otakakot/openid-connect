package database

import (
	"database/sql"

	_ "github.com/syumai/workers/cloudflare/d1"
)

var D1 *sql.DB

func init() {
	db, err := sql.Open("d1", "DB")
	if err != nil {
		panic("failed to connect database. error: " + err.Error())
	}

	if err = db.Ping(); err != nil {
		panic("failed to ping database. error: " + err.Error())
	}

	D1 = db
}
