package main

import (
	"fmt"
	"strings"
)

// Column map
var (
	mPipesColumnMap = map[string]string{
		"pid":  "p.pid",
		"name": "p.name",
		"pipe": "pipe.name",
		"flag": "pipe.flags",
	}
)

// Outputs a basic pipes query
func BasicPipesQuery(szColumnName string, szValue string, bCalcHash bool) string {
	// Checking if hash needs to be calculated
	if bCalcHash {
		fmt.Println("Calculating hash is not supported")
	}

	var szOperator string
	szQuery := "SELECT p.name, p.path, p.pid, pipe.name, pipe.flags FROM pipes pipe JOIN processes p ON p.pid=pipe.pid WHERE "

	// Checking if changes need to be made to the vlaue
	if strings.ContainsAny(szValue, "*") {
		szValue = strings.ReplaceAll(szValue, "*", "%")
		szOperator = " LIKE "
	} else {
		szOperator = "="
	}

	//  Checking if column exists in map
	if tempVal, ok := mPipesColumnMap[szColumnName]; ok {
		// REturning query
		return szQuery + tempVal + szOperator + "'" + szValue + "';"
	} else {
		return "Incorrect Column Name \n Correct names are:\n name - process name\n pid - process id\n pipe - pipe name\n flag - flags indicating whether the pipe is client or server, and if the pipe is sending messages or bytes"
	}
}
