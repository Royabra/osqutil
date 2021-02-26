package main

import (
	"fmt"
	"strings"
)

// Column map
var (
	mMemoryColumnMap = map[string]string{
		"name":        "p.name",
		"pid":         "p.pid",
		"permissions": "pmm.permissions",
		"path":        "pmm.path",
	}
)

// Outputs a basic users query
func BasicMemoryQuery(szColumnName string, szValue string, bCalcHash bool) string {
	// Checking if hash needs to be calculated
	if bCalcHash {
		fmt.Println("Calculating hash is not supported")
	}

	var szOperator string
	szQuery := "SELECT p.name, p.pid, pmm.permissions, pmm.path, pmm.start, pmm.end FROM process_memory_map pmm JOIN processes p ON p.pid=pmm.pid WHERE "

	// Checking if changes need to be made to the vlaue
	if strings.ContainsAny(szValue, "*") {
		szValue = strings.ReplaceAll(szValue, "*", "%")
		szOperator = " LIKE "
	} else {
		szOperator = "="
	}

	//  Checking if column exists in map
	if tempVal, ok := mMemoryColumnMap[szColumnName]; ok {
		// REturning query
		return szQuery + tempVal + szOperator + "'" + szValue + "';"
	} else {
		return "Incorrect Column Name \n Correct names are:\n name - process name\n pid  - process id\n permissions - page permissions\n path - loaded module path"
	}
}
