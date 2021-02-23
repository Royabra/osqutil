package main

import (
	"fmt"
	"strings"
)

// Outputs a query that queries services by name
func ServiceQueryByName(szServiceName string, bCalcHash bool) string {

	if bCalcHash {
		println("Calculating hash is not supported")
	}

	if strings.ContainsAny(szServiceName, "*") {
		return "SELECT name, path, user_account, status, start_type FROM services WHERE name LIKE '" + strings.ReplaceAll(szServiceName, "*", "%") + "';"
	} else {
		return "SELECT name, path, user_account, status, start_type FROM services WHERE name='" + szServiceName + "';"
	}
}

// Outputs a query that queries services by their binary path
func ServiceQueryByPath(szBinaryPath string, bCalcHash bool) string {
	if !CheckPath(szBinaryPath) {
		fmt.Println("WARNING! this path wasn't found on your machine, are you sure it's spelled correctly? \n")
	}

	if bCalcHash {
		println("Calculating hash is not supported")
	}

	if strings.ContainsAny(szBinaryPath, "*") {
		return "SELECT name, path, user_account, status, start_type FROM services WHERE path LIKE '" + strings.ReplaceAll(szBinaryPath, "*", "%") + "';"
	} else {
		return "SELECT name, path, user_account, status, start_type FROM services WHERE path='" + szBinaryPath + "';"
	}
}
