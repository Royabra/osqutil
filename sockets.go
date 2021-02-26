package main

import (
	"fmt"
	"strings"
)

// Column map
var (
	mSocketsColumnMap = map[string]string{
		"pid":     "p.pid",
		"name":    "p.name",
		"lport":   "pos.local_port",
		"rport":   "pos.remote_port",
		"address": "pos.remote_address",
	}
)

func BasicSocketsQuery(szColumnName string, szValue string, bCalcHash bool) string {
	// Checking if hash needs to be calculated
	if bCalcHash {
		fmt.Println("Calculating hash is not supported")
	}

	// Varibale declaration
	var szOperator string
	szQuery := "SELECT p.name, p.pid, pos.remote_address, pos.local_port, pos.remote_port FROM process_open_sockets pos JOIN processes p ON p.pid=pos.pid WHERE "

	// Checking if changes need to be made to the vlaue
	if strings.ContainsAny(szValue, "*") {
		szValue = strings.ReplaceAll(szValue, "*", "%")
		szOperator = " LIKE "
	} else {
		szOperator = "="
	}

	//  Checking if column exists in map
	if tempVal, ok := mSocketsColumnMap[szColumnName]; ok {
		// REturning query
		return szQuery + tempVal + szOperator + "'" + szValue + "';"
	} else {
		return "Incorrect Column Name\n Correct names are:\n pid - process id\n name - process name\n lport - local port\n rport - remote port\n address - remote address"
	}
}
