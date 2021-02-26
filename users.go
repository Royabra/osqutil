package main

import (
	"fmt"
	"strings"
)

// Column map
var (
	mUsersColumnMap = map[string]string{
		"name":  "username",
		"sid":   "uuid",
		"shell": "shell",
	}
)

// Outputs a basic users query
func BasicUsersQuery(szColumnName string, szValue string, bCalcHash bool) string {
	// Checking if hash needs to be calculated
	if bCalcHash {
		fmt.Println("Calculating hash is not supported")
	}

	var szOperator string
	szQuery := "SELECT username, uuid, type, directory, shell FROM users WHERE "

	// Checking if changes need to be made to the vlaue
	if strings.ContainsAny(szValue, "*") {
		szValue = strings.ReplaceAll(szValue, "*", "%")
		szOperator = " LIKE "
	} else {
		szOperator = "="
	}

	//  Checking if column exists in map
	if tempVal, ok := mUsersColumnMap[szColumnName]; ok {
		// REturning query
		return szQuery + tempVal + szOperator + "'" + szValue + "';"
	} else {
		return "Incorrect Column Name \n Correct names are:\n name - username\n sid - user's security identifier\n shell - user's configured default shell"
	}
}
