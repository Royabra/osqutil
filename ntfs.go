package main

import (
	"fmt"
	"strings"
)

// Outputs a basic ntfs_acl_permissions query
func BasicNtfsQuery(szPath string, bCalcHash bool) string {
	var szOperator string
	if strings.ContainsAny(szPath, ".") {
		szOperator = "="
	} else {
		szPath = strings.ReplaceAll(szPath, "*", "%")
		szOperator = " LIKE "
	}
	var szBasicNtfsQuery string

	if !CheckPath(szPath) {
		fmt.Println("WARNING! this path wasn't found on your machine, are you sure it's spelled correctly? \n")
	}

	if bCalcHash {
		szBasicNtfsQuery = "SELECT nap.path, nap.type, nap.principal, nap.access, nap.inherited_from, h.sha1 from ntfs_acl_permissions nap JOIN " +
			"hash h ON nap.path=h.path WHERE path"
	} else {
		szBasicNtfsQuery = "SELECT * from ntfs_acl_permissions WHERE path"
	}

	return szBasicNtfsQuery + szOperator + "'" + szPath + "';"
}
