package main

import (
	"fmt"
	"strings"
)

// Outputs a basic ntfs_acl_permissions query
func BasicNtfsQuery(szPath string, bCalcHash bool) string {
	bIsFile := strings.ContainsAny(szPath, ".")
	szBasicNtfsQuery := "SELECT "

	if !CheckPath(szPath) {
		fmt.Println("WARNING! this path wasn't found on your machine, are you sure it's spelled correctly? \n")
	}

	if bIsFile && bCalcHash {
		szBasicNtfsQuery = szBasicNtfsQuery + "nap.path, nap.type, nap.principal, nap.access, nap.inherited_from, h.sha1 from ntfs_acl_permissions nap JOIN " +
			"hash h ON nap.path=h.path WHERE path='" + szPath + "';"
	} else if bIsFile {
		szBasicNtfsQuery = szBasicNtfsQuery + "* from ntfs_acl_permissions WHERE path='" + szPath + "';"
	} else if bCalcHash {
		szBasicNtfsQuery = szBasicNtfsQuery + "nap.path, nap.type, nap.principal, nap.access, nap.inherited_from, h.sha1 from ntfs_acl_permissions nap JOIN " +
			"hash h ON nap.path=h.path WHERE path LIKE '" + strings.ReplaceAll(szPath, "*", "%") + "%';"
	} else {
		szBasicNtfsQuery = szBasicNtfsQuery + "* from ntfs_acl_permissions WHERE path LIKE '" + strings.ReplaceAll(szPath, "*", "%") + "%';"
	}

	return szBasicNtfsQuery
}
