package main

import (
	"fmt"
	"strings"
)

func BasicPatchesQuery(szPatchName string, bExist bool, bCalcHash bool) string {
	if bCalcHash {
		fmt.Println("Calculating hash is not supported")
	}

	szQuery := "SELECT * FROM patches WHERE "
	szSearchOperator := "="
	if strings.ContainsAny(szPatchName, "*") {
		szPatchName = strings.ReplaceAll(szPatchName, "*", "%")
		szSearchOperator = " LIKE "
	}

	if bExist {
		szQuery += "hotfix_id" + szSearchOperator + szPatchName + ";"
	} else {
		szQuery = "SELECT distinct 1 FROM patches WHERE NOT ('" + szPatchName + "'" + szSearchOperator + "(select hotfix_id from patches));"
	}

	return szQuery
}
