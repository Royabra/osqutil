package main

import (
	"fmt"
	"strings"
)

func ParseRegKey(szRegKey string) (string, bool) {
	szSplitString := strings.Split(szRegKey, "\\")
	szHive := ParseHive(szSplitString[0])
	bContainsWildcard := strings.ContainsAny("*", szRegKey)
	if bContainsWildcard {
		szNewKey := strings.ReplaceAll(strings.Replace(szRegKey, szSplitString[0], szHive, 1), "*", "%")
		return szNewKey, bContainsWildcard
	} else {
		szNewKey := strings.Replace(szRegKey, szSplitString[0], szHive, 1)
		return szNewKey, bContainsWildcard
	}
}

// Checks specific hive in registry
func ParseHive(szHive string) string {
	szUpperHive := strings.ToUpper(szHive)
	switch szUpperHive {
	case "HKLM":
		return "HKEY_LOCAL_MACHINE"
	case "HKU":
		return "HKEY_USERS"
	case "HKCU":
		return "HKEY_CURRENT_USER"
	case "HKCR":
		return "HKEY_CLASSES_ROOT"
	case "HKCC":
		return "HKEY_CURRENT_CONFIG"
	default:
		return szUpperHive
	}
}

// Outputs the basic registry query for osquery
func BasicRegQuery(szRegKey string, bCalcHash bool) string {
	if bCalcHash {
		fmt.Println("Calculating hash is not supported")
	}

	szBasicQuery := "SELECT datetime(mtime, 'unixepoch', 'localtime') AS last_edited, data, path FROM registry WHERE path"
	szRegKey, bContainsWildcard := ParseRegKey(szRegKey)

	if bContainsWildcard {
		// checking if searching in hku for specific query
		if strings.Contains(szRegKey, "HKEY_USERS") {
			szBasicQuery = "SELECT datetime(reg.mtime, 'unixepoch', 'localtime') AS last_edited, reg.data, reg.path, u.username FROM registry reg JOIN users u ON split(reg.path, '\\', 1)=u.uuid WHERE path LIKE \"" + strings.ReplaceAll(szRegKey, "*", "%") + "\";"
		} else {
			szBasicQuery = szBasicQuery + " LIKE \"" + szRegKey + "\";"
		}
	} else {
		szBasicQuery = szBasicQuery + "=\"" + szRegKey + "\";"
	}
	return szBasicQuery
}
