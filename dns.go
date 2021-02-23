package main

import (
	"fmt"
	"strings"
)

// Outputs a basic dns_cache query
func BasicDnsQuery(szDomain string, bCalcHash bool) string {
	if bCalcHash {
		fmt.Println("Calculating hash is not supported")
	}

	if strings.ContainsAny(szDomain, "*") {
		return "SELECT * FROM dns_cache WHERE name LIKE '" + strings.ReplaceAll(szDomain, "*", "%") + "';"
	} else {
		return "SELECT * FROM dns_cache WHERE name='" + szDomain + "'"
	}
}
