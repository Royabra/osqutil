package main

import (
	"fmt"
	"strings"
)

// Outputs a simple query for processes by their path
func ProcQueryByPath(szBinaryPath string, bCalcHash bool) string {
	if !CheckPath(szBinaryPath) {
		fmt.Println("WARNING! this path wasn't found on your machine, are you sure it's spelled correctly?")
	}

	if strings.ContainsAny(szBinaryPath, "*") && bCalcHash {
		return "SELECT p.name, p.pid, p.path, p.cmdline, u.username, h.sha1 FROM processes p JOIN users u ON u.uid=p.uid JOIN hash h ON h.path=p.path WHERE p.path LIKE '" +
			strings.ReplaceAll(szBinaryPath, "*", "%") + "';"
	} else if bCalcHash {
		return "SELECT p.name, p.pid, p.path, p.cmdline, u.username FROM processes p JOIN users u ON u.uid=p.uid JOIN hash h ON h.path=p.path WHERE p.path='" + szBinaryPath + "';"
	} else if strings.ContainsAny(szBinaryPath, "*") {
		return "SELECT p.name, p.pid, p.path, p.cmdline, u.username FROM processes p JOIN users u ON u.uid=p.uid JOIN WHERE p.path LIKE '" +
			strings.ReplaceAll(szBinaryPath, "*", "%") + "';"
	} else {
		return "SELECT p.name, p.pid, p.path, p.cmdline, u.username FROM processes p JOIN users u ON u.uid=p.uid WHERE p.path='" + szBinaryPath + "';"
	}
}

// A less wrapped query generator for processes
func ProcGenericQuery(szColumn string, szValue string, bCalcHash bool) string {
	if bCalcHash {
		fmt.Println("Calculating hash is not supported, try by path")
	}

	if strings.ContainsAny(szValue, "*") {
		return "SELECT p.name, p.pid, p.path, p.cmdline, u.username FROM processes p JOIN users u ON p.uid=u.uid WHERE p." +
			szColumn + " LIKE '" + strings.ReplaceAll(szValue, "*", "%") + "';"
	} else {
		return "SELECT p.name, p.pid, p.path, p.cmdline, u.username FROM processes p JOIN users u ON p.uid=u.uid WHERE p." +
			szColumn + "='" + szValue + "';"
	}
}
