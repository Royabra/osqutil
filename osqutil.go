package main

import (
	//"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	cfUnicodetext = 13
	gmemMoveable  = 0x0002
)

var (
	user32           = syscall.MustLoadDLL("user32")
	openClipboard    = user32.MustFindProc("OpenClipboard")
	closeClipboard   = user32.MustFindProc("CloseClipboard")
	emptyClipboard   = user32.MustFindProc("EmptyClipboard")
	getClipboardData = user32.MustFindProc("GetClipboardData")
	setClipboardData = user32.MustFindProc("SetClipboardData")

	kernel32     = syscall.NewLazyDLL("kernel32")
	globalAlloc  = kernel32.NewProc("GlobalAlloc")
	globalFree   = kernel32.NewProc("GlobalFree")
	globalLock   = kernel32.NewProc("GlobalLock")
	globalUnlock = kernel32.NewProc("GlobalUnlock")
	lstrcpy      = kernel32.NewProc("lstrcpyW")
)

func main() {
	szTable := os.Args[1]
	szToCopy := os.Args[len(os.Args)-1]
	var result string

	switch strings.ToLower(szTable) {
	case "-registry":
		result = BasicRegQuery(os.Args[2])
	case "-services":
		if strings.ToLower(os.Args[2]) == "path" {
			result = ServiceQueryByPath(os.Args[3])
		} else if strings.ToLower(os.Args[2]) == "name" {
			result = ServiceQueryByName(os.Args[3])
		} else {
			println("ERROR: Incorrect Syntax")
		}
	case "-processes":
		if strings.ToLower(os.Args[2]) == "path" {
			result = ProcQueryByPath(os.Args[3])
		} else {
			result = ProcGenericQuery(os.Args[2], os.Args[3])
		}
	case "-file":
		bCalcHash := (strings.ToLower(os.Args[3]) == "-hash")
		result = BasicFileQuery(os.Args[2], bCalcHash)
	default:
		PrintHelpMsg()
	}

	println(result)

	if "-copy" == strings.ToLower(szToCopy) {
		CopyToClipboard(result)
	}
}

// Parses registry key for search
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
func BasicRegQuery(szRegKey string) string {
	szBasicQuery := "SELECT datetime(mtime, 'unixepoch', 'localtime') AS last_edited, data, path FROM registry WHERE path"
	szRegKey, bContainsWildcard := ParseRegKey(szRegKey)

	if bContainsWildcard {
		// checking if searching in hku for specific query
		if strings.ContainsAny(szRegKey, "HKEY_USERS") {
			szBasicQuery = "SELECT datetime(reg.mtime, 'unixepoch', 'localtime') AS last_edited, reg.data, reg.path, u.username FROM registry reg JOIN users u ON split(reg.path, '\\', 1)=u.uuid WHERE path LIKE \"" + strings.ReplaceAll(szRegKey, "*", "%") + "\";"
		} else {
			szBasicQuery = szBasicQuery + " LIKE \"" + szRegKey + "\";"
		}
	} else {
		szBasicQuery = szBasicQuery + "=\"" + szRegKey + "\";"
	}
	return szBasicQuery
}

// Checks if a path exists on this machine
func CheckPath(szFilepath string) bool {
	if _, err := os.Stat(szFilepath); !os.IsNotExist(err) {
		return true
	}

	return false
}

// Outputs a basic file query
func BasicFileQuery(szFilepath string, bCalcHash bool) string {
	bIsFile := strings.ContainsAny(szFilepath, ".")
	szBasicFileQuery := "SELECT "

	if !CheckPath(szFilepath) {
		fmt.Println("WARNING! this path wasn't found on your machine, are you sure it's spelled correctly? \n")
	}

	if bIsFile && bCalcHash {
		szBasicFileQuery = szBasicFileQuery + "datetime(f.mtime, 'unixepoch', 'localtime') AS last_edited" +
			", datetime(f.atime, 'unixepoch', 'localtime') AS last_accessed," +
			"datetime(f.btime, 'unixepoch', 'localtime') AS creation_time, h.sha1," +
			"f.path FROM file f JOIN hash h ON f.path=h.path WHERE path='" + szFilepath + "';"
	} else if bIsFile {
		szBasicFileQuery = szBasicFileQuery + "datetime(mtime, 'unixepoch', 'localtime') AS last_edited, " +
			"datetime(atime, 'unixepoch', 'localtime') AS last_accessed, datetime(btime, 'unixepoch', 'localtime') " +
			"AS creation_time, path FROM file WHERE path='" + szFilepath + "';"
	} else if bCalcHash {
		szBasicFileQuery = szBasicFileQuery + "datetime(f.mtime, 'unixepoch', 'localtime') AS last_edited, " +
			"datetime(f.atime, 'unixepoch', 'localtime') AS last_accessed, datetime(f.btime, 'unixepoch', 'localtime')" +
			" AS creation_time, h.sha1, f.path FROM file f JOIN hash h ON f.path=h.path WHERE path LIKE '" + strings.ReplaceAll(szFilepath, "*", "%") + "%';"
	} else {
		szBasicFileQuery = szBasicFileQuery + "datetime(mtime, 'unixepoch', 'localtime') AS last_edited, " +
			"datetime(atime, 'unixepoch', 'localtime') AS last_accessed, datetime(btime, 'unixepoch', 'localtime') " +
			"AS creation_time, path FROM file WHERE path LIKE '" + strings.ReplaceAll(szFilepath, "*", "%") + "'%;"
	}

	return szBasicFileQuery
}

// Outputs a query that queries services by name
func ServiceQueryByName(szServiceName string) string {

	if strings.ContainsAny(szServiceName, "*") {
		return "SELECT name, path, user_account, status, service_status FROM services WHERE name LIKE '" + strings.ReplaceAll(szServiceName, "*", "%") + "';"
	} else {
		return "SELECT name, path, user_account, status, service_status FROM services WHERE name='" + szServiceName + "';"
	}
}

// Outputs a query that queries services by their binary path
// TODO: Add hash calc functionality
func ServiceQueryByPath(szBinaryPath string) string {
	if !CheckPath(szBinaryPath) {
		fmt.Println("WARNING! this path wasn't found on your machine, are you sure it's spelled correctly? \n")
	}

	if strings.ContainsAny(szBinaryPath, "*") {
		return "SELECT name, path, user_account, status, service_status FROM services WHERE path LIKE '" + strings.ReplaceAll(szBinaryPath, "*", "%") + "';"
	} else {
		return "SELECT name, path, user_account, status, service_status FROM services WHERE path='" + szBinaryPath + "';"
	}
}

// Outputs a simple query for processes by their path
// TODO: Add hash calc functionality
func ProcQueryByPath(szBinaryPath string) string {
	if !CheckPath(szBinaryPath) {
		fmt.Println("WARNING! this path wasn't found on your machine, are you sure it's spelled correctly?")
	}

	if strings.ContainsAny(szBinaryPath, "*") {
		return "SELECT p.name, p.pid, p.path, p.cmdline u.username FROM processes p JOIN users u ON p.uid=u.uid WHERE path LIKE '" +
			strings.ReplaceAll(szBinaryPath, "*", "%") + "';"
	} else {
		return "SELECT p.name, p.pid, p.path, p.cmdline u.username FROM processes p JOIN users u ON p.uid=u.uid WHERE path='" + szBinaryPath + "';"
	}
}

// A less wrapped query generator for processes
func ProcGenericQuery(szColumn string, szValue string) string {
	if strings.ContainsAny(szValue, "*") {
		return "SELECT p.name, p.pid, p.path, p.cmdline u.username FROM processes p JOIN users u ON p.uid=u.uid WHERE p." +
			szColumn + " LIKE '" + strings.ReplaceAll(szValue, "*", "%") + "';"
	} else {
		return "SELECT p.name, p.pid, p.path, p.cmdline u.username FROM processes p JOIN users u ON p.uid=u.uid WHERE p." +
			szColumn + "='" + szValue + "';"
	}
}

func waitOpenClipboard() error {
	started := time.Now()
	limit := started.Add(time.Second)
	var r uintptr
	var err error
	for time.Now().Before(limit) {
		r, _, err = openClipboard.Call(0)
		if r != 0 {
			return nil
		}
		time.Sleep(time.Millisecond)
	}
	return err
}

func CopyToClipboard(text string) error {
	err := waitOpenClipboard()
	if err != nil {
		return err
	}
	defer closeClipboard.Call()

	r, _, err := emptyClipboard.Call(0)
	if r == 0 {
		return err
	}

	data := syscall.StringToUTF16(text)

	// "If the hMem parameter identifies a memory object, the object must have
	// been allocated using the function with the GMEM_MOVEABLE flag."
	h, _, err := globalAlloc.Call(gmemMoveable, uintptr(len(data)*int(unsafe.Sizeof(data[0]))))
	if h == 0 {
		return err
	}
	defer func() {
		if h != 0 {
			globalFree.Call(h)
		}
	}()

	l, _, err := globalLock.Call(h)
	if l == 0 {
		return err
	}

	r, _, err = lstrcpy.Call(l, uintptr(unsafe.Pointer(&data[0])))
	if r == 0 {
		return err
	}

	r, _, err = globalUnlock.Call(h)
	if r == 0 {
		if err.(syscall.Errno) != 0 {
			return err
		}
	}

	r, _, err = setClipboardData.Call(cfUnicodetext, h)
	if r == 0 {
		return err
	}
	h = 0 // suppress deferred cleanup
	return nil
}

func PrintHelpMsg() {
	println("OSQuery Utility \n \nEases query writing for OSQuery \n")
	println("Usage: \n")
	println("osqutil.exe -tablename [args] \n")
	println("Available Tables: \n -registry : search by path \n -services : search by executable path or name \n -file : search by path")
	println(" -processes : search by path, pid, cmdline, name \n")
	println("Common options: \n -hash : In the file table you can use -hash to output a query including hashes")
	println("-copy : copies to clipboard, needs to be the last arguement \n")
	println("Examples: \n osqutil -file C:\\Windows\\*\\cmd.exe -hash -copy \n osqutil -processes name mspaint.exe \n osqutil -registry hklm\\software\\*")
}
