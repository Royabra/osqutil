package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
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
	var szTable string
	// Variable Declaration
	if len(os.Args) == 1 {
		szTable = "-help"
	} else {
		szTable = os.Args[1]
	}
	var result string
	bCalcHash := false
	bToCopy := false
	bToExecute := false
	szFileType := ""
	bCheckFilePath := false
	szOutputFile := ""

	// checking command line arguements
	for i := 0; i < len(os.Args); i++ {
		szLowerArg := strings.ToLower(os.Args[i])
		if szLowerArg == "-hash" {
			bCalcHash = true
		} else if szLowerArg == "-copy" {
			bToCopy = true
		} else if szLowerArg == "-execute" {
			bToExecute = true
		} else if szLowerArg == "-csv" {
			szFileType = szLowerArg
			bCheckFilePath = true
		} else if szLowerArg == "-json" {
			szFileType = szLowerArg
			bCheckFilePath = true
		}

		if bCheckFilePath && i+1 < len(os.Args) {
			szOutputFile = os.Args[i+1]
		}
	}

	// Checking table
	switch strings.ToLower(szTable) {
	case "-registry":
		result = BasicRegQuery(os.Args[2], bCalcHash)
	case "-services":
		if strings.ToLower(os.Args[2]) == "path" {
			result = ServiceQueryByPath(os.Args[3], bCalcHash)
		} else if strings.ToLower(os.Args[2]) == "name" {
			result = ServiceQueryByName(os.Args[3], bCalcHash)
		} else {
			println("ERROR: Incorrect Syntax, columns supported are path and name")
		}
	case "-processes":
		if strings.ToLower(os.Args[2]) == "path" {
			result = ProcQueryByPath(os.Args[3], bCalcHash)
		} else {
			result = ProcGenericQuery(os.Args[2], os.Args[3], bCalcHash)
		}
	case "-file":
		result = BasicFileQuery(os.Args[2], bCalcHash)
	case "-ntfs":
		result = BasicNtfsQuery(os.Args[2], bCalcHash)
	case "-dns":
		result = BasicDnsQuery(os.Args[2], bCalcHash)
	case "-patches":
		if len(os.Args) > 3 {
			if strings.ToLower(os.Args[3]) == "exists" {
				result = BasicPatchesQuery(os.Args[2], true, bCalcHash)
			} else if strings.ToLower(os.Args[3]) == "!exists" {
				result = BasicPatchesQuery(os.Args[2], false, bCalcHash)
			}
		} else {
			PrintHelpMsg()
		}
	default:
		PrintHelpMsg()
	}

	// Checking if needing to execute query
	if bToExecute {
		ExecuteQuery(result, szFileType, szOutputFile)
	} else {
		// if not, printing results
		fmt.Println(result)
	}

	// Copying to clipboard if mentioned
	if bToCopy {
		CopyToClipboard(result)
	}
}

// Checks if a path exists on this machine
func CheckPath(szFilepath string) bool {
	if _, err := os.Stat(szFilepath); !os.IsNotExist(err) {
		return true
	}

	return false
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
	println("osqutil.exe -tablename column value -OptionalCommands \n")
	println("Available Tables: \n -registry : search by path \n -services : search by executable path or name \n -file : search by path, supports -hash")
	println(" -processes : search by path, pid, cmdline, name, supports -hash when searching by path \n -ntfs : ntfs_acl_permissions, search by path, supports -hash")
	println(" -dns : dns_cache, search by domain name")
	println(" -patches : search by hotfix id, needs to specified is specific patch exists or not")
	println("Common options: \n -hash : add a hash calculation to your query")
	println(" -copy : copies to clipboard, needs to be the last arguement ")
	println(" -execute : executes the query in osqueryi, can be formatted with -csv or -json and stored in a file \n")
	println("Examples: \n osqutil -file C:\\Windows\\*\\cmd.exe -hash -copy \n osqutil -processes name mspaint.exe -execute\n osqutil -registry hklm\\software\\*")
	println(" osqutil -ntfs C:\\windows\\System32\\* -execute -csv > myfile.csv")
	println(" osqutil -patches 'KB4534170' !exists -execute -json")
	println("For More Information Please visit github.com/Roybara/osqutil")
}

func ExecuteQuery(szQuery string, szFileType string, szOutputFile string) {
	// Checking if osqueryi is present
	szOsqueryiPath := "\"C:\\Program Files\\osquery\\osqueryi.exe\""
	if CheckPath(szOsqueryiPath) {
		szCommandLine := szOsqueryiPath + " \"" + szQuery + "\""
		cmd := exec.Command("cmd")
		cmd.Stdout = os.Stdout
		stdin, err := cmd.StdinPipe()
		if err != nil {
			log.Fatal(err)
		}

		// Checking if values are initilized and customizing accordingly
		if szFileType != "" {
			if szFileType == "-csv" {
				szCommandLine = szCommandLine + " -" + szFileType + " --separator ,"
			} else {
				szCommandLine = szCommandLine + " -" + szFileType
			}

			if szOutputFile != "" {
				szCommandLine = szCommandLine + " > " + szOutputFile
			}
		}

		// Executing commandline
		go func() {
			defer stdin.Close()
			io.WriteString(stdin, szCommandLine+"\n")
		}()
		err = cmd.Run()
		if err != nil {
			log.Fatalf("cmd.Run() failed with %s\n", err)
		}
	} else {
		fmt.Println("osqueryi.exe wasn't found on your machine, assumed path is " + szOsqueryiPath)
	}
}
