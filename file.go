package main

import (
	"fmt"
	"strings"
)

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
			"AS creation_time, path FROM file WHERE path LIKE '" + strings.ReplaceAll(szFilepath, "*", "%") + "%';"
	}

	return szBasicFileQuery
}
