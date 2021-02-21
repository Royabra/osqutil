# osqutil

osqutil is an OSQuery Command-Line Utility tool designed to simplify writing basic queries.
[Learn More About OSQuery](https://osquery.io/)

Supported Tables:
  - registry  : search by path
  - processes : search by path, pid, cmdline, name 
  - file      : search by path, you can use -hash to output a query including hashes
  - services  : search by name or binary path

Optional Commands:
  -hash : add a hash calculation to the query, check tables that support this kind of command
  -copy : copies query to the clipboard

Syntax is as follows:
osqutil.exe -tablename column value -OptionalCommands

**Examples:**

outputs a query for a specific registry path and copies it to the clipboard (-copy flag)
````console
osqutil -registry HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\* -copy
````
outputs a query for processes whose name is evil.exe
````console
osqutil -processes name evil.exe
````
outputs a query to calculate the hash of the given path
````console
osqutil -file C:\Windows\*\cmd.exe -hash
````
