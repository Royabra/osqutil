# osqutil

osqutil is an OSQuery Command-Line Utility tool designed to simplify writing basic queries.
[Learn More About OSQuery](https://osquery.io/)

**Supported Tables:**
  - registry  : search by path
  - processes : search by path, pid, cmdline, name, supports -hash for path only
  - file      : search by path, supports -hash
  - services  : search by name or path
  - dns       : search by domain name
  - ntfs      : search by path, supports -hash
  - patches   : search by hotfix_id, must specify if specific hotfix_id searched is present or not (exists or !exists)
  - users     : search by name, SID and shell
  - memory    : presents loaded modules in memory, search by name (of the process), pid, permissions and path (of loaded module)
  - pipes     : search by pid, name (of process), pipe (name of the pipe), flags
  - sockets   : search by pid, name (of process), lport (local port), rport (remote port), address (remote address)

**Optional Commands:**
  - hash    : add a hash calculation to the query, check tables that support this kind of command
  - copy    : copies query to the clipboard
  - execute : executes the generated query in osqueryi
  - csv     : must come after -execute, formats the result to csv, results can be saved in a file (see examples!)
  - json    : must come after -execute, formats the result to json, results can be saved in a file

**Syntax is as follows:**
osqutil.exe -tablename column value -OptionalCommands

A Good rule of thumb is that if a table only supports one column, such as -dns or -ntfs, the column name isn't specified

**Examples:**

outputs a query for a specific registry path and copies it to the clipboard (-copy flag)
````console
osqutil -registry HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\* -copy
````
outputs a query for processes whose name is evil.exe and executes it
````console
osqutil -processes name evil.exe -execute
````
outputs a query to calculate the hash of the given path
````console
osqutil -file C:\Windows\*\cmd.exe -hash
````
outputs a query searching a domain name that contains bad.com, executes it and saves to json file
````console
osqutil -dns *bad.com* -execute -json C:\path\to\myfile.json
````
outputs a query searching if the patch is not present, executes it and presents results as csv
````console
osqutil -patch KB4534170 !exists -execute -csv
````
outputs a query searching for all modules loaded by 'evil.exe'
````console
osqutil -memory name evil.exe
````
outputs a query searching for sockets whose local port is 4444
````console
osqutil -sockets lport 4444
````
