# Deployment - MDT

Microsoft Deployment Toolkit (MDT) is a free tool from Microsoft used to automate the deployment of Windows operating systems and applications.

It lets IT admins create a central deployment share with OS images, drivers, updates, and apps, then use automated scripts (task sequences) to install them on multiple computers, either over the network (Lite Touch) or from media (USB/DVD).

## Deployment Share

These files contains credentials used by Microsoft Deployment Toolkit to join a computer to the domain and to access network resources.

* **Bootstrap.ini** - Located in `DeploymentShare\Control\Bootstrap.ini`
* **CustomSettings.ini** - Located in `DeploymentShare\Control\CustomSettings.ini`

| Name | Description |
| --- | --- |
| DomainAdmin | Account used to join the computer to the domain |
| DomainAdminPassword | Password used to join the computer to the domain |
| UserID | Account used for accessing network resources |
| UserPassword | Password used for accessing network resources |
| AdminPassword | The local administrator account on the computer |
| ADDSUserName | Account used when promoting to DC during deployment |
| ADDSPassword | Password used when promoting to DC during deployment |
| Password | Password to use for promoting member server to a domain controller |
| SafeModeAdminPassword | Used when deploying DCs, it is the AD restore mode password |
| TPMOwnerPassword | The TPM password if not set already |
| DBID | Account used to connect to SQL server during deployment |
| DBPwd | Password used to connect to SQL server during deployment |
| OSDBitLockerRecoveryPassword | BitLocker recovery password |

Other credentials can be found inside the files hosted in the deployment share:

* `DeploymentShare\Control\TASKSEQUENCENAME\ts.xml`
* `DeploymentShare\Scripts\` folder
* `DeploymentShare\Applications` folder
* `LiteTouchPE_x86|x64.iso`, extract files and look for `bootstrap.ini`
* `LiteTouchPE_x86|x64.wim`, extract files and look for `bootstrap.ini`

## References

* [Red Team Gold: Extracting Credentials from MDT Shares - Oddvar Moe - May 20, 2025](https://trustedsec.com/blog/red-team-gold-extracting-credentials-from-mdt-shares)
* [MDT, where are you? - BlackWasp - June 27, 2025](https://hideandsec.sh/books/windows-sNL/page/mdt-where-are-you)
