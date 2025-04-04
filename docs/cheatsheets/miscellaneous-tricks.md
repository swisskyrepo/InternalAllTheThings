# Miscellaneous & Tricks

All the tricks that couldn't be classified somewhere else.

## Send Messages to Other Users

* Windows

```powershell
PS C:\> msg Swissky /SERVER:CRASHLAB "Stop rebooting the XXXX service !"
PS C:\> msg * /V /W /SERVER:CRASHLAB "Hello all !"
```

* Linux

```powershell
wall "Stop messing with the XXX service !"
wall -n "System will go down for 2 hours maintenance at 13:00 PM"  # "-n" only for root
who
write root pts/2 # press Ctrl+D  after typing the message. 
```

## NetExec Credential Database

```ps1
nxcdb (default) > workspace create test
nxcdb (test) > workspace default
nxcdb (test) > proto smb
nxcdb (test)(smb) > creds
nxcdb (test)(smb) > export creds csv /tmp/creds
```

NetExec workspaces

```ps1
# get current workspace
poetry run nxcdb -gw 

# create workspace
poetry run nxcdb -cw testing

# set workspace
poetry run nxcdb -sw testing 
```
