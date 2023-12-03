# Active Directory - Tricks

## Kerberos Clock Synchronization

In Kerberos, time is used to ensure that tickets are valid. To achieve this, the clocks of all Kerberos clients and servers in a realm must be synchronized to within a certain tolerance. The default clock skew tolerance in Kerberos is `5 minutes`, which means that the difference in time between the clocks of any two Kerberos entities should be no more than 5 minutes.


* Detect clock skew automatically with `nmap`
  ```powershell
  $ nmap -sV -sC 10.10.10.10
  clock-skew: mean: -1998d09h03m04s, deviation: 4h00m00s, median: -1998d11h03m05s
  ```
* Compute yourself the difference between the clocks
  ```ps1
  nmap -sT 10.10.10.10 -p445 --script smb2-time -vv
  ```
* Fix #1: Modify your clock
  ```ps1
  sudo date -s "14 APR 2015 18:25:16" # Linux
  net time /domain /set # Windows
  ```
* Fix #2: Fake your clock
  ```ps1
  faketime -f '+8h' date
  ```


## References

* [BUILDING AND ATTACKING AN ACTIVE DIRECTORY LAB WITH POWERSHELL - @myexploit2600 & @5ub34x](https://1337red.wordpress.com/building-and-attacking-an-active-directory-lab-with-powershell/)
* [Becoming Darth Sidious: Creating a Windows Domain (Active Directory) and hacking it - @chryzsh](https://chryzsh.gitbooks.io/darthsidious/content/building-a-lab/building-a-lab/building-a-small-lab.html)
* [Chump2Trump - AD Privesc talk at WAHCKon 2017 - @l0ss](https://github.com/l0ss/Chump2Trump/blob/master/ChumpToTrump.pdf)
* [How to build a SQL Server Virtual Lab with AutomatedLab in Hyper-V - October 30, 2017 - Craig Porteous](https://www.sqlshack.com/build-sql-server-virtual-lab-automatedlab-hyper-v/)
