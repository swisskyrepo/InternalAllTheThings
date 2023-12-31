# AWS - IOC & Detections

## CloudTrail

### Disable CloudTrail

```powershell
$ aws cloudtrail delete-trail --name cloudgoat_trail --profile administrator
```

Disable monitoring of events from global services 

```powershell
$ aws cloudtrail update-trail --name cloudgoat_trail --no-include-global-service-event 
```

Disable Cloud Trail on specific regions

```powershell
$ aws cloudtrail update-trail --name cloudgoat_trail --no-include-global-service-event --no-is-multi-region --region=eu-west
```


## GuardDuty

### OS User Agent

:warning: When using awscli on Kali Linux, Pentoo and Parrot Linux, a log is generated based on the user-agent.

Pacu bypass this problem by defining a custom User-Agent: [pacu.py#L1473](https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu.py#L1473)

```python
boto3_session = boto3.session.Session()
ua = boto3_session._session.user_agent()
if 'kali' in ua.lower() or 'parrot' in ua.lower() or 'pentoo' in ua.lower():  # If the local OS is Kali/Parrot/Pentoo Linux
    # GuardDuty triggers a finding around API calls made from Kali Linux, so let's avoid that...
    self.print('Detected environment as one of Kali/Parrot/Pentoo Linux. Modifying user agent to hide that from GuardDuty...')
```
