# AWS - Service - Lambda


## Extract function's code

```powershell
aws lambda list-functions --profile uploadcreds
aws lambda get-function --function-name "LAMBDA-NAME-HERE-FROM-PREVIOUS-QUERY" --query 'Code.Location' --profile uploadcreds
wget -O lambda-function.zip url-from-previous-query --profile uploadcreds
```


## References

* [Getting shell and data access in AWS by chaining vulnerabilities - Appsecco - Riyaz Walikar - Aug 29, 2019](https://blog.appsecco.com/getting-shell-and-data-access-in-aws-by-chaining-vulnerabilities-7630fa57c7ed)