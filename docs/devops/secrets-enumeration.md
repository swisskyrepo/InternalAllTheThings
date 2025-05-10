# Hardcoded Secrets Enumeration

## Tools

* [synacktiv/nord-stream](https://github.com/synacktiv/nord-stream) - List the secrets stored inside CI/CD environments and extract them by deploying malicious pipelines
* [xforcered/SCMKit](https://github.com/xforcered/SCMKit) - Source Code Management Attack Toolkit

## Search inside Repositories, Files and Codes

* Discover repositories being used in a particular SCM system

    ```ps1
    SCMKit.exe -s gitlab -m listrepo -c userName:password -u https://gitlab.something.local
    SCMKit.exe -s gitlab -m listrepo -c apiKey -u https://gitlab.something.local
    ```

* Search for repositories by repository name in a particular SCM system

    ```ps1
    SCMKit.exe -s github -m searchrepo -c userName:password -u https://github.something.local -o "some search term"
    SCMKit.exe -s gitlab -m searchrepo -c apikey -u https://gitlab.something.local -o "some search term"
    ```

* Search for code containing a given keyword in a particular SCM system

    ```ps1
    SCMKit.exe -s github -m searchcode -c userName:password -u https://github.something.local -o "some search term"
    SCMKit.exe -s github -m searchcode -c apikey -u https://github.something.local -o "some search term"
    ```

* Search for files in repositories containing a given keyword in the file name in a particular SCM system

    ```ps1
    SCMKit.exe -s gitlab -m searchfile -c userName:password -u https://gitlab.something.local -o "some search term"
    SCMKit.exe -s gitlab -m searchfile -c apikey -u https://gitlab.something.local -o "some search term"
    ```

* List snippets owned by the current user in GitLab

    ```ps1
    SCMKit.exe -s gitlab -m listsnippet -c userName:password -u https://gitlab.something.local
    SCMKit.exe -s gitlab -m listsnippet -c apikey -u https://gitlab.something.local
    ```
