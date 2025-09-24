# CI/CD Attacks

> CI/CD pipelines are often triggered by untrusted actions such a forked pull requests and new issue submissions for public git repositories. These systems often contain sensitive secrets or run in privileged environments. Attackers may gain an RCE into such systems by submitting crafted payloads that trigger the pipelines. Such vulnerabilities are also known as Poisoned Pipeline Execution (PPE).

## Summary

- [Tools](#tools)
- [CI/CD Products](#summary)
    - [GitHub Actions](./cicd-github-actions)
    - [Gitlab CI](./cicd-gitlab-ci)
    - [Azure Pipelines (Azure DevOps)](./cicd-azure-devops)
    - [Circle CI](./cicd-circle-ci)
    - [Drone CI](./cicd-drone-ci)
    - [BuildKite](./cicd-buildkite)
- [Hardcoded Secrets Enumeration](./secrets-enumeration)
- [Package Managers and Build Files](./package-managers)
- [References](#references)

## Tools

- [praetorian-inc/gato](https://github.com/praetorian-inc/gato) - GitHub Self-Hosted Runner Enumeration and Attack Tool
- [AdnaneKhan/Gato-X](https://github.com/AdnaneKhan/Gato-X) - Fork of Gato - Gato (Github Attack TOolkit) - Extreme Edition
- [messypoutine/gravy-overflow](https://github.com/messypoutine/gravy-overflow) - A GitHub Actions Supply Chain CTF / Goat
- [xforcered/SCMKit](https://github.com/xforcered/SCMKit) - Source Code Management Attack Toolkit
- [synacktiv/octoscan](https://github.com/synacktiv/octoscan) - Octoscan is a static vulnerability scanner for GitHub action workflows.
- [synacktiv/gh-hijack-runner](https://github.com/synacktiv/gh-hijack-runner) - A python script to create a fake GitHub runner and hijack pipeline jobs to leak CI/CD secrets.
- [synacktiv/nord-stream](https://github.com/synacktiv/nord-stream) - List the secrets stored inside CI/CD environments and extract them by deploying malicious pipelines
- [praetorian-inc/glato](https://github.com/praetorian-inc/glato) - GitLab Attack TOolkit

## References

- [Poisoned Pipeline Execution](https://web.archive.org/web/20240226215436/https://www.cidersecurity.io/top-10-cicd-security-risks/poisoned-pipeline-execution-ppe/)
- [DEF CON 25 - Exploiting Continuous Integration (CI) and Automated Build systems - spaceB0x - 2 nov. 2017](https://youtu.be/mpUDqo7tIk8)
- [Controlling the Source: Abusing Source Code Management Systems - Brett Hawkins - August 9, 2022](https://securityintelligence.com/posts/abusing-source-code-management-systems/)
- [Fixing Typos and Breaching Microsoft’s Perimeter - John Stawinski IV - April 15, 2024](https://johnstawinski.com/2024/04/15/fixing-typos-and-breaching-microsofts-perimeter/)
