# CI/CD - Azure DevOps

## Azure Pipelines

The configuration files for azure pipelines are normally located in the root directory of the repository and called - `azure-pipelines.yml`\
You can tell if the pipeline builds pull requests based on its trigger instructions. Look for `pr:` instruction:

```yaml
trigger:
  branches:
      include:
      - master
      - refs/tags/*
pr:
- master
```

## Secret Extractions

Extract secrets for these service connection:

* AzureRM
* GitHub
* AWS
* SonarQube
* SSH

```ps1
nord-stream.py devops ... --build-yaml test.yml --build-type ssh  
```

## References

* [Azure DevOps CICD Pipelines - Command Injection with Parameters, Variables and a discussion on Runner hijacking - Sana Oshika - May 1 2023](https://pulsesecurity.co.nz/advisories/Azure-Devops-Command-Injection)
