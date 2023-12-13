[![Logo](https://mend-toolkit-resources-public.s3.amazonaws.com/img/mend-io-logo-horizontal.svg)](https://www.mend.io/)  

[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/mend-toolkit/mend-azure-pipeline-workitems/actions/workflows/ci.yml/badge.svg)](https://github.com/mend-toolkit/mend-azure-pipeline-workitems/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/v/release/mend-toolkit/mend-azure-pipeline-workitems)](https://github.com/mend-toolkit/mend-azure-pipeline-workitems/releases/latest)

# Integrate Mend SCA with Azure Work Items
A self-hosted tool that creates and updates Azure Work Items based on Mend SCA Issue Tracking policies.  

The tool is deployed within an Azure Pipeline triggered on fixed intervals by a cron schedule.  
It utilizes Mend's [Issue Tracking API](https://docs.mend.io/bundle/integrations/page/creating_your_own_issue_tracker_plugin.html) to identify the Mend SCA projects that were [modified](https://docs.mend.io/bundle/integrations/page/creating_your_own_issue_tracker_plugin.html#getOrganizationLastModifiedProjects) since the last execution, obtain the list of [policy matched issues](https://docs.mend.io/bundle/integrations/page/creating_your_own_issue_tracker_plugin.html#fetchProjectPolicyIssues) for each of them and create or update the corresponding Work Item.  

## Table of Contents
- [Supported Operating Systems](#supported-operating-systems)
- [Prerequisites](#prerequisites)
- [Planning Your WorkItems Setup](#planning-your-work-items-setup)
- [Azure DevOps Setup](#azure-devops-setup)
- [Mend SCA Setup](#mend-sca-setup)
- [Azure Pipeline Variables](#azure-pipeline-variables)
- [Custom Field Mapping](#custom-field-mapping)
  - [Examples](#examples)
  - [Execution](#execution)

## Supported Operating Systems
- **Linux:**	CentOS, Debian, Ubuntu
- **Windows:**	10, 2012, 2016
<br />

## Prerequisites
* Python 3.9+
* Azure DevOps Services or Server instance
* Azure DevOps service user Personal Access Token (PAT) with **Read & write** permissions for both "Work Items" and the "Project and Team" scopes on any organization where you want to run the integration.
* Azure DevOps service user added to a group with the following permissions in the project: **Create tag definition**, **Manage project properties** and **View permissions for this node** 
	* The user needs to be added to the team for each area path you wish to create work items for.
* Mend SCA [Issue Tracking policies](#mend-sca)
* Mend SCA service user with associated with a [role assignment](https://docs.mend.io/bundle/sca_user_guide/page/managing_groups.html#Assigning-a-Role-to-a-Group) of either **Organization Administrator** or **Organization Auditor**  
<br />

## Planning your Work Items Setup
The Mend Work Items integration has the flexibility for creating work items with granularity. Before setting up the integration, make sure you have a clear understanding of which projects and/or products should have work items created. The below list specifies where you should place the `mend-azure-wi-sync.yml` file in step 2 below for proper implementation
- If only a single repository should have work items created, then add the example pipeline file to the specific repository where you want workitems created. In this type of implementation, you want to make sure that `MEND_PROJECTTOKEN` is set appropriately
- If a full project, or more than one repository inside of a project need Work Items created, then create a new repository where the pipeline file will live. In this type of implementation, you can use a combination of  `MEND_PRODUCTTOKEN` and `MEND_EXCLUDETOKEN` to exclude certain projects inside of a product
- If your full Mend organization needs work-items created, then it is recommended to create a separate repository for the pipeline. In this type of implementation, leaving both `MEND_PRODUCTTOKEN` and `MEND_PROJECTTOKEN` empty, and using `MEND_EXCLUDETOKEN` to exclude projects where needed is advised

See [Azure Pipeline Variables](#azure-pipeline-variables) for details.  
<br />

## Azure DevOps Setup
1. Create a [Personal Access Token (PAT)](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate) with **Read & write** permissions for the **Work Items** scope and **Project and Team** scope
2. Create a new Azure pipeline from the example file [examples/mend-azure-wi-sync.yml](./examples/mend-azure-wi-sync.yml)
3. Make sure the user you created the PAT for has the following permissions in each repository where workitems are needed: **Create tag definition**, **Manage project properties** and **View permissions for this node** 
4. Set up the appropriate environment variables/secrets for the pipeline. The minimum requirements for these variables are: `MEND_URL`, `MEND_USERKEY`, `MEND_APIKEY`, `MEND_AZUREPAT`, and `MEND_RESET`. We recommend also setting `MEND_PRODUCTTOKEN`, `MEND_PROJECTTOKEN`, and/or `MEND_EXCLUDETOKEN` as detailed above. The `MEND_RESET` variable should be configured to allow users to override its value
5. **For your first scan, the integration requires `MEND_RESET` to be true for initial workitem creation. For all other scans, this variable can be set to false**
<br />

## Mend SCA Setup
Set up a policy with [**Issue**](https://docs.mend.io/bundle/sca_user_guide/page/managing_automated_policies.html#Applying-Actions-to-a-Library) action for each use case you wish a Work Item to be created for.  

The naming convention should include, other than a self explanatory description of what the policy does, a square-bracketed prefix, either `[License]` or `[Security]`.  

> **_NOTE_**: Refer to the Mend SCA documentation for detailed instructions on how to [create new policies](https://docs.mend.io/bundle/sca_user_guide/page/managing_automated_policies.html#Creating-a-New-Policy).  
>For best practices concerning desigining your policy scheme, refer to [Best Practices for Mend SCA Policies](https://docs.mend.io/bundle/wsk/page/best_practices_for_mend_sca_policies.html)  
<br />

## Azure Pipeline Variables 
The following variables can be placed into the pipeline where the integration is run, to configure its behavior: 

| Variable            |  Type   | Required | Default | Description |
|---------------------|:-------:|:--------:|:--------|-------------|
| `MEND_URL`          | string  |   Yes    | N/A | Mend server URL |
| `MEND_USERKEY`      | secret  |   Yes    | N/A | Your Mend User Key   |
| `MEND_APIKEY`       | secret  |   Yes    | N/A | Mend Organization API Key    |
| `MEND_AZUREPAT`     | secret  |   Yes    | N/A | Azure DevOps [Personal Access Token](https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows) |
| `MEND_AZUREURI`     | string  |   Yes    | N/A | Azure DevOps organization URI (e.g. `https://dev.azure.com/MyOrganization`). <br/> Accepts the [system variable](https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml#system-variables-devops-services)  `$(System.CollectionUri)` |
| `MEND_AZUREPROJECT` | string  |   Yes    | N/A | Azure Team Project name. <br/> Accepts the [system variable](https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml#system-variables-devops-services) `$(System.TeamProject)` |
| `MEND_PRODUCTTOKEN` | string  |    No    | Empty String <br />(Include all products) | Comma-separated list of Mend Product Tokens that should be monitored for changes. |
| `MEND_PROJECTTOKEN` | string  |    No    | Empty String <br />(Include all projects) | Comma-separated list of Mend Project Tokens that should be monitored for changes. |
| `MEND_EXCLUDETOKEN` | string  |    No    | Empty String <br /> (No exclusions) | Comma-separated list of Mend Project Tokens that should not be monitored. |
| `MEND_AZUREAREA`    | string  |    No    | `$MEND_AZUREPROJECT` | [Area Path](https://learn.microsoft.com/en-us/azure/devops/organizations/settings/set-area-paths?view=azure-devops) to group created Work Items under. <br/> For example: `TeamProject\Area1\SubArea2` or `Area1\SubArea2`. Use double-backslashes when specifying sub-areas. |
| `MEND_AZURETYPE`    | string  |    No    | Task | Work Item type for creating new Work Items. <br/> Must be one of the [built-in](https://learn.microsoft.com/en-us/azure/devops/boards/work-items/about-work-items?view=azure-devops&tabs=agile-process#track-work-with-different-work-item-types) or [custom](https://learn.microsoft.com/en-us/azure/devops/boards/work-items/about-work-items?view=azure-devops&tabs=agile-process#customize-a-work-item-type) types that are available for the project's [process](https://learn.microsoft.com/en-us/azure/devops/boards/work-items/guidance/choose-process?view=azure-devops&tabs=agile-process). (Basic, Agile, Scrum, etc.) associated with the specified Team Project in the `MEND_AZUREPROJECT` variable. |
| `MEND_RESET`        | boolean |    No    | `false` |  Whether to force Work Item creation for a Mend Projects' full history (rather than just the diff since the last run). Creates work items for the diff when set to `false`.|
| `MEND_CUSTOMFIELDS` | string  |   No*    | Empty String <br /> (No custom fields) | Used for mapping additional information from Mend's Issue Policy objects into custom fields of the specified Work Item type (`$MEND_AZURETYPE`). <br/> See [Custom Work Item Types](#custom-field-mapping) below for syntax guidelines. <br/>  This variable is required when using custom Work Item types. |
| `MEND_REPONAME`     | string  |   No*    | <Name of Repository\> <br /> **_Do not change_** | The field contains Repo Name which can be used as value for any Custom field according Custom Fields syntax. See [Custom Work Item Types](#custom-field-mapping) below for syntax guidelines (`$MEND_REPONAME`). |
| `MEND_DEPENDENCY`   | boolean |   No*    | True | Specify whether to create work items based on the dependency (value: True) or based on the CVE (value: False). Typically creates more work items if set to `false`. |
| `MEND_DESCRIPTION` | string | No* | "ReproSteps" | Used to tell the Integrations which field should contain the description. Use "ReproSteps" for bugs, "Description" for issues, or a custom name for a custom field. |
| `MEND_CALCULATEPRIORITY` | boolean |   No*    | False | Priority will be calculated according to Mend’s severity (CSS3) value if the value is equal to True. If not, it will be set to 2 (default priority). |
| `MEND_ALERT`        | boolean |   No*    | True | Whether to include ignored vulnerabilities. Set to false for exclude ignored vulnerabilities. |

>**_NOTE_**: `azure-wi-sync` would accept all environment variables with either `MEND_` or `WS_` prefix.
<br />

## Execution
The recommended way to implement this integration, is by having the pipeline run on a cron schedule. We recommend that the cron schedule run on a daily basis, or by your desired frequency. This is demonstrated in the [example pipeline file](./examples/azure-pipelines.yml).
```yaml
schedules:
  - cron: "0 */1 * * *"
    displayName: Mend SCA Sync Scheduler
    branches:
      include:
        - main
    always: true
```
When the configured pipeline is executed, the integration fetches all the Issue policy matches that were created since the last execution.  
<br />

## Custom Field Mapping
When specifying a [custom Work Item type](https://learn.microsoft.com/en-us/azure/devops/boards/work-items/about-work-items?view=azure-devops&tabs=agile-process#customize-a-work-item-type) with `$MEND_AZURETYPE`, the integration will utilize the [Azure API](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-item-types/get) to automatically obtain its definition.  

The `"issues": []` objects returned by the [fetchProjectPolicyIssues](https://docs.mend.io/bundle/integrations/page/creating_your_own_issue_tracker_plugin.html#fetchProjectPolicyIssues) API response will be used to populate the corresponding Work Item fields. However, you can choose to use the `MEND_CUSTOMFIELDS` variable to populate additional information into any custom fields of that Work Item, if its type has any of those. 
<br />

### Setting the Custom Fields Variable
The `MEND_CUSTOMFIELDS` variable accepts a string that is a semi-colon separated list of key-value pairs in the format of `FieldName::StaticValue` or `FieldName::MEND:MappedValue`. More than one mapped value can be placed into a custom field by concatenating them with "&" like: `CustomField:MEND:MappedValue&MEND:MappedValue` The field name directly corresponds to the "name" property data returned in the API "[WorkItemTypeFieldInstance](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-item-types/get?view=azure-devops-rest-7.0&tabs=HTTP#workitemtypefieldinstance)", whereas the mapped value directly corresponds to the API Response for Mend's "[fetchProjectPolicyIssues](https://docs.mend.io/bundle/integrations/page/creating_your_own_issue_tracker_plugin.html#fetchProjectPolicyIssues)". Please refer to the response example in the API documentation for an example of what you can parse, or you can run the API itself to get real data. 

>**_NOTE_**: If the definition of the specified Work Item type (`$MEND_AZURETYPE`) includes any fields that are set up as mandatory (`"alwaysRequired": true`), you must also use `MEND_CUSTOMFIELDS` to map values to those fields.
<br />

### Guidelines
- The value of `MEND_CUSTOMFIELDS` should be a quoted string (single or double quotes)
- The string should contain all the desired `Key::Value` mapping pairs, separated by semicolons (`;`)
- The `Key` of each pair should be the name of the Work Item field (the `name` property, AKA "friendly name". See [WorkItemTypeFieldInstance](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-item-types/get?view=azure-devops-rest-7.0&tabs=HTTP#workitemtypefieldinstance) for details)
- The value can contain a dot-separated JSON path of the desired property from the `fetchProjectPolicyIssues` response, prefixed by the namespace `MEND:` (case sensitive)
- The process iterates through the objects under the `"issues": []` array of the `fetchProjectPolicyIssues` response, so any `MEND:` values must be from under that object. Values cannot include JSON paths for other properties from outside `"issues": []`
- The value can also contain custom text, either dynamic (using pipeline variables) or static
- The value can combine multiple parts, both `MEND:` proeprties and/or free text. Parts should be delimited by an ampersand (`&`)
- If you plan to use the `MEND_REPONAME` or `MEND_DESCRIPTION` variables then you can add this to a custom field with `$MEND_REPONAME` or `$MEND_DESCRIPTION`

**Syntax**  
```yaml
  env:
    ...
    MEND_AZURETYPE: 'SCA Issue'
    MEND_CUSTOMFIELDS: 'Field 1::MEND:path.to.property1;Field 2::MEND:property2& Free Text &MEND:property3;Field 4::$MEND_REPONAME'
```
<br />

### Examples
All the following examples assume a custom Work Item type named **SCA Issue**, which was configured to inherit fields from the **Bug** Work Item of the **Agile** process flow.

**Example 1**  
Populating the Work Item's custom fields **Issue Type** and **Issue Reference** with the vulnerability's type and identifier (name):  

```yaml
  env:
    ...
    MEND_AZURETYPE: 'SCA Issue'
    MEND_CUSTOMFIELDS: 'Issue Type::MEND:policyViolations.vulnerability.type;Issue Reference::MEND:policyViolations.vulnerability.name'
```
<br />

**Example 2**  
Populating the Work Item's custom field **Team Comments** with the initial text:  
**Mend policy name: *POLICY_NAME* (scope: *POLICY_SCOPE*)**  

```yaml
  env:
    ...
    MEND_AZURETYPE: 'SCA Issue'
    MEND_CUSTOMFIELDS: 'Team Comments::Mend policy name: &MEND:policy.name& (scope: &MEND:policy.policyContext&)'
```
