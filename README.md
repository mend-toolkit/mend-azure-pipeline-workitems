[![Logo](https://mend-toolkit-resources-public.s3.amazonaws.com/img/mend-io-logo-horizontal.svg)](https://www.mend.io/)  

[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/mend-toolkit/mend-azure-pipeline-workitems/actions/workflows/ci.yml/badge.svg)](https://github.com/mend-toolkit/mend-azure-pipeline-workitems/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/v/release/mend-toolkit/mend-azure-pipeline-workitems)](https://github.com/mend-toolkit/mend-azure-pipeline-workitems/releases/latest)

# Integrate Mend SCA with Azure Work Items
A self-hosted tool that creates and updates Azure Work Items based on Mend SCA Issue Tracking policies.  

The tool is deployed within an Azure Pipeline triggered on fixed intervals by a cron schedule.  
It utilizes Mend's [Issue Tracking API](https://docs.mend.io/bundle/integrations/page/creating_your_own_issue_tracker_plugin.html) to identify the Mend SCA projects that were [modified](https://docs.mend.io/bundle/integrations/page/creating_your_own_issue_tracker_plugin.html#getOrganizationLastModifiedProjects) since the last execution, obtain the list of [policy matched issues](https://docs.mend.io/bundle/integrations/page/creating_your_own_issue_tracker_plugin.html#fetchProjectPolicyIssues) for each of them and create or update the corresponding Work Item.  

> **_BEHAVIOR CHANGE_**: On any run where the sync did not fully complete (for example, a transient error talking to Azure DevOps or Mend), this integration now exits with a **non-zero exit code**, and it withholds the per-project sync state for each Mend project that failed, so those projects are re-processed on the next run while the projects that succeeded keep the progress they made. Previously such a run still exited `0` and could silently advance one org-wide watermark past a window it never finished processing. If your pipeline treats a non-zero exit as a failed/red run (the normal case), you should now expect an existing, otherwise-healthy nightly sync to occasionally go red on a single transient failure — that failure is retried automatically on the next scheduled run. This is intentional: it replaces silent data loss with a visible, self-recovering failure. It is a large reduction in the risk of losing work rather than a guarantee: a run killed outright (agent timeout, pipeline cancellation) records no verdict at all for the projects it never reached, so those are picked up again by the next run's selection window, which reaches back to the oldest per-project watermark and is bounded by `MEND_MAXLOOKBACK`.

## Table of Contents
- [Supported Operating Systems](#supported-operating-systems)
- [Prerequisites](#prerequisites)
- [Planning Your WorkItems Setup](#planning-your-work-items-setup)
- [Azure DevOps Setup](#azure-devops-setup)
- [Mend SCA Setup](#mend-sca-setup)
- [Azure Pipeline Variables](#azure-pipeline-variables)
- [Setting Scan Tags for Tag-Based Routing](#setting-scan-tags-for-tag-based-routing)
- [Enrichment: Reachability, EPSS and Exploit Code Maturity](#enrichment-reachability-epss-and-exploit-code-maturity)
- [Custom Field Mapping](#custom-field-mapping)
  - [Examples](#examples)
  - [Execution](#execution)

## Supported Operating Systems
- **Linux:**	CentOS, Debian, Ubuntu
- **Windows:**	10, 2012, 2016
<br />

## Prerequisites
* Python 3.12+
* Azure DevOps Services or Server instance
* Azure DevOps service user Personal Access Token (PAT) with **Read & write** permissions for both "Work Items" and the "Project and Team" scopes on any organization where you want to run the integration.
* Azure DevOps service user added to a group with the following permissions in the project: **Create tag definition** and **View permissions for this node** 
	* The user needs to be added to the team for each area path you wish to create work items for.
* Mend SCA [Issue Tracking policies](#mend-sca)
* Mend SCA service user with associated with a [role assignment](https://docs.mend.io/bundle/sca_user_guide/page/managing_groups.html#Assigning-a-Role-to-a-Group) of either **Organization Administrator** or **Organization Auditor**  

The PAT needs **Work Items (Read, write & manage)** and **Project and Team (Read)**.

*Manage project properties* is **no longer required.** Sync state is stored as tags on the Mend
project (`azure-wi-lastrun`, `azure-wi-failed`, `azure-wi-revsync`), so the `MEND_USERKEY` must be
permitted to save project tags instead. If tag writes fail, the tool still runs correctly — every
window falls back to `MEND_MAXLOOKBACK` and overlapping work is repeated each run, with one error
logged per run explaining why.

**Onboarding a new organization:** run once with `MEND_RESET=true` to pick up existing findings,
then leave it unset. Tags carry the state from then on.
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
3. Make sure the user you created the PAT for has the following permissions in each repository where workitems are needed: **Create tag definition** and **View permissions for this node** 
4. Set up the appropriate environment variables/secrets for the pipeline. The minimum requirements for these variables are: `MEND_URL`, `MEND_USERKEY`, `MEND_APIKEY`, `MEND_AZUREPAT`, and `MEND_RESET`. We recommend also setting `MEND_PRODUCTTOKEN`, `MEND_PROJECTTOKEN`, and/or `MEND_EXCLUDETOKEN` as detailed above. The `MEND_RESET` variable should be configured to allow users to override its value
5. **For your first scan, the integration requires `MEND_RESET` to be true for initial workitem creation. For all other scans, this variable can be set to false**
<br />

## Mend SCA Setup
Set up a policy with [**Issue**](https://docs.mend.io/bundle/sca_user_guide/page/managing_automated_policies.html#Applying-Actions-to-a-Library) action for each use case you wish a Work Item to be created for.  

> **_IMPORTANT_**: The **Issue** action is mandatory. The integration only ever requests policy matches of the `CREATE_ISSUE` action type, so a policy configured with any other action (Reject, Approve, Reassign, etc.) is never returned by Mend and will **not** produce a Work Item, regardless of what it matches. The policy must also be **enabled** — matches from disabled policies are ignored.  

The naming convention should include, other than a self explanatory description of what the policy does, a square-bracketed prefix, either `[License]` or `[Security]`.  

> **_NOTE_**: Refer to the Mend SCA documentation for detailed instructions on how to [create new policies](https://docs.mend.io/bundle/sca_user_guide/page/managing_automated_policies.html#Creating-a-New-Policy).  
>For best practices concerning desigining your policy scheme, refer to [Best Practices for Mend SCA Policies](https://docs.mend.io/bundle/wsk/page/best_practices_for_mend_sca_policies.html)  
<br />

## Azure Pipeline Variables 
The following variables can be placed into the pipeline where the integration is run, to configure its behavior: 

| Variable                 |  Type   | Required | Default | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|--------------------------|:-------:|:--------:|:--------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `MEND_URL`               | string  |   Yes    | N/A | Mend server URL                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `MEND_USERKEY`           | secret  |   Yes    | N/A | Your Mend User Key                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `MEND_APIKEY`            | secret  |   Yes    | N/A | Mend Organization API Key                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `MEND_AZUREPAT`          | secret  |   Yes    | N/A | Azure DevOps [Personal Access Token](https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `MEND_AZUREURI`          | string  |   Yes    | N/A | Azure DevOps organization URI (e.g. `https://dev.azure.com/MyOrganization`). <br/> Accepts the [system variable](https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml#system-variables-devops-services)  `$(System.CollectionUri)`                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `MEND_AZUREPROJECT`      | string  |   Yes    | N/A | Azure Team Project name. <br/> Accepts the [system variable](https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml#system-variables-devops-services) `$(System.TeamProject)`. Under `MEND_ROUTING` this is no longer the destination — targets come from tags. It remains required, and is the project whose Work Item type definition is read at startup.                                                                                                                                                                                                                                                                                                                                                  |
| `MEND_PRODUCTTOKEN`      | string  |    No    | Empty String <br />(Include all products) | Comma-separated list of Mend Product Tokens that should be monitored for changes. Under `MEND_ROUTING` these narrow the set of Mend projects considered rather than choosing Azure targets.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `MEND_PROJECTTOKEN`      | string  |    No    | Empty String <br />(Include all projects) | Comma-separated list of Mend Project Tokens that should be monitored for changes. Under `MEND_ROUTING` these narrow the set of Mend projects considered rather than choosing Azure targets.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `MEND_EXCLUDETOKEN`      | string  |    No    | Empty String <br /> (No exclusions) | Comma-separated list of Mend Project Tokens that should not be monitored. Under `MEND_ROUTING` these narrow the set of Mend projects considered rather than choosing Azure targets.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `MEND_AZUREAREA`         | string  |    No    | `$MEND_AZUREPROJECT` | [Area Path](https://learn.microsoft.com/en-us/azure/devops/organizations/settings/set-area-paths?view=azure-devops) to group created Work Items under. <br/> For example: `TeamProject\Area1\SubArea2` or `Area1\SubArea2`. Use double-backslashes when specifying sub-areas.                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `MEND_AZURETYPE`         | string  |    No    | Task | Work Item type for creating new Work Items. <br/> Must be one of the [built-in](https://learn.microsoft.com/en-us/azure/devops/boards/work-items/about-work-items?view=azure-devops&tabs=agile-process#track-work-with-different-work-item-types) or [custom](https://learn.microsoft.com/en-us/azure/devops/boards/work-items/about-work-items?view=azure-devops&tabs=agile-process#customize-a-work-item-type) types that are available for the project's [process](https://learn.microsoft.com/en-us/azure/devops/boards/work-items/guidance/choose-process?view=azure-devops&tabs=agile-process). (Basic, Agile, Scrum, etc.) associated with the specified Team Project in the `MEND_AZUREPROJECT` variable. |
| `MEND_RESET`             | boolean |    No    | `false` | Whether to force Work Item creation for a Mend Projects' full history (rather than just the diff since the last run). Creates work items for the diff when set to `false`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `MEND_CUSTOMFIELDS`      | string  |   No*    | Empty String <br /> (No custom fields) | Used for mapping additional information from Mend's Issue Policy objects into custom fields of the specified Work Item type (`$MEND_AZURETYPE`). <br/> See [Custom Work Item Types](#custom-field-mapping) below for syntax guidelines. <br/>  This variable is required when using custom Work Item types.                                                                                                                                                                                                                                                                                                                                                                                                       |
| `MEND_REPONAME`          | string  |   No*    | <Name of Repository\> <br /> **_Do not change_** | The field contains Repo Name which can be used as value for any Custom field according Custom Fields syntax. See [Custom Work Item Types](#custom-field-mapping) below for syntax guidelines (`$MEND_REPONAME`). When `MEND_ROUTING` is enabled this is set per Mend project from the scan tag rather than read from the environment.                                                                                                                                                                                                                                                                                                                  |
| `MEND_ROUTING`           | boolean |    No    | `false` | Route findings to Azure DevOps projects using tags recorded on each Mend project at scan time, instead of choosing targets from `MEND_PRODUCTTOKEN` / `MEND_PROJECTTOKEN`. Requires the scan pipeline to set the `azure-project`, `azure-repo` and `azure-branch` tags on each Mend project. When `false` (the default) behaviour is unchanged. |
| `MEND_BRANCHES`          | string  |    No    | `main,master` | Comma-separated glob patterns of branches to sync when `MEND_ROUTING` is enabled. Matched against the branch recorded at scan time with the `refs/heads/` prefix stripped — e.g. `main,release/*`. Applied at sync time, so changing it does not require rescanning. |
| `MEND_DEPENDENCY`        | boolean |   No*    | True | Specify whether to create work items based on the dependency (value: True) or based on the CVE (value: False). Typically creates more work items if set to `false`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `MEND_DESCRIPTION`       | string | No* | "ReproSteps" | Used to tell the Integrations which field should contain the description. Use "ReproSteps" for bugs, "Description" for issues, or a custom name for a custom field.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `MEND_CALCULATEPRIORITY` | boolean |   No*    | False | Priority will be calculated according to Mend’s severity (CSS3) value if the value is equal to True. If not, it will be set to 2 (default priority).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `MEND_PROXY`             | string  |    No    | Empty String <br /> | The Proxy URL. The right format is <proxy_ip>:<proxy_port>. In case of a proxy requires Basic Authentication the format should be like this <proxy_username>:<proxy_password>@<proxy_ip>:<proxy_port>.If http:// or https:// prefix is not provided, the prefix http:// will be used by default.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `MEND_ALERT`             | boolean |   No*    | True | Whether to include ignored vulnerabilities. Set to false for exclude ignored vulnerabilities.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `MEND_EPSS`              | boolean |    No    | `false` | When `true`, adds EPSS score and Exploit Code Maturity to each work item, read from **Mend API 1.4** — the same API, the same host and the same `MEND_USERKEY` as every other call this integration makes. No extra variable, no extra permission and no separate login. See [Enrichment: Reachability, EPSS and Exploit Code Maturity](#enrichment-reachability-epss-and-exploit-code-maturity) below. |
| `MEND_REACHABILITY`      | boolean |    No    | `false` | When `true`, adds Reachability to each work item, read the same way as `MEND_EPSS`. An org without reachability analysis enabled can leave this off while still using `MEND_EPSS`. Turning on both costs exactly one alerts call per project, the same as turning on either one alone. See [Enrichment: Reachability, EPSS and Exploit Code Maturity](#enrichment-reachability-epss-and-exploit-code-maturity) below. |
| `MEND_MAXLOOKBACK`       | integer |    No    | `720` | Maximum hours to look back for any single Mend project when its stored sync state is missing or stale. Bounds the cost of a project that keeps failing. Set higher if repos may go unscanned for longer than 30 days. |

>**_NOTE_**: `azure-wi-sync` would accept all environment variables with either `MEND_` or `WS_` prefix. For the Azure DevOps settings (`*AZUREURI`, `*AZUREPAT`, `*AZUREPROJECT`, `*AZUREAREA`, `*AZURETYPE`), if both prefixes are set for the same setting, the `WS_` variable wins.

> **Changed:** work item titles are now keyed on the library name alone (and, with
> `MEND_DEPENDENCY: false`, on the CVE and library). Previously they embedded the vulnerability
> count and the highest severity score, which meant suppressing or rescoring a single
> vulnerability renamed the work item — the tool then failed to recognise it, created a
> duplicate and left the original open.
>
> On your first run after upgrading, existing work items are matched by their old title and
> **renamed in place**. Their ids, comments, assignees, links and history are preserved. No
> action is required.
<br />

## Enrichment: Reachability, EPSS and Exploit Code Maturity
Set `MEND_EPSS: true` to add **EPSS score** and **Exploit Code Maturity** to each work item, and/or `MEND_REACHABILITY: true` to add **Reachability**, both read from Mend API 1.4. Each defaults to `false` and is controlled independently — an org without reachability analysis enabled can turn on `MEND_EPSS` alone. Leaving both unset changes nothing about existing behavior.

Enabling either costs you nothing else. Both read the same Mend API 1.4 alerts endpoint, on the same `MEND_URL` host, authenticated with the same `MEND_USERKEY` — so there is no additional variable to set, no additional Mend permission to grant, and no additional login for the integration to perform. Turning on both flags still costs exactly one alerts call per project, the same as turning on either one alone: both signals arrive in the same response.

When enabled, the requested values appear on every **vulnerability** work item — license policy violations carry no CVE and so gain nothing, in either `MEND_DEPENDENCY` mode. Where the values land depends on `MEND_DEPENDENCY`:
- `MEND_DEPENDENCY: true` (default) — as additional columns in the CVE table, and as additional lines in each CVE's expandable detail section. The exploit-code-maturity column's header is the short **`Exploit`**; only the expandable detail line spells it out as `Exploit Code Maturity:`.
- `MEND_DEPENDENCY: false` — there is no table and no expandable section (each CVE is its own work item), so the lines land directly in the flat description.

**EPSS** is rendered exactly as Mend reports it, as a percentage on a 0-100 scale, to one decimal place — `92.4%` is a high-probability finding. It is not rescaled. Anything below one percent renders as `<1%` rather than a decimal, because the great majority of findings sit there and a column of `0.3%` / `0.8%` / `0.2%` values carries no triage signal; a real `0.0` is a genuine answer and also shows as `<1%`, not as `-`.

>**_NOTE_**: Reachability renders as `Reachable`, `Unreachable`, or `-`. **`-` is ambiguous by design and cannot be read as a failure**: it covers both "Mend has no reachability analysis for this project or library" and "this tool could not retrieve the value", and the output does not distinguish them. Mend API 1.4 reports reachability as `{reachable, analyzed}`, and an unanalyzed library carries no verdict to render, so it lands in the same bucket as a failed lookup. If `-` appears everywhere, check the log: a wholesale alerts failure logs one `Could not read Mend alerts for enrichment` warning per run, naming whichever of Reachability, EPSS and Exploit Code Maturity was actually requested. The same applies to Exploit Code Maturity, which renders one of `Unproven`, `PoC Code`, `Functional`, `High`, `Not Defined`, or `-` — there is no `Yes`/`No`.

>**_NOTE_**: Existing work items do not gain these fields retroactively. A work item is only updated when its Mend project next appears in the modified-projects window, so items created before you turned on `MEND_EPSS` / `MEND_REACHABILITY` keep showing the old, shorter table until then. To backfill the new fields onto all existing work items immediately, run once with `MEND_RESET: true` after enabling them.

These same values can also be mapped into custom fields — see [Custom Field Mapping](#custom-field-mapping) below.
<br />

## Setting Scan Tags for Tag-Based Routing
`MEND_ROUTING` reads its destinations from tags on each Mend **project** — `azure-project`, `azure-repo` and `azure-branch` (an optional fourth, `azure-schema`, is used for validation). Those tags are not set on this pipeline. They are set as **Mend CLI scan tags**, in each repository's own build pipeline, at the point where that repository is scanned; Mend then promotes the scan tags onto the Mend project record, which is what this integration later reads. Consult your Mend CLI's documentation for the current flag/property syntax for attaching tags to a scan, and set the three tag values to:

| Tag            | Azure Pipelines variable    |
|----------------|------------------------------|
| `azure-project`| `$(System.TeamProject)`      |
| `azure-repo`   | `$(Build.Repository.Name)`   |
| `azure-branch` | `$(Build.SourceBranch)`      |

>**_IMPORTANT_**: When `MEND_ROUTING: true`, a run that cannot read the Mend project tags does **no work at all** — it logs `Aborted: could not read Mend project tags.` and reports a failed run, rather than syncing some projects and skipping the rest. Routing now reads its tags from the same Mend API 1.4 sweep (`getOrganizationProjectTags`) that carries the integration's own sync state, so an unreadable or structurally unexpected sweep means no destination is known for any project. Aborting is deliberate: continuing would route nothing while reporting success, which looks identical to "nothing changed this window". Earlier versions read routing tags over a separate API and would carry on doing degraded work in this situation. Non-routed runs (`MEND_ROUTING: false`, the default) are unaffected — they only lose their per-project watermarks and fall back to `MEND_MAXLOOKBACK`.

>**_IMPORTANT_**: Use `$(Build.SourceBranch)`, **not** `$(Build.SourceBranchName)`. `SourceBranchName` returns only the final path segment of the ref (`refs/heads/release/1.2` becomes `1.2`), which loses the `release/` prefix and cannot express a `MEND_BRANCHES` pattern like `release/*`. `SourceBranch` carries the full ref (`refs/heads/release/1.2`); this integration strips the `refs/heads/` prefix itself before matching it against `MEND_BRANCHES`.

>**_WARNING_**: Azure Pipelines variable substitution uses `$(...)` parentheses. `${...}` curly braces are **not** pipeline variable syntax — inside a `script` step they are handed to the shell, and bash will fail with `bad substitution`. Also note that tag values (especially `azure-repo`) may contain spaces or other shell-significant characters; the safest pattern is to map each one through the step's `env:` block first and quote it there, rather than interpolating `$(...)` directly into a shell command line:
>```yaml
>  env:
>    AZURE_PROJECT: $(System.TeamProject)
>    AZURE_REPO: $(Build.Repository.Name)
>    AZURE_BRANCH: $(Build.SourceBranch)
>  script: |
>    your-mend-cli-scan-command --tag "azure-project=$AZURE_PROJECT" \
>                               --tag "azure-repo=$AZURE_REPO" \
>                               --tag "azure-branch=$AZURE_BRANCH"
>```
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
<br />

**Example 3**  
Populating custom fields **Reachability**, **EPSS** and **Exploit Maturity** with the risk signals added by `MEND_EPSS` and `MEND_REACHABILITY` (see [Enrichment: Reachability, EPSS and Exploit Code Maturity](#enrichment-reachability-epss-and-exploit-code-maturity)):

```yaml
  env:
    ...
    MEND_EPSS: true
    MEND_REACHABILITY: true
    MEND_AZURETYPE: 'SCA Issue'
    MEND_CUSTOMFIELDS: 'Reachability::MEND:policyViolations.reachability;EPSS::MEND:policyViolations.vulnerability.threatAssessment.epssPercentage;Exploit Maturity::MEND:policyViolations.vulnerability.threatAssessment.exploitCodeMaturity'
```

>**_NOTE_**: These three paths are real, but inherit pre-existing `MEND:` resolution behavior that will surprise you if you expect them to match the description table's CVE columns:
>- A path into `policyViolations` resolves against the **last** violation in the list, not the first — if a library matched more than one CVE, the custom field only ever reflects the last one.
>- When the value is missing, the custom field receives the literal string `No content`, not an empty string.
>- Values arrive **raw**, not the human-readable wording used in the description table: `REACHABLE` rather than `Reachable`, and `0.8` rather than `0.8%` (the number is the same — the custom field just has no `%` suffix). Expect the custom field and the description table to disagree in wording for the same finding.
