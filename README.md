[![Logo](https://mend-toolkit-resources-public.s3.amazonaws.com/img/mend-io-logo-horizontal.svg)](https://www.mend.io/)  

[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/mend-toolkit/mend-azure-pipeline-workitems/actions/workflows/ci.yml/badge.svg)](https://github.com/mend-toolkit/mend-azure-pipeline-workitems/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/v/release/mend-toolkit/mend-azure-pipeline-workitems)](https://github.com/mend-toolkit/mend-azure-pipeline-workitems/releases/latest)

# Integrate Mend SCA with Azure Work Items
A self-hosted tool that creates, updates and closes Azure Work Items from Mend SCA findings.  

The tool is deployed within an Azure Pipeline triggered on fixed intervals by a cron schedule.  
It runs entirely on **Mend API 3.0**. Every run reads each in-scope Mend project's **complete current state** — its security findings, its license policy violations and its library licenses — and then reconciles Azure DevOps against it: it creates a Work Item for a finding that has none, updates one whose finding has changed, **closes** one whose finding is gone, and **reopens** one whose finding has come back.  

There is no watermark, no "modified since" window and no stored sync state. A run that fails is simply repeated in full on the next schedule.  

> ## ⚠️ BREAKING CHANGES — read before upgrading
>
> This release moves the integration off Mend API 1.4 entirely and onto **Mend API 3.0**. The upgrade is **one-way**: once a pipeline is on this version there is no supported way back to the 1.4 behaviour, so upgrade one pipeline first and confirm the Work Items it produces before rolling it out.
>
> 1. **`MEND_EMAIL` is now required.** It is the email address of the Mend user whose `MEND_USERKEY` you are using. It logs in against Mend API 2.0 to obtain the JWT that authenticates every 3.0 call. Without it the run cannot authenticate to Mend and does no work.
> 2. **`MEND_PRODUCTTOKEN`, `MEND_PROJECTTOKEN` and `MEND_EXCLUDETOKEN` now take Mend 3.0 UUIDs**, not the 1.4 tokens you have today. A stale 1.4 token aborts the run with a message naming the offending variable — it never silently syncs the wrong scope.
> 3. **`MEND_ALERT`, `MEND_EPSS`, `MEND_RESET` and `MEND_MAXLOOKBACK` are removed**, along with the per-project sync-state tags (`azure-wi-lastrun`, `azure-wi-failed`). There is no window to reset, no watermark to advance and no retry queue. Mend 3.0 reports a finding's suppression state on the finding itself, so nothing is left for `MEND_ALERT` to filter, and EPSS and Exploit Code Maturity now always render. Leaving any of these set in your pipeline is harmless — they are ignored.
> 4. **`MEND_CUSTOMFIELDS` paths must be rewritten.** A `MEND:` dot-path is now walked into a **Mend 3.0 finding**, not a 1.4 policy issue. Every existing path — `MEND:policyViolations.*`, `MEND:vulnerability.*`, `MEND:library.*`, `MEND:policy.*` — resolves to an empty value or to the literal string `No content`. See [Custom Field Mapping](#custom-field-mapping) for the new paths and a migration table.
> 5. **The reverse sync is gone.** Work Item status is no longer pushed back to Mend. Closing a Work Item in Azure DevOps has no effect in Mend; the flow is now one-way, Mend → Azure DevOps. To stop a Work Item being recreated, resolve or suppress the finding in Mend — which now also **closes** the Work Item (see [Closing and Reopening Work Items](#closing-and-reopening-work-items)).
> 6. **`MEND_SEVERITY` is now live.** It was inert in previous releases. It defaults to `high`, which means findings below CVSS **7.0** no longer produce Work Items — and any existing Work Item below that floor is **closed** on the first run. If you want the previous "everything" behaviour, set `MEND_SEVERITY: low`.
>
> A run that did not fully complete still exits with a **non-zero exit code**.

## Table of Contents
- [Supported Operating Systems](#supported-operating-systems)
- [Prerequisites](#prerequisites)
- [Planning Your WorkItems Setup](#planning-your-work-items-setup)
- [Azure DevOps Setup](#azure-devops-setup)
- [Mend SCA Setup](#mend-sca-setup)
- [Azure Pipeline Variables](#azure-pipeline-variables)
- [Enrichment: Reachability, EPSS and Exploit Code Maturity](#enrichment-reachability-epss-and-exploit-code-maturity)
- [Root Library Grouping and Remediation](#root-library-grouping-and-remediation)
- [Setting Scan Tags for Tag-Based Routing](#setting-scan-tags-for-tag-based-routing)
- [Closing and Reopening Work Items](#closing-and-reopening-work-items)
- [Unchanged Work Items and State Preservation](#unchanged-work-items-and-state-preservation)
- [Execution](#execution)
- [Custom Field Mapping](#custom-field-mapping)
  - [Available `MEND:` Paths](#available-mend-paths)
  - [Migrating from Mend API 1.4 Paths](#migrating-from-mend-api-14-paths)
  - [Examples](#examples)

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
* Mend SCA license policies, if you want license Work Items — see [Mend SCA Setup](#mend-sca-setup). Vulnerability Work Items need no policy.
* Mend SCA service user with associated with a [role assignment](https://docs.mend.io/bundle/sca_user_guide/page/managing_groups.html#Assigning-a-Role-to-a-Group) of either **Organization Administrator** or **Organization Auditor**  
* The **email address** of that Mend service user, supplied as `MEND_EMAIL`. It is required: the integration logs in against Mend API 2.0 with `MEND_EMAIL` + `MEND_USERKEY` + `MEND_APIKEY` to obtain the JWT that authenticates every Mend API 3.0 call.  

The PAT needs **Work Items (Read, write & manage)** and **Project and Team (Read)**.

*Manage project properties* is **no longer required**, and neither is any Mend project-tag write:
the integration stores no sync state at all. Every run reads each Mend project's full current
state from Mend API 3.0, so an interrupted run costs nothing but the time to read it again.

**Onboarding a new organization:** nothing special to do. The first run picks up every existing
finding, because every run does.
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
4. Set up the appropriate environment variables/secrets for the pipeline. The minimum requirements for these variables are: `MEND_URL`, `MEND_USERKEY`, `MEND_APIKEY`, `MEND_EMAIL`, and `MEND_AZUREPAT`. We recommend also setting `MEND_PRODUCTTOKEN`, `MEND_PROJECTTOKEN`, and/or `MEND_EXCLUDETOKEN` as detailed above
<br />

## Mend SCA Setup
Two different things drive Work Item creation, and only one of them involves a policy:

**Vulnerability Work Items need no policy at all.** They come from the project's Mend API 3.0 security findings, selected by CVSS score against `MEND_SEVERITY` (default `high` = 7.0). There is nothing to configure in Mend — every active finding at or above the floor gets a Work Item.

> **_BEHAVIOR CHANGE_**: Earlier releases created vulnerability Work Items only for libraries matched by a Mend **Issue** policy. They are now driven by `MEND_SEVERITY` instead, so your Issue policies no longer decide which vulnerabilities become Work Items. If your policies were narrower than "CVSS ≥ 7.0" you will see **more** Work Items on the first run; if they were broader, tune `MEND_SEVERITY` down.

**License Work Items come from the project's license policy violations.** Set up a policy for each license case you wish a Work Item to be created for. The naming convention should include, other than a self explanatory description of what the policy does, a square-bracketed prefix, either `[License]` or `[Security]` — the integration strips that prefix and renders the rest as the violation's policy name on the Work Item.

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
| `MEND_PRODUCTTOKEN`      | string  |    No    | Empty String <br />(Include all products) | Comma-separated list of Mend **product UUIDs** to monitor. **Mend API 3.0 UUIDs** — not the 1.4 product tokens used by earlier releases. A value that is neither a UUID nor a token aborts the run with a message naming this variable. Under `MEND_ROUTING` these narrow the set of Mend projects considered rather than choosing Azure targets.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `MEND_PROJECTTOKEN`      | string  |    No    | Empty String <br />(Include all projects) | Comma-separated list of Mend **project UUIDs** to monitor. **Mend API 3.0 UUIDs** — not the 1.4 project tokens used by earlier releases. A value that is neither a UUID nor a token aborts the run with a message naming this variable. Under `MEND_ROUTING` these narrow the set of Mend projects considered rather than choosing Azure targets.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `MEND_EXCLUDETOKEN`      | string  |    No    | Empty String <br /> (No exclusions) | Comma-separated list of Mend **project UUIDs** that should not be monitored. **Mend API 3.0 UUIDs** — not the 1.4 project tokens used by earlier releases. A value that is neither a UUID nor a token aborts the run with a message naming this variable. Under `MEND_ROUTING` these narrow the set of Mend projects considered rather than choosing Azure targets.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `MEND_AZUREAREA`         | string  |    No    | `$MEND_AZUREPROJECT` | [Area Path](https://learn.microsoft.com/en-us/azure/devops/organizations/settings/set-area-paths?view=azure-devops) to group created Work Items under. <br/> For example: `TeamProject\Area1\SubArea2` or `Area1\SubArea2`. Use double-backslashes when specifying sub-areas.                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `MEND_AZURETYPE`         | string  |    No    | Task | Work Item type for creating new Work Items. <br/> Must be one of the [built-in](https://learn.microsoft.com/en-us/azure/devops/boards/work-items/about-work-items?view=azure-devops&tabs=agile-process#track-work-with-different-work-item-types) or [custom](https://learn.microsoft.com/en-us/azure/devops/boards/work-items/about-work-items?view=azure-devops&tabs=agile-process#customize-a-work-item-type) types that are available for the project's [process](https://learn.microsoft.com/en-us/azure/devops/boards/work-items/guidance/choose-process?view=azure-devops&tabs=agile-process). (Basic, Agile, Scrum, etc.) associated with the specified Team Project in the `MEND_AZUREPROJECT` variable. |
| `MEND_CUSTOMFIELDS`      | string  |   No*    | Empty String <br /> (No custom fields) | Used for mapping additional information from Mend's Issue Policy objects into custom fields of the specified Work Item type (`$MEND_AZURETYPE`). <br/> See [Custom Work Item Types](#custom-field-mapping) below for syntax guidelines. <br/>  This variable is required when using custom Work Item types.                                                                                                                                                                                                                                                                                                                                                                                                       |
| `MEND_REPONAME`          | string  |   No*    | <Name of Repository\> <br /> **_Do not change_** | The field contains Repo Name which can be used as value for any Custom field according Custom Fields syntax. See [Custom Work Item Types](#custom-field-mapping) below for syntax guidelines (`$MEND_REPONAME`). When `MEND_ROUTING` is enabled this is set per Mend project from the scan tag rather than read from the environment.                                                                                                                                                                                                                                                                                                                  |
| `MEND_ROUTING`           | boolean |    No    | `false` | Route findings to Azure DevOps projects using tags recorded on each Mend project at scan time, instead of choosing targets from `MEND_PRODUCTTOKEN` / `MEND_PROJECTTOKEN`. Requires the scan pipeline to set the `azure-project`, `azure-repo` and `azure-branch` tags on each Mend project. When `false` (the default) behaviour is unchanged. |
| `MEND_BRANCHES`          | string  |    No    | `main,master` | Comma-separated glob patterns of branches to sync when `MEND_ROUTING` is enabled. Matched against the branch recorded at scan time with the `refs/heads/` prefix stripped — e.g. `main,release/*`. Applied at sync time, so changing it does not require rescanning. |
| `MEND_DEPENDENCY`        | boolean |   No*    | True | Specify whether to create work items based on the dependency (value: True) or based on the CVE (value: False). `true` (default) creates one Work Item per **root library** — the direct dependency you can actually upgrade — listing every vulnerable library that root pulls in, including transitive ones; a vulnerable library reachable from more than one root appears under each of them. `false` creates one Work Item per CVE per vulnerable library instead, and typically creates more work items. See [Root Library Grouping and Remediation](#root-library-grouping-and-remediation) below.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `MEND_DESCRIPTION`       | string | No* | "ReproSteps" | Used to tell the Integrations which field should contain the description. Use "ReproSteps" for bugs, "Description" for issues, or a custom name for a custom field.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `MEND_CALCULATEPRIORITY` | boolean |   No*    | False | Priority will be calculated according to Mend’s severity (CSS3) value if the value is equal to True. If not, it will be set to 2 (default priority).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `MEND_SSLVERIFY`         | boolean |    No    | `true` | TLS certificate verification for both the Mend and Azure DevOps calls. Leave it unset: `requests` ships a CA bundle and both hosts serve publicly trusted certificates, so an agent verifies them with nothing to install. Set `false` only to unblock a run where verification fails -- it is the behaviour of versions before this one and is the only setting that produces urllib3's `InsecureRequestWarning`. To supply a CA bundle for a self-hosted agent behind a TLS-inspecting proxy, set the standard `REQUESTS_CA_BUNDLE` environment variable to its path -- `requests` reads that directly, and this variable does not take a path. |
| `MEND_DEPPATHS`          | boolean |    No    | `true` | Whether to fetch and render each transitive library's root-to-leaf dependency chain ("Dependency Hierarchy") in its work item description. Fetched from a Mend 2.0 endpoint, one call per distinct library, concurrently (see `MEND_DEPPATHS_CONCURRENCY`). Set `false` to skip this entirely -- no calls are made and descriptions fall back to the flat parents list -- as an emergency kill switch if the endpoint is unavailable or unacceptably slow for your org. Only an explicit false-y value (`false`/`no`/`0`) turns it off; anything else, including unset, fetches as normal. |
| `MEND_DEPPATHS_CONCURRENCY` | integer | No    | `16`   | How many `/paths` calls run at once when `MEND_DEPPATHS` is fetching dependency hierarchies. Mend imposes no rate limit on this endpoint, so this is purely a throughput knob, not a politeness one -- raise it if a run with many transitive libraries is still slow, lower it (down to `1` for genuinely serial, one call at a time) if you want to diagnose a problem without concurrency in the way. A non-numeric value, `0`, or a negative number is treated as unset and falls back to `16` (logged as a warning); a value above `64` is clamped to `64`. |
| `MEND_PROXY`             | string  |    No    | Empty String <br /> | The Proxy URL. The right format is <proxy_ip>:<proxy_port>. In case of a proxy requires Basic Authentication the format should be like this <proxy_username>:<proxy_password>@<proxy_ip>:<proxy_port>.If http:// or https:// prefix is not provided, the prefix http:// will be used by default.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `MEND_REACHABILITY`      | boolean |    No    | `false` | When `true`, adds Reachability to each work item, read from the same Mend API 3.0 finding that produced it. An org without reachability analysis enabled can leave this off and avoid a column of `-`. EPSS and Exploit Code Maturity always render and have no switch. See [Enrichment: Reachability, EPSS and Exploit Code Maturity](#enrichment-reachability-epss-and-exploit-code-maturity) below. |
| `MEND_EMAIL`             | string  |   Yes    | N/A | The email address of the Mend user whose `MEND_USERKEY` this is. **Required.** It is sent with `MEND_USERKEY` and `MEND_APIKEY` to the Mend API 2.0 login, which returns the JWT that authenticates every Mend API 3.0 call. Without it the run cannot authenticate to Mend and does no work. |
| `MEND_ORGUUID`           | string  |    No    | `MEND_APIKEY` | The organization UUID used by Mend API 3.0 paths. Defaults to `MEND_APIKEY`, which is the same value for most orgs — set it only if your Organization UUID differs from your API key. |
| `MEND_SEVERITY`          | string  |    No    | `high` | The minimum CVSS severity a finding must reach to earn a Work Item. Accepts a band — `low` (0.1), `medium` (4.0), `high` (7.0), `critical` (9.0) — or a number from `0` to `10`. **The same floor governs creation and closure**: a finding below it produces no Work Item, and an existing Work Item whose findings have all dropped below it is closed. An unscored finding is always included, because it cannot be compared and losing a real vulnerability is worse than one extra Work Item. An unparseable value falls back to `high` rather than to `0`, so a typo cannot silently open the floodgates. |
| `MEND_CLOSEDSTATE`       | string  |    No    | auto | The `System.State` value written when a work item is closed because its finding is no longer present in Mend. **Leave it unset** and the tool tries the states Azure's out-of-box processes use — `Closed` (Agile, CMMI) then `Done` (Scrum, Basic) — remembering whichever the board accepts, so a mix of processes needs no configuration. Set it only for a **derived process with a renamed state**: an explicit value is used alone and never followed by a fallback. Accepts a comma-separated list tried in order (`Retired,Closed`), which is how one variable serves a fleet mixing a derived process with an out-of-box one. See [Closing and Reopening Work Items](#closing-and-reopening-work-items). It has no effect on Work Item creation. |
| `MEND_REOPENSTATE`       | string  |    No    | auto | The `System.State` value written when a closed work item's finding comes back in Mend. **Leave it unset** and the tool tries `New` (Agile, Scrum backlog items) then `To Do` (Basic, Scrum tasks) then `Proposed` (CMMI). Set it only for a **derived process with a renamed state**; an explicit value is used alone. Accepts a comma-separated list tried in order (`Reopened,New`). See [Closing and Reopening Work Items](#closing-and-reopening-work-items). It has no effect on Work Item creation. |

>**_NOTE_**: `azure-wi-sync` would accept all environment variables with either `MEND_` or `WS_` prefix. For the Azure DevOps settings (`*AZUREURI`, `*AZUREPAT`, `*AZUREPROJECT`, `*AZUREAREA`, `*AZURETYPE`), if both prefixes are set for the same setting, the `WS_` variable wins.

<br />

## Enrichment: Reachability, EPSS and Exploit Code Maturity
**EPSS score** and **Exploit Code Maturity** are always added to each work item — there is no switch, because both values arrive on the Mend API 3.0 finding the work item is built from and always carry a value. `MEND_EPSS` has been **removed**; leaving it set in your pipeline is harmless.

**Reachability** is added when `MEND_REACHABILITY: true`. It keeps its switch because it is blank for an organization that has not enabled reachability analysis, and the toggle spares them a column of `-` in every row. It defaults to `false`.

None of this costs an extra call: every value arrives on the finding the integration already reads — no additional Mend permission and no additional login.

These values appear on every **vulnerability** work item — license policy violations carry no CVE and so gain nothing, in either `MEND_DEPENDENCY` mode. Where the values land depends on `MEND_DEPENDENCY`:
- `MEND_DEPENDENCY: true` (default) — as additional columns in the CVE table, and as additional lines in each CVE's expandable detail section. The exploit-code-maturity column's header is the short **`Exploit`**; only the expandable detail line spells it out as `Exploit Code Maturity:`.
- `MEND_DEPENDENCY: false` — there is no table and no expandable section (each CVE is its own work item), so the lines land directly in the flat description.

**EPSS** is rendered exactly as Mend reports it, as a percentage on a 0-100 scale, to one decimal place — `92.4%` is a high-probability finding. It is not rescaled. Anything below one percent renders as `<1%` rather than a decimal, because the great majority of findings sit there and a column of `0.3%` / `0.8%` / `0.2%` values carries no triage signal; a real `0.0` is a genuine answer and also shows as `<1%`, not as `-`.

>**_NOTE_**: Reachability renders as `Reachable`, `Unreachable`, or `-`. **`-` is ambiguous by design and cannot be read as a failure**: it covers both "Mend has no reachability analysis for this project or library" and "this tool could not retrieve the value", and the output does not distinguish them. An unanalyzed library carries no verdict to render, so it lands in the same bucket as a missing value. If `-` appears everywhere, the likely cause is that reachability analysis is not enabled for the organization. The same applies to Exploit Code Maturity, which renders one of `Unproven`, `PoC Code`, `Functional`, `High`, `Not Defined`, or `-` — there is no `Yes`/`No`.

>**_NOTE_**: Existing work items do not gain these fields retroactively. Every run reads each project's full current state, so the first run after you enable `MEND_REACHABILITY` updates every work item.

These same values can also be mapped into custom fields — see [Custom Field Mapping](#custom-field-mapping) below.
<br />

## Root Library Grouping and Remediation
In `MEND_DEPENDENCY: true` (the default), each vulnerability work item now covers one **root library** — the direct dependency you can actually upgrade — rather than one vulnerable library. The work item lists every vulnerable library that root pulls in, including ones only reachable transitively. A vulnerable library reachable from more than one root appears under **each** of them: whoever owns `express` needs to see everything upgrading `express` would fix, and so does whoever owns `webpack`, even when both roots pull in the same vulnerable library. This matches how Mend's own repository integrations group findings. On a live project, `cookie-0.3.1.tgz` has three roots.

Each root-library work item shows **Recommended Fix** and **Recommended Major Version**, prominently, above the CVE table. Both come from Mend's root-library remediation data and are Mend's verdict for the root library **as a whole** — not for any single CVE.

>**_NOTE_**: Mend does not publish which individual CVEs a given root version clears. Its remediation fields are aggregate over the root's entire CVE set, and no Mend endpoint joins a CVE to a root-library version. That is why dependency mode's CVE table has no per-CVE **Fixed in** column: the column it replaced showed the *transitive* library's own fix version, which is not something an operator can set by upgrading the root. Treat the absence as a documented Mend API limitation, not a missing feature. `MEND_DEPENDENCY: false` is unaffected and keeps its "Fixed in" column, because a per-CVE work item genuinely is about one CVE in one library.

>**_NOTE_**: This grouping change is a **one-time, disruptive changeover**. Existing dependency-mode vulnerability work items were titled per vulnerable library, and none of those titles match the new root-library titles. The first run after upgrading therefore closes every existing dependency-mode vulnerability work item and creates root-library work items in their place. Comments, assignees and history do not carry across to the new items — the closed items remain in Azure DevOps as a record and are never deleted. On a sampled project this took roughly 40 work items down to 10. Pilot the upgrade on one project before running it fleet-wide.
<br />

## Setting Scan Tags for Tag-Based Routing
`MEND_ROUTING` reads its destinations from tags on each Mend **project** — `azure-project`, `azure-repo` and `azure-branch` (an optional fourth, `azure-schema`, is used for validation). Those tags are not set on this pipeline. They are set as **Mend CLI scan tags**, in each repository's own build pipeline, at the point where that repository is scanned; Mend then promotes the scan tags onto the Mend project record, which is what this integration later reads. Consult your Mend CLI's documentation for the current flag/property syntax for attaching tags to a scan, and set the three tag values to:

| Tag            | Azure Pipelines variable    |
|----------------|------------------------------|
| `azure-project`| `$(System.TeamProject)`      |
| `azure-repo`   | `$(Build.Repository.Name)`   |
| `azure-branch` | `$(Build.SourceBranch)`      |

>**_IMPORTANT_**: When `MEND_ROUTING: true`, a run that cannot read the Mend project tags does **no work at all** — it logs `Aborted: could not read Mend project tags.` and reports a failed run, rather than syncing some projects and skipping the rest. Routing reads its tags from the Mend API 3.0 project payload, so an unreadable project list means no destination is known for any project. Aborting is deliberate: continuing would route nothing while reporting success, which looks identical to "nothing changed this window". Earlier versions read routing tags over a separate API and would carry on doing degraded work in this situation.

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

## Closing and Reopening Work Items
Every run reads each in-scope Mend project's **complete current state** and reconciles the Work Items in Azure DevOps against it. A Work Item whose Mend finding is no longer there is **closed**; if the finding comes back, the *same* Work Item is **reopened**.

**A Work Item is closed when its finding is gone from Mend.** That covers every way a finding can leave:
- the finding is **suppressed** or **ignored** in Mend
- the vulnerable **library is removed** from the project (upgraded, replaced, or the dependency dropped)
- the library is marked **in-house** or **whitelisted**
- for a license Work Item, the **license policy violation** no longer matches
- the finding's CVSS score drops below `MEND_SEVERITY` (see the [variable table](#azure-pipeline-variables))

Closing sets the Work Item's `System.State` to a closed state, and reopening to an open one. **You do not normally configure either.** Azure DevOps's four out-of-box processes use only two closed names between them — `Closed` for Agile and CMMI, `Done` for Scrum and Basic — so the tool tries them in order, per Azure project, and remembers which one that board accepted. A board on a second process therefore costs one rejected request on the first item it closes, and none afterwards.

Set `MEND_CLOSEDSTATE` / `MEND_REOPENSTATE` only if a **derived process** renames the state. An explicit value is then used *alone* — the tool will not quietly try something else, because an operator who asks for `Retired` did not ask for `Closed`.

Both accept a **comma-separated list**, tried in order — `MEND_CLOSEDSTATE: Retired,Closed`. That is what you need if your projects span a derived process *and* an out-of-box one: leaving it unset fails the derived board, and naming only `Retired` fails the out-of-box board, because an explicit value is never followed by a fallback. Listing both covers both, and each Azure project still remembers whichever entry it accepted.

>**_NOTE_**: A state name that no process on the board accepts is reported per work item, naming every value tried and the variable to set. That one item is left as it was and the run continues.

>**_IMPORTANT_**: **Closure never deletes a Work Item.** It only changes the state field. The Work Item keeps its **id**, its history, its comments, its links and any fields your team edited. A finding that comes back reopens *that* Work Item — you do not get a fresh id and you do not lose the discussion that happened on the original.

>**_IMPORTANT_**: **Closure is skipped for any project whose Mend read did not complete.** If a page of findings fails to load, an incomplete result is indistinguishable from a project whose findings were all remediated — and acting on that would be a mass-closure event. When a project's read is incomplete the run logs it, skips every closure for that project, and reports a failed run with a non-zero exit code. **Reopening still runs**, because reopening cannot destroy anything. A failed read can therefore never be mistaken for a resolved backlog.

>**_NOTE_**: Reconciliation identifies Work Items by their **title** and by the `{product}/{project}` tag the integration writes. A Work Item whose title was hand-edited is no longer recognised, and will neither be updated nor closed — a second Work Item is created for the finding instead. Do not rename the titles the integration generates.

>**_NOTE_**: In `MEND_DEPENDENCY: true` (the default) one Work Item covers one root library and every vulnerable library beneath it, so it is closed only once **every** vulnerability in that group is gone. In `MEND_DEPENDENCY: false` one Work Item is one CVE and is closed as soon as that CVE is gone.
<br />

## Unchanged Work Items and State Preservation
**A Work Item whose content has not changed is not written at all.** Before updating a Work Item the integration compares what it is about to write — title, priority, tags, the description field selected by `MEND_DESCRIPTION`, the area path, and any custom fields — against what Azure DevOps already holds. When every one of them already matches, the update is skipped and the run logs it (at `DEBUG`) as unchanged. Tags are compared as a set and case-insensitively, so Azure's own `"; "` formatting never counts as a change. If the Work Item could not be read, the update is issued anyway — an unreadable item is never assumed to be up to date.

This matters beyond saving API calls. **Some Azure DevOps processes have a rule that resets a Work Item's state whenever the item is edited.** With such a rule in place, an update that changed nothing would still drag a Work Item an operator had moved to `Active` back to `New`, once per run. Skipping the write removes that entirely for the Work Items that did not change.

**When a content update genuinely is needed, the previous state is restored.** The integration records the Work Item's `System.State` before the update and checks it afterwards. If a process rule moved it, the original value is written back and the run logs at `INFO` that the state was restored. A restore that itself fails is logged and the run carries on — it never costs a Work Item or fails the run.

>**_NOTE_**: This does **not** interfere with [closing and reopening](#closing-and-reopening-work-items). Those deliberately set `System.State` to `MEND_CLOSEDSTATE` / `MEND_REOPENSTATE`, run as a separate reconciliation step after the content updates, and are never undone by state preservation.
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
Each run reads each in-scope Mend project's complete current state from Mend API 3.0 and reconciles Azure DevOps against it. There is no "since the last execution" window: a scheduled run is always a full comparison, so a missed or failed run costs nothing but the delay.  
<br />

## Custom Field Mapping
When specifying a [custom Work Item type](https://learn.microsoft.com/en-us/azure/devops/boards/work-items/about-work-items?view=azure-devops&tabs=agile-process#customize-a-work-item-type) with `$MEND_AZURETYPE`, the integration will utilize the [Azure API](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-item-types/get) to automatically obtain its definition.

The `MEND_CUSTOMFIELDS` variable then populates any of that type's custom fields from the **Mend API 3.0 entry** that produced the Work Item.

> **_BREAKING_**: In releases before the move to Mend API 3.0, a `MEND:` path was walked into a Mend API 1.4 policy issue. It is now walked into a **3.0 entry**, and **every 1.4 path must be rewritten**. See [Migrating from Mend API 1.4 Paths](#migrating-from-mend-api-14-paths).
<br />

### Setting the Custom Fields Variable
The `MEND_CUSTOMFIELDS` variable accepts a string that is a semi-colon separated list of key-value pairs in the format of `FieldName::StaticValue` or `FieldName::MEND:MappedValue`. More than one mapped value can be placed into a custom field by concatenating them with `&`, like `CustomField::MEND:MappedValue&MEND:MappedValue`. The field name directly corresponds to the `name` property returned in the Azure API's "[WorkItemTypeFieldInstance](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-item-types/get?view=azure-devops-rest-7.0&tabs=HTTP#workitemtypefieldinstance)".

>**_NOTE_**: If the definition of the specified Work Item type (`$MEND_AZURETYPE`) includes any fields that are set up as mandatory (`"alwaysRequired": true`), you must also use `MEND_CUSTOMFIELDS` to map values to those fields.
<br />

### Guidelines
- The value of `MEND_CUSTOMFIELDS` should be a quoted string (single or double quotes)
- The string should contain all the desired `Key::Value` mapping pairs, separated by semicolons (`;`)
- The `Key` of each pair should be the name of the Work Item field (the `name` property, AKA "friendly name". See [WorkItemTypeFieldInstance](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-item-types/get?view=azure-devops-rest-7.0&tabs=HTTP#workitemtypefieldinstance) for details)
- The value can contain a dot-separated path into the **Mend 3.0 entry** the Work Item was built from, prefixed by the namespace `MEND:` (case sensitive). The available paths are listed in [Available `MEND:` Paths](#available-mend-paths) below
- The value can also contain custom text, either dynamic (using pipeline variables) or static
- The value can combine multiple parts, both `MEND:` properties and/or free text. Parts should be delimited by an ampersand (`&`)
- If you plan to use the `MEND_REPONAME` or `MEND_DESCRIPTION` variables then you can add these to a custom field with `$MEND_REPONAME` or `$MEND_DESCRIPTION`

**Syntax**
```yaml
  env:
    ...
    MEND_AZURETYPE: 'SCA Issue'
    MEND_CUSTOMFIELDS: 'Field 1::MEND:path.to.property1;Field 2::MEND:property2& Free Text &MEND:property3;Field 4::$MEND_REPONAME'
```
<br />

### Available `MEND:` Paths
A `MEND:` path is walked into one of the **entries** the Work Item was built from. An entry is one root library (in the default `MEND_DEPENDENCY: true` mode) or one CVE (in `MEND_DEPENDENCY: false`), and it has this shape:

```
{
  "library":  "log4j-core",           <- MEND:library
  "kind":     "vulnerability",        <- MEND:kind
  "findings": [ <Mend 3.0 finding>, ... ],   <- MEND:findings.<...>
  "licenses": [ {"name", "url", "reference_file"}, ... ]   <- MEND:licenses.<...>
}
```

Every path below has been verified to resolve. The right-hand column shows what each one returns for a `log4j-core` entry carrying `CVE-2021-44228`:

| Path                                             | Resolves to                                                | Notes |
|--------------------------------------------------|------------------------------------------------------------|-------|
| `MEND:library`                                     | `log4j-core`                                               | The vulnerable library name. Present on every entry, in both `MEND_DEPENDENCY` modes. |
| `MEND:kind`                                        | `vulnerability`                                            | Either `vulnerability` or `license`. |
| `MEND:findings.vulnerability.name`                 | `CVE-2021-44228`                                           | The CVE (or Mend `WS-`) identifier. |
| `MEND:findings.vulnerability.score`                | `10.0`                                                     | CVSS base score, as a number. |
| `MEND:findings.vulnerability.severity`             | `HIGH`                                                     | Raw Mend wording, upper-case — not the `High` used in the description. |
| `MEND:findings.vulnerability.description`          | `JNDI lookup RCE`                                          | The vulnerability description text. |
| `MEND:findings.component.name`                     | `log4j-core`                                               | Same value as `MEND:library`. |
| `MEND:findings.component.version`                  | `2.14.1`                                                   | The resolved library version. |
| `MEND:findings.component.groupId`                  | `org.apache.logging.log4j`                                 | Maven coordinate; empty for ecosystems that have none. |
| `MEND:findings.component.artifactId`               | `log4j-core`                                               | Maven coordinate; empty for ecosystems that have none. |
| `MEND:findings.component.dependencyType`           | `TRANSITIVE`                                               | `DIRECT` or `TRANSITIVE`. |
| `MEND:findings.component.references.homePage`      | `https://logging.apache.org/log4j/2.x/`                    | The library's home page. |
| `MEND:findings.findingInfo.status`                 | `ACTIVE`                                                   | A Work Item only exists while this is `ACTIVE`; anything else closes it. |
| `MEND:findings.findingInfo.detectedAt`             | `2026-08-01T10:00:00Z`                                     | When Mend first detected the finding. |
| `MEND:findings.threatAssessment.epssPercentage`    | `97.5`                                                     | EPSS on a 0-100 scale. **Raw** — no `%` suffix, and no `<1%` collapsing. |
| `MEND:findings.threatAssessment.exploitCodeMaturity` | `HIGH`                                                   | Raw wording, upper-case — not the `High` used in the description. |
| `MEND:findings.reachability`                       | `REACHABLE`                                                | Raw wording — `REACHABLE` rather than `Reachable`. Blank for an org without reachability analysis. |
| `MEND:findings.topFix.fixResolution`               | `2.17.1`                                                   | The recommended fix version, when Mend has one. |
| `MEND:licenses.name`                               | `Apache-2.0`                                               | License name, from the project's due-diligence report. |
| `MEND:licenses.url`                                | URL to the license text                                    | |
| `MEND:licenses.reference_file`                     | `pom.xml`                                                  | The artifact that evidenced the license. |

<br />

#### Two behaviours that will surprise you

Both of these are long-standing `MEND:` resolution behaviours, not new — but they matter much more now that the paths have changed.

**1. `findings.X` resolves against the LAST finding, not the first and not the most severe.**

In the default `MEND_DEPENDENCY: true` mode, one Work Item covers a whole root library and every vulnerable library beneath it, and `findings` is a *list*. A path through it resolves against **whichever finding Mend returned last** — which is arbitrary. It is *not* the first finding, and it is *not* the highest-severity one:

```
entry.findings = [ CVE-2020-8203 (7.4, HIGH),
                   CVE-2021-23337 (9.8, CRITICAL),
                   CVE-2019-10744 (3.1, LOW) ]

MEND:findings.vulnerability.name      ->  CVE-2019-10744
MEND:findings.vulnerability.score     ->  3.1
MEND:findings.vulnerability.severity  ->  LOW
```

A field mapped to `MEND:findings.vulnerability.score` on a library with several CVEs will therefore **disagree with the "highest severity is …" figure in the Work Item's own title**, and will not be the CVE a reader would expect. The same applies to `MEND:licenses.*` when a library carries more than one license.

If you need one value per CVE, use `MEND_DEPENDENCY: false` — each Work Item is then a single CVE and its entry holds exactly one finding, so there is no ambiguity.

**2. An unresolvable path writes the literal string `No content` into the field.**

A typo does **not** leave the Azure field blank — it fills it with the two words `No content`:

```
MEND:findings.vulnerability.nmae   ->  "No content"     (typo in the last segment)
MEND:library.filename              ->  "No content"     (1.4 path; `library` is a string, `.filename` is not on it)
```

The one case that yields an empty value instead is a path whose **first** segment does not exist on the entry at all — the run logs `Custom field parsing failed` and leaves the field empty (for a `Custom.` field, the field is explicitly cleared):

```
MEND:vulnerability.name            ->  ""    (1.4 path; no top-level `vulnerability` key)
MEND:policyViolations.name         ->  ""    (1.4 path; no top-level `policyViolations` key)
```

Either way, check your pipeline log for `Custom field parsing failed` and for `The field '…' is empty. Check the MEND_CUSTOMFIELDS syntax.` after changing `MEND_CUSTOMFIELDS`, and check one produced Work Item before rolling the change out.
<br />

### Migrating from Mend API 1.4 Paths
Every `MEND:` path written against Mend API 1.4 is now dead. Rewrite them:

| Old (Mend API 1.4)                                                  | New (Mend API 3.0)                                    |
|----------------------------------------------------------------------|--------------------------------------------------------|
| `MEND:library.filename` / `MEND:library.name`                          | `MEND:library`                                         |
| `MEND:library.version`                                                 | `MEND:findings.component.version`                      |
| `MEND:library.groupId`                                                 | `MEND:findings.component.groupId`                      |
| `MEND:library.artifactId`                                              | `MEND:findings.component.artifactId`                   |
| `MEND:vulnerability.name`                                              | `MEND:findings.vulnerability.name`                     |
| `MEND:vulnerability.score`                                             | `MEND:findings.vulnerability.score`                    |
| `MEND:vulnerability.severity`                                          | `MEND:findings.vulnerability.severity`                 |
| `MEND:vulnerability.description`                                       | `MEND:findings.vulnerability.description`              |
| `MEND:policyViolations.vulnerability.name`                             | `MEND:findings.vulnerability.name`                     |
| `MEND:policyViolations.vulnerability.type`                             | `MEND:kind`                                            |
| `MEND:policyViolations.vulnerability.threatAssessment.epssPercentage`  | `MEND:findings.threatAssessment.epssPercentage`        |
| `MEND:policyViolations.vulnerability.threatAssessment.exploitCodeMaturity` | `MEND:findings.threatAssessment.exploitCodeMaturity` |
| `MEND:policyViolations.reachability`                                   | `MEND:findings.reachability`                           |
| `MEND:policy.name` / `MEND:policy.policyContext`                       | *No equivalent.* Mend API 3.0 does not carry the matched policy on a security finding. Use static text, or `MEND:kind`. |

>**_NOTE_**: `MEND:findings.threatAssessment.*` and `MEND:findings.reachability` sit directly on the **finding**, not under `vulnerability` as they did in 1.4. This is the single easiest path to get wrong: `MEND:findings.vulnerability.threatAssessment.epssPercentage` resolves to `No content`, silently.
<br />

### Examples
All the following examples assume a custom Work Item type named **SCA Issue**, which was configured to inherit fields from the **Bug** Work Item of the **Agile** process flow.

**Example 1**
Populating the Work Item's custom fields **Library** and **Issue Reference** with the vulnerable library and the CVE identifier:

```yaml
  env:
    ...
    MEND_AZURETYPE: 'SCA Issue'
    MEND_CUSTOMFIELDS: 'Library::MEND:library;Issue Reference::MEND:findings.vulnerability.name'
```
<br />

**Example 2**
Populating the Work Item's custom field **Team Comments** with the text
**Library: *LIBRARY* version *VERSION* (repo: *REPONAME*)**, combining `MEND:` paths, free text and a pipeline variable with `&`:

```yaml
  env:
    ...
    MEND_AZURETYPE: 'SCA Issue'
    MEND_CUSTOMFIELDS: 'Team Comments::Library: &MEND:library& version &MEND:findings.component.version& (repo: &$MEND_REPONAME&)'
```
<br />

**Example 3**
Populating custom fields **Reachability**, **EPSS** and **Exploit Maturity** with the risk signals on each finding (see [Enrichment: Reachability, EPSS and Exploit Code Maturity](#enrichment-reachability-epss-and-exploit-code-maturity)):

```yaml
  env:
    ...
    MEND_REACHABILITY: true
    MEND_AZURETYPE: 'SCA Issue'
    MEND_CUSTOMFIELDS: 'Reachability::MEND:findings.reachability;EPSS::MEND:findings.threatAssessment.epssPercentage;Exploit Maturity::MEND:findings.threatAssessment.exploitCodeMaturity'
```

>**_NOTE_**: These values arrive **raw**, not in the human-readable wording used in the description table: `REACHABLE` rather than `Reachable`, and `97.5` rather than `97.5%` (the number is the same — the custom field just has no `%` suffix, and no `<1%` collapsing). Expect the custom field and the description table to disagree in wording for the same finding. In `MEND_DEPENDENCY: true` mode they will also disagree about *which* CVE, for the reason described [above](#two-behaviours-that-will-surprise-you).
<br />

**Example 4**
A worked, complete pipeline fragment — a full custom Work Item type populated from a single Mend 3.0 entry:

```yaml
- script: python mend_azure_wi_sync/azure_wi_sync.py
  displayName: 'Mend SCA Work Item Sync'
  env:
    MEND_URL: $(MEND_URL)
    MEND_USERKEY: $(MEND_USERKEY)
    MEND_APIKEY: $(MEND_APIKEY)
    MEND_EMAIL: $(MEND_EMAIL)
    MEND_AZUREPAT: $(MEND_AZUREPAT)
    MEND_AZUREURI: $(System.CollectionUri)
    MEND_AZUREPROJECT: $(System.TeamProject)
    MEND_AZURETYPE: 'SCA Issue'
    MEND_DEPENDENCY: false          # one Work Item per CVE, so every MEND: path is unambiguous
    MEND_SEVERITY: high
    MEND_REACHABILITY: true
    MEND_CUSTOMFIELDS: 'Library::MEND:library;Version::MEND:findings.component.version;Issue Reference::MEND:findings.vulnerability.name;CVSS::MEND:findings.vulnerability.score;EPSS::MEND:findings.threatAssessment.epssPercentage;Exploit Maturity::MEND:findings.threatAssessment.exploitCodeMaturity;Reachability::MEND:findings.reachability;Fixed In::MEND:findings.topFix.fixResolution;Source Repo::$MEND_REPONAME'
```

>**_NOTE_**: `MEND_CUSTOMFIELDS` must be a **single-line** string. Field names are matched exactly, with no trimming, so a YAML folded block (`>-`) breaks it — the fold inserts a space and ` Version` no longer matches the field `Version`.

>**_NOTE_**: `MEND_DEPENDENCY: false` is used here deliberately. In the default `true` mode the same mapping still works, but each of the `MEND:findings.*` fields would reflect an arbitrary one of the library's CVEs — see [Two behaviours that will surprise you](#two-behaviours-that-will-surprise-you).
