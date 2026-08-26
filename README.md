[![Logo](https://mend-toolkit-resources-public.s3.amazonaws.com/img/mend-io-logo-horizontal.svg)](https://www.mend.io/)  

[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/mend-toolkit/mend-azure-pipeline-workitems/actions/workflows/ci.yml/badge.svg)](https://github.com/mend-toolkit/mend-azure-pipeline-workitems/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/v/release/mend-toolkit/mend-azure-pipeline-workitems)](https://github.com/mend-toolkit/mend-azure-pipeline-workitems/releases/latest)

# Integrate Mend SCA with Azure Work Items

Creates, updates, closes and reopens Azure DevOps Work Items from Mend SCA findings.
Runs as a scheduled Azure Pipeline job.

**How it works:** every run reads each in-scope Mend project's complete current state
(its security findings, its license workflow violations and its library licenses) and
reconciles Azure DevOps against it:

| Finding in Mend | Work Item in Azure |
|---|---|
| New | Created |
| Changed | Updated |
| Gone (fixed or suppressed) | Closed |
| Back again | Reopened |

## Table of Contents
- [Prerequisites](#prerequisites)
- [Planning Your Work Items Setup](#planning-your-work-items-setup)
- [Azure DevOps Setup](#azure-devops-setup)
- [Mend SCA Setup](#mend-sca-setup)
- [Azure Pipeline Variables](#azure-pipeline-variables)
- [Reachability](#reachability)
- [Routing to Multiple Azure Projects](#routing-to-multiple-azure-projects)
- [Closing and Reopening Work Items](#closing-and-reopening-work-items)
- [Execution](#execution)
- [Custom Field Mapping](#custom-field-mapping)
  - [Syntax](#syntax)
  - [Available `MEND:` Paths](#available-mend-paths)
  - [Examples](#examples)

## Prerequisites

* Python 3.12+

**In Azure DevOps**
* A Personal Access Token (PAT) with **Work Items (Read, write & manage)** and **Project and Team (Read)**
* The PAT's user added to a group with **Create tag definition** and **View permissions for this node**, and added to the team for each area path you want Work Items in

**In Mend**
* A service user with the **Organization Administrator** or **Organization Auditor** [role](https://docs.mend.io/bundle/sca_user_guide/page/managing_groups.html#Assigning-a-Role-to-a-Group)
* License workflows
	* Required for License Work Items. See [Mend SCA Setup](#mend-sca-setup)
<br />

## Planning Your Work Items Setup

Decide your scope first: which Mend products and projects should produce Work Items.
That decides where the `mend-azure-wi-sync.yml` pipeline file lives.

| Scope | Where the pipeline file lives | Variables to set |
|---|---|---|
| One repository | In that repository | `MEND_PROJECTTOKEN` |
| A product, or several repositories | A new, separate repository | `MEND_PRODUCTTOKEN`, plus `MEND_EXCLUDETOKEN` to carve out projects |
| The whole Mend organization | A new, separate repository | Leave both empty; use `MEND_EXCLUDETOKEN` to carve out projects |

**Where do Work Items land?** By default, all of them go into the single Azure DevOps project named by `MEND_AZUREPROJECT`, regardless of how many Mend projects are in scope. To send findings to *different* Azure projects, set `MEND_ROUTING: true` and tag each Mend project with its destination at scan time. See [Routing to Multiple Azure Projects](#routing-to-multiple-azure-projects).

See [Azure Pipeline Variables](#azure-pipeline-variables) for details.
<br />

## Azure DevOps Setup
1. Create a [Personal Access Token (PAT)](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate) with the scopes and permissions listed in [Prerequisites](#prerequisites)
2. Create a new Azure pipeline from the example file [examples/mend-azure-wi-sync.yml](./examples/mend-azure-wi-sync.yml)
3. Set the pipeline variables. At minimum: `MEND_URL`, `MEND_USERKEY`, `MEND_ORGUUID`, `MEND_EMAIL` and `MEND_AZUREPAT`, plus the scope variables you picked in [Planning Your Work Items Setup](#planning-your-work-items-setup)
<br />

## Mend SCA Setup

**Vulnerability Work Items need no setup in Mend.** They come from the project's security findings, selected by CVSS score against `MEND_SEVERITY` (default `high`, meaning 7.0). Every active finding at or above that floor gets a Work Item.

**License Work Items come from license workflow violations.** Create a workflow for each license case you want a Work Item for. Give each workflow name a `[License]` prefix in square brackets, followed by the title. The integration strips the prefix and renders the title as the violation's name on the Work Item.

> **_NOTE_**: See [Create an Automation Workflow in the Mend Platform](https://docs.mend.io/platform/latest/create-an-automation-workflow-in-the-mend-platform) for detailed instructions.
<br />

## Azure Pipeline Variables

Set these in the pipeline where the integration runs. They are grouped in the order you
are likely to fill them in.

### Required

| Variable | Type | Default | Description |
|---|---|---|---|
| `MEND_URL` | string | N/A | Mend server URL |
| `MEND_EMAIL` | string | N/A | Email address of the Mend user whose `MEND_USERKEY` this is. Used to log in and obtain the token that authenticates every Mend call |
| `MEND_USERKEY` | secret | N/A | Your Mend user key |
| `MEND_ORGUUID` | string | N/A | UUID of your Mend organization. Identifies the organization on every Mend API call |
| `MEND_AZUREURI` | string | N/A | Azure DevOps organization URI, for example `https://dev.azure.com/MyOrganization`. Accepts the [system variable](https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml#system-variables-devops-services) `$(System.CollectionUri)` |
| `MEND_AZUREPAT` | secret | N/A | Azure DevOps [Personal Access Token](https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows) |
| `MEND_AZUREPROJECT` | string | N/A | Azure Team Project name. Accepts the [system variable](https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml#system-variables-devops-services) `$(System.TeamProject)`. Under `MEND_ROUTING` it is not the destination, but is still required: it is the project whose Work Item type definition is read at startup |

### Choosing what to sync

| Variable | Type | Default | Description |
|---|---|---|---|
| `MEND_PRODUCTTOKEN` | string | Empty <br />(all products) | Comma-separated list of Mend **product UUIDs** to monitor. A value that is not a valid UUID or token aborts the run with a message naming this variable |
| `MEND_PROJECTTOKEN` | string | Empty <br />(all projects) | Comma-separated list of Mend **project UUIDs** to monitor. A value that is not a valid UUID or token aborts the run with a message naming this variable |
| `MEND_EXCLUDETOKEN` | string | Empty <br />(no exclusions) | Comma-separated list of Mend **project UUIDs** to skip. A value that is not a valid UUID or token aborts the run with a message naming this variable |
| `MEND_SEVERITY` | string | `high` | Minimum CVSS severity a finding must reach to earn a Work Item. Accepts a band (`low` 0.1, `medium` 4.0, `high` 7.0, `critical` 9.0) or a number from `0` to `10`. The same floor governs creation and closure: a Work Item whose findings all drop below it is closed. Unscored findings are always included, and an unparseable value falls back to `high` |
| `MEND_ROUTING` | boolean | `false` | Send Work Items to different Azure DevOps projects using tags recorded on each Mend project at scan time. See [Routing to Multiple Azure Projects](#routing-to-multiple-azure-projects) |
| `MEND_BRANCHES` | string | `main,master` | Comma-separated glob patterns of branches to sync when `MEND_ROUTING` is enabled, for example `main,release/*`. Applied at sync time, so changing it does not require rescanning |

`MEND_ROUTING` changes *where* Work Items are created, not *which* Mend projects are
synced. The three token variables still select the projects; routing then sends each
one's findings to the Azure project named by its tag.

### Shaping the Work Item

| Variable | Type | Default | Description |
|---|---|---|---|
| `MEND_AZURETYPE` | string | `Task` | Work Item type to create. Must be a [built-in](https://learn.microsoft.com/en-us/azure/devops/boards/work-items/about-work-items?view=azure-devops&tabs=agile-process#track-work-with-different-work-item-types) or [custom](https://learn.microsoft.com/en-us/azure/devops/boards/work-items/about-work-items?view=azure-devops&tabs=agile-process#customize-a-work-item-type) type available in the project's [process](https://learn.microsoft.com/en-us/azure/devops/boards/work-items/guidance/choose-process?view=azure-devops&tabs=agile-process) (Basic, Agile, Scrum, and so on) |
| `MEND_AZUREAREA` | string | `$MEND_AZUREPROJECT` | [Area Path](https://learn.microsoft.com/en-us/azure/devops/organizations/settings/set-area-paths?view=azure-devops) to group created Work Items under, for example `TeamProject\Area1\SubArea2`. Use double backslashes for sub-areas |
| `MEND_DESCRIPTION` | string | `ReproSteps` | Which field holds the description. Use `ReproSteps` for bugs, `Description` for issues, or a custom field name |
| `MEND_DEPENDENCY` | boolean | `true` | `true` creates one Work Item per **root library**, the direct dependency you can actually upgrade, listing every vulnerable library it pulls in. `false` creates one Work Item per CVE per vulnerable library, and typically creates many more |
| `MEND_CALCULATEPRIORITY` | boolean | `false` | When `true`, Priority is calculated from Mend's CVSS3 severity. Otherwise it is set to `2` |
| `MEND_CUSTOMFIELDS` | string | Empty <br />(no custom fields) | Maps Mend data into custom fields of the Work Item type. Required when using a custom Work Item type. See [Custom Field Mapping](#custom-field-mapping) |
| `MEND_REPONAME` | string | `$MEND_AZUREPROJECT` | Repository name, available as `$MEND_REPONAME` in [Custom Field Mapping](#custom-field-mapping). Under `MEND_ROUTING` it is set per Mend project from that project's `azure-repo` scan tag and added to the Work Item as a tag, ignoring any value set here |
| `MEND_CLOSEDSTATE` | string | auto | `System.State` value written when a Work Item is closed. Needed only when a derived process renames the closed state; otherwise leave it unset and the tool finds it. Accepts a comma-separated list tried in order, such as `Retired,Closed`. See [Closing and Reopening Work Items](#closing-and-reopening-work-items) |
| `MEND_REOPENSTATE` | string | auto | `System.State` value written when a closed Work Item reopens. Needed only when a derived process renames the open state; otherwise leave it unset and the tool finds it. Accepts a comma-separated list tried in order, such as `Reopened,New`. See [Closing and Reopening Work Items](#closing-and-reopening-work-items) |

### Description content

| Variable | Type | Default | Description |
|---|---|---|---|
| `MEND_REACHABILITY` | boolean | `false` | When `true`, adds Reachability to each Work Item. Leave it off if you are not enabling reachability analysis in your scans, to avoid a column of `-`. See [Reachability](#reachability) |
| `MEND_DEPPATHS` | boolean | `true` | Whether to render each transitive library's root-to-leaf dependency chain in the description. Set `false` to speed up Work Item creation; descriptions then fall back to the flat parents list |
| `MEND_DEPPATHS_CONCURRENCY` | integer | `16` | How many dependency-path calls run at once. Raise it if a run with many transitive libraries is slow. Values above `64` are clamped; invalid values fall back to `16` |

### Network and advanced

| Variable | Type | Default | Description |
|---|---|---|---|
| `MEND_PROXY` | string | Empty | Proxy URL, in the format `<proxy_ip>:<proxy_port>`. For a proxy requiring basic authentication, use `<username>:<password>@<proxy_ip>:<proxy_port>`. Without an `http://` or `https://` prefix, `http://` is assumed |
| `MEND_SSLVERIFY` | boolean | `true` | TLS certificate verification for the Mend and Azure DevOps calls. Set `false` to unblock a run where verification fails. To supply a CA bundle for a self-hosted agent behind a TLS-inspecting proxy, set the standard `REQUESTS_CA_BUNDLE` environment variable to its path; this variable does not take a path |

<br />

## Reachability

**Reachability** is included on each vulnerability Work Item when `MEND_REACHABILITY: true`.
License violations carry no CVE, so they never show it. It renders as `Reachable`,
`Unreachable`, or `-`.

Where it lands depends on `MEND_DEPENDENCY`:
- `true` (default): an extra column in the CVE table, and an extra line in each CVE's expandable section
- `false`: directly in the flat description, since there is no table

This requires reachability analysis to be performed by the scan. See
[SCA Reachability](https://docs.mend.io/platform/latest/sca-reachability) for details.

Enabling `MEND_REACHABILITY` updates existing Work Items on the next run. Reachability can
also be mapped into a custom field, see [Custom Field Mapping](#custom-field-mapping).
<br />

## Routing to Multiple Azure Projects

By default every Work Item is created in `MEND_AZUREPROJECT`. With `MEND_ROUTING: true`,
each Mend project carries its own destination, so one pipeline can serve many Azure
DevOps projects.

The destination comes from three tags on each Mend **project**:

| Tag | Set it to |
|---|---|
| `azure-project` | `$(System.TeamProject)` |
| `azure-repo` | `$(Build.Repository.Name)` |
| `azure-branch` | `$(Build.SourceBranch)` |

**These tags are not set on this pipeline.** They are set as Mend CLI scan tags in each
repository's own build pipeline, at the point where that repository is scanned. Mend then
promotes them onto the Mend project record, which is what this integration reads. See the [Mend CLI SCA upload parameters](https://docs.mend.io/platform/latest/configure-the-mend-cli-for-sca#Mend-CLI-SCA---Upload-parameters)
for the flag syntax for attaching tags to a scan.

```yaml
  env:
    AZURE_PROJECT: $(System.TeamProject)
    AZURE_REPO: $(Build.Repository.Name)
    AZURE_BRANCH: $(Build.SourceBranch)
  script: |
    mend dep --reachability -u -s "*//$AZURE_PROJECT//$AZURE_REPO" \
      --tags "azure-project=$AZURE_PROJECT,azure-repo=$AZURE_REPO,azure-branch=$AZURE_BRANCH"
```

Map the variables through `env:` and quote them as above, since a tag value such as
`azure-repo` can contain spaces. Azure Pipelines substitution uses `$(...)`; `${...}` is
shell syntax and fails with `bad substitution`.

>**_IMPORTANT_**: Use `$(Build.SourceBranch)`, **not** `$(Build.SourceBranchName)`. `SourceBranchName` returns only the last path segment, so `refs/heads/release/1.2` becomes `1.2` and cannot match a `MEND_BRANCHES` pattern like `release/*`. The integration strips the `refs/heads/` prefix itself.

>**_IMPORTANT_**: With `MEND_ROUTING: true`, a run that cannot read the Mend project tags does **no work at all**. It logs `Aborted: could not read Mend project tags.` and reports a failed run, rather than syncing some projects and skipping others.
<br />

## Closing and Reopening Work Items

A Work Item whose Mend finding is no longer there is **closed**. If the finding comes back,
the *same* Work Item is **reopened**, keeping its id, history and comments.

A finding counts as gone when:
- it is **suppressed** or **ignored** in Mend
- the vulnerable **library is removed** from the project (upgraded, replaced, or dropped)
- the library is marked **in-house** or **allowlisted**
- for a license Work Item, the **license workflow violation** no longer matches
- its CVSS score drops below `MEND_SEVERITY`

In `MEND_DEPENDENCY: true` (the default) one Work Item covers a root library and everything
beneath it, so it closes only once **every** vulnerability in that group is gone. In `false`
mode one Work Item is one CVE, and closes as soon as that CVE is gone.

### Which state is used

You do not normally configure this. The tool tries the out-of-box process states in order,
per Azure project, and remembers which one that board accepted:

| Action | Tried in order |
|---|---|
| Close | `Closed` (Agile, CMMI), then `Done` (Scrum, Basic) |
| Reopen | `New` (Agile, Scrum backlog items), then `To Do` (Basic, Scrum tasks), then `Proposed` (CMMI) |

Set `MEND_CLOSEDSTATE` / `MEND_REOPENSTATE` only if a derived process renames the state. An
explicit value is used *alone* and is never followed by a fallback, so if your projects span
a derived process and an out-of-box one, give a comma-separated list tried in order:
`MEND_CLOSEDSTATE: Retired,Closed`.

>**_IMPORTANT_**: **Closure never deletes a Work Item.** It only changes the state field, so the Work Item keeps its id, history, comments, links and any fields your team edited.

>**_NOTE_**: Work Items are matched by **title** plus the `{product}/{project}` tag the integration writes. A Work Item whose title was hand-edited is no longer recognised: it is neither updated nor closed, and a second Work Item is created for the finding. Do not rename generated titles.
<br />

## Execution
Run the pipeline on a cron schedule, daily or at whatever frequency suits you. See the
[example pipeline file](./examples/azure-pipelines.yml).

```yaml
schedules:
  - cron: "0 6 * * *"
    displayName: Mend SCA Sync Scheduler
    branches:
      include:
        - main
    always: true
```
Each run is a full comparison, not a "since the last execution" window, so a missed or
failed run costs nothing but the delay.
<br />

## Custom Field Mapping

When `MEND_AZURETYPE` names a [custom Work Item type](https://learn.microsoft.com/en-us/azure/devops/boards/work-items/about-work-items?view=azure-devops&tabs=agile-process#customize-a-work-item-type), the integration reads its definition from the [Azure API](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-item-types/get) automatically. `MEND_CUSTOMFIELDS` then populates that type's fields from the Mend entry that produced the Work Item.

### Syntax

`MEND_CUSTOMFIELDS` is a quoted string of `FieldName::Value` pairs separated by semicolons:

```yaml
  env:
    MEND_AZURETYPE: 'SCA Issue'
    MEND_CUSTOMFIELDS: 'Field 1::MEND:path.to.property;Field 2::MEND:property& Free Text &MEND:other;Field 3::$MEND_REPONAME'
```

| Part | Rule |
|---|---|
| Field name | The field's `name` property, its friendly name. See [WorkItemTypeFieldInstance](https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-item-types/get?view=azure-devops-rest-7.0&tabs=HTTP#workitemtypefieldinstance) |
| `MEND:path` | Dot-separated path into the Mend entry, case sensitive. See [Available `MEND:` Paths](#available-mend-paths) |
| `$MEND_REPONAME` / `$MEND_DESCRIPTION` | Substituted from those pipeline variables |
| Free text | Any static or pipeline-derived text |
| `&` | Joins several parts into one field |
| `;` | Separates one field mapping from the next |

>**_NOTE_**: If the Work Item type has mandatory fields (`"alwaysRequired": true`), you must map values to them with `MEND_CUSTOMFIELDS` or Work Item creation fails.
<br />

### Available `MEND:` Paths

A `MEND:` path is walked into one of the **entries** the Work Item was built from. An entry
is one root library (in the default `MEND_DEPENDENCY: true` mode) or one CVE (in
`MEND_DEPENDENCY: false`):

```
{
  "library":  "log4j-core",                    <- MEND:library
  "kind":     "vulnerability",                 <- MEND:kind
  "findings": [ <security finding>, ... ],     <- MEND:findings.<...>
  "licenses": [ <license>, ... ]               <- MEND:licenses.<...>
}
```

`library` and `kind` are composed by the integration. Everything under `findings` and
`licenses` is the Mend API response verbatim, so **any field those endpoints return can be
used as a path**:

| Prefix | Source |
|---|---|
| `MEND:findings.` | [Get security vulnerability findings](https://api-docs.mend.io/platform/3.0/findings-project/getsecurityvulnerabilityfindings) |
| `MEND:licenses.` | [Get due diligence info by multiple contexts](https://api-docs.mend.io/platform/3.0/findings-project/getduediligenceinfobymultiplecontexts) |

The security findings response nests `vulnerability`, `component`, `findingInfo`,
`threatAssessment` and `topFix` objects, giving paths such as
`MEND:findings.vulnerability.name`, `MEND:findings.component.version` or
`MEND:findings.threatAssessment.epssPercentage`.

>**_IMPORTANT_**: In `MEND_DEPENDENCY: true`, `findings` is a list, and a `MEND:findings.*` path resolves against **whichever finding Mend returned last**. That is arbitrary: not the first, and not the most severe. A field mapped this way can disagree with the highest-severity figure in the Work Item's own title. The same applies to `MEND:licenses.*` when a library carries more than one license.

```
entry.findings = [ CVE-2020-8203 (7.4, HIGH),
                   CVE-2021-23337 (9.8, CRITICAL),
                   CVE-2019-10744 (3.1, LOW) ]

MEND:findings.vulnerability.name   ->  CVE-2019-10744
MEND:findings.vulnerability.score  ->  3.1
```

If you need one value per CVE, use `MEND_DEPENDENCY: false`. Each Work Item is then a single
CVE whose entry holds exactly one finding.

>**_IMPORTANT_**: An unresolvable path does **not** leave the field blank. A typo in any segment after the first writes the literal string `No content` into the field. A first segment that does not exist on the entry logs `Custom field parsing failed` and leaves the field empty. After changing `MEND_CUSTOMFIELDS`, check the pipeline log and inspect one produced Work Item before rolling it out.

>**_NOTE_**: Values resolve to Mend's raw wording, which is upper-case: `HIGH`, `REACHABLE`, `TRANSITIVE`. The description rendered on the Work Item uses `High`, `Reachable` and so on, so a custom field will not match it character for character.
<br />

### Examples
All the following examples assume a custom Work Item type named **SCA Issue**, which was configured to inherit fields from the **Bug** Work Item of the **Agile** process flow.

**Example 1**
Populating the Work Item's custom fields **Library** and **Issue Reference** with the vulnerable library and the CVE identifier:

```yaml
  env:
    MEND_AZURETYPE: 'SCA Issue'
    MEND_CUSTOMFIELDS: 'Library::MEND:library;Issue Reference::MEND:findings.vulnerability.name'
```
<br />

**Example 2**
Populating the Work Item's custom field **Team Comments** with the text
**Library: *LIBRARY* version *VERSION* (repo: *REPONAME*)**, combining `MEND:` paths, free text and a pipeline variable with `&`:

```yaml
  env:
    MEND_AZURETYPE: 'SCA Issue'
    MEND_CUSTOMFIELDS: 'Team Comments::Library: &MEND:library& version &MEND:findings.component.version& (repo: &$MEND_REPONAME&)'
```
<br />

**Example 3**
Populating custom fields **Reachability**, **EPSS** and **Exploit Maturity** with the risk signals on each finding (see [Reachability](#reachability)):

```yaml
  env:
    MEND_REACHABILITY: true
    MEND_AZURETYPE: 'SCA Issue'
    MEND_CUSTOMFIELDS: 'Reachability::MEND:findings.reachability;EPSS::MEND:findings.threatAssessment.epssPercentage;Exploit Maturity::MEND:findings.threatAssessment.exploitCodeMaturity'
```

>**_NOTE_**: In `MEND_DEPENDENCY: true` mode these fields reflect an arbitrary one of the library's CVEs, so they can disagree with the description table about *which* CVE. See [Available `MEND:` Paths](#available-mend-paths).
<br />

**Example 4**
A complete pipeline fragment: a full custom Work Item type populated from a single Mend entry.

```yaml
- script: python mend_azure_wi_sync/azure_wi_sync.py
  displayName: 'Mend SCA Work Item Sync'
  env:
    MEND_URL: $(MEND_URL)
    MEND_USERKEY: $(MEND_USERKEY)
    MEND_ORGUUID: $(MEND_ORGUUID)
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

>**_NOTE_**: `MEND_CUSTOMFIELDS` must be a **single-line** string. Field names are matched exactly, with no trimming, so a YAML folded block (`>-`) breaks it: the fold inserts a space, and ` Version` no longer matches the field `Version`.

>**_NOTE_**: `MEND_DEPENDENCY: false` is used here deliberately. In the default `true` mode the same mapping still works, but each of the `MEND:findings.*` fields would reflect an arbitrary one of the library's CVEs. See [Available `MEND:` Paths](#available-mend-paths).
