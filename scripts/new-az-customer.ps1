#Requires -Version 5.1
<#
.SYNOPSIS
    Give a customer folder (or a single repo) its own isolated Azure CLI login.

.DESCRIPTION
    For the folder at -Path (relative to -WorkRoot, default D:\Git\Work):
      * writes <folder>\.azcustomer.json   (profile name, tenant, subscription)
      * creates ~\.azure-profiles\<name>\   (that customer's private az config + token cache)
      * logs in to the tenant inside that profile and selects the subscription
      * installs a PowerShell prompt hook: whenever you cd into the folder, or any repo
        beneath it, AZURE_CONFIG_DIR and ARM_* switch to that customer automatically, and
        switch back when you leave (direnv-style, no direnv needed).

    Put the marker on a customer folder to cover every repo under it, or on one repo to
    override the customer default - the nearest marker above the current directory wins.

    Markers are only honoured if this script wrote them (path + SHA-256 allow-list in the
    profile root), so a .azcustomer.json committed in someone else's repo cannot silently
    point your shell at a different tenant.

    Safe to re-run: an identical marker is kept, a still-valid login is reused, and the
    hook is refreshed.

.EXAMPLE
    .\new-az-customer.ps1 -Path Contoso -TenantId <guid> -SubscriptionId <guid>

.EXAMPLE
    # One repo pinned to a different subscription, sharing the customer's login
    .\new-az-customer.ps1 -Path 'Contoso\landing-zones' -Name contoso -TenantId <guid> -SubscriptionId <guid>

.EXAMPLE
    .\new-az-customer.ps1 -Path Fabrikam -TenantId <guid> -SubscriptionId <guid> -DeviceCode
#>
[CmdletBinding()]
param(
    # Customer folder or repo, relative to -WorkRoot or absolute. Created if missing.
    [Parameter(Mandatory, Position = 0)]
    [string]$Path,

    [Parameter(Mandatory, Position = 1)]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [Parameter(Mandatory, Position = 2)]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$SubscriptionId,

    # Profile name. Defaults to the folder name, lower-cased, spaces/punctuation -> hyphens.
    # Markers that share a name share one az login (useful for per-repo subscriptions).
    [ValidatePattern('^[a-z0-9][a-z0-9-]*$')]
    [string]$Name,

    [switch]$DeviceCode,        # az login --use-device-code
    [switch]$Relogin,           # force a fresh login even if the cached one is still valid
    [switch]$SkipLogin,         # write marker/profile/hook only; re-run later to log in
    [switch]$Force,             # replace an existing marker that has different values
    [switch]$NoProfileInstall,  # don't add the hook to your PowerShell profile(s)
    [switch]$NoAgentRule,       # don't write the Claude Code rule (~\.claude\rules\azure-customer-credentials.md)

    # Limit agent changes in this folder to one resource group: az defaults to it, and the
    # cloud-write guard blocks changes naming another group. Soft limit - Azure RBAC decides
    # what the login can really do (the script reports it after login).
    [ValidatePattern('^[-\w\.\(\)]{1,90}$')]
    [string]$ResourceGroup,

    [string]$WorkRoot    = $(if ($env:AZ_WORK_ROOT)    { $env:AZ_WORK_ROOT }    else { 'D:\Git\Work' }),
    [string]$ProfileRoot = $(if ($env:AZ_PROFILE_ROOT) { $env:AZ_PROFILE_ROOT } else { Join-Path $HOME '.azure-profiles' })
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$MarkerName     = '.azcustomer.json'
$TenantId       = $TenantId.ToLowerInvariant()
$SubscriptionId = $SubscriptionId.ToLowerInvariant()

function Write-Step([string]$Message) { Write-Host "  * $Message" }

# Native commands don't honour $ErrorActionPreference - check exit codes explicitly.
function Invoke-Az {
    & az @args
    if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed (exit $LASTEXITCODE)" }
}

# Run a native command for its exit code only, swallowing stderr. EAP is relaxed locally
# because Windows PowerShell 5.1 turns redirected stderr into terminating errors under 'Stop'.
function Test-Native {
    $ErrorActionPreference = 'Continue'
    $exe, $rest = $args
    $out = & $exe @rest 2>$null
    if ($LASTEXITCODE -eq 0) { return @{ Ok = $true; Out = $out } }
    return @{ Ok = $false; Out = $null }
}

foreach ($cmd in 'az', 'git') {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "'$cmd' not found on PATH" }
}

# --- Resolve target folder and profile name -----------------------------------------------

$target = if ([IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $WorkRoot $Path }
if (-not (Test-Path -LiteralPath $target -PathType Container)) {
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    Write-Step "created $target"
}
$target = (Resolve-Path -LiteralPath $target).ProviderPath.TrimEnd('\')

if (-not $Name) {
    $Name = ((Split-Path -Path $target -Leaf).ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
    if ($Name -notmatch '^[a-z0-9][a-z0-9-]*$') { throw "Can't derive a profile name from '$target' - pass -Name." }
}

$profileDir = Join-Path $ProfileRoot $Name
$markerPath = Join-Path $target $MarkerName
$allowFile  = Join-Path $ProfileRoot 'allowed-markers.txt'
$hookFile   = Join-Path $ProfileRoot 'az-customer-hook.ps1'

Write-Host "Customer profile '$Name' -> $target"

# --- Marker ---------------------------------------------------------------------------------

$writeMarker = $true
if (Test-Path -LiteralPath $markerPath) {
    $existing = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    $existingRg = "$($existing.PSObject.Properties['resourceGroup'].Value)"
    if ($existing.name -eq $Name -and $existing.tenantId -eq $TenantId -and $existing.subscriptionId -eq $SubscriptionId -and
        $existingRg -eq "$ResourceGroup") {
        $writeMarker = $false
        Write-Step "$MarkerName already up to date"
    }
    elseif (-not $Force) {
        throw ("$markerPath already exists for '$($existing.name)' (tenant $($existing.tenantId), " +
               "subscription $($existing.subscriptionId)). Use -Force to replace it.")
    }
}
if ($writeMarker) {
    $markerData = [ordered]@{ name = $Name; tenantId = $TenantId; subscriptionId = $SubscriptionId }
    if ($ResourceGroup) { $markerData.resourceGroup = $ResourceGroup }
    $markerData | ConvertTo-Json | Set-Content -LiteralPath $markerPath -Encoding UTF8
    Write-Step "wrote $markerPath"
}

# If the marker sits inside a git work tree, keep it out of commits via .git/info/exclude
# (local only - nothing to add to the customer's .gitignore).
$top = Test-Native git -C $target rev-parse --show-toplevel
if ($top.Ok) {
    $topPath = ("$($top.Out)".Trim()) -replace '/', '\'
    $rel = ''
    if ($target.Length -gt $topPath.Length -and $target.StartsWith($topPath, [StringComparison]::OrdinalIgnoreCase)) {
        $rel = $target.Substring($topPath.Length).TrimStart('\') -replace '\\', '/'
    }
    $entry = '/' + $(if ($rel) { "$rel/" } else { '' }) + $MarkerName
    $excl = Test-Native git -C $target rev-parse --path-format=absolute --git-path info/exclude
    if ($excl.Ok) {
        $exclPath = ("$($excl.Out)".Trim()) -replace '/', '\'
        New-Item -ItemType Directory -Force -Path (Split-Path -Path $exclPath -Parent) | Out-Null
        $present = (Test-Path -LiteralPath $exclPath) -and
                   ((Get-Content -LiteralPath $exclPath) -contains $entry)
        if (-not $present) {
            Add-Content -LiteralPath $exclPath -Value $entry
            Write-Step "added $entry to $exclPath"
        }
    }
}

# --- Profile dir + allow-list ---------------------------------------------------------------

New-Item -ItemType Directory -Force -Path $profileDir | Out-Null
if (-not $profileDir.StartsWith($HOME, [StringComparison]::OrdinalIgnoreCase)) {
    Write-Warning "$profileDir is outside your user profile - make sure only you can read it (it holds refresh tokens)."
}

# One line per trusted marker: "<sha256>`t<path>". Replace any older entry for this path.
$hash = (Get-FileHash -LiteralPath $markerPath -Algorithm SHA256).Hash
$allowed = @(if (Test-Path -LiteralPath $allowFile) { Get-Content -LiteralPath $allowFile })
$allowed = @($allowed | Where-Object { $_ -and ($_ -split "`t", 2)[-1] -ne $markerPath }) + "$hash`t$markerPath"
Set-Content -LiteralPath $allowFile -Value $allowed -Encoding UTF8

# --- Prompt hook ----------------------------------------------------------------------------

$hookSource = @'
# az-customer prompt hook - generated by new-az-customer.ps1. Re-run that script to update;
# edits here are overwritten. Switches AZURE_CONFIG_DIR / ARM_* to the nearest allow-listed
# .azcustomer.json above the current directory, and restores the previous values on leaving.

$global:AzCustomerRoot = $PSScriptRoot
$global:AzCustomerVars = @(
    'AZ_CUSTOMER', 'AZURE_CONFIG_DIR', 'AZURE_EXTENSION_DIR',
    'ARM_TENANT_ID', 'ARM_SUBSCRIPTION_ID', 'ARM_USE_CLI', 'AZURE_DEFAULTS_GROUP', 'AZ_RESOURCE_GROUP',
    # stray service-principal / OIDC / MSI creds would override the CLI login - clear them
    'ARM_CLIENT_ID', 'ARM_CLIENT_SECRET', 'ARM_CLIENT_CERTIFICATE_PATH', 'ARM_CLIENT_CERTIFICATE_PASSWORD',
    'ARM_USE_OIDC', 'ARM_OIDC_TOKEN', 'ARM_USE_MSI',
    'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_CLIENT_CERTIFICATE_PATH', 'AZURE_USERNAME', 'AZURE_PASSWORD'
)
if (-not (Get-Variable -Name AzCustomerSeen -Scope Global -ErrorAction SilentlyContinue)) {
    $global:AzCustomerSeen  = $null   # marker path last evaluated
    $global:AzCustomerSaved = $null   # env snapshot from before the first customer was applied
}

$global:AzCustomerLastDir = $null   # (re)loading re-evaluates on the next prompt

# Worktrees (T3 Code, Claude Code, ...) can live outside your Git root. Returns the main checkout's
# folder for a linked worktree, or $null.
function global:Get-GitMainCheckoutDir([string]$Dir) {
    $ErrorActionPreference = 'Continue'
    $common = & git -C $Dir rev-parse --path-format=absolute --git-common-dir 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $common) { return $null }
    $common = ("$common".Trim()) -replace '/', '\'
    if ((Split-Path -Path $common -Leaf) -ne '.git') { return $null }
    $main = Split-Path -Path $common -Parent
    if ($Dir.StartsWith($main, [StringComparison]::OrdinalIgnoreCase)) { return $null }   # not a linked worktree
    return $main
}

function global:Search-AzCustomerMarker([string]$Dir) {
    while ($Dir) {
        $candidate = Join-Path $Dir '.azcustomer.json'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        $parent = Split-Path -Path $Dir -Parent
        if (-not $parent -or $parent -eq $Dir) { break }
        $Dir = $parent
    }
    return $null
}

function global:Find-AzCustomerMarker {
    $here  = (Get-Location -PSProvider FileSystem).ProviderPath
    $found = Search-AzCustomerMarker $here
    if (-not $found) {
        $main = Get-GitMainCheckoutDir $here
        if ($main) { $found = Search-AzCustomerMarker $main }
    }
    return $found
}

function global:Test-AzCustomerAllowed([string]$Marker) {
    $list = Join-Path $global:AzCustomerRoot 'allowed-markers.txt'
    if (-not (Test-Path -LiteralPath $list)) { return $false }
    $entry = (Get-FileHash -LiteralPath $Marker -Algorithm SHA256).Hash + "`t" + $Marker
    return [bool](@(Get-Content -LiteralPath $list) -contains $entry)
}

function global:Reset-AzCustomerEnv {
    if ($null -ne $global:AzCustomerSaved) {
        foreach ($k in $global:AzCustomerVars) {
            $v = $global:AzCustomerSaved[$k]
            if ($null -eq $v) { Remove-Item -LiteralPath "Env:$k" -ErrorAction SilentlyContinue }
            else { Set-Item -LiteralPath "Env:$k" -Value $v }
        }
    }
    $global:AzCustomerSaved = $null
}

function global:Update-AzCustomerEnv {
    $dir = (Get-Location -PSProvider FileSystem).ProviderPath
    if ($dir -eq $global:AzCustomerLastDir) { return }
    $global:AzCustomerLastDir = $dir
    $marker = Find-AzCustomerMarker
    if ($marker -eq $global:AzCustomerSeen) { return }
    $global:AzCustomerSeen = $marker
    $wasActive = $null -ne $global:AzCustomerSaved

    if (-not $marker) {
        Reset-AzCustomerEnv
        if ($wasActive) { Write-Host 'az: default profile' -ForegroundColor DarkGray }
        return
    }

    $cfg = $null
    try {
        if (-not (Test-AzCustomerAllowed $marker)) { throw 'not created by new-az-customer.ps1, or changed since - re-run it for this folder to trust it' }
        $cfg  = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
        $guid = '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'
        if ("$($cfg.name)" -notmatch '^[a-z0-9][a-z0-9-]*$' -or
            "$($cfg.tenantId)" -notmatch $guid -or "$($cfg.subscriptionId)" -notmatch $guid) { throw 'malformed' }
        $rg = "$($cfg.PSObject.Properties['resourceGroup'].Value)"
        if ($rg -and $rg -notmatch '^[-\w\.\(\)]{1,90}$') { throw 'malformed resourceGroup' }
    }
    catch {
        # Never leave a previous customer's tenant active when the new marker is rejected.
        Reset-AzCustomerEnv
        Write-Warning "az-customer: ignoring ${marker}: $_"
        return
    }

    if (-not $wasActive) {
        $global:AzCustomerSaved = @{}
        foreach ($k in $global:AzCustomerVars) {
            $global:AzCustomerSaved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process')
        }
    }
    foreach ($k in $global:AzCustomerVars) { Remove-Item -LiteralPath "Env:$k" -ErrorAction SilentlyContinue }

    $env:AZ_CUSTOMER         = $cfg.name
    $env:AZURE_CONFIG_DIR    = Join-Path $global:AzCustomerRoot $cfg.name
    $env:AZURE_EXTENSION_DIR = Join-Path $HOME '.azure\cliextensions'   # share az extensions across customers
    $env:ARM_TENANT_ID       = $cfg.tenantId
    $env:ARM_SUBSCRIPTION_ID = $cfg.subscriptionId
    $env:ARM_USE_CLI         = 'true'
    $scopeText = ''
    if ($rg) {
        $env:AZURE_DEFAULTS_GROUP = $rg   # az uses it wherever --resource-group is omitted
        $env:AZ_RESOURCE_GROUP    = $rg
        $scopeText = ", resource group $rg"
    }
    Write-Host "az: $($cfg.name) (subscription $($cfg.subscriptionId)$scopeText)" -ForegroundColor DarkCyan
}

# Wrap whatever prompt is current (default, oh-my-posh, starship...) exactly once per session.
if (-not (Get-Variable -Name AzCustomerInnerPrompt -Scope Global -ErrorAction SilentlyContinue)) {
    $global:AzCustomerInnerPrompt = $function:prompt
    function global:prompt {
        $code = $global:LASTEXITCODE
        try { Update-AzCustomerEnv } catch { Write-Warning "az-customer: $_" }
        $global:LASTEXITCODE = $code
        if ($global:AzCustomerInnerPrompt) { & $global:AzCustomerInnerPrompt } else { "PS $($executionContext.SessionState.Path.CurrentLocation)> " }
    }
}
'@
Set-Content -LiteralPath $hookFile -Value $hookSource -Encoding UTF8

if (-not $NoProfileInstall) {
    $quoted   = $hookFile -replace "'", "''"
    $hookLine = "if (Test-Path -LiteralPath '$quoted') { . '$quoted' }  # az-customer hook"
    $docs     = [Environment]::GetFolderPath('MyDocuments')
    # Current host's profile always; the other edition's only if you use it (folder exists).
    $targets  = @($PROFILE.CurrentUserAllHosts) + @(
        (Join-Path $docs 'PowerShell\profile.ps1'),
        (Join-Path $docs 'WindowsPowerShell\profile.ps1') |
            Where-Object { Test-Path -LiteralPath (Split-Path -Path $_ -Parent) }
    ) | Select-Object -Unique
    foreach ($p in $targets) {
        if ((Test-Path -LiteralPath $p) -and (Select-String -LiteralPath $p -SimpleMatch '# az-customer hook' -Quiet)) { continue }
        New-Item -ItemType Directory -Force -Path (Split-Path -Path $p -Parent) | Out-Null
        Add-Content -LiteralPath $p -Value "`r`n$hookLine"
        Write-Step "added hook to $p"
    }
}
. $hookFile   # activate in this session too

# --- Agent instructions ---------------------------------------------------------------------
# Agent shells (Claude Code etc.) start with -NoProfile, so the prompt hook never runs there.
# One user-level rule tells agents how to load a customer's login. It lives outside every repo
# (nothing to gitignore) and, unlike a CLAUDE.md above the repo, doesn't stop Claude reading a
# repo's AGENTS.md. Per-customer IDs stay in .azcustomer.json, which the agent reads.

$agentRule = @'
# Azure customer credentials ({{WORKROOT}})

Managed by {{SCRIPT}}. Re-running it overwrites this file.

A folder under {{WORKROOT}} with a `.azcustomer.json` in it or above it belongs to one customer's Azure tenant. The file holds `name`, `tenantId` and `subscriptionId`. Each customer has its own az login, stored outside the repo.

Agent shells start with -NoProfile, so the user's folder hook never runs, and plain `az` uses the user's default login, which may be a different customer. In every PowerShell command that needs Azure, load the customer first, in the same command:

```powershell
. '{{HOOK}}'; Update-AzCustomerEnv; <command>
```

This points `az` at the customer's own login (`AZURE_CONFIG_DIR`), sets `ARM_TENANT_ID` and `ARM_SUBSCRIPTION_ID` for Terraform, and prints `az: <name> (subscription <id>)`. Each command is a fresh shell, so repeat the prefix every time. Use the PowerShell tool for this, not Git Bash.

- Never run `az` or Terraform in a customer folder without the prefix. If it prints no `az:` line, there is no customer here: ask the user rather than using another login.
- Before the first Azure command in a task, run `az account show --query tenantId -o tsv` with the prefix and check it matches `tenantId` in `.azcustomer.json`. If it doesn't, stop and tell the user.
- The login is the user's own account with full rights; there is no read-only credential. Read freely (`show`, `list`, `what-if`, `terraform plan`).
- Terraform changes are pipeline-controlled: never run `terraform apply`, `destroy`, `import` or state changes here. Make the change in code and tell the user it is ready for the pipeline. A PreToolUse hook blocks these. Exception: folders listed in `~\.claude\hooks\local-apply-allowed.txt` are not pipeline-managed; there they prompt the user instead. Never edit that list yourself.
- Any other change (`az ... create/update/delete`, role assignments, deployments, `New-/Set-/Remove-Az*`) triggers an approval prompt. Before running one, say why it can't go through the pipeline; if it can, do it in code instead.
- To use another subscription, pass `--subscription` on the command. Don't run `az account set`, `az login` or `az logout`. If the login has expired, tell the user to re-run `{{SCRIPT}}`.
- If `.azcustomer.json` has a `resourceGroup`, change only resources in that resource group. `az` defaults to it (`AZURE_DEFAULTS_GROUP`), but pass `-g`/`--resource-group` explicitly on every change. The PreToolUse hook blocks changes that name another resource group, and creating or deleting resource groups. Reading other resource groups is fine.
- Don't edit `.azcustomer.json` or anything under `{{PROFILEROOT}}`.
'@
if (-not $NoAgentRule) {
    $ruleFile = Join-Path $HOME '.claude\rules\azure-customer-credentials.md'
    New-Item -ItemType Directory -Force -Path (Split-Path -Path $ruleFile -Parent) | Out-Null
    $agentRule.Replace('{{WORKROOT}}', $WorkRoot).Replace('{{SCRIPT}}', $PSCommandPath).
        Replace('{{HOOK}}', ($hookFile -replace "'", "''")).Replace('{{PROFILEROOT}}', $ProfileRoot) |
        Set-Content -LiteralPath $ruleFile -Encoding UTF8
    Write-Step "agent rule: $ruleFile"
}

# --- Login (inside the customer's profile only) --------------------------------------------

if ($SkipLogin) {
    Write-Step 'skipped login (-SkipLogin) - re-run without it to log in'
}
else {
    $saved = @{}
    foreach ($k in 'AZURE_CONFIG_DIR', 'AZURE_EXTENSION_DIR') { $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process') }
    try {
        $env:AZURE_CONFIG_DIR    = $profileDir
        $env:AZURE_EXTENSION_DIR = Join-Path $HOME '.azure\cliextensions'

        # Skip the interactive subscription picker newer az versions show after login.
        $null = Test-Native az config set core.login_experience_v2=off --only-show-errors

        $valid = (-not $Relogin) -and (Test-Native az account get-access-token --tenant $TenantId --only-show-errors --output none).Ok
        if ($valid) {
            Write-Step "cached login for tenant $TenantId still valid - reusing (-Relogin to force)"
        }
        else {
            Write-Step "logging in to tenant $TenantId (profile: $profileDir)"
            $loginArgs = @('login', '--tenant', $TenantId, '--only-show-errors', '--output', 'none')
            if ($DeviceCode) { $loginArgs += '--use-device-code' }
            Invoke-Az @loginArgs
        }

        Invoke-Az account set --subscription $SubscriptionId --only-show-errors
        # -join: az emits multi-line JSON, and 5.1's ConvertFrom-Json can't take it line by line.
        $acct = (Invoke-Az account show --output json --only-show-errors) -join "`n" | ConvertFrom-Json
        if ("$($acct.tenantId)".ToLowerInvariant() -ne $TenantId) {
            throw "Subscription $SubscriptionId is in tenant $($acct.tenantId), not $TenantId - check the IDs."
        }
        Write-Host ''
        [pscustomobject]@{ Customer = $Name; Tenant = $acct.tenantId; Subscription = $acct.name; User = $acct.user.name } | Format-Table -AutoSize

        if ($ResourceGroup) {
            $rgId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
            $g = Test-Native az group show --name $ResourceGroup --subscription $SubscriptionId --query id --output tsv --only-show-errors
            if ($g.Ok) { Write-Step "resource group $ResourceGroup found" }
            else { Write-Warning "Resource group $ResourceGroup not found in subscription $SubscriptionId, or this login can't read it." }

            # What can this login really change? Best-effort: needs directory read for --assignee.
            $ra = Test-Native az role assignment list --assignee $acct.user.name --all --include-inherited --include-groups `
                --query '[].{role:roleDefinitionName, scope:scope}' --output json --only-show-errors
            $list = $null
            if ($ra.Ok) { try { $list = @((@($ra.Out) -join "`n") | ConvertFrom-Json) } catch { $list = $null } }
            if ($null -eq $list) {
                Write-Warning "Couldn't list your role assignments - check in the portal whether your rights go beyond $ResourceGroup."
            }
            else {
                $broader = @($list | Where-Object { -not "$($_.scope)".StartsWith($rgId, [StringComparison]::OrdinalIgnoreCase) })
                if ($broader.Count -eq 0) {
                    Write-Step "all your role assignments are within $ResourceGroup - Azure itself enforces the limit"
                }
                else {
                    Write-Warning "Your login has rights beyond $ResourceGroup, so the limit is enforced only by the agent guard, not by Azure:"
                    $broader | ForEach-Object { Write-Host "      $($_.role) @ $($_.scope)" }
                }
            }
        }
    }
    finally {
        foreach ($k in $saved.Keys) {
            if ($null -eq $saved[$k]) { Remove-Item -LiteralPath "Env:$k" -ErrorAction SilentlyContinue }
            else { Set-Item -LiteralPath "Env:$k" -Value $saved[$k] }
        }
    }
}

Write-Host "Done. cd '$target' (or any repo under it) and az / Terraform use profile '$Name'."
