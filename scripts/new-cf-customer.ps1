#Requires -Version 5.1
<#
.SYNOPSIS
    Give a customer folder (or a single repo) its own Cloudflare account ID + API tokens.

.DESCRIPTION
    For the folder at -Path - relative to -GitRoot (default D:\Git), so 'Work\<customer>',
    'Personal' or 'Work\<customer>\<repo>'; '.\x' is relative to the current directory:
      * writes <folder>\.cfcustomer.json        (profile name + Cloudflare account ID, no secrets)
      * stores a READ and a WRITE API token in ~\.cloudflare-profiles\<name>\, encrypted with
        Windows DPAPI (only your Windows user on this machine can decrypt them)
      * verifies both tokens are active and can see the account
      * installs a PowerShell prompt hook: whenever you cd into the folder, or any repo beneath
        it, CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN switch to that customer - READ token
        by default - and switch back when you leave.

    CLOUDFLARE_API_TOKEN takes priority over any cf / wrangler login or profile, and the
    Terraform Cloudflare provider reads it too, so all three follow the folder.

    In a customer folder:
        cfw <command> [args]     run one command with the WRITE token   (cfw wrangler deploy)
        Use-CfToken Write        stay on the WRITE token until you leave the customer folder
        Use-CfToken Read         back to READ
    The prompt shows [cf:WRITE] in red while the write token is active.

    Markers are only honoured if this script wrote them (path + SHA-256 allow-list), so a
    .cfcustomer.json committed in someone else's repo can't select an account for you.

    Safe to re-run: an identical marker is kept, stored tokens are kept (-ResetTokens to
    replace them), and the hook is refreshed.

.EXAMPLE
    .\new-cf-customer.ps1 -Path 'Work\Contoso' -AccountId <32-hex>
    # prompts for the read and write tokens (input hidden)

.EXAMPLE
    # rotate tokens
    .\new-cf-customer.ps1 -Path 'Work\Contoso' -AccountId <32-hex> -ResetTokens
#>
[CmdletBinding()]
param(
    # Customer folder, repo, or a whole root (e.g. Personal). Relative to -GitRoot unless it
    # starts with .\ or is absolute. Created if missing, as long as its parent exists.
    [Parameter(Mandatory, Position = 0)]
    [string]$Path,

    [Parameter(Mandatory, Position = 1)]
    [ValidatePattern('^[0-9a-fA-F]{32}$')]
    [string]$AccountId,

    # Profile name. Defaults to the folder name, lower-cased, spaces/punctuation -> hyphens.
    [ValidatePattern('^[a-z0-9][a-z0-9-]*$')]
    [string]$Name,

    # Tokens can be passed in (e.g. from Get-Secret); otherwise you're prompted.
    [securestring]$ReadToken,
    [securestring]$WriteToken,

    [switch]$ResetTokens,       # replace stored tokens
    [switch]$SingleToken,       # one token for both read and write (POCs, API token limits) - no read-only protection
    [switch]$SkipAccountCheck,  # token must still be active, but don't require proof it can see the account
    [switch]$SkipVerify,        # don't call the Cloudflare API to check the tokens
    [switch]$Force,             # replace an existing marker that has a different account
    [switch]$NoProfileInstall,  # don't add the hook to your PowerShell profile(s)
    [switch]$NoAgentRule,       # don't write the Claude Code rule (~\.claude\rules\cloudflare-customer-credentials.md)

    [string]$GitRoot     = $(if ($env:CF_GIT_ROOT)     { $env:CF_GIT_ROOT }     else { 'D:\Git' }),
    [string]$ProfileRoot = $(if ($env:CF_PROFILE_ROOT) { $env:CF_PROFILE_ROOT } else { Join-Path $HOME '.cloudflare-profiles' })
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

$MarkerName = '.cfcustomer.json'
$AccountId  = $AccountId.ToLowerInvariant()

function Write-Step([string]$Message) { Write-Host "  * $Message" }

# Run a native command for its exit code only, swallowing stderr (5.1-safe under EAP Stop).
function Test-Native {
    $ErrorActionPreference = 'Continue'
    $exe, $rest = $args
    $out = & $exe @rest 2>$null
    if ($LASTEXITCODE -eq 0) { return @{ Ok = $true; Out = $out } }
    return @{ Ok = $false; Out = $null }
}

function ConvertTo-PlainText([securestring]$Secure) {
    return [Net.NetworkCredential]::new('', $Secure).Password
}

# Calls the Cloudflare API with a token; returns the parsed body, or $null + reason on failure.
function Invoke-CfApi([string]$Token, [string]$Uri) {
    try {
        $r = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4$Uri" -Headers @{ Authorization = "Bearer $Token" } -UseBasicParsing
        return @{ Ok = [bool]$r.success; Body = $r; Error = $null }
    }
    catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            try { $msg = (($_.ErrorDetails.Message | ConvertFrom-Json).errors | ForEach-Object { "$($_.code): $($_.message)" }) -join '; ' } catch {}
        }
        return @{ Ok = $false; Body = $null; Error = $msg }
    }
}

# Account-owned tokens verify at /accounts/<id>/tokens/verify, user tokens at /user/tokens/verify.
function Test-CfToken([string]$Label, [string]$Token) {
    $seen = $null
    $v = Invoke-CfApi $Token "/accounts/$AccountId/tokens/verify"
    if ($v.Ok) { $seen = 'account-owned token for this account' }
    else { $v = Invoke-CfApi $Token '/user/tokens/verify' }
    if (-not $v.Ok) { throw "$Label token failed verification: $($v.Error)" }
    if ($v.Body.result.status -ne 'active') { throw "$Label token status is '$($v.Body.result.status)', not active" }
    $expires = if ($v.Body.result.PSObject.Properties['expires_on'] -and $v.Body.result.expires_on) { " (expires $($v.Body.result.expires_on))" } else { '' }

    # Confirm the token reaches this account. /accounts/<id> needs "Account Settings: Read",
    # which narrow tokens often lack (9109), so fall back to other read-only views of it.
    $a = Invoke-CfApi $Token "/accounts/$AccountId"
    if (-not $seen -and $a.Ok) { $seen = "account '$($a.Body.result.name)'" }
    if (-not $seen) {
        $l = Invoke-CfApi $Token '/accounts?per_page=50'
        if ($l.Ok) {
            $m = @($l.Body.result | Where-Object { $_.id -eq $AccountId })
            if ($m.Count -gt 0) { $seen = "account '$($m[0].name)' (via account list)" }
        }
    }
    if (-not $seen) {
        $z = Invoke-CfApi $Token "/zones?account.id=$AccountId&per_page=1"
        if ($z.Ok -and @($z.Body.result).Count -gt 0) { $seen = "account $AccountId (via its zones)" }
    }
    if (-not $seen) {
        $w = Invoke-CfApi $Token "/accounts/$AccountId/workers/scripts"
        if ($w.Ok) { $seen = "account $AccountId (via Workers)" }
    }

    if ($seen) { Write-Step "$Label token active$expires, $seen"; return }
    if ($SkipAccountCheck) {
        Write-Warning "$Label token is active, but nothing it can read confirms account $AccountId - continuing (-SkipAccountCheck). Double-check the account ID."
        return
    }
    throw ("$Label token is active, but nothing it can read confirms access to account $AccountId ($($a.Error)). " +
           "Check the account ID; if it's right and the token is narrowly scoped, re-run with -SkipAccountCheck.")
}

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# --- Resolve target folder and profile name -----------------------------------------------

$target = if ([IO.Path]::IsPathRooted($Path)) { $Path }
          elseif ($Path -match '^\.\.?([\\/]|$)') { Join-Path (Get-Location -PSProvider FileSystem).ProviderPath $Path }
          else { Join-Path $GitRoot $Path }
if (-not (Test-Path -LiteralPath $target -PathType Container)) {
    # Only create the last level, so a typo in the root ('Wrok\...') fails instead.
    if (-not (Test-Path -LiteralPath (Split-Path -Path $target -Parent) -PathType Container)) {
        throw "Neither $target nor its parent exists. Relative paths start at $GitRoot, e.g. 'Work\<customer>' or 'Personal'."
    }
    New-Item -ItemType Directory -Path $target | Out-Null
    Write-Step "created $target"
}
$target = (Resolve-Path -LiteralPath $target).ProviderPath.TrimEnd('\')

# Which git identity covers this folder (global includeIf "gitdir:" roots) - informational.
$identity = $null
$includes = Test-Native git config --global --get-regexp '^includeif\.gitdir'
if ($includes.Ok) {
    foreach ($line in @($includes.Out)) {
        if ("$line" -match '^includeif\.gitdir(?:/i)?:(.+?)\.path\s+(.+)$') {
            $root = $Matches[1] -replace '\\', '/'
            if (-not $root.EndsWith('/')) { $root += '/' }
            if ((($target -replace '\\', '/') + '/').StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
                $identity = "$($Matches[2]) (repos under $root)"
            }
        }
    }
}

if (-not $Name) {
    $Name = ((Split-Path -Path $target -Leaf).ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
    if ($Name -notmatch '^[a-z0-9][a-z0-9-]*$') { throw "Can't derive a profile name from '$target' - pass -Name." }
}

$profileDir = Join-Path $ProfileRoot $Name
$markerPath = Join-Path $target $MarkerName
$allowFile  = Join-Path $ProfileRoot 'allowed-markers.txt'
$hookFile   = Join-Path $ProfileRoot 'cf-customer-hook.ps1'
$tokenFiles = @{ read = Join-Path $profileDir 'read.token'; write = Join-Path $profileDir 'write.token' }

Write-Host "Cloudflare profile '$Name' -> $target"
if ($identity) { Write-Step "git identity: $identity" }
else { Write-Warning "$target isn't under any includeIf gitdir root, so repos here use your default git identity." }

# --- Tokens (collected and verified before anything is written) -----------------------------

New-Item -ItemType Directory -Force -Path $profileDir | Out-Null
if (-not $profileDir.StartsWith($HOME, [StringComparison]::OrdinalIgnoreCase)) {
    Write-Warning "$profileDir is outside your user profile - make sure only you can read it."
}

# Profile names come from the folder name, so Work\acme and Personal\acme would collide.
$accountFile = Join-Path $profileDir 'account-id.txt'
if (Test-Path -LiteralPath $accountFile) {
    $owner = (Get-Content -LiteralPath $accountFile -Raw).Trim()
    if ($owner -ne $AccountId) {
        throw "Profile '$Name' already belongs to account $owner. Pass a different -Name for this one."
    }
}

$supplied = @{ read = $ReadToken; write = $WriteToken }
$plain = @{}
foreach ($mode in 'read', 'write') {
    if ($SingleToken -and $mode -eq 'write') {
        $plain.write    = $plain.read
        $supplied.write = $true   # always store write = read, even if read came from storage
        continue
    }
    $file = $tokenFiles[$mode]
    $secure = $supplied[$mode]
    if (-not $secure -and -not $ResetTokens -and (Test-Path -LiteralPath $file)) {
        $secure = (Get-Content -LiteralPath $file -Raw).Trim() | ConvertTo-SecureString   # DPAPI, current user
        Write-Step "$mode token: using stored one"
    }
    elseif (-not $secure) {
        $label = if ($SingleToken) { 'API token (used for BOTH read and write)' }
                 elseif ($mode -eq 'read') { 'READ-ONLY (Read All)' } else { 'WRITE (Edit All)' }
        $secure = Read-Host -AsSecureString "  Paste $label API token for '$Name'"
        $supplied[$mode] = $secure   # mark as new so it gets saved
    }
    $plain[$mode] = (ConvertTo-PlainText $secure).Trim()
    if (-not $plain[$mode]) { throw "$mode token is empty" }
}
if ($SingleToken) {
    Write-Step 'single token: used for read AND write - there is no read-only protection in this folder'
}
elseif ($plain.read -eq $plain.write) {
    Write-Warning 'Read and write tokens are identical - the read-only default gives no protection. Use -SingleToken if that is intended.'
}

if ($SkipVerify) { Write-Step 'skipped token verification (-SkipVerify)' }
else {
    Test-CfToken 'READ' $plain.read
    if ($plain.write -ne $plain.read) { Test-CfToken 'WRITE' $plain.write }
    else { Write-Step 'WRITE token: same as read, already checked' }
}

foreach ($mode in 'read', 'write') {
    if ($supplied[$mode]) {
        ConvertTo-SecureString $plain[$mode] -AsPlainText -Force | ConvertFrom-SecureString |
            Set-Content -LiteralPath $tokenFiles[$mode] -Encoding ASCII
        Write-Step "saved $mode token (DPAPI) to $($tokenFiles[$mode])"
    }
}
$plain = $null
Set-Content -LiteralPath $accountFile -Value $AccountId -Encoding ASCII

# --- Marker ---------------------------------------------------------------------------------

$writeMarker = $true
if (Test-Path -LiteralPath $markerPath) {
    $existing = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
    if ($existing.name -eq $Name -and $existing.accountId -eq $AccountId) {
        $writeMarker = $false
        Write-Step "$MarkerName already up to date"
    }
    elseif (-not $Force) {
        throw "$markerPath already exists for '$($existing.name)' (account $($existing.accountId)). Use -Force to replace it."
    }
}
if ($writeMarker) {
    [ordered]@{ name = $Name; accountId = $AccountId } | ConvertTo-Json | Set-Content -LiteralPath $markerPath -Encoding UTF8
    Write-Step "wrote $markerPath"
}

# Keep the marker out of commits via .git/info/exclude when it sits inside a git work tree.
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
        $present = (Test-Path -LiteralPath $exclPath) -and ((Get-Content -LiteralPath $exclPath) -contains $entry)
        if (-not $present) {
            Add-Content -LiteralPath $exclPath -Value $entry
            Write-Step "added $entry to $exclPath"
        }
    }
}

# Allow-list: "<sha256>`t<marker path>", replacing any older entry for this path.
$hash = (Get-FileHash -LiteralPath $markerPath -Algorithm SHA256).Hash
$allowed = @(if (Test-Path -LiteralPath $allowFile) { Get-Content -LiteralPath $allowFile })
$allowed = @($allowed | Where-Object { $_ -and ($_ -split "`t", 2)[-1] -ne $markerPath }) + "$hash`t$markerPath"
Set-Content -LiteralPath $allowFile -Value $allowed -Encoding UTF8

# --- Prompt hook ----------------------------------------------------------------------------

$hookSource = @'
# cf-customer prompt hook - generated by new-cf-customer.ps1. Re-run that script to update;
# edits here are overwritten. Sets CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_API_TOKEN from the nearest
# allow-listed .cfcustomer.json above the current directory (READ token by default), and
# restores the previous values on leaving.

$global:CfCustomerRoot = $PSScriptRoot
$global:CfCustomerVars = @(
    'CF_CUSTOMER', 'CF_TOKEN_MODE', 'CLOUDFLARE_ACCOUNT_ID', 'CLOUDFLARE_API_TOKEN',
    # anything that could override or mix with the customer token - clear it
    'CLOUDFLARE_API_KEY', 'CLOUDFLARE_EMAIL', 'CLOUDFLARE_AUTH_PROFILE', 'CLOUDFLARE_ZONE_ID',
    'CF_API_TOKEN', 'CF_API_KEY', 'CF_API_EMAIL', 'CF_ACCOUNT_ID'
)
if (-not (Get-Variable -Name CfCustomerSeen -Scope Global -ErrorAction SilentlyContinue)) {
    $global:CfCustomerSeen  = $null   # marker path last evaluated
    $global:CfCustomerSaved = $null   # env snapshot from before the first customer was applied
}

$global:CfCustomerLastDir = $null   # (re)loading re-evaluates on the next prompt

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

function global:Search-CfCustomerMarker([string]$Dir) {
    while ($Dir) {
        $candidate = Join-Path $Dir '.cfcustomer.json'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        $parent = Split-Path -Path $Dir -Parent
        if (-not $parent -or $parent -eq $Dir) { break }
        $Dir = $parent
    }
    return $null
}

function global:Find-CfCustomerMarker {
    $here  = (Get-Location -PSProvider FileSystem).ProviderPath
    $found = Search-CfCustomerMarker $here
    if (-not $found) {
        $main = Get-GitMainCheckoutDir $here
        if ($main) { $found = Search-CfCustomerMarker $main }
    }
    return $found
}

function global:Test-CfCustomerAllowed([string]$Marker) {
    $list = Join-Path $global:CfCustomerRoot 'allowed-markers.txt'
    if (-not (Test-Path -LiteralPath $list)) { return $false }
    $entry = (Get-FileHash -LiteralPath $Marker -Algorithm SHA256).Hash + "`t" + $Marker
    return [bool](@(Get-Content -LiteralPath $list) -contains $entry)
}

# Decrypts a stored token (DPAPI, current user). Returns $null if it isn't there.
function global:Get-CfCustomerToken([string]$Customer, [ValidateSet('read', 'write')][string]$Mode) {
    $file = Join-Path (Join-Path $global:CfCustomerRoot $Customer) "$Mode.token"
    if (-not (Test-Path -LiteralPath $file)) { return $null }
    $secure = (Get-Content -LiteralPath $file -Raw).Trim() | ConvertTo-SecureString
    return [Net.NetworkCredential]::new('', $secure).Password
}

function global:Reset-CfCustomerEnv {
    if ($null -ne $global:CfCustomerSaved) {
        foreach ($k in $global:CfCustomerVars) {
            $v = $global:CfCustomerSaved[$k]
            if ($null -eq $v) { Remove-Item -LiteralPath "Env:$k" -ErrorAction SilentlyContinue }
            else { Set-Item -LiteralPath "Env:$k" -Value $v }
        }
    }
    $global:CfCustomerSaved = $null
}

function global:Update-CfCustomerEnv {
    $dir = (Get-Location -PSProvider FileSystem).ProviderPath
    if ($dir -eq $global:CfCustomerLastDir) { return }
    $global:CfCustomerLastDir = $dir
    $marker = Find-CfCustomerMarker
    if ($marker -eq $global:CfCustomerSeen) { return }
    $global:CfCustomerSeen = $marker
    $wasActive = $null -ne $global:CfCustomerSaved

    if (-not $marker) {
        Reset-CfCustomerEnv
        if ($wasActive) { Write-Host 'cf: no customer' -ForegroundColor DarkGray }
        return
    }

    $cfg = $null
    $token = $null
    try {
        if (-not (Test-CfCustomerAllowed $marker)) { throw 'not created by new-cf-customer.ps1, or changed since - re-run it for this folder to trust it' }
        $cfg = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
        if ("$($cfg.name)" -notmatch '^[a-z0-9][a-z0-9-]*$' -or "$($cfg.accountId)" -notmatch '^[0-9a-f]{32}$') { throw 'malformed' }
        $token = Get-CfCustomerToken $cfg.name 'read'
    }
    catch {
        # Never leave a previous customer's account/token active when the new marker is rejected.
        Reset-CfCustomerEnv
        Write-Warning "cf-customer: ignoring ${marker}: $_"
        return
    }

    if (-not $wasActive) {
        $global:CfCustomerSaved = @{}
        foreach ($k in $global:CfCustomerVars) {
            $global:CfCustomerSaved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process')
        }
    }
    foreach ($k in $global:CfCustomerVars) { Remove-Item -LiteralPath "Env:$k" -ErrorAction SilentlyContinue }

    $env:CF_CUSTOMER           = $cfg.name
    $env:CLOUDFLARE_ACCOUNT_ID = $cfg.accountId
    if ($token) {
        $env:CLOUDFLARE_API_TOKEN = $token
        $env:CF_TOKEN_MODE        = 'read'
        Write-Host "cf: $($cfg.name) (account $($cfg.accountId), read token)" -ForegroundColor DarkCyan
    }
    else {
        Write-Warning "cf-customer: no read token stored for '$($cfg.name)' - re-run new-cf-customer.ps1"
    }
}

# Switch the current customer's token until you leave its folder.
function global:Use-CfToken {
    param([Parameter(Mandatory)][ValidateSet('Read', 'Write')][string]$Mode)
    if (-not $env:CF_CUSTOMER) { throw 'Not in a Cloudflare customer folder.' }
    $m = $Mode.ToLowerInvariant()
    $token = Get-CfCustomerToken $env:CF_CUSTOMER $m
    if (-not $token) { throw "No $m token stored for '$env:CF_CUSTOMER' - re-run new-cf-customer.ps1" }
    $env:CLOUDFLARE_API_TOKEN = $token
    $env:CF_TOKEN_MODE = $m
    $color = if ($m -eq 'write') { 'Red' } else { 'DarkCyan' }
    Write-Host "cf: $env:CF_CUSTOMER now using $m token" -ForegroundColor $color
}

# Run one command with the WRITE token, then go back to whatever was active.
function global:cfw {
    if (-not $env:CF_CUSTOMER) { throw 'Not in a Cloudflare customer folder.' }
    if ($args.Count -eq 0) { throw 'Usage: cfw <command> [args]   e.g. cfw wrangler deploy' }
    $token = Get-CfCustomerToken $env:CF_CUSTOMER 'write'
    if (-not $token) { throw "No write token stored for '$env:CF_CUSTOMER' - re-run new-cf-customer.ps1" }
    $prevToken = $env:CLOUDFLARE_API_TOKEN
    $prevMode  = $env:CF_TOKEN_MODE
    try {
        $env:CLOUDFLARE_API_TOKEN = $token
        $env:CF_TOKEN_MODE = 'write'
        $cmd, $rest = $args
        & $cmd @rest
    }
    finally {
        $env:CLOUDFLARE_API_TOKEN = $prevToken
        $env:CF_TOKEN_MODE = $prevMode
    }
}

# Wrap whatever prompt is current exactly once per session.
if (-not (Get-Variable -Name CfCustomerInnerPrompt -Scope Global -ErrorAction SilentlyContinue)) {
    $global:CfCustomerInnerPrompt = $function:prompt
    function global:prompt {
        $code = $global:LASTEXITCODE
        try { Update-CfCustomerEnv } catch { Write-Warning "cf-customer: $_" }
        if ($env:CF_TOKEN_MODE -eq 'write') { Write-Host '[cf:WRITE] ' -NoNewline -ForegroundColor Red }
        $global:LASTEXITCODE = $code
        if ($global:CfCustomerInnerPrompt) { & $global:CfCustomerInnerPrompt } else { "PS $($executionContext.SessionState.Path.CurrentLocation)> " }
    }
}
'@
Set-Content -LiteralPath $hookFile -Value $hookSource -Encoding UTF8

if (-not $NoProfileInstall) {
    $quoted   = $hookFile -replace "'", "''"
    $hookLine = "if (Test-Path -LiteralPath '$quoted') { . '$quoted' }  # cf-customer hook"
    $docs     = [Environment]::GetFolderPath('MyDocuments')
    $targets  = @($PROFILE.CurrentUserAllHosts) + @(
        (Join-Path $docs 'PowerShell\profile.ps1'),
        (Join-Path $docs 'WindowsPowerShell\profile.ps1') |
            Where-Object { Test-Path -LiteralPath (Split-Path -Path $_ -Parent) }
    ) | Select-Object -Unique
    foreach ($p in $targets) {
        if ((Test-Path -LiteralPath $p) -and (Select-String -LiteralPath $p -SimpleMatch '# cf-customer hook' -Quiet)) { continue }
        New-Item -ItemType Directory -Force -Path (Split-Path -Path $p -Parent) | Out-Null
        Add-Content -LiteralPath $p -Value "`r`n$hookLine"
        Write-Step "added hook to $p"
    }
}
. $hookFile   # activate in this session too

# --- Agent instructions ---------------------------------------------------------------------
# Agent shells (Claude Code etc.) start with -NoProfile, so the prompt hook never runs there.
# One user-level rule tells agents how to load a customer's tokens. It lives outside every repo
# (nothing to gitignore) and, unlike a CLAUDE.md above the repo, doesn't stop Claude reading a
# repo's AGENTS.md. Per-customer IDs stay in .cfcustomer.json, which the agent reads.

$agentRule = @'
# Cloudflare customer credentials ({{GITROOT}})

Managed by {{SCRIPT}}. Re-running it overwrites this file.

Any folder with a `.cfcustomer.json` in it or above it belongs to one Cloudflare account. These sit anywhere under {{GITROOT}}: on a customer folder under Work, on a whole root such as Personal, or on a single repo (the nearest one wins). The file holds `name` and `accountId`. The customer's API tokens (one read-only, one write) are stored encrypted outside the repo.

Agent shells start with -NoProfile, so the user's folder hook never runs and no customer token is set. In every PowerShell command that needs Cloudflare, load it first, in the same command:

```powershell
. '{{HOOK}}'; Update-CfCustomerEnv; <command>
```

This sets `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN` to the customer's read-only token and prints `cf: <name> (account <id>, read token)`. `cf`, `wrangler` and Terraform all use them ahead of any stored login. Each command is a fresh shell, so repeat the prefix every time. Use the PowerShell tool for this, not Git Bash.

- If the prefix prints no `cf:` line, there is no customer here: ask the user rather than using another login or token.
- Use the read token for all inspection: `list`/`get`, `terraform plan`, `wrangler tail`, dev servers.
- Cloudflare changes are pipeline-controlled and never run from this machine: no `terraform apply`, `wrangler deploy`/`put`/`delete`, `cf ... create/update/delete`, or write calls to the API. Make the change in code and tell the user it is ready for the pipeline. A PreToolUse hook blocks these commands, along with `cfw` and `Use-CfToken Write` (the write token is for the user only). If a block seems wrong, tell the user; don't work around it.
- Exception: folders listed in `~\.claude\hooks\local-apply-allowed.txt` are not pipeline-managed. There these commands prompt the user instead of being blocked; still say what the change does before running it. Never edit that list yourself.
- Never print, echo, log or copy a token, and never read the `.token` files under `{{PROFILEROOT}}`.
- Don't edit `.cfcustomer.json` or anything under `{{PROFILEROOT}}`. If the prefix warns or a token is rejected, tell the user to re-run `{{SCRIPT}}`.
- If any result shows an account other than the `accountId` in `.cfcustomer.json`, stop and tell the user.
'@
if (-not $NoAgentRule) {
    $ruleFile = Join-Path $HOME '.claude\rules\cloudflare-customer-credentials.md'
    New-Item -ItemType Directory -Force -Path (Split-Path -Path $ruleFile -Parent) | Out-Null
    $agentRule.Replace('{{GITROOT}}', $GitRoot).Replace('{{SCRIPT}}', $PSCommandPath).
        Replace('{{HOOK}}', ($hookFile -replace "'", "''")).Replace('{{PROFILEROOT}}', $ProfileRoot) |
        Set-Content -LiteralPath $ruleFile -Encoding UTF8
    Write-Step "agent rule: $ruleFile"
}

Write-Host "Done. cd '$target' (or any repo under it): cf / wrangler / Terraform use account $AccountId with the READ token."
Write-Host "      Writes: cfw <command>  or  Use-CfToken Write"
