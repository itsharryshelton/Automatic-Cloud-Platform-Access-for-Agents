#Requires -Version 5.1
<#
.SYNOPSIS
    Make the GitHub CLI (gh) use the right GitHub account per folder, matching your SSH keys.

.DESCRIPTION
    Git already picks the SSH key and author per root (Work, Personal, ...) through
    global includeIf "gitdir:" rules. SSH only covers clone/push/pull - PRs, issues, releases
    and API calls go through gh, which has one active account for the whole machine.

    This script:
      * records the GitHub login for a root as `github.user` in that root's included config
        file (e.g. D:\Git\.gitconfig-personal), next to its SSH key
      * logs gh in to that account if it isn't already (browser sign-in), then restores
        whichever account was active before, so nothing else changes
      * checks every mapped account's token really is that account (and, with -Org, that it
        can see the org - catches SSO / enterprise policy problems)
      * installs a PowerShell prompt hook: in any folder under a mapped root, GH_TOKEN is set
        to that root's account (from gh's own keyring - no new secret storage), and restored
        when you leave
      * writes a Claude Code rule so agents load the right account too (their shells start
        with -NoProfile, so the hook never runs there)

    Run with no arguments to just refresh the hook/rule and show the status of every root.

.EXAMPLE
    .\setup-gh-identity.ps1 -Root Personal -User octocat

.EXAMPLE
    .\setup-gh-identity.ps1 -Root Client -User jdoe_acme -Org acme-corp

.EXAMPLE
    .\setup-gh-identity.ps1          # status + refresh hook and rule
#>
[CmdletBinding()]
param(
    # Root folder name ('Work', 'Personal', 'Client'), or the full path of an includeIf gitdir root.
    [string]$Root,

    # GitHub login for that root. Enterprise managed users keep their _shortcode suffix.
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]*(_[A-Za-z0-9]+)?$')]
    [string]$User,

    # Optional org to check the account can reach (SSO / IP allow-list / app policy).
    [string]$Org,

    [switch]$NoLogin,           # don't start a browser login for a missing account
    [switch]$NoProfileInstall,  # don't add the hook to your PowerShell profile(s)
    [switch]$NoAgentRule,       # don't write ~\.claude\rules\github-identity.md

    [string]$HookRoot = $(Join-Path $HOME '.gh-identity')
)

Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

if ([bool]$Root -ne [bool]$User) { throw 'Pass -Root and -User together (or neither, for status only).' }
foreach ($cmd in 'gh', 'git') {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "'$cmd' not found on PATH" }
}

function Write-Step([string]$Message) { Write-Host "  * $Message" }

# Native calls with EAP relaxed locally (5.1 turns redirected stderr into terminating errors).
function Invoke-Native {
    $ErrorActionPreference = 'Continue'
    $exe, $rest = $args
    $out = & $exe @rest 2>&1
    return @{ Ok = ($LASTEXITCODE -eq 0); Out = (($out | ForEach-Object { "$_" }) -join "`n").Trim() }
}

# Token for one account from gh's keyring, or $null if gh isn't logged in as that account.
function Get-GhToken([string]$Login) {
    $ErrorActionPreference = 'Continue'
    $t = & gh auth token --hostname github.com --user $Login 2>$null
    if ($LASTEXITCODE -eq 0 -and $t) { return "$t".Trim() }
    return $null
}

# Run gh with a specific token.
function Invoke-GhAs([string]$Token) {
    $env:GH_TOKEN = $Token
    try { return Invoke-Native gh @args }
    finally { Remove-Item -LiteralPath Env:GH_TOKEN -ErrorAction SilentlyContinue }
}

# includeIf gitdir roots -> config file -> github.user
function Get-IdentityRoots {
    $r = Invoke-Native git config --global --get-regexp '^includeif\.gitdir'
    if (-not $r.Ok) { return @() }
    $list = foreach ($line in ($r.Out -split "`n")) {
        if ($line -match '^includeif\.gitdir(?:/i)?:(.+?)\.path\s+(.+)$') {
            $rootPath = $Matches[1] -replace '\\', '/'
            if (-not $rootPath.EndsWith('/')) { $rootPath += '/' }
            $file = $Matches[2].Trim()
            if ($file.StartsWith('~')) { $file = $HOME + $file.Substring(1) }
            $u = Invoke-Native git config -f $file --get github.user
            [pscustomobject]@{
                Name = Split-Path -Path $rootPath.TrimEnd('/') -Leaf
                Root = $rootPath
                File = $file
                User = $(if ($u.Ok) { $u.Out } else { $null })
            }
        }
    }
    return @($list)
}

# The script talks to gh as specific accounts; don't let an inherited token get in the way.
$savedEnv = @{}
foreach ($k in 'GH_TOKEN', 'GITHUB_TOKEN') {
    $savedEnv[$k] = [Environment]::GetEnvironmentVariable($k, 'Process')
    Remove-Item -LiteralPath "Env:$k" -ErrorAction SilentlyContinue
}

try {
    $roots = Get-IdentityRoots
    if (-not $roots) { throw 'No includeIf "gitdir:" rules found in your global git config.' }

    # --- Map a root to an account ------------------------------------------------------------
    if ($Root) {
        $want = $Root -replace '\\', '/'
        if (-not $want.EndsWith('/')) { $want += '/' }
        $entry = @($roots | Where-Object { $_.Name -eq $Root -or $_.Root -eq $want })
        if ($entry.Count -ne 1) {
            throw "No includeIf root matches '$Root'. Known roots: $(($roots | ForEach-Object { "$($_.Name) ($($_.Root))" }) -join ', ')"
        }
        $entry = $entry[0]
        Write-Host "GitHub identity for $($entry.Root) -> $User"

        if ($entry.User -ne $User) {
            $set = Invoke-Native git config -f $entry.File github.user $User
            if (-not $set.Ok) { throw "Couldn't write github.user to $($entry.File): $($set.Out)" }
            Write-Step "set github.user = $User in $($entry.File)"
            $entry.User = $User
        }
        else { Write-Step "github.user already $User in $($entry.File)" }

        if (-not (Get-GhToken $User)) {
            if ($NoLogin) {
                Write-Warning "gh isn't logged in as $User - re-run without -NoLogin to sign in."
            }
            else {
                $before = Invoke-Native gh api user --jq .login
                $prevActive = if ($before.Ok) { $before.Out } else { $null }

                Write-Host ''
                Write-Host "  gh will open a browser sign-in. Sign in as $User - if the browser is already" -ForegroundColor Yellow
                Write-Host "  signed in to GitHub as someone else, open the link in a private window instead." -ForegroundColor Yellow
                Write-Host ''
                & gh auth login --hostname github.com --git-protocol ssh --skip-ssh-key --web
                if ($LASTEXITCODE -ne 0) { throw "gh auth login failed (exit $LASTEXITCODE)" }

                $after = Invoke-Native gh api user --jq .login
                if ($after.Ok -and $after.Out -ne $User) {
                    Write-Warning "You signed in as '$($after.Out)', not '$User'. That account was added to gh; run this again and sign in as $User."
                }
                # gh makes the new account active - put the previous one back so nothing else changes.
                if ($prevActive -and $after.Ok -and $after.Out -ne $prevActive) {
                    $sw = Invoke-Native gh auth switch --hostname github.com --user $prevActive
                    if ($sw.Ok) { Write-Step "gh active account restored to $prevActive" }
                    else { Write-Warning "Couldn't switch gh back to ${prevActive}: $($sw.Out)" }
                }
            }
        }
    }

    # --- Check every mapped account ----------------------------------------------------------
    $status = foreach ($r in $roots) {
        $state = 'no github.user set'
        if ($r.User) {
            $token = Get-GhToken $r.User
            if (-not $token) { $state = 'gh not logged in' }
            else {
                $who = Invoke-GhAs $token api user --jq .login
                if (-not $who.Ok) { $state = "token error: $($who.Out)" }
                elseif ($who.Out -ne $r.User) { $state = "token is for $($who.Out)!" }
                else {
                    $state = 'ok'
                    if ($Org -and $Root -and $r.Name -eq $entry.Name) {
                        $o = Invoke-GhAs $token api "orgs/$Org" --jq .login
                        $state = if ($o.Ok) { "ok, can see org $Org" } else { "ok, but org ${Org}: $($o.Out)" }
                    }
                }
            }
        }
        [pscustomobject]@{ Root = $r.Root; User = $r.User; Status = $state }
    }

    # --- Prompt hook -------------------------------------------------------------------------
    New-Item -ItemType Directory -Force -Path $HookRoot | Out-Null
    $hookFile = Join-Path $HookRoot 'gh-identity-hook.ps1'
    $hookSource = @'
# gh-identity prompt hook - generated by setup-gh-identity.ps1. Re-run that script to update;
# edits here are overwritten. Sets GH_TOKEN to the GitHub account mapped (github.user in the
# includeIf config) to the root you're in, from gh's own keyring; restores it when you leave.

$global:GhIdentityVars = @('GH_TOKEN', 'GH_IDENTITY')
if (-not (Get-Variable -Name GhIdentitySaved -Scope Global -ErrorAction SilentlyContinue)) {
    $global:GhIdentitySaved = $null   # env snapshot from before the first identity was applied
}
# (Re)loading refreshes the mapping and re-evaluates on the next prompt.
$global:GhIdentityMap     = $null
$global:GhIdentityLastDir = $null
$global:GhIdentitySeen    = $null

function global:Get-GhIdentityMap {
    if ($null -ne $global:GhIdentityMap) { return $global:GhIdentityMap }
    $ErrorActionPreference = 'Continue'
    $map = @()
    foreach ($line in @(& git config --global --get-regexp '^includeif\.gitdir' 2>$null)) {
        if ("$line" -match '^includeif\.gitdir(?:/i)?:(.+?)\.path\s+(.+)$') {
            $root = $Matches[1] -replace '\\', '/'
            if (-not $root.EndsWith('/')) { $root += '/' }
            $file = $Matches[2].Trim()
            if ($file.StartsWith('~')) { $file = $HOME + $file.Substring(1) }
            $user = & git config -f $file --get github.user 2>$null
            if ($LASTEXITCODE -eq 0 -and $user) { $map += [pscustomobject]@{ Root = $root; User = "$user".Trim() } }
        }
    }
    $global:GhIdentityMap = @($map | Sort-Object -Property { $_.Root.Length } -Descending)   # nested roots win
    return $global:GhIdentityMap
}

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

function global:Find-GhIdentityFor([string]$Dir) {
    $d = ($Dir -replace '\\', '/').TrimEnd('/') + '/'
    foreach ($m in (Get-GhIdentityMap)) {
        if ($d.StartsWith($m.Root, [StringComparison]::OrdinalIgnoreCase)) { return $m.User }
    }
    return $null
}

function global:Find-GhIdentity {
    $here = (Get-Location -PSProvider FileSystem).ProviderPath
    $user = Find-GhIdentityFor $here
    if (-not $user) {
        $main = Get-GitMainCheckoutDir $here
        if ($main) { $user = Find-GhIdentityFor $main }
    }
    return $user
}

function global:Reset-GhIdentityEnv {
    if ($null -ne $global:GhIdentitySaved) {
        foreach ($k in $global:GhIdentityVars) {
            $v = $global:GhIdentitySaved[$k]
            if ($null -eq $v) { Remove-Item -LiteralPath "Env:$k" -ErrorAction SilentlyContinue }
            else { Set-Item -LiteralPath "Env:$k" -Value $v }
        }
    }
    $global:GhIdentitySaved = $null
}

function global:Update-GhIdentityEnv {
    $dir = (Get-Location -PSProvider FileSystem).ProviderPath
    if ($dir -eq $global:GhIdentityLastDir) { return }
    $global:GhIdentityLastDir = $dir

    $user = Find-GhIdentity
    if ($user -eq $global:GhIdentitySeen) { return }
    $global:GhIdentitySeen = $user
    $wasActive = $null -ne $global:GhIdentitySaved

    if (-not $user) {
        Reset-GhIdentityEnv
        if ($wasActive) { Write-Host 'gh: default account' -ForegroundColor DarkGray }
        return
    }

    # Ask gh's keyring for this account's token, with any env token out of the way.
    $ErrorActionPreference = 'Continue'
    $hold = @{ GH_TOKEN = $env:GH_TOKEN; GITHUB_TOKEN = $env:GITHUB_TOKEN }
    Remove-Item -LiteralPath Env:GH_TOKEN, Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
    try { $token = & gh auth token --hostname github.com --user $user 2>$null; $ok = ($LASTEXITCODE -eq 0) }
    finally { foreach ($k in $hold.Keys) { if ($null -ne $hold[$k]) { Set-Item -LiteralPath "Env:$k" -Value $hold[$k] } } }

    if (-not $ok -or -not $token) {
        Reset-GhIdentityEnv
        Write-Warning "gh-identity: gh isn't logged in as '$user' - run setup-gh-identity.ps1 -Root <root> -User $user"
        return
    }

    if (-not $wasActive) {
        $global:GhIdentitySaved = @{}
        foreach ($k in $global:GhIdentityVars) {
            $global:GhIdentitySaved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process')
        }
    }
    $env:GH_TOKEN    = "$token".Trim()
    $env:GH_IDENTITY = $user
    Write-Host "gh: $user" -ForegroundColor DarkCyan
}

# Wrap whatever prompt is current exactly once per session.
if (-not (Get-Variable -Name GhIdentityInnerPrompt -Scope Global -ErrorAction SilentlyContinue)) {
    $global:GhIdentityInnerPrompt = $function:prompt
    function global:prompt {
        $code = $global:LASTEXITCODE
        try { Update-GhIdentityEnv } catch { Write-Warning "gh-identity: $_" }
        $global:LASTEXITCODE = $code
        if ($global:GhIdentityInnerPrompt) { & $global:GhIdentityInnerPrompt } else { "PS $($executionContext.SessionState.Path.CurrentLocation)> " }
    }
}
'@
    Set-Content -LiteralPath $hookFile -Value $hookSource -Encoding UTF8

    if (-not $NoProfileInstall) {
        $quoted   = $hookFile -replace "'", "''"
        $hookLine = "if (Test-Path -LiteralPath '$quoted') { . '$quoted' }  # gh-identity hook"
        $docs     = [Environment]::GetFolderPath('MyDocuments')
        $targets  = @($PROFILE.CurrentUserAllHosts) + @(
            (Join-Path $docs 'PowerShell\profile.ps1'),
            (Join-Path $docs 'WindowsPowerShell\profile.ps1') |
                Where-Object { Test-Path -LiteralPath (Split-Path -Path $_ -Parent) }
        ) | Select-Object -Unique
        foreach ($p in $targets) {
            if ((Test-Path -LiteralPath $p) -and (Select-String -LiteralPath $p -SimpleMatch '# gh-identity hook' -Quiet)) { continue }
            New-Item -ItemType Directory -Force -Path (Split-Path -Path $p -Parent) | Out-Null
            Add-Content -LiteralPath $p -Value "`r`n$hookLine"
            Write-Step "added hook to $p"
        }
    }

    # --- Agent rule --------------------------------------------------------------------------
    $agentRule = @'
# GitHub account per folder (gh CLI)

Managed by {{SCRIPT}}. Re-running it overwrites this file.

Each root has its own GitHub account, set as `github.user` in the root's includeIf git config:

{{MAP}}

Git push/pull already uses the right SSH key per root. `gh` does not switch by itself: its active account is global, and agent shells start with -NoProfile, so the user's folder hook never runs. In every PowerShell command that runs `gh` (PRs, issues, releases, `gh api`), load the folder's account first, in the same command:

```powershell
. '{{HOOK}}'; Update-GhIdentityEnv; gh <args>
```

This sets `GH_TOKEN` to that account and prints `gh: <login>`. Each command is a fresh shell, so repeat the prefix every time. Use the PowerShell tool for this, not Git Bash.

- If the prefix prints no `gh:` line, the folder isn't under a mapped root: ask the user which account to use before running `gh`.
- If it warns that gh isn't logged in, or gh returns 401/403 or mentions SAML/SSO, stop and tell the user. Don't work around it with another account.
- Never run `gh auth login`, `gh auth logout`, `gh auth switch`, `gh auth refresh` or `gh auth token`, and never print `GH_TOKEN`.
- Content you create (PR and issue text, comments) is posted as the folder's account, so it is visible to that org; write it accordingly.
'@
    if (-not $NoAgentRule) {
        $mapText = ($status | Where-Object { $_.User } | ForEach-Object { "- ``$($_.Root)`` -> ``$($_.User)``" }) -join "`n"
        if (-not $mapText) { $mapText = '- (no roots mapped yet)' }
        $ruleFile = Join-Path $HOME '.claude\rules\github-identity.md'
        New-Item -ItemType Directory -Force -Path (Split-Path -Path $ruleFile -Parent) | Out-Null
        $agentRule.Replace('{{SCRIPT}}', $PSCommandPath).Replace('{{HOOK}}', ($hookFile -replace "'", "''")).Replace('{{MAP}}', $mapText) |
            Set-Content -LiteralPath $ruleFile -Encoding UTF8
        Write-Step "agent rule: $ruleFile"
    }

    . $hookFile   # activate in this session too

    Write-Host ''
    $status | Format-Table -AutoSize
}
finally {
    foreach ($k in $savedEnv.Keys) {
        if ($null -eq $savedEnv[$k]) { Remove-Item -LiteralPath "Env:$k" -ErrorAction SilentlyContinue }
        else { Set-Item -LiteralPath "Env:$k" -Value $savedEnv[$k] }
    }
}
