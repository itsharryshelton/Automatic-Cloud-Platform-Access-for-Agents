# GitHub account per folder (gh CLI)

Managed by D:\Git\setup-gh-identity.ps1. Re-running it overwrites this file.

Each root has its own GitHub account, set as `github.user` in the root's includeIf git config:

- `D:/Git/Work/` -> `jdoe-work`
- `D:/Git/Personal/` -> `octocat`
- `D:/Git/Client/` -> `jdoe_acme`

Git push/pull already uses the right SSH key per root. `gh` does not switch by itself: its active account is global, and agent shells start with -NoProfile, so the user's folder hook never runs. In every PowerShell command that runs `gh` (PRs, issues, releases, `gh api`), load the folder's account first, in the same command:

```powershell
. 'C:\Users\you\.gh-identity\gh-identity-hook.ps1'; Update-GhIdentityEnv; gh <args>
```

This sets `GH_TOKEN` to that account and prints `gh: <login>`. Each command is a fresh shell, so repeat the prefix every time. Use the PowerShell tool for this, not Git Bash.

- If the prefix prints no `gh:` line, the folder isn't under a mapped root: ask the user which account to use before running `gh`.
- If it warns that gh isn't logged in, or gh returns 401/403 or mentions SAML/SSO, stop and tell the user. Don't work around it with another account.
- Never run `gh auth login`, `gh auth logout`, `gh auth switch`, `gh auth refresh` or `gh auth token`, and never print `GH_TOKEN`.
- Content you create (PR and issue text, comments) is posted as the folder's account, so it is visible to that org; write it accordingly.
