# Cloudflare customer credentials (D:\Git)

Managed by D:\Git\new-cf-customer.ps1. Re-running it overwrites this file.

Any folder with a `.cfcustomer.json` in it or above it belongs to one Cloudflare account. These sit anywhere under D:\Git: on a customer folder under Work, on a whole root such as Personal, or on a single repo (the nearest one wins). The file holds `name` and `accountId`. The customer's API tokens (one read-only, one write) are stored encrypted outside the repo.

Agent shells start with -NoProfile, so the user's folder hook never runs and no customer token is set. In every PowerShell command that needs Cloudflare, load it first, in the same command:

```powershell
. 'C:\Users\you\.cloudflare-profiles\cf-customer-hook.ps1'; Update-CfCustomerEnv; <command>
```

This sets `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN` to the customer's read-only token and prints `cf: <name> (account <id>, read token)`. `cf`, `wrangler` and Terraform all use them ahead of any stored login. Each command is a fresh shell, so repeat the prefix every time. Use the PowerShell tool for this, not Git Bash.

- If the prefix prints no `cf:` line, there is no customer here: ask the user rather than using another login or token.
- Use the read token for all inspection: `list`/`get`, `terraform plan`, `wrangler tail`, dev servers.
- Cloudflare changes are pipeline-controlled and never run from this machine: no `terraform apply`, `wrangler deploy`/`put`/`delete`, `cf ... create/update/delete`, or write calls to the API. Make the change in code and tell the user it is ready for the pipeline. A PreToolUse hook blocks these commands, along with `cfw` and `Use-CfToken Write` (the write token is for the user only). If a block seems wrong, tell the user; don't work around it.
- Exception: folders listed in `~\.claude\hooks\local-apply-allowed.txt` are not pipeline-managed. There these commands prompt the user instead of being blocked; still say what the change does before running it. Never edit that list yourself.
- Never print, echo, log or copy a token, and never read the `.token` files under `C:\Users\you\.cloudflare-profiles`.
- Don't edit `.cfcustomer.json` or anything under `C:\Users\you\.cloudflare-profiles`. If the prefix warns or a token is rejected, tell the user to re-run `D:\Git\new-cf-customer.ps1`.
- If any result shows an account other than the `accountId` in `.cfcustomer.json`, stop and tell the user.
