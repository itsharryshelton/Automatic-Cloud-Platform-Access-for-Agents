# Azure customer credentials (D:\Git\Work)

Managed by D:\Git\new-az-customer.ps1. Re-running it overwrites this file.

A folder under D:\Git\Work with a `.azcustomer.json` in it or above it belongs to one customer's Azure tenant. The file holds `name`, `tenantId` and `subscriptionId`. Each customer has its own az login, stored outside the repo.

Agent shells start with -NoProfile, so the user's folder hook never runs, and plain `az` uses the user's default login, which may be a different customer. In every PowerShell command that needs Azure, load the customer first, in the same command:

```powershell
. 'C:\Users\you\.azure-profiles\az-customer-hook.ps1'; Update-AzCustomerEnv; <command>
```

This points `az` at the customer's own login (`AZURE_CONFIG_DIR`), sets `ARM_TENANT_ID` and `ARM_SUBSCRIPTION_ID` for Terraform, and prints `az: <name> (subscription <id>)`. Each command is a fresh shell, so repeat the prefix every time. Use the PowerShell tool for this, not Git Bash.

- Never run `az` or Terraform in a customer folder without the prefix. If it prints no `az:` line, there is no customer here: ask the user rather than using another login.
- Before the first Azure command in a task, run `az account show --query tenantId -o tsv` with the prefix and check it matches `tenantId` in `.azcustomer.json`. If it doesn't, stop and tell the user.
- The login is the user's own account with full rights; there is no read-only credential. Read freely (`show`, `list`, `what-if`, `terraform plan`).
- Terraform changes are pipeline-controlled: never run `terraform apply`, `destroy`, `import` or state changes here. Make the change in code and tell the user it is ready for the pipeline. A PreToolUse hook blocks these. Exception: folders listed in `~\.claude\hooks\local-apply-allowed.txt` are not pipeline-managed; there they prompt the user instead. Never edit that list yourself.
- Any other change (`az ... create/update/delete`, role assignments, deployments, `New-/Set-/Remove-Az*`) triggers an approval prompt. Before running one, say why it can't go through the pipeline; if it can, do it in code instead.
- To use another subscription, pass `--subscription` on the command. Don't run `az account set`, `az login` or `az logout`. If the login has expired, tell the user to re-run `D:\Git\new-az-customer.ps1`.
- If `.azcustomer.json` has a `resourceGroup`, change only resources in that resource group. `az` defaults to it (`AZURE_DEFAULTS_GROUP`), but pass `-g`/`--resource-group` explicitly on every change. The PreToolUse hook blocks changes that name another resource group, and creating or deleting resource groups. Reading other resource groups is fine.
- Don't edit `.azcustomer.json` or anything under `C:\Users\you\.azure-profiles`.
