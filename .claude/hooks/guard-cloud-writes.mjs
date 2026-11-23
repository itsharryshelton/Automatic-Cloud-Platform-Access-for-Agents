// PreToolUse guard for Bash / PowerShell (and Write / Edit / NotebookEdit) tool calls.
//
// Cloud changes (Terraform, Cloudflare) are pipeline-controlled: agents don't apply them from
// this machine. Login/credential switching is the user's job. Other Azure changes need the
// user's approval.
//
//   deny -> blocked outright, the model is told why
//   ask  -> the user gets an approval prompt
//
// Exception: folders listed in local-apply-allowed.txt (next to this file) are ones the user
// runs locally (not pipeline-managed). There, the "LOCAL" rules below become ask instead of
// deny, or allow for entries prefixed "allow:". Login/token rules never relax. Agent edits to the list, this script or settings.json
// always ask, so an agent can't unlock itself.
//
// Pattern matching on command text is a guardrail, not a sandbox: a command hidden inside a
// script file or built at runtime won't be seen. The agent rules in ~/.claude/rules cover intent.

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ALLOW_FILE = join(HERE, 'local-apply-allowed.txt');

const SEG = String.raw`[^\n;|&]*?`;   // stay within one command segment
const LOCAL = true;                    // rule relaxes to "ask" in allow-listed folders
const AZ = 'az';                       // Azure change: subject to a folder's resourceGroup limit
const CFASK = 'cf';                    // Cloudflare "ask" rule: silent in allow-mode folders
const GUARD = 'guard';                 // the guard's own config: always ask

const DENY = [
  // Terraform / OpenTofu / Terragrunt / Pulumi: state changes only via pipeline.
  [new RegExp(String.raw`\b(terraform|tofu|terragrunt)(\.exe)?\b${SEG}\s(apply|destroy|import|taint|untaint|force-unlock)\b`, 'i'),
    'Terraform apply/destroy/import/taint/force-unlock is pipeline-only. Prepare the change in code and let the pipeline apply it. terraform plan is fine.', LOCAL],
  [new RegExp(String.raw`\b(terraform|tofu|terragrunt)(\.exe)?\b${SEG}\sstate\s+(rm|mv|push|replace-provider)\b`, 'i'),
    'Terraform state changes are pipeline-only.', LOCAL],
  [new RegExp(String.raw`\bpulumi\b${SEG}\s(up|destroy|import|refresh)\b`, 'i'),
    'Pulumi changes are pipeline-only.', LOCAL],

  // Cloudflare write token / write helpers.
  [/(^|[\s;|&({])cfw(\s|$)/i, 'cfw (Cloudflare write token) is not for agents: Cloudflare changes are pipeline-only.', LOCAL],
  [/\bUse-CfToken\b[^\n;|&]*\bWrite\b/i, 'The Cloudflare write token is not for agents: Cloudflare changes are pipeline-only.', LOCAL],
  [/\bGet-CfCustomerToken\b/i, 'Reading Cloudflare tokens directly is not allowed. Use the hook prefix (Update-CfCustomerEnv) for the read token.'],
  [/cloudflare-profiles[\\/][^'"\s]*\.token\b/i, 'Cloudflare token files must not be read.'],

  // Wrangler changes (local-only --local operations are fine).
  [new RegExp(String.raw`\bwrangler\b(?!${SEG}--local\b)${SEG}\s(deploy|publish|delete|rollback|put|create|bulk|upload|apply)\b`, 'i'),
    'wrangler changes to Cloudflare are pipeline-only (deploy/put/delete/create/...). Local dev (wrangler dev, --local) is fine.', LOCAL],
  [/\bwrangler\b[^\n;|&]*\s(login|logout)\b/i, 'wrangler login/logout is the user\'s job.'],

  // cf CLI changes and auth.
  [/(^|[\s;|&({])cf(\.ps1|\.cmd)?\s+auth\s+(login|logout|create|delete|activate|deactivate)\b/i,
    'cf auth changes are the user\'s job.'],
  [new RegExp(String.raw`(^|[\s;|&({])cf(\.ps1|\.cmd)?\s+(?!(cli|docs|schema|auth)\b)${SEG}\b(create|update|delete|edit|put|patch|purge|deploy|import|upload|replace|enable|disable|rollback|bulk)\b(?!${SEG}--dry-run\b)`, 'i'),
    'Cloudflare changes via cf are pipeline-only. Read commands (list/get) are fine.', LOCAL],

  // Raw Cloudflare API writes.
  [/api\.cloudflare\.com[^\n]*(-X\s*|--request\s+|-Method\s+)['"]?(POST|PUT|PATCH|DELETE)\b|(-X\s*|--request\s+|-Method\s+)['"]?(POST|PUT|PATCH|DELETE)\b[^\n]*api\.cloudflare\.com/i,
    'Write calls to the Cloudflare API are pipeline-only.', LOCAL],

  // Credential / identity switching is the user's job (never relaxed).
  [/\baz(\.cmd)?\s+(login|logout)\b/i, 'az login/logout is the user\'s job: re-run new-az-customer.ps1.'],
  [/\baz(\.cmd)?\s+account\s+(set|clear)\b/i, 'Don\'t change the az default subscription: pass --subscription on the command instead.'],
  [/\b(Connect|Disconnect)-AzAccount\b/i, 'Az PowerShell sign-in changes are the user\'s job.'],
  [/\bgh(\.exe)?\s+auth\s+(login|logout|switch|refresh|token|setup-git)\b/i, 'gh auth changes are the user\'s job; use the gh-identity prefix.'],
];

const ASK = [
  // The guard's own configuration: an agent must not be able to loosen it silently.
  [/local-apply-allowed\.txt|guard-cloud-writes\.mjs|[\\/]\.claude[\\/]settings(\.local)?\.json/i,
    'This touches the cloud-write guard\'s configuration (allow-list, guard script or Claude settings).', GUARD],

  [/\baz(\.cmd)?\s+(?!account\b)[^\n;|&]*?\s(create|delete|update|set|add|remove|start|stop|restart|deallocate|assign|purge|import|invoke|run-command|reset|regenerate|rotate|move|upgrade|scale|swap|enable|disable|apply|deploy|renew|revoke|grant|restore|failover)\b/i,
    'This az command changes Azure resources: confirm it should run from here rather than through the pipeline.', AZ],
  [/\baz(\.cmd)?\s+rest\b[^\n;|&]*--method\s+['"]?(put|post|patch|delete)\b/i,
    'This az rest call writes to Azure.', AZ],
  // (?!CustomerEnv) skips the az-customer hook's own Update-/Reset-AzCustomerEnv.
  [/\b(New|Set|Remove|Update|Start|Stop|Restart|Add|Register|Unregister|Enable|Disable|Grant|Revoke|Restore|Move|Reset|Invoke|Import|Publish)-Az(?!CustomerEnv\b)[A-Z]\w*/,
    'This Az PowerShell command changes Azure resources.', AZ],
  [/management\.azure\.com[^\n]*(-X\s*|--request\s+|-Method\s+)['"]?(PUT|POST|PATCH|DELETE)\b|(-X\s*|--request\s+|-Method\s+)['"]?(PUT|POST|PATCH|DELETE)\b[^\n]*management\.azure\.com/i,
    'This is a write call to the Azure management API.', AZ],
  [new RegExp(String.raw`\bwrangler\b${SEG}\sd1\s+execute\b(?!${SEG}--local\b)`, 'i'),
    'wrangler d1 execute against the remote database can change data.', CFASK],
];

const PROTECTED_FILE = /(local-apply-allowed\.txt|guard-cloud-writes\.mjs|[\\/]\.claude[\\/]settings(\.local)?\.json|[\\/]\.(az|cf)customer\.json)$/i;

// Nearest .azcustomer.json at or above cwd (parsed), or null.
export function findAzMarker(cwd) {
  let dir = String(cwd || '');
  for (let i = 0; dir && i < 64; i++) {
    const p = join(dir, '.azcustomer.json');
    if (existsSync(p)) {
      try { return JSON.parse(readFileSync(p, 'utf8').replace(/^﻿/, '')); } catch { return null; }
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

// Resource groups a command names: -g / --resource-group / -ResourceGroupName, and /resourceGroups/<x> in ids, scopes and URLs.
export function resourceGroupRefs(command) {
  const refs = new Set();
  for (const m of command.matchAll(/(?:^|\s)(?:-g|--resource-group|-ResourceGroupName)(?:\s+|=|:)['"]?([^\s'"]+)/gi)) refs.add(m[1].toLowerCase());
  for (const m of command.matchAll(/\/resourceGroups\/([^\/\s'"?]+)/gi)) refs.add(m[1].toLowerCase());
  return [...refs];
}

const RG_LIFECYCLE = /\baz(\.cmd)?\s+group\s+(create|delete|update)\b|\b(New|Remove|Set|Update)-AzResourceGroup\b/i;

function azScoped(command, why, rg, mode = null) {
  if (RG_LIFECYCLE.test(command)) {
    return { decision: 'deny', why: `This folder is limited to resource group ${rg}: creating, changing or deleting resource groups isn't allowed here. Ask the user to run it if it's needed.` };
  }
  const refs = resourceGroupRefs(command);
  const other = refs.filter((r) => r !== rg.toLowerCase());
  if (other.length) {
    return { decision: 'deny', why: `This folder is limited to resource group ${rg}, but the command targets ${other.join(', ')}. Ask the user to run it if it's needed.` };
  }
  if (!refs.length) {
    return { decision: 'ask', why: `${why} This folder is limited to resource group ${rg}, but the command doesn't name a resource group - check it only touches ${rg}.` };
  }
  if (mode === 'allow') return { decision: 'allow', why: `Allowed: change in ${rg}, folder is allow-listed for local changes.` };
  return { decision: 'ask', why: `${why} (resource group ${rg})` };
}

const norm = (p) => String(p || '').replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();

// Folders (and everything under them) where local Terraform/Cloudflare changes may run with approval.
export function loadAllowList(file = ALLOW_FILE) {
  try {
    return readFileSync(file, 'utf8').split(/\r?\n/)
      .map((l) => l.replace(/#.*$/, '').trim())
      .filter(Boolean)
      .map((l) => {
        const m = l.match(/^(allow|ask)\s*:\s*(.+)$/i);
        return m ? { path: norm(m[2].trim()), mode: m[1].toLowerCase() } : { path: norm(l), mode: 'ask' };
      });
  } catch { return []; }
}

export function localApplyMode(cwd, allow = loadAllowList()) {
  const c = norm(cwd);
  if (!c) return null;
  let best = null;
  for (const e of allow) {
    const entry = typeof e === 'string' ? { path: norm(e), mode: 'ask' } : e;
    if ((c === entry.path || c.startsWith(entry.path + '/')) && (!best || entry.path.length > best.path.length)) best = entry;
  }
  return best ? best.mode : null;
}

export function isLocalApplyFolder(cwd, allow = loadAllowList()) {
  return localApplyMode(cwd, allow) !== null;
}

export function decide(command, cwd = '', allow = undefined, markerFor = findAzMarker) {
  if (!command) return null;
  const mode = localApplyMode(cwd, allow);   // null | 'ask' | 'allow'
  for (const [re, why, local] of DENY) {
    if (!re.test(command)) continue;
    if (local && mode === 'allow') {
      return { decision: 'allow', why: 'Allowed: folder is allow-listed for local changes (allow mode).' };
    }
    if (local && mode === 'ask') {
      return { decision: 'ask', why: `${why} This folder is in local-apply-allowed.txt, so it can run locally with your approval.` };
    }
    return { decision: 'deny', why: `${why} If this really must run locally, ask the user to run it.` };
  }
  for (const [re, why, tag] of ASK) {
    if (!re.test(command)) continue;
    if (tag === AZ) {
      const rg = markerFor(cwd)?.resourceGroup;
      if (typeof rg === 'string' && rg) return azScoped(command, why, rg, mode);
      if (mode === 'allow') return { decision: 'allow', why: 'Allowed: folder is allow-listed for local changes (allow mode).' };
    }
    if (tag === CFASK && mode === 'allow') {
      return { decision: 'allow', why: 'Allowed: folder is allow-listed for local changes (allow mode).' };
    }
    return { decision: 'ask', why };
  }
  return null;
}

export function decideFileEdit(filePath) {
  return PROTECTED_FILE.test(String(filePath || '').replace(/\\/g, '/'))
    ? { decision: 'ask', why: 'This edits the cloud-write guard\'s configuration (allow-list, guard script or Claude settings).' }
    : null;
}

async function main() {
  let raw = '';
  for await (const chunk of process.stdin) raw += chunk;
  let input;
  try { input = JSON.parse(raw); } catch { return; }
  const ti = input?.tool_input ?? {};
  const result = ['Write', 'Edit', 'NotebookEdit', 'MultiEdit'].includes(input?.tool_name)
    ? decideFileEdit(ti.file_path ?? ti.notebook_path)
    : decide(typeof ti.command === 'string' ? ti.command : '', input?.cwd);
  if (!result) return;
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: result.decision,
      permissionDecisionReason: `[guard-cloud-writes] ${result.why}`,
    },
  }));
}

if (process.argv[1] && fileURLToPath(import.meta.url).toLowerCase() === process.argv[1].replace(/\//g, '\\').toLowerCase()) {
  main();
}
