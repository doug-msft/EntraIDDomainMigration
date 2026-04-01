# Entra ID Domain Management Scripts

PowerShell scripts for managing custom domain lifecycles in Microsoft Entra ID — check dependencies before removing a domain, and promote subdomains to independent root domains.

## Scripts

| Script | Purpose |
|--------|---------|
| `Check-EntraDomainDependencies.ps1` | Audit and remediate all objects referencing a domain before removal |
| `Promote-EntraSubdomainToRoot.ps1` | Promote a verified subdomain to an independent root domain |

---

## Prerequisites

- **PowerShell 7+** (recommended) or Windows PowerShell 5.1
- **Microsoft Graph PowerShell SDK** modules:
  ```powershell
  Install-Module Microsoft.Graph.Users -Scope CurrentUser
  Install-Module Microsoft.Graph.Groups -Scope CurrentUser
  Install-Module Microsoft.Graph.Applications -Scope CurrentUser
  Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
  ```
- **Exchange Online Management** module (only needed for `-Remediate` in the dependency checker):
  ```powershell
  Install-Module ExchangeOnlineManagement -Scope CurrentUser
  ```
- An Entra ID account with sufficient privileges (Global Administrator or a combination of Domain, User, Group, and Application administrator roles)

---

## Check-EntraDomainDependencies.ps1

Scans your Entra ID tenant for every object that references a given domain — users (UPN, mail, proxy addresses, other mails), groups, application registrations, service principals, and catch-all domain name references. All dependencies must be cleared before a domain can be deleted.

### Usage

**Audit only** — list all dependencies without making changes:

```powershell
.\Check-EntraDomainDependencies.ps1 -DomainName "contoso.com"
```

**Audit + remediate** — interactively clean up user UPNs, proxy addresses, group mail addresses, and application URIs:

```powershell
.\Check-EntraDomainDependencies.ps1 -DomainName "contoso.com" -Remediate
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-DomainName` | Yes | The domain to check (e.g., `contoso.com`) |
| `-Remediate` | No | Interactively fix discovered dependencies — migrate UPNs to the `.onmicrosoft.com` fallback domain, remove proxy addresses via Exchange Online, and update application URIs |

### What it checks

1. **Users** — UPN and mail address matching the domain
2. **Groups** — mail-enabled groups using the domain
3. **Application registrations** — identifier URIs and redirect URIs
4. **Service principals** — service principal names
5. **Devices** — informational count
6. **Domain name references** — catch-all via `Get-MgDomainNameReference` with detailed per-object breakdown

### Remediation modes

When you run with `-Remediate`, you are prompted to choose:

- **All** — remediate every dependency with a single confirmation
- **One-by-one** — review and confirm each object individually
- **Cancel** — abort remediation

> **Note:** Remediation only targets the exact domain specified — subdomains are preserved. Objects synced from on-premises AD cannot be modified in the cloud and must be changed at the source.

---

## Promote-EntraSubdomainToRoot.ps1

Promotes a verified Entra ID subdomain to an independent root domain using the [Microsoft Graph promote API](https://learn.microsoft.com/en-us/entra/identity/users/domains-verify-custom-subdomain). This is required when you want to remove a parent domain while keeping its subdomain, or when you need to manage a subdomain's authentication type independently.

### Usage

**Check and promote** (will fail if users exist on the subdomain):

```powershell
.\Promote-EntraSubdomainToRoot.ps1 -SubdomainName "sub.contoso.com"
```

**Automatically migrate users, promote, then restore** — temporarily moves users to the `.onmicrosoft.com` domain, promotes the subdomain, then moves them back:

```powershell
.\Promote-EntraSubdomainToRoot.ps1 -SubdomainName "sub.contoso.com" -MigrateUsers
```

**Skip all confirmation prompts:**

```powershell
.\Promote-EntraSubdomainToRoot.ps1 -SubdomainName "sub.contoso.com" -MigrateUsers -Force
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-SubdomainName` | Yes | The subdomain to promote (e.g., `sub.contoso.com`) |
| `-MigrateUsers` | No | Temporarily move users off the subdomain so the promote API can succeed, then restore them afterward |
| `-Force` | No | Skip all confirmation prompts |

### How it works

1. Connects to Microsoft Graph with `Domain.ReadWrite.All`, `User.ReadWrite.All`, and `Directory.ReadWrite.All` scopes
2. Validates the subdomain exists, is verified, and is not already a root domain
3. Checks for user references and non-user object references on the subdomain
4. *(If `-MigrateUsers`)* Migrates users to the `.onmicrosoft.com` fallback domain and saves a migration map JSON file to disk
5. Calls `POST /domains/{id}/promote` to promote the subdomain
6. Verifies the promotion succeeded
7. *(If `-MigrateUsers`)* Restores users back to their original UPNs

### Safety features

- **Migration map file** — a JSON log of all user UPN changes is saved to the script directory after every individual migration, so nothing is lost if the script is interrupted
- **Automatic rollback** — if the promote fails or you cancel, migrated users are automatically restored to their original UPNs
- **Confirmation prompts** — each destructive step requires confirmation (unless `-Force` is used)

---

## Typical Workflow

A common scenario is removing a parent domain while keeping its subdomain:

```
1.  Promote the subdomain to a root domain:
      .\Promote-EntraSubdomainToRoot.ps1 -SubdomainName "sub.contoso.com" -MigrateUsers

2.  Check the parent domain for remaining dependencies:
      .\Check-EntraDomainDependencies.ps1 -DomainName "contoso.com"

3.  Remediate any dependencies found:
      .\Check-EntraDomainDependencies.ps1 -DomainName "contoso.com" -Remediate

4.  Once clean, remove the parent domain:
      Remove-MgDomain -DomainId "contoso.com"
```

---

## License

MIT
