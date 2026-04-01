<#
.SYNOPSIS
    Promotes an Entra ID subdomain to a root domain.

.DESCRIPTION
    Promotes a verified subdomain to a root domain in Microsoft Entra ID using the
    Microsoft Graph promote API. This is required when you want to manage a subdomain's
    authentication type independently from its parent domain (e.g., to remove the
    parent domain while keeping the subdomain).

    The promote API requires that NO user references exist on the subdomain. This
    script checks for user references and optionally migrates them to a temporary
    holding domain (the .onmicrosoft.com default) before promoting.

    Based on: https://learn.microsoft.com/en-us/entra/identity/users/domains-verify-custom-subdomain

.PARAMETER SubdomainName
    The subdomain to promote to a root domain (e.g., "osm.dougcopilot.us").

.PARAMETER MigrateUsers
    When specified, migrates users off the subdomain (temporarily changes their UPN
    to the .onmicrosoft.com domain) so the promote can succeed, then moves them back
    after promotion.

.PARAMETER Force
    Skip confirmation prompts.

.EXAMPLE
    .\Promote-EntraSubdomainToRoot.ps1 -SubdomainName "osm.dougcopilot.us"

.EXAMPLE
    .\Promote-EntraSubdomainToRoot.ps1 -SubdomainName "osm.dougcopilot.us" -MigrateUsers
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SubdomainName,

    [Parameter()]
    [switch]$MigrateUsers,

    [Parameter()]
    [switch]$Force
)

#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Identity.DirectoryManagement

# ── Helper ────────────────────────────────────────────────────────────────────
function Write-Section([string]$Title) {
    Write-Host "`n$('=' * 70)" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "$('=' * 70)" -ForegroundColor Cyan
}

# ── Step 1: Connect to Microsoft Graph ────────────────────────────────────────
Write-Section "Step 1: Connecting to Microsoft Graph"

$requiredScopes = @(
    "Domain.ReadWrite.All",
    "User.ReadWrite.All",
    "Directory.ReadWrite.All"
)

try {
    $context = Get-MgContext
    if ($context) {
        Write-Host "  Existing session found for $($context.Account). Disconnecting..." -ForegroundColor Gray
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Host "  Connecting (you will be prompted once to sign in)..." -ForegroundColor Gray
    $null = Connect-MgGraph -Scopes $requiredScopes -ErrorAction Stop
    $context = Get-MgContext
    Write-Host "  Connected as $($context.Account)" -ForegroundColor Green
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

# ── Step 2: Validate the subdomain exists and is not already a root domain ────
Write-Section "Step 2: Validating subdomain '$SubdomainName'"

try {
    $domain = Get-MgDomain -DomainId $SubdomainName -ErrorAction Stop
}
catch {
    Write-Error "Domain '$SubdomainName' was not found in this tenant. $_"
    exit 1
}

Write-Host "  Domain found:" -ForegroundColor Green
Write-Host "    Name                : $($domain.Id)" -ForegroundColor Gray
Write-Host "    Authentication Type : $($domain.AuthenticationType)" -ForegroundColor Gray
Write-Host "    Is Root             : $($domain.IsRoot)" -ForegroundColor Gray
Write-Host "    Is Verified         : $($domain.IsVerified)" -ForegroundColor Gray
Write-Host "    Supported Services  : $($domain.SupportedServices -join ', ')" -ForegroundColor Gray

if ($domain.IsRoot) {
    Write-Host "`n  '$SubdomainName' is already a root domain. Nothing to do." -ForegroundColor Green
    exit 0
}

if (-not $domain.IsVerified) {
    Write-Error "'$SubdomainName' is not verified. A subdomain must be verified before it can be promoted."
    Write-Host "  Verify the parent root domain first — subdomains inherit verification automatically." -ForegroundColor Yellow
    exit 1
}

# ── Step 3: Check for user references on the subdomain ────────────────────────
Write-Section "Step 3: Checking for user references on '$SubdomainName'"

$usersOnSubdomain = @(Get-MgUser -All `
    -Filter "endsWith(userPrincipalName, '@$SubdomainName')" `
    -ConsistencyLevel eventual -CountVariable usersCount `
    -Property Id, DisplayName, UserPrincipalName, Mail `
    -ErrorAction SilentlyContinue)

Write-Host "  Users with UPN on @$SubdomainName : $($usersOnSubdomain.Count)" -ForegroundColor $(if ($usersOnSubdomain.Count -gt 0) { 'Yellow' } else { 'Green' })

if ($usersOnSubdomain.Count -gt 0) {
    foreach ($u in $usersOnSubdomain) {
        Write-Host "    - $($u.DisplayName) ($($u.UserPrincipalName))" -ForegroundColor Gray
    }
}

# Also check domain name references for any other object types
try {
    $domainRefs = @(Get-MgDomainNameReference -DomainId $SubdomainName -All -ErrorAction Stop)
    $nonUserRefs = @($domainRefs | Where-Object {
        $type = $_.AdditionalProperties.'@odata.type'
        $type -and $type -notlike '*user'
    })

    if ($nonUserRefs.Count -gt 0) {
        Write-Host "`n  [WARN] Non-user objects also reference this subdomain:" -ForegroundColor Yellow
        foreach ($ref in $nonUserRefs) {
            $type = ($ref.AdditionalProperties.'@odata.type' -split '\.')[-1]
            Write-Host "    - [$type] Object ID: $($ref.Id)" -ForegroundColor Gray
        }
        Write-Host "  These may also need to be addressed before or after promotion." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  [WARN] Could not query domain name references: $_" -ForegroundColor DarkYellow
}

# ── Step 4: Migrate users if needed ──────────────────────────────────────────
if ($usersOnSubdomain.Count -gt 0) {
    if (-not $MigrateUsers) {
        Write-Host ""
        Write-Error "The promote API requires NO user references on the subdomain."
        Write-Host "  Found $($usersOnSubdomain.Count) user(s) with UPN on @$SubdomainName." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Options:" -ForegroundColor White
        Write-Host "    1. Re-run with -MigrateUsers to temporarily move users to .onmicrosoft.com," -ForegroundColor Gray
        Write-Host "       promote the subdomain, then move them back." -ForegroundColor Gray
        Write-Host "    2. Manually change user UPNs to another domain before running this script." -ForegroundColor Gray
        exit 1
    }

    Write-Section "Step 4: Migrating users off '$SubdomainName'"

    # Determine fallback domain
    $allDomains     = Get-MgDomain -All
    $fallbackDomain = ($allDomains | Where-Object { $_.Id -like '*.onmicrosoft.com' -and $_.Id -notlike '*mail.onmicrosoft.com' } | Select-Object -First 1).Id

    if (-not $fallbackDomain) {
        Write-Error "Could not determine the fallback .onmicrosoft.com domain."
        exit 1
    }

    Write-Host "  Temporary fallback domain: $fallbackDomain" -ForegroundColor Gray
    Write-Host "  Users will be moved to @$fallbackDomain, then moved back after promotion." -ForegroundColor Gray
    Write-Host ""

    if (-not $Force) {
        $confirm = Read-Host "  Proceed with migrating $($usersOnSubdomain.Count) user(s)? [Y]es/[N]o"
        if ($confirm -notmatch '^(y|yes)$') {
            Write-Host "  Aborted." -ForegroundColor Yellow
            exit 0
        }
    }

    # Store original UPNs for rollback — persisted to disk as JSON
    $userMigrationMap  = @()
    $migrationErrors   = 0
    $migrationLogFile  = Join-Path $PSScriptRoot "MigrationMap_$($SubdomainName -replace '\.','_')_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"

    foreach ($user in $usersOnSubdomain) {
        $localPart  = ($user.UserPrincipalName -split '@')[0]
        $tempUpn    = "$localPart@$fallbackDomain"
        $originalUpn = $user.UserPrincipalName

        Write-Host "  Migrating: $originalUpn -> $tempUpn" -ForegroundColor Gray

        try {
            Update-MgUser -UserId $user.Id -UserPrincipalName $tempUpn -ErrorAction Stop
            Write-Host "    [OK]" -ForegroundColor Green

            $userMigrationMap += [PSCustomObject]@{
                UserId      = $user.Id
                OriginalUpn = $originalUpn
                TempUpn     = $tempUpn
                MigratedAt  = (Get-Date).ToString('o')
                Restored    = $false
            }

            # Save to disk after every successful migration so nothing is lost
            $userMigrationMap | ConvertTo-Json -Depth 3 | Set-Content -Path $migrationLogFile -Encoding UTF8
        }
        catch {
            Write-Host "    [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            $migrationErrors++
        }
    }

    Write-Host "`n  Migration map saved to: $migrationLogFile" -ForegroundColor Cyan

    if ($migrationErrors -gt 0) {
        Write-Host ""
        Write-Warning "$migrationErrors user(s) could not be migrated. The promote may fail."
        if (-not $Force) {
            $continueAnyway = Read-Host "  Continue with promotion anyway? [Y]es/[N]o"
            if ($continueAnyway -notmatch '^(y|yes)$') {
                # Rollback
                Write-Host "`n  Rolling back migrated users..." -ForegroundColor Yellow
                foreach ($entry in $userMigrationMap) {
                    try {
                        Update-MgUser -UserId $entry.UserId -UserPrincipalName $entry.OriginalUpn -ErrorAction Stop
                        Write-Host "    Restored: $($entry.OriginalUpn)" -ForegroundColor Green
                    }
                    catch {
                        Write-Host "    [ERROR] Could not restore $($entry.OriginalUpn): $_" -ForegroundColor Red
                    }
                }
                exit 1
            }
        }
    }

    Write-Host "`n  User migration complete. $($userMigrationMap.Count) user(s) moved." -ForegroundColor Green

    # Brief pause to allow directory replication
    Write-Host "  Waiting 30 seconds for directory replication..." -ForegroundColor Gray
    Start-Sleep -Seconds 30
}
else {
    Write-Host "`n  No users on this subdomain. Proceeding directly to promotion." -ForegroundColor Green
    $userMigrationMap = @()
}

# ── Step 5: Promote the subdomain to a root domain ───────────────────────────
Write-Section "Step 5: Promoting '$SubdomainName' to root domain"

if (-not $Force) {
    Write-Host "  This will promote '$SubdomainName' from a subdomain to an independent root domain." -ForegroundColor White
    Write-Host "  After promotion, this domain will no longer inherit authentication settings" -ForegroundColor White
    Write-Host "  from its parent domain." -ForegroundColor White
    Write-Host ""
    $confirm = Read-Host "  Proceed with promotion? [Y]es/[N]o"
    if ($confirm -notmatch '^(y|yes)$') {
        # Rollback users if they were migrated
        if ($userMigrationMap.Count -gt 0) {
            Write-Host "`n  Rolling back migrated users..." -ForegroundColor Yellow
            foreach ($entry in $userMigrationMap) {
                try {
                    Update-MgUser -UserId $entry.UserId -UserPrincipalName $entry.OriginalUpn -ErrorAction Stop
                    Write-Host "    Restored: $($entry.OriginalUpn)" -ForegroundColor Green
                }
                catch {
                    Write-Host "    [ERROR] Could not restore $($entry.OriginalUpn): $_" -ForegroundColor Red
                }
            }
        }
        Write-Host "  Aborted." -ForegroundColor Yellow
        exit 0
    }
}

Write-Host "  Calling promote API..." -ForegroundColor Gray

try {
    # The promote API is: POST /domains/{id}/promote
    $promoteUri = "https://graph.microsoft.com/v1.0/domains/$SubdomainName/promote"
    $result = Invoke-MgGraphRequest -Method POST -Uri $promoteUri -ErrorAction Stop

    if ($result.value -eq $true) {
        Write-Host "  [OK] '$SubdomainName' has been promoted to a root domain!" -ForegroundColor Green
    }
    else {
        Write-Host "  [WARN] Promote API returned: $($result | ConvertTo-Json -Compress)" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  [ERROR] Promote failed: $($_.Exception.Message)" -ForegroundColor Red

    # Rollback users
    if ($userMigrationMap.Count -gt 0) {
        Write-Host "`n  Rolling back migrated users..." -ForegroundColor Yellow
        foreach ($entry in $userMigrationMap) {
            try {
                Update-MgUser -UserId $entry.UserId -UserPrincipalName $entry.OriginalUpn -ErrorAction Stop
                Write-Host "    Restored: $($entry.OriginalUpn)" -ForegroundColor Green
            }
            catch {
                Write-Host "    [ERROR] Could not restore $($entry.OriginalUpn): $_" -ForegroundColor Red
            }
        }
    }
    exit 1
}

# ── Step 6: Verify the promotion ─────────────────────────────────────────────
Write-Section "Step 6: Verifying promotion"

# Brief pause for propagation
Start-Sleep -Seconds 5

try {
    $updatedDomain = Get-MgDomain -DomainId $SubdomainName -ErrorAction Stop
    Write-Host "  Domain: $($updatedDomain.Id)" -ForegroundColor Gray
    Write-Host "    Is Root             : $($updatedDomain.IsRoot)" -ForegroundColor $(if ($updatedDomain.IsRoot) { 'Green' } else { 'Yellow' })
    Write-Host "    Is Verified         : $($updatedDomain.IsVerified)" -ForegroundColor Gray
    Write-Host "    Authentication Type : $($updatedDomain.AuthenticationType)" -ForegroundColor Gray
    Write-Host "    Supported Services  : $($updatedDomain.SupportedServices -join ', ')" -ForegroundColor Gray

    if (-not $updatedDomain.IsRoot) {
        Write-Host "`n  [WARN] Domain does not yet show as root. This may take a few minutes to propagate." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  [WARN] Could not verify domain status: $_" -ForegroundColor DarkYellow
}

# ── Step 7: Move users back to the subdomain (now root) ──────────────────────
if ($userMigrationMap.Count -gt 0) {
    Write-Section "Step 7: Restoring users to '$SubdomainName'"

    Write-Host "  Waiting 15 seconds for promotion to propagate..." -ForegroundColor Gray
    Start-Sleep -Seconds 15

    $restoreErrors = 0
    foreach ($entry in $userMigrationMap) {
        Write-Host "  Restoring: $($entry.TempUpn) -> $($entry.OriginalUpn)" -ForegroundColor Gray

        try {
            Update-MgUser -UserId $entry.UserId -UserPrincipalName $entry.OriginalUpn -ErrorAction Stop
            Write-Host "    [OK]" -ForegroundColor Green
            $entry.Restored = $true
        }
        catch {
            Write-Host "    [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "    You may need to manually restore this user's UPN." -ForegroundColor DarkYellow
            $restoreErrors++
        }

        # Update the migration log on disk after each restore
        if ($migrationLogFile) {
            $userMigrationMap | ConvertTo-Json -Depth 3 | Set-Content -Path $migrationLogFile -Encoding UTF8
        }
    }

    if ($restoreErrors -gt 0) {
        Write-Host "`n  [WARN] $restoreErrors user(s) could not be restored. Manual intervention needed." -ForegroundColor Yellow
        Write-Host "  Review the migration map file for details:" -ForegroundColor Gray
        Write-Host "    $migrationLogFile" -ForegroundColor Cyan
        $userMigrationMap | Format-Table UserId, OriginalUpn, TempUpn, Restored -AutoSize
    }
    else {
        Write-Host "`n  All users restored successfully." -ForegroundColor Green
        Write-Host "  Migration map file retained at: $migrationLogFile" -ForegroundColor DarkGray
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Section "Summary"

Write-Host "  Domain '$SubdomainName' has been promoted to an independent root domain." -ForegroundColor Green
Write-Host ""
Write-Host "  What this means:" -ForegroundColor White
Write-Host "    - The domain no longer inherits authentication settings from its parent." -ForegroundColor Gray
Write-Host "    - It can be managed independently (Managed or Federated)." -ForegroundColor Gray
Write-Host "    - The parent domain can now be removed without affecting this domain." -ForegroundColor Gray
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor White
Write-Host "    1. Verify the domain status in the Entra admin center." -ForegroundColor Gray
Write-Host "    2. If needed, update the authentication type:" -ForegroundColor Gray
Write-Host "       Update-MgDomain -DomainId '$SubdomainName' -BodyParameter @{AuthenticationType='Managed'}" -ForegroundColor DarkGray
Write-Host "    3. You can now safely remove the parent domain if desired." -ForegroundColor Gray
Write-Host "       Run: .\Check-EntraDomainDependencies.ps1 -DomainName '<parentdomain>' -Remediate" -ForegroundColor DarkGray
Write-Host ""
