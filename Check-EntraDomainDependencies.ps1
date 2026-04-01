<#
.SYNOPSIS
    Validates dependencies in Microsoft Entra ID before removing a domain name.

.DESCRIPTION
    Checks for users, groups, applications, service principals, and other objects
    that reference the specified domain. All dependencies must be removed or migrated
    before a domain can be deleted from Entra ID.

    Use -Remediate to interactively clean up user UPNs, proxy addresses, and
    mail-enabled group references. You can choose to remediate all at once or
    review each object one by one.

.PARAMETER DomainName
    The domain name to check for dependencies (e.g., "contoso.com").

.PARAMETER Remediate
    When specified, prompts to remediate discovered user and group dependencies
    by updating UPNs, removing proxy addresses, and updating group mail addresses.

.EXAMPLE
    .\Check-EntraDomainDependencies.ps1 -DomainName "contoso.com"

.EXAMPLE
    .\Check-EntraDomainDependencies.ps1 -DomainName "contoso.com" -Remediate
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DomainName,

    [Parameter()]
    [switch]$Remediate
)

#Requires -Modules Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Applications, Microsoft.Graph.Identity.DirectoryManagement

# ── Helper ────────────────────────────────────────────────────────────────────
function Write-Section([string]$Title) {
    Write-Host "`n$('=' * 70)" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "$('=' * 70)" -ForegroundColor Cyan
}

function Write-DependencyResult([string]$Label, [int]$Count, [array]$Items, [string]$Property) {
    if ($Count -gt 0) {
        Write-Host "  [!] $Label : $Count found" -ForegroundColor Yellow
        $Items | Select-Object -First 10 | ForEach-Object {
            Write-Host "      - $($_.$Property)" -ForegroundColor Gray
        }
        if ($Count -gt 10) {
            Write-Host "      ... and $($Count - 10) more" -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host "  [OK] $Label : None found" -ForegroundColor Green
    }
}

# ── Connect to Microsoft Graph ────────────────────────────────────────────────
Write-Section "Connecting to Microsoft Graph"

$requiredScopes = @(
    "User.Read.All",
    "Group.Read.All",
    "Application.Read.All",
    "Domain.Read.All",
    "Directory.Read.All"
)

# Add write scopes when remediation is requested
if ($Remediate) {
    $requiredScopes += @(
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
        "Application.ReadWrite.All"
    )
}

try {
    # Always disconnect first to ensure a clean session with all required scopes
    $context = Get-MgContext
    if ($context) {
        Write-Host "  Existing session found for $($context.Account). Disconnecting to ensure proper scopes..." -ForegroundColor Gray
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }

    Write-Host "  Connecting to Microsoft Graph (you will be prompted once to sign in)..." -ForegroundColor Gray
    $null = Connect-MgGraph -Scopes $requiredScopes -ErrorAction Stop

    $context = Get-MgContext
    Write-Host "  Connected as $($context.Account)" -ForegroundColor Green
    Write-Host "  Granted scopes: $($context.Scopes -join ', ')" -ForegroundColor DarkGray

    # Verify all required scopes were granted
    $grantedScopes = $context.Scopes | ForEach-Object { $_.ToLower() }
    $missingScopes = $requiredScopes | Where-Object { $_.ToLower() -notin $grantedScopes }
    if ($missingScopes) {
        Write-Warning "The following scopes were not granted: $($missingScopes -join ', ')"
        Write-Host "  TIP: Ask a Global Admin to grant admin consent for the 'Microsoft Graph Command Line Tools'" -ForegroundColor Yellow
        Write-Host "       enterprise application in Entra ID > Enterprise apps > Permissions.`n" -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

# ── Verify the domain exists ─────────────────────────────────────────────────
Write-Section "Verifying domain: $DomainName"

try {
    $domain = Get-MgDomain -DomainId $DomainName -ErrorAction Stop
    Write-Host "  Domain found." -ForegroundColor Green
    Write-Host "  Authentication Type : $($domain.AuthenticationType)" -ForegroundColor Gray
    Write-Host "  Is Default          : $($domain.IsDefault)" -ForegroundColor Gray
    Write-Host "  Is Verified         : $($domain.IsVerified)" -ForegroundColor Gray

    if ($domain.IsDefault) {
        Write-Host "`n  [BLOCK] This is the DEFAULT domain. You cannot remove the default domain." -ForegroundColor Red
        Write-Host "  Change the default domain first, then re-run this script." -ForegroundColor Red
    }
}
catch {
    Write-Error "Domain '$DomainName' was not found in this tenant. $_"
    exit 1
}

# ── Track totals ──────────────────────────────────────────────────────────────
$totalDependencies = 0

# ── 1. Users with UPN or proxy addresses using the domain ────────────────────
Write-Section "1. Users (UPN or Mail)"

$users = Get-MgUser -All -Filter "endsWith(userPrincipalName, '@$DomainName')" `
    -ConsistencyLevel eventual -CountVariable usersCount `
    -Property Id, DisplayName, UserPrincipalName, Mail, AccountEnabled `
    -ErrorAction SilentlyContinue

$upnUsers = @($users)
Write-DependencyResult "Users with UPN @$DomainName" $upnUsers.Count $upnUsers "UserPrincipalName"
$totalDependencies += $upnUsers.Count

# Also check mail / proxy addresses
$mailUsers = Get-MgUser -All -Filter "endsWith(mail, '@$DomainName')" `
    -ConsistencyLevel eventual -CountVariable mailUsersCount `
    -Property Id, DisplayName, UserPrincipalName, Mail `
    -ErrorAction SilentlyContinue

$mailOnlyUsers = @($mailUsers | Where-Object { $_.UserPrincipalName -notlike "*@$DomainName" })
Write-DependencyResult "Users with Mail (not UPN) @$DomainName" $mailOnlyUsers.Count $mailOnlyUsers "Mail"
$totalDependencies += $mailOnlyUsers.Count

# ── 2. Groups ─────────────────────────────────────────────────────────────────
Write-Section "2. Groups (Mail / Mail-enabled)"

$groups = Get-MgGroup -All -Filter "endsWith(mail, '@$DomainName')" `
    -ConsistencyLevel eventual -CountVariable groupsCount `
    -Property Id, DisplayName, Mail, GroupTypes `
    -ErrorAction SilentlyContinue

$groupList = @($groups)
Write-DependencyResult "Groups with mail @$DomainName" $groupList.Count $groupList "DisplayName"
$totalDependencies += $groupList.Count

# ── 3. Applications (identifierUris, web redirectUris) ───────────────────────
Write-Section "3. Application Registrations"

$allApps = Get-MgApplication -All -Property Id, DisplayName, IdentifierUris, Web `
    -ErrorAction SilentlyContinue

$appsWithDomain = @($allApps | Where-Object {
        ($_.IdentifierUris -join ';') -match [regex]::Escape($DomainName) -or
        ($_.Web.RedirectUris -join ';') -match [regex]::Escape($DomainName)
    })

Write-DependencyResult "Applications referencing $DomainName" $appsWithDomain.Count $appsWithDomain "DisplayName"
$totalDependencies += $appsWithDomain.Count

# ── 4. Service Principals ────────────────────────────────────────────────────
Write-Section "4. Service Principals"

$allSPs = Get-MgServicePrincipal -All `
    -Property Id, DisplayName, ServicePrincipalNames `
    -ErrorAction SilentlyContinue

$spsWithDomain = @($allSPs | Where-Object {
        ($_.ServicePrincipalNames -join ';') -match [regex]::Escape($DomainName)
    })

Write-DependencyResult "Service Principals referencing $DomainName" $spsWithDomain.Count $spsWithDomain "DisplayName"
$totalDependencies += $spsWithDomain.Count

# ── 5. Devices ────────────────────────────────────────────────────────────────
Write-Section "5. Devices"

try {
    $devices = Get-MgDevice -All -Property Id, DisplayName, OperatingSystem `
        -ErrorAction SilentlyContinue

    # Devices don't directly reference domains, but registered owners might
    # We'll flag this as informational
    Write-Host "  [INFO] $(@($devices).Count) devices total. Review device owners manually if needed." -ForegroundColor DarkGray
}
catch {
    Write-Host "  [WARN] Could not enumerate devices: $_" -ForegroundColor DarkYellow
}

# ── 6. Domain Name References (catch-all via Directory Objects) ──────────────
Write-Section "6. Domain Name References (via Get-MgDomainNameReference)"

try {
    $domainRefs = Get-MgDomainNameReference -DomainId $DomainName -All -ErrorAction Stop

    $domainRefList = @($domainRefs)

    if ($domainRefList.Count -gt 0) {
        Write-Host "  [!] Total domain name references: $($domainRefList.Count)" -ForegroundColor Yellow
        Write-Host ""

        # Ensure these are counted — deduplicate against objects already found in steps 1-4
        # by collecting IDs already counted
        $alreadyCounted = @()
        if ($upnUsers)        { $alreadyCounted += $upnUsers.Id }
        if ($mailOnlyUsers)   { $alreadyCounted += $mailOnlyUsers.Id }
        if ($groupList)       { $alreadyCounted += $groupList.Id }
        if ($appsWithDomain)  { $alreadyCounted += $appsWithDomain.Id }
        if ($spsWithDomain)   { $alreadyCounted += $spsWithDomain.Id }

        $newRefs = @($domainRefList | Where-Object { $_.Id -notin $alreadyCounted })
        $totalDependencies += $newRefs.Count

        foreach ($ref in $domainRefList) {
            # Determine the object type from AdditionalProperties or by resolving it
            $odataType = $ref.AdditionalProperties.'@odata.type'
            $objectId  = $ref.Id

            # Resolve object type name for display
            $typeFriendly = switch -Wildcard ($odataType) {
                '*user'             { 'User' }
                '*group'            { 'Group' }
                '*application'      { 'Application' }
                '*servicePrincipal' { 'Service Principal' }
                '*device'           { 'Device' }
                '*contact'          { 'Contact' }
                default             { $null }
            }

            # If @odata.type was empty, try to look up the directory object directly
            if (-not $typeFriendly) {
                try {
                    $dirObj = Get-MgDirectoryObject -DirectoryObjectId $objectId -ErrorAction Stop
                    $odataType = $dirObj.AdditionalProperties.'@odata.type'
                    $typeFriendly = switch -Wildcard ($odataType) {
                        '*user'             { 'User' }
                        '*group'            { 'Group' }
                        '*application'      { 'Application' }
                        '*servicePrincipal' { 'Service Principal' }
                        '*device'           { 'Device' }
                        '*contact'          { 'Contact' }
                        default             { $odataType ?? 'Unknown' }
                    }
                }
                catch {
                    $typeFriendly = 'Unknown'
                }
            }

            # Now fetch details based on type
            $displayName = $null
            $detail      = $null

            try {
                switch ($typeFriendly) {
                    'User' {
                        $user = Get-MgUser -UserId $objectId `
                            -Property Id, DisplayName, UserPrincipalName, Mail, ProxyAddresses, `
                                      OtherMails, OnPremisesUserPrincipalName, ImAddresses `
                            -ErrorAction Stop
                        $displayName = $user.DisplayName

                        # Find which properties actually reference the domain (including subdomains)
                        $domainPattern = [regex]::Escape($DomainName)
                        $matchingProps = @()

                        if ($user.UserPrincipalName -match $domainPattern) {
                            $matchingProps += "UPN: $($user.UserPrincipalName)"
                        }
                        if ($user.Mail -match $domainPattern) {
                            $matchingProps += "Mail: $($user.Mail)"
                        }
                        $matchingProxies = @($user.ProxyAddresses | Where-Object { $_ -match $domainPattern })
                        if ($matchingProxies) {
                            $matchingProps += "ProxyAddresses: $($matchingProxies -join ', ')"
                        }
                        $matchingOtherMails = @($user.OtherMails | Where-Object { $_ -match $domainPattern })
                        if ($matchingOtherMails) {
                            $matchingProps += "OtherMails: $($matchingOtherMails -join ', ')"
                        }
                        if ($user.OnPremisesUserPrincipalName -match $domainPattern) {
                            $matchingProps += "OnPremUPN: $($user.OnPremisesUserPrincipalName)"
                        }
                        $matchingIm = @($user.ImAddresses | Where-Object { $_ -match $domainPattern })
                        if ($matchingIm) {
                            $matchingProps += "ImAddresses: $($matchingIm -join ', ')"
                        }

                        if ($matchingProps.Count -gt 0) {
                            $detail = $matchingProps -join "`n      "
                        }
                        else {
                            # Show all values so the user can investigate
                            $detail = "UPN: $($user.UserPrincipalName)  |  Mail: $($user.Mail)"
                            if ($user.ProxyAddresses) {
                                $detail += "`n      ProxyAddresses: $($user.ProxyAddresses -join ', ')"
                            }
                            if ($user.OtherMails) {
                                $detail += "`n      OtherMails: $($user.OtherMails -join ', ')"
                            }
                            if ($user.ImAddresses) {
                                $detail += "`n      ImAddresses: $($user.ImAddresses -join ', ')"
                            }
                            $detail += "`n      (No obvious match — check Exchange Online for additional proxy addresses)"
                        }
                    }
                    'Group' {
                        $grp = Get-MgGroup -GroupId $objectId -Property Id, DisplayName, Mail, GroupTypes -ErrorAction Stop
                        $displayName = $grp.DisplayName
                        $detail      = "Mail: $($grp.Mail)  |  Types: $($grp.GroupTypes -join ', ')"
                    }
                    'Application' {
                        $app = Get-MgApplication -ApplicationId $objectId -Property Id, DisplayName, IdentifierUris -ErrorAction Stop
                        $displayName = $app.DisplayName
                        $detail      = "IdentifierUris: $($app.IdentifierUris -join ', ')"
                    }
                    'Service Principal' {
                        $sp = Get-MgServicePrincipal -ServicePrincipalId $objectId -Property Id, DisplayName, ServicePrincipalNames -ErrorAction Stop
                        $displayName = $sp.DisplayName
                        $detail      = "SPNs: $($sp.ServicePrincipalNames -join ', ')"
                    }
                    'Contact' {
                        $contact = Get-MgContact -OrgContactId $objectId -Property Id, DisplayName, Mail -ErrorAction Stop
                        $displayName = $contact.DisplayName
                        $detail      = "Mail: $($contact.Mail)"
                    }
                    default {
                        $dirObj = Get-MgDirectoryObject -DirectoryObjectId $objectId -ErrorAction Stop
                        $displayName = $dirObj.AdditionalProperties.displayName
                        $detail      = "Additional properties: $($dirObj.AdditionalProperties.Keys -join ', ')"
                    }
                }
            }
            catch {
                $displayName = '(could not resolve)'
                $detail      = $_.Exception.Message
            }

            Write-Host "  [$typeFriendly] $displayName" -ForegroundColor Yellow
            Write-Host "      Object ID : $objectId" -ForegroundColor Gray
            Write-Host "      $detail" -ForegroundColor Gray
            Write-Host ""
        }

        # Summary by type
        Write-Host "  --- Breakdown by type ---" -ForegroundColor Cyan
        $domainRefList | ForEach-Object {
            $t = $_.AdditionalProperties.'@odata.type'
            if (-not $t) {
                try {
                    $d = Get-MgDirectoryObject -DirectoryObjectId $_.Id -ErrorAction SilentlyContinue
                    $t = $d.AdditionalProperties.'@odata.type'
                } catch { $t = 'Unknown' }
            }
            [PSCustomObject]@{ Type = $t }
        } | Group-Object Type | ForEach-Object {
            $friendlyName = ($_.Name -split '\.')[-1]
            if (-not $friendlyName) { $friendlyName = 'Unknown' }
            Write-Host "      $friendlyName : $($_.Count)" -ForegroundColor Gray
        }
    }
    else {
        Write-Host "  [OK] No domain name references found." -ForegroundColor Green
    }
}
catch {
    Write-Host "  [WARN] Could not query domain name references: $_" -ForegroundColor DarkYellow
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Section "Summary for domain: $DomainName"

if ($domain.IsDefault) {
    Write-Host "`n  RESULT: BLOCKED - This is the default domain." -ForegroundColor Red
    Write-Host "  You must change the default domain before removal.`n" -ForegroundColor Red
}
elseif ($totalDependencies -gt 0) {
    Write-Host "`n  RESULT: $totalDependencies dependency/dependencies found." -ForegroundColor Yellow
    Write-Host "  You must remove or migrate all dependencies before you can delete this domain." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Recommended actions:" -ForegroundColor White
    Write-Host "    1. Change UPNs of users to a different domain" -ForegroundColor Gray
    Write-Host "    2. Update or remove mail-enabled groups using this domain" -ForegroundColor Gray
    Write-Host "    3. Update Application registration URIs" -ForegroundColor Gray
    Write-Host "    4. Update Service Principal names" -ForegroundColor Gray
    Write-Host "    5. Re-run this script to verify all dependencies are cleared" -ForegroundColor Gray
    if (-not $Remediate) {
        Write-Host "`n  TIP: Re-run with -Remediate to interactively clean up dependencies.`n" -ForegroundColor Cyan
    }
}
else {
    Write-Host "`n  RESULT: No dependencies found. Domain '$DomainName' appears safe to remove." -ForegroundColor Green
    Write-Host "  You can proceed with: Remove-MgDomain -DomainId '$DomainName'`n" -ForegroundColor Green
}

# ── Remediation ───────────────────────────────────────────────────────────────
if ($Remediate -and $totalDependencies -gt 0 -and -not $domain.IsDefault) {

    Write-Section "Remediation"

    # Determine the fallback domain (initial .onmicrosoft.com domain)
    $allDomains   = Get-MgDomain -All
    $fallbackDomain = ($allDomains | Where-Object { $_.Id -like '*.onmicrosoft.com' -and $_.Id -notlike '*mail.onmicrosoft.com' } | Select-Object -First 1).Id

    if (-not $fallbackDomain) {
        Write-Error "Could not determine the fallback .onmicrosoft.com domain. Aborting remediation."
        exit 1
    }

    Write-Host "  Fallback domain for UPN migration: $fallbackDomain" -ForegroundColor Gray
    Write-Host ""

    # ── Connect to Exchange Online for proxy address management ───────────────
    Write-Host "  Connecting to Exchange Online (required to manage proxy addresses)..." -ForegroundColor Gray
    try {
        $exoSession = Get-ConnectionInformation -ErrorAction SilentlyContinue
        if (-not $exoSession) {
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
        else {
            Write-Host "  Already connected to Exchange Online." -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Could not connect to Exchange Online: $_"
        Write-Host "  Proxy address removal requires Exchange Online. Install with:" -ForegroundColor Yellow
        Write-Host "    Install-Module ExchangeOnlineManagement -Scope CurrentUser" -ForegroundColor Gray
        Write-Host "  UPN changes will still be attempted via Microsoft Graph.`n" -ForegroundColor Yellow
    }
    $exoConnected = $null -ne (Get-ConnectionInformation -ErrorAction SilentlyContinue)

    # ── Prompt for remediation mode ───────────────────────────────────────────
    Write-Host "  How would you like to remediate?" -ForegroundColor White
    Write-Host "    [A] Remediate ALL dependencies (prompt once to confirm)" -ForegroundColor Gray
    Write-Host "    [O] Review ONE by ONE (prompt for each object)" -ForegroundColor Gray
    Write-Host "    [C] Cancel remediation" -ForegroundColor Gray
    Write-Host ""

    $mode = $null
    while ($mode -notin @('A', 'O', 'C')) {
        $mode = (Read-Host "  Select [A]ll, [O]ne-by-one, or [C]ancel").ToUpper()
    }

    if ($mode -eq 'C') {
        Write-Host "`n  Remediation cancelled.`n" -ForegroundColor Yellow
        exit 0
    }

    if ($mode -eq 'A') {
        Write-Host ""
        $confirm = Read-Host "  Are you sure you want to remediate ALL dependencies? This will modify user UPNs, remove proxy addresses, and update groups. (yes/no)"
        if ($confirm -ne 'yes') {
            Write-Host "`n  Remediation cancelled.`n" -ForegroundColor Yellow
            exit 0
        }
    }

    # Match ONLY the exact domain, not subdomains
    # e.g., @dougcopilot.us but NOT @osm.dougcopilot.us
    $domainPatternExact = '(?<![.\w])' + [regex]::Escape($DomainName) + '$'
    # For display/detection in step 6 we still use the broad pattern (includes subdomains)
    $domainPatternBroad = [regex]::Escape($DomainName)
    $remediatedCount = 0
    $skippedCount    = 0
    $errorCount      = 0

    # ── Helper: Prompt for individual object ──────────────────────────────────
    function Confirm-Remediation([string]$ObjectDescription) {
        if ($mode -eq 'A') { return $true }
        # One-by-one mode
        Write-Host ""
        $answer = Read-Host "  Remediate '$ObjectDescription'? [Y]es / [N]o / [A]ll remaining / [C]ancel"
        switch ($answer.ToUpper()) {
            'Y' { return $true }
            'N' { return $false }
            'A' { $script:mode = 'A'; return $true }
            'C' { $script:mode = 'C'; return $false }
            default { return $false }
        }
    }

    # ── Remediate Users ───────────────────────────────────────────────────────
    Write-Section "Remediating Users"

    # Get all users that reference this domain (including subdomains)
    $refUsers = @()
    if ($domainRefList) {
        foreach ($ref in $domainRefList) {
            $odataType = $ref.AdditionalProperties.'@odata.type'
            if (-not $odataType) {
                try {
                    $d = Get-MgDirectoryObject -DirectoryObjectId $ref.Id -ErrorAction SilentlyContinue
                    $odataType = $d.AdditionalProperties.'@odata.type'
                } catch {}
            }
            if ($odataType -like '*user') {
                try {
                    $u = Get-MgUser -UserId $ref.Id `
                        -Property Id, DisplayName, UserPrincipalName, Mail, ProxyAddresses, OtherMails, ImAddresses `
                        -ErrorAction Stop
                    $refUsers += $u
                } catch {}
            }
        }
    }

    foreach ($user in $refUsers) {
        if ($script:mode -eq 'C') { break }

        $changes = @()

        # 1. Check UPN — exact domain only
        $needsUpnChange = $user.UserPrincipalName -match $domainPatternExact
        if ($needsUpnChange) {
            $localPart = ($user.UserPrincipalName -split '@')[0]
            $newUpn    = "$localPart@$fallbackDomain"
            $changes  += "UPN: $($user.UserPrincipalName) -> $newUpn"
        }

        # 2. Check ProxyAddresses — exact domain only (preserve subdomains)
        $proxyToRemove = @($user.ProxyAddresses | Where-Object { $_ -match $domainPatternExact })
        if ($proxyToRemove) {
            $changes += "Remove ProxyAddresses: $($proxyToRemove -join ', ')"
        }
        # Show subdomain proxies that will be KEPT for transparency
        $proxyKept = @($user.ProxyAddresses | Where-Object { $_ -match $domainPatternBroad -and $_ -notmatch $domainPatternExact })
        if ($proxyKept) {
            $changes += "KEEP (subdomain): $($proxyKept -join ', ')"
        }

        # 3. Check OtherMails — exact domain only
        $otherMailsToRemove = @($user.OtherMails | Where-Object { $_ -match $domainPatternExact })
        if ($otherMailsToRemove) {
            $changes += "Remove OtherMails: $($otherMailsToRemove -join ', ')"
        }

        if (($changes | Where-Object { $_ -notlike 'KEEP*' }).Count -eq 0) { continue }

        Write-Host "`n  User: $($user.DisplayName) ($($user.UserPrincipalName))" -ForegroundColor Yellow
        foreach ($c in $changes) {
            Write-Host "    -> $c" -ForegroundColor Gray
        }

        if (-not (Confirm-Remediation "$($user.DisplayName)")) {
            $skippedCount++
            Write-Host "    SKIPPED" -ForegroundColor DarkGray
            continue
        }

        try {
            # Update UPN via Microsoft Graph
            if ($needsUpnChange) {
                Update-MgUser -UserId $user.Id -UserPrincipalName $newUpn -ErrorAction Stop
                Write-Host "    [OK] UPN changed to $newUpn" -ForegroundColor Green
            }

            # Remove proxy addresses via Exchange Online
            if ($proxyToRemove) {
                if ($exoConnected) {
                    # Build a list of identities to try (UPN, Mail, ObjectId)
                    $identitiesToTry = @()
                    if ($user.UserPrincipalName) { $identitiesToTry += $user.UserPrincipalName }
                    if ($user.Mail -and $user.Mail -ne $user.UserPrincipalName) { $identitiesToTry += $user.Mail }
                    $identitiesToTry += $user.Id

                    $proxyRemoved = $false
                    foreach ($identity in $identitiesToTry) {
                        if ($proxyRemoved) { break }

                        # Try Set-Mailbox
                        try {
                            Set-Mailbox -Identity $identity -EmailAddresses @{Remove = $proxyToRemove } -ErrorAction Stop
                            Write-Host "    [OK] Removed $($proxyToRemove.Count) proxy address(es) via Set-Mailbox ($identity)" -ForegroundColor Green
                            $proxyRemoved = $true
                        } catch {}

                        if ($proxyRemoved) { break }

                        # Try Set-MailUser (for users without an Exchange mailbox)
                        try {
                            Set-MailUser -Identity $identity -EmailAddresses @{Remove = $proxyToRemove } -ErrorAction Stop
                            Write-Host "    [OK] Removed $($proxyToRemove.Count) proxy address(es) via Set-MailUser ($identity)" -ForegroundColor Green
                            $proxyRemoved = $true
                        } catch {}
                    }

                    if (-not $proxyRemoved) {
                        # Last resort: try Remove-MgUser proxy via Graph PATCH on the directory object
                        Write-Host "    [WARN] Exchange Online could not find this user as a Mailbox or MailUser." -ForegroundColor DarkYellow
                        Write-Host "    This user may not be mail-enabled. Attempting removal via Microsoft Graph..." -ForegroundColor DarkYellow
                        try {
                            $bodyParams = @{
                                '@odata.type'  = '#microsoft.graph.user'
                                proxyAddresses = @($user.ProxyAddresses | Where-Object { $_ -notmatch $domainPatternExact })
                            }
                            Update-MgUser -UserId $user.Id -BodyParameter $bodyParams -ErrorAction Stop
                            Write-Host "    [OK] Removed proxy address(es) via Microsoft Graph" -ForegroundColor Green
                            $proxyRemoved = $true
                        }
                        catch {
                            Write-Host "    [ERROR] Could not remove proxy addresses by any method." -ForegroundColor Red
                            Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
                            Write-Host "    TIP: Check if this user is synced from on-premises AD (proxy addresses must be changed there)." -ForegroundColor DarkYellow
                            $errorCount++
                        }
                    }
                }
                else {
                    Write-Host "    [SKIP] Cannot remove proxy addresses — Exchange Online not connected." -ForegroundColor DarkYellow
                    Write-Host "    TIP: Set-Mailbox -Identity '$($user.UserPrincipalName)' -EmailAddresses @{Remove='$($proxyToRemove -join "','")' }" -ForegroundColor DarkGray
                }
            }

            # Remove OtherMails via Microsoft Graph (this property IS writable)
            if ($otherMailsToRemove) {
                $currentUser       = Get-MgUser -UserId $user.Id -Property OtherMails -ErrorAction Stop
                $updatedOtherMails = @($currentUser.OtherMails | Where-Object { $_ -notmatch $domainPatternExact })
                Update-MgUser -UserId $user.Id -OtherMails $updatedOtherMails -ErrorAction Stop
                Write-Host "    [OK] Removed $($otherMailsToRemove.Count) OtherMails entry/entries" -ForegroundColor Green
            }

            $remediatedCount++
        }
        catch {
            Write-Host "    [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            $errorCount++
        }
    }

    # ── Remediate Groups ──────────────────────────────────────────────────────
    if ($script:mode -ne 'C' -and $groupList.Count -gt 0) {
        Write-Section "Remediating Groups"

        foreach ($grp in $groupList) {
            if ($script:mode -eq 'C') { break }

            Write-Host "`n  Group: $($grp.DisplayName) (Mail: $($grp.Mail))" -ForegroundColor Yellow
            Write-Host "    -> This group's mail address uses the domain." -ForegroundColor Gray
            Write-Host "    NOTE: Mail-enabled groups managed by Exchange must be updated in Exchange Admin Center." -ForegroundColor DarkYellow

            if (-not (Confirm-Remediation "$($grp.DisplayName)")) {
                $skippedCount++
                Write-Host "    SKIPPED" -ForegroundColor DarkGray
                continue
            }

            try {
                $fullGroup = Get-MgGroup -GroupId $grp.Id -Property Id, DisplayName, ProxyAddresses, GroupTypes -ErrorAction Stop
                $proxyToRemove = @($fullGroup.ProxyAddresses | Where-Object { $_ -match $domainPatternExact })

                if ($proxyToRemove -and $exoConnected) {
                    # Try Distribution Group first, then Mail-Enabled Security Group, then Unified Group (M365)
                    $groupRemediated = $false
                    $isUnifiedGroup  = $fullGroup.GroupTypes -contains 'Unified'

                    if ($isUnifiedGroup) {
                        try {
                            Set-UnifiedGroup -Identity $grp.Id -EmailAddresses @{Remove = $proxyToRemove } -ErrorAction Stop
                            $groupRemediated = $true
                        } catch {}
                    }

                    if (-not $groupRemediated) {
                        try {
                            Set-DistributionGroup -Identity $grp.Id -EmailAddresses @{Remove = $proxyToRemove } -ErrorAction Stop
                            $groupRemediated = $true
                        } catch {}
                    }

                    if ($groupRemediated) {
                        Write-Host "    [OK] Removed $($proxyToRemove.Count) proxy address(es) from group via Exchange Online" -ForegroundColor Green
                        $remediatedCount++
                    }
                    else {
                        Write-Host "    [ERROR] Could not update group via Exchange Online." -ForegroundColor Red
                        Write-Host "    TIP: Try manually in Exchange Admin Center." -ForegroundColor DarkYellow
                        $errorCount++
                    }
                }
                elseif ($proxyToRemove -and -not $exoConnected) {
                    Write-Host "    [SKIP] Cannot remove proxy addresses — Exchange Online not connected." -ForegroundColor DarkYellow
                    $skippedCount++
                }
                else {
                    Write-Host "    [OK] No proxy addresses to remove." -ForegroundColor Green
                }
            }
            catch {
                Write-Host "    [ERROR] $($_.Exception.Message)" -ForegroundColor Red
                $errorCount++
            }
        }
    }

    # ── Remediate Applications ────────────────────────────────────────────────
    if ($script:mode -ne 'C' -and $appsWithDomain.Count -gt 0) {
        Write-Section "Remediating Applications"

        foreach ($app in $appsWithDomain) {
            if ($script:mode -eq 'C') { break }

            $matchingUris = @($app.IdentifierUris | Where-Object { $_ -match $domainPatternExact })
            $matchingRedirects = @()
            if ($app.Web.RedirectUris) {
                $matchingRedirects = @($app.Web.RedirectUris | Where-Object { $_ -match $domainPatternExact })
            }

            Write-Host "`n  Application: $($app.DisplayName)" -ForegroundColor Yellow
            if ($matchingUris)      { Write-Host "    IdentifierUris: $($matchingUris -join ', ')" -ForegroundColor Gray }
            if ($matchingRedirects) { Write-Host "    RedirectUris:   $($matchingRedirects -join ', ')" -ForegroundColor Gray }
            Write-Host "    NOTE: Application URIs require manual review — automated removal may break functionality." -ForegroundColor DarkYellow

            if (-not (Confirm-Remediation "$($app.DisplayName)")) {
                $skippedCount++
                Write-Host "    SKIPPED" -ForegroundColor DarkGray
                continue
            }

            try {
                # Remove matching IdentifierUris
                if ($matchingUris) {
                    $updatedUris = @($app.IdentifierUris | Where-Object { $_ -notmatch $domainPatternExact })
                    Update-MgApplication -ApplicationId $app.Id -IdentifierUris $updatedUris -ErrorAction Stop
                    Write-Host "    [OK] Removed $($matchingUris.Count) IdentifierUri(s)" -ForegroundColor Green
                }

                # Remove matching RedirectUris
                if ($matchingRedirects) {
                    $updatedRedirects = @($app.Web.RedirectUris | Where-Object { $_ -notmatch $domainPatternExact })
                    $webSettings = @{ RedirectUris = $updatedRedirects }
                    Update-MgApplication -ApplicationId $app.Id -Web $webSettings -ErrorAction Stop
                    Write-Host "    [OK] Removed $($matchingRedirects.Count) RedirectUri(s)" -ForegroundColor Green
                }

                $remediatedCount++
            }
            catch {
                Write-Host "    [ERROR] $($_.Exception.Message)" -ForegroundColor Red
                $errorCount++
            }
        }
    }

    # ── Remediation Summary ───────────────────────────────────────────────────
    Write-Section "Remediation Summary"
    Write-Host "  Remediated : $remediatedCount" -ForegroundColor Green
    Write-Host "  Skipped    : $skippedCount" -ForegroundColor DarkGray
    Write-Host "  Errors     : $errorCount" -ForegroundColor $(if ($errorCount -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""

    if ($errorCount -gt 0) {
        Write-Host "  Some remediations failed. Review errors above and fix manually." -ForegroundColor Yellow
        Write-Host "  For Exchange-managed objects, use Exchange Online PowerShell or the Exchange Admin Center." -ForegroundColor Gray
    }

    Write-Host "  Re-run this script without -Remediate to verify all dependencies are cleared.`n" -ForegroundColor Cyan
}
