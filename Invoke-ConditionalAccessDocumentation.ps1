<#PSScriptInfo

.DESCRIPTION
    This script documents Microsoft Entra Conditional Access Policies.

.SYNOPSIS
    This script retrieves all Conditional Access Policies and translates Microsoft Entra Object IDs to display names for users, groups, directory roles, locations...

.EXAMPLE
    Connect-MgGraph -Scopes "Application.Read.All", "Group.Read.All", "Policy.Read.All", "RoleManagement.Read.Directory", "User.Read.All"
    & .\Invoke-ConditionalAccessDocumentation.ps1
    Generates the documentation and exports the csv to the script directory.
.NOTES
    Author:           Nicola Suter
    Creation Date:    31.01.2022
    Updated:          24.11.2025

.VERSION 1.9.0

.GUID 6c861af7-d12e-4ea2-b5dc-56fee16e0107

.AUTHOR Nicola Suter

.TAGS ConditionalAccess, AzureAD, Identity

.PROJECTURI https://github.com/nicolonsky/ConditionalAccessDocumentation

.ICONURI https://raw.githubusercontent.com/microsoftgraph/g-raph/master/g-raph.png
#>

#Requires -Module @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.29.1' }

function Test-Guid {
    <#
    .SYNOPSIS
    Validates a given input string and checks string is a valid GUID
    .DESCRIPTION
    Validates a given input string and checks string is a valid GUID by using the .NET method Guid.TryParse
    .EXAMPLE
    Test-Guid -InputObject "3363e9e1-00d8-45a1-9c0c-b93ee03f8c13"
    .NOTES
    Uses .NET method [guid]::TryParse()
    #>
    [Cmdletbinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyString()]
        [string]$InputObject
    )
    process {
        return [guid]::TryParse($InputObject, $([ref][guid]::Empty))
    }
}

function Resolve-MgObject {
    <#
    .SYNOPSIS
    Resolve a Microsoft Graph item to display name
    .DESCRIPTION
    Resolves a Microsoft Graph Directory Object to a Display Name when possible
    .EXAMPLE

    .NOTES

    #>
    [Cmdletbinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyString()]
        [string]$InputObject
    )
    process {
        if (Test-Guid -InputObject $InputObject) {
            try {
                # use hashtable as cache to limit API calls
                if ($displayNameCache.ContainsKey($InputObject)) {
                    Write-Debug "Cached display name for `"$InputObject`""
                    return $displayNameCache[$InputObject]
                } else {
                    $directoryObject = Invoke-MgGraphRequest -Uri ('beta/directoryObjects/{0}?$select=displayName' -f $InputObject) -Method GET -OutputType PSObject -ErrorAction Stop
                    $displayName = $directoryObject.displayName
                    $displayNameCache[$InputObject] = $displayName
                    return $displayName
                }
            } catch {
                Write-Warning "Unable to resolve directory object with ID $InputObject, might have been deleted!"
            }
        }
        return $InputObject
    }
}

# Add GetOrDefault to hashtables
$etd = @{
    TypeName   = 'System.Collections.Hashtable'
    MemberType = 'Scriptmethod'
    MemberName = 'GetOrDefault'
    Value      = {
        param(
            $key,
            $defaultValue
        )

        if (-not [string]::IsNullOrEmpty($key)) {
            if ($this.ContainsKey($key)) {
                if ($this[$key].DisplayName) {
                    return $this[$key].DisplayName
                } else {
                    return $this[$key]
                }
            } else {
                return $defaultValue
            } 
        }
    }
}
Update-TypeData @etd -Force

Write-Progress -PercentComplete -1 -Activity 'Fetching conditional access policies and related data from Graph API'

# Get Conditional Access Policies
$conditionalAccessPolicies = Invoke-MgGraphRequest -Uri 'beta/identity/conditionalAccess/policies?$expand=*&top=999' -Method GET -OutputType PSObject -ErrorAction Stop | Select-Object -ExpandProperty value


# Get Conditional Access Named / Trusted Locations
$namedLocations = Invoke-MgGraphRequest -Uri 'beta/identity/conditionalAccess/namedLocations?$top=999' -Method GET -OutputType PSObject -ErrorAction Stop | Select-Object -ExpandProperty value | Group-Object -Property Id -AsHashTable
if (-not $namedLocations) { $namedLocations = @{} }

# Get Azure AD Directory Role Templates (in latest module, use Get-MgDirectoryRoleTemplate)
$directoryRoleTemplates = Invoke-MgGraphRequest -Uri 'beta/directoryRoleTemplates' -Method GET -OutputType PSObject -ErrorAction Stop | Select-Object -ExpandProperty value | Group-Object -Property Id -AsHashTable

# Get service principals incl. paging
$servicePrincipalBatches = @()
$servicePrincipalsRequest = Invoke-MgGraphRequest -Uri 'beta/servicePrincipals' -Method GET -OutputType PSObject -ErrorAction Stop

while ($servicePrincipalsRequest.'@odata.nextLink') {
    $servicePrincipalBatches += $servicePrincipalsRequest.value
    $servicePrincipalsRequest = Invoke-MgGraphRequest -Uri $servicePrincipalsRequest.'@odata.nextLink' -Method GET -OutputType PSObject -ErrorAction Stop
}

$servicePrincipals = $servicePrincipalBatches | Group-Object -Property AppId -AsHashTable

# GSA network filtering (no direct beta endpoint in new modules, use Invoke-MgGraphRequest as fallback)
$networkFilteringProfiles = Invoke-MgGraphRequest -Uri '/beta/networkAccess/filteringProfiles' -Method GET -OutputType PSObject -ErrorAction SilentlyContinue | Select-Object -ExpandProperty value | Group-Object -Property id -AsHashTable

# Init report 
$documentation = [System.Collections.Generic.List[Object]]::new()

# Cache for resolved display names
$displayNameCache = @{}

# Process all Conditional Access Policies
foreach ($policy in $conditionalAccessPolicies) {

    # Display some progress (based on policy count)
    $currentIndex = $conditionalAccessPolicies.indexOf($policy) + 1

    $progress = @{
        Activity         = 'Generating Conditional Access Documentation...'
        PercentComplete  = [Decimal]::Divide($currentIndex, $conditionalAccessPolicies.Count) * 100
        CurrentOperation = ('Processing policy: {0}' -f $policy.DisplayName)
    }
    if ($currentIndex -eq $conditionalAccessPolicies.Count) { $progress.Add('Completed', $true) }

    Write-Progress @progress

    Write-Output ('Processing policy: {0}' -f $policy.DisplayName)

    try {
        # Resolve object IDs of included users
        $includeUsers = $policy.conditions.users.includeUsers | ForEach-Object {
            Resolve-MgObject -InputObject $PSItem
        }
        # Resolve object IDs of excluded users
        $excludeUsers = $policy.conditions.users.excludeUsers | ForEach-Object {
            Resolve-MgObject -InputObject $PSItem
        }
        # Resolve object IDs of included groups
        $includeGroups = $policy.conditions.users.includeGroups | ForEach-Object {
            Resolve-MgObject -InputObject $PSItem
        }
        # Resolve object IDs of excluded groups
        $excludeGroups = $policy.conditions.users.excludeGroups | ForEach-Object {
            Resolve-MgObject -InputObject $PSItem
        }
        # Resolve object IDs of included roles
        $includeRoles = $policy.conditions.users.includeRoles | ForEach-Object {
            $directoryRoleTemplates.GetOrDefault($PSItem, $PSItem)
        }

        # Resolve object IDs of excluded roles
        $excludeRoles = $policy.conditions.users.excludeRoles | ForEach-Object {
            $directoryRoleTemplates.GetOrDefault($PSItem, $PSItem)
        }
        # Resolve object IDs of included apps
        $includeApps = $policy.conditions.applications.includeApplications | ForEach-Object {
            $servicePrincipals.GetOrDefault($PSItem, $PSItem)
        }
        # Resolve object IDs of excluded apps
        $excludeApps = $policy.conditions.applications.excludeApplications | ForEach-Object {
            $servicePrincipals.GetOrDefault($PSItem, $PSItem)
        }

        # Resolve object IDs of referenced service and resource principals
        $includeServicePrincipals = [System.Collections.Generic.List[Object]]::new()
        $excludeServicePrincipals = [System.Collections.Generic.List[Object]]::new()

        $policy.conditions.clientApplications.includeServicePrincipals | ForEach-Object {
            $includeServicePrincipals.add($servicePrincipals.GetOrDefault($PSItem, $PSItem))
        }
        $policy.conditions.clientApplications.excludeServicePrincipals | ForEach-Object {
            $excludeServicePrincipals.add($servicePrincipals.GetOrDefault($PSItem, $PSItem))
        }
        
        # Resolve object IDs of included authentication contexts
        $includeAuthenticationContext = [System.Collections.Generic.List[Object]]::new()
        $policy.conditions.applications.includeAuthenticationContextClassReferences | ForEach-Object {
            $authContext = Invoke-MgGraphRequest -Uri "beta/identity/conditionalAccess/authenticationContextClassReferences/$PSItem" -Method GET -OutputType PSObject
            $includeAuthenticationContext.Add($authContext.displayName)
        }

        # Resolve object IDs of included locations
        $includeLocations = $policy.conditions.locations.includeLocations | ForEach-Object {
            $namedLocations.GetOrDefault($PSItem, $PSItem)
        }
        # Resolve object IDs of excluded locations
        $excludeLocations = $policy.conditions.locations.excludeLocations | ForEach-Object {
            $namedLocations.GetOrDefault($PSItem, $PSItem)
        }

        # GSA web filtering profiles
        $webFilteringProfile = if ($policy.sessionControls.globalSecureAccessFilteringProfile) {
            Write-Output $networkFilteringProfiles[$policy.sessionControls.globalSecureAccessFilteringProfile.profileId].name
        } else {
            Write-Output $null
        }

        # figure out sign-in frequency: every time vs time-based
        $signInFrequency = if ($policy.sessionControls.SignInFrequency) { 
            if ($policy.sessionControls.signInFrequency.frequencyInterval -eq 'timeBased' ) {
                "$($policy.sessionControls.SignInFrequency.Value) $($policy.sessionControls.SignInFrequency.Type)"
            } else {
                $policy.sessionControls.signInFrequency.frequencyInterval
            }

        } else { $null }

        # delimiter for arrays in csv report
        $separator = "`r`n"
        # when terms of use are present just add a generic hint.
        if ($policy.grantControls.termsOfUse) { $policy.grantControls.builtInControls += 'termsOfUse' }

        if ($policy.grantControls.authenticationStrength) { $policy.grantControls.builtInControls += 'authenticationStrength' }

        # only include authN strength if it's actually there
        $grantControls = $policy.grantControls.builtInControls | Where-Object { $_ -notin 'authenticationStrength' }
        if ($policy.grantControls.authenticationStrength.DisplayName) {
            $grantControls += 'authenticationStrength'
        }

        # construct entry for report
        $documentation.Add(
            [PSCustomObject]@{
                Name                                      = $policy.DisplayName
                # conditions
                IncludeUsers                              = $includeUsers -join $separator
                IncludeGroups                             = $includeGroups -join $separator
                IncludeRoles                              = $includeRoles -join $separator

                ExcludeUsers                              = $excludeUsers -join $separator
                ExcludeGuestOrExternalUserTypes           = $policy.conditions.users.excludeGuestsOrExternalUsers.guestOrExternalUserTypes
                ExcludeGuestOrExternalUserTenants         = $policy.conditions.users.excludeGuestsOrExternalUsers.externalTenants.members -join $separator

                ExcludeGroups                             = $excludeGroups -join $separator
                ExcludeRoles                              = $excludeRoles -join $separator

                IncludeApps                               = $includeApps -join $separator
                ExcludeApps                               = $excludeApps -join $separator

                ApplicationFilterMode                     = $policy.conditions.applications.applicationFilter.mode
                ApplicationFilterRule                     = $policy.conditions.applications.applicationFilter.rule

                IncludeAuthenticationContext              = $includeAuthenticationContext -join $separator
                IncludeUserActions                        = $policy.conditions.applications.includeUserActions -join $separator
                ClientAppTypes                            = $policy.conditions.clientAppTypes -join $separator

                IncludePlatforms                          = $policy.conditions.platforms.includePlatforms -join $separator
                ExcludePlatforms                          = $policy.conditions.platforms.excludePlatforms -join $separator

                IncludeLocations                          = $includeLocations -join $separator
                ExcludeLocations                          = $excludeLocations -join $separator

                DeviceFilterMode                          = $policy.conditions.devices.deviceFilter.mode
                DeviceFilterRule                          = $policy.conditions.devices.deviceFilter.rule

                SignInRiskLevels                          = $policy.conditions.signInRiskLevels -join $separator
                UserRiskLevels                            = $policy.conditions.userRiskLevels -join $separator
                ServicePrincipalRiskLevels                = $policy.conditions.servicePrincipalRiskLevels -join $separator
               
                # Workload Identity Protection
                IncludeServicePrincipals                  = $includeServicePrincipals -join $separator
                ExcludeServicePrincipals                  = $excludeServicePrincipals -join $separator
                ServicePrincipalFilterMode                = $policy.conditions.ClientApplications.ServicePrincipalFilter.mode
                ServicePrincipalFilter                    = $policy.conditions.ClientApplications.ServicePrincipalFilter.rule
               
                # Grantcontrols
                GrantControls                             = $grantControls -join $separator
                GrantControlsOperator                     = $policy.grantControls.operator
                AuthenticationStrength                    = $policy.grantControls.authenticationStrength.displayName
                AuthenticationStrengthAllowedCombinations = $policy.grantControls.authenticationStrength.allowedCombinations -join $separator

                # Session controls
                ApplicationEnforcedRestrictions           = $policy.sessionControls.ApplicationEnforcedRestrictions.IsEnabled
                CloudAppSecurity                          = $policy.sessionControls.CloudAppSecurity.IsEnabled
                DisableResilienceDefaults                 = $policy.sessionControls.DisableResilienceDefaults
                PersistentBrowser                         = $policy.sessionControls.PersistentBrowser.Mode
                SignInFrequency                           = $signInFrequency
                RequireTokenProtection                    = $policy.sessionControls.secureSignInSession.isEnabled # Require Token Protection
                GlobalSecureAccessFilteringProfile        = $webFilteringProfile
                ContinuousAccessEvaluationMode            = $policy.sessionControls.continuousAccessEvaluation.mode

                # State
                State                                     = $policy.State
            }
        )
    } catch {
        Write-Error $PSItem
    }
}

# Build export path (script directory)
$exportPath = Join-Path $PSScriptRoot 'ConditionalAccessDocumentation.csv'

# Export report as csv
$documentation | Export-Csv -Path $exportPath -NoTypeInformation
Write-Output "Exported Documentation to '$($exportPath)'"
