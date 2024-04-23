<#PSScriptInfo

.VERSION 1.8.0

.GUID 6c861af7-d12e-4ea2-b5dc-56fee16e0107

.AUTHOR Nicola Suter

.TAGS ConditionalAccess, AzureAD, Identity

.PROJECTURI https://github.com/nicolonsky/ConditionalAccessDocumentation

.ICONURI https://raw.githubusercontent.com/microsoftgraph/g-raph/master/g-raph.png

.DESCRIPTION This script documents Azure AD Conditional Access Policies.

.SYNOPSIS This script retrieves all Conditional Access Policies and translates Azure AD Object IDs to display names for users, groups, directory roles, locations...

.EXAMPLE
    Connect-Graph -Scopes "Application.Read.All", "Group.Read.All", "Policy.Read.All", "RoleManagement.Read.Directory", "User.Read.All"
    & .\Invoke-ConditionalAccessDocumentation.ps1
    Generates the documentation and exports the csv to the script directory.
.NOTES
    Author:           Nicola Suter
    Creation Date:    31.01.2022
#>

#Requires -Module @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '2.12.0'}, @{ ModuleName = 'Microsoft.Graph.Beta.Applications'; ModuleVersion = '2.12.0' }, @{ ModuleName = 'Microsoft.Graph.Beta.Identity.SignIns'; ModuleVersion = '2.12.0' }, @{ ModuleName = 'Microsoft.Graph.Beta.Identity.DirectoryManagement'; ModuleVersion = '2.12.0'}, @{ ModuleName = 'Microsoft.Graph.Beta.DirectoryObjects'; ModuleVersion = '2.12.0'}

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
                    $directoryObject = Get-MgBetaDirectoryObject -DirectoryObjectId $InputObject -ErrorAction Stop
                    $displayName = $directoryObject.AdditionalProperties['displayName']
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
$conditionalAccessPolicies = Get-MgBetaIdentityConditionalAccessPolicy -ExpandProperty '*' -All -ErrorAction Stop
#Get Conditional Access Named / Trusted Locations
$namedLocations = Get-MgBetaIdentityConditionalAccessNamedLocation -All -ErrorAction Stop | Group-Object -Property Id -AsHashTable
if (-not $namedLocations) { $namedLocations = @{} }
# Get Azure AD Directory Role Templates
$directoryRoleTemplates = Get-MgBetaDirectoryRoleTemplate -All -ErrorAction Stop | Group-Object -Property Id -AsHashTable
# Service Principals
$servicePrincipals = Get-MgBetaServicePrincipal -All -ErrorAction Stop | Group-Object -Property AppId -AsHashTable
# GSA network filtering
$networkFilteringProfiles = Invoke-MgGraphRequest -Uri 'beta/networkAccess/filteringProfiles' -OutputType PSObject -ErrorAction SilentlyContinue | Select-Object -ExpandProperty value | Group-Object -Property id -AsHashTable

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
        CurrentOperation = "Processing Policy `"$($policy.DisplayName)`""
    }
    if ($currentIndex -eq $conditionalAccessPolicies.Count) { $progress.Add('Completed', $true) }

    Write-Progress @progress

    Write-Output "Processing policy `"$($policy.DisplayName)`""
    
    try {
        # Resolve object IDs of included users
        $includeUsers = $policy.Conditions.Users.IncludeUsers | ForEach-Object {
            Resolve-MgObject -InputObject $PSItem
        }
        # Resolve object IDs of excluded users
        $excludeUsers = $policy.Conditions.Users.ExcludeUsers | ForEach-Object {
            Resolve-MgObject -InputObject $PSItem
        }
        # Resolve object IDs of included groups
        $includeGroups = $policy.Conditions.Users.IncludeGroups | ForEach-Object {
            Resolve-MgObject -InputObject $PSItem
        }
        # Resolve object IDs of excluded groups
        $excludeGroups = $policy.Conditions.Users.ExcludeGroups | ForEach-Object {
            Resolve-MgObject -InputObject $PSItem
        }
        # Resolve object IDs of included roles
        $includeRoles = $policy.Conditions.Users.IncludeRoles | ForEach-Object {
            $directoryRoleTemplates.GetOrDefault($PSItem, $PSItem)
        }

        # Resolve object IDs of excluded roles
        $excludeRoles = $policy.Conditions.Users.ExcludeRoles | ForEach-Object {
            $directoryRoleTemplates.GetOrDefault($PSItem, $PSItem)
        }
        # Resolve object IDs of included apps
        $includeApps = $policy.Conditions.Applications.IncludeApplications | ForEach-Object {
            $servicePrincipals.GetOrDefault($PSItem, $PSItem)
        }
        # Resolve object IDs of excluded apps
        $excludeApps = $policy.Conditions.Applications.ExcludeApplications | ForEach-Object {
            $servicePrincipals.GetOrDefault($PSItem, $PSItem)
        }

        $includeServicePrincipals = [System.Collections.Generic.List[Object]]::new()
        $excludeServicePrincipals = [System.Collections.Generic.List[Object]]::new()

        $policy.Conditions.ClientApplications.IncludeServicePrincipals | ForEach-Object {
            $includeServicePrincipals.add($servicePrincipals.GetOrDefault($PSItem, $PSItem))
        }
        $policy.Conditions.ClientApplications.ExcludeServicePrincipals | ForEach-Object {
            $excludeServicePrincipals.add($servicePrincipals.GetOrDefault($PSItem, $PSItem))
        }
        
        $includeAuthenticationContext = [System.Collections.Generic.List[Object]]::new()
        $policy.Conditions.Applications.IncludeAuthenticationContextClassReferences | ForEach-Object {
            $context = Get-MgBetaIdentityConditionalAccessAuthenticationContextClassReference -Filter "Id eq '$PSItem'"
            $includeAuthenticationContext.Add($context.DisplayName)
        }

        # Resolve object IDs of included locations
        $includeLocations = $policy.conditions.Locations.IncludeLocations | ForEach-Object {
            $namedLocations.GetOrDefault($PSItem, $PSItem)
        }
        # Resolve object IDs of excluded locations
        $excludeLocations = $policy.conditions.Locations.ExcludeLocations | ForEach-Object {
            $namedLocations.GetOrDefault($PSItem, $PSItem)
        }

        # GSA web filtering profiles
    
        $webFilteringProfile = if ($policy.SessionControls.AdditionalProperties.ContainsKey('globalSecureAccessFilteringProfile')) {
            Write-Output $networkFilteringProfiles[$policy.SessionControls.AdditionalProperties['globalSecureAccessFilteringProfile']['profileId']].name
        } else {
            Write-Output $null
        }

        # delimiter for arrays in csv report
        $separator = "`r`n"
        # when terms of use are present just add a generic hint.
        if ($policy.GrantControls.TermsOfUse) { $policy.GrantControls.BuiltInControls += 'termsOfUse' }
        
        if ($policy.GrantControls.AuthenticationStrength) { $policy.GrantControls.BuiltInControls += 'authenticationStrength' }

        # only include authN strength if it's actually there
        $grantControls = $policy.GrantControls.BuiltInControls | Where-Object { $_ -notin 'authenticationStrength' }
        if ($policy.GrantControls.AuthenticationStrength.DisplayName) {
            $grantControls += 'authenticationStrength'
        }

        # construct entry for report
        $documentation.Add(
            [PSCustomObject]@{
                Name                                      = $policy.DisplayName
                # Conditions
                IncludeUsers                              = $includeUsers -join $separator
                IncludeGroups                             = $includeGroups -join $separator
                IncludeRoles                              = $includeRoles -join $separator

                ExcludeUsers                              = $excludeUsers -join $separator
                ExcludeGuestOrExternalUserTypes           = $policy.Conditions.Users.ExcludeGuestsOrExternalUsers.guestOrExternalUserTypes
                ExcludeGuestOrExternalUserTenants         = $policy.Conditions.Users.ExcludeGuestsOrExternalUsers.externalTenants.AdditionalProperties['members'] -join $separator

                ExcludeGroups                             = $excludeGroups -join $separator
                ExcludeRoles                              = $excludeRoles -join $separator

                IncludeApps                               = $includeApps -join $separator
                ExcludeApps                               = $excludeApps -join $separator

                ApplicationFilterMode                     = $policy.Conditions.Applications.ApplicationFilter.mode
                ApplicationFilterRule                     = $policy.Conditions.Applications.ApplicationFilter.rule

                IncludeAuthenticationContext              = $includeAuthenticationContext -join $separator
                IncludeUserActions                        = $policy.Conditions.Applications.IncludeUserActions -join $separator
                ClientAppTypes                            = $policy.Conditions.ClientAppTypes -join $separator

                IncludePlatforms                          = $policy.Conditions.Platforms.IncludePlatforms -join $separator
                ExcludePlatforms                          = $policy.Conditions.Platforms.ExcludePlatforms -join $separator

                IncludeLocations                          = $includeLocations -join $separator
                ExcludeLocations                          = $excludeLocations -join $separator

                DeviceFilterMode                          = $policy.Conditions.Devices.DeviceFilter.Mode
                DeviceFilterRule                          = $policy.Conditions.Devices.DeviceFilter.Rule

                SignInRiskLevels                          = $policy.Conditions.SignInRiskLevels -join $separator
                UserRiskLevels                            = $policy.Conditions.UserRiskLevels -join $separator
                ServicePrincipalRiskLevels                = $policy.Conditions.servicePrincipalRiskLevels -join $separator
               
                # Workload Identity Protection
                IncludeServicePrincipals                  = $includeServicePrincipals -join $separator
                ExcludeServicePrincipals                  = $excludeServicePrincipals -join $separator
                ServicePrincipalFilterMode                = $policy.Conditions.ClientApplications.ServicePrincipalFilter.mode
                ServicePrincipalFilter                    = $policy.Conditions.ClientApplications.ServicePrincipalFilter.rule
               
                # Grantcontrols
                GrantControls                             = $grantControls -join $separator
                GrantControlsOperator                     = $policy.GrantControls.Operator
                AuthenticationStrength                    = $policy.GrantControls.AuthenticationStrength.DisplayName
                AuthenticationStrengthAllowedCombinations = $policy.GrantControls.AuthenticationStrength.AllowedCombinations -join $separator

                # Session controls
                ApplicationEnforcedRestrictions           = $policy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled
                CloudAppSecurity                          = $policy.SessionControls.CloudAppSecurity.IsEnabled
                DisableResilienceDefaults                 = $policy.SessionControls.DisableResilienceDefaults
                PersistentBrowser                         = $policy.SessionControls.PersistentBrowser.Mode
                SignInFrequency                           = "$($policy.SessionControls.SignInFrequency.Value) $($policy.SessionControls.SignInFrequency.Type)"
                SecureSignInSession                       = $policy.SessionControls.AdditionalProperties['secureSignInSession'].isEnabled # Require Token Protection
                GlobalSecureAccessFilteringProfile        = $webFilteringProfile

                # State
                State                                     = $policy.State
            }
        )
    } catch {
        #Throw $_
        Write-Error $PSItem
    }
}

# Build export path (script directory)
$exportPath = Join-Path $PSScriptRoot 'ConditionalAccessDocumentation.csv'
# Export report as csv
$documentation | Export-Csv -Path $exportPath -NoTypeInformation

Write-Output "Exported Documentation to '$($exportPath)'"