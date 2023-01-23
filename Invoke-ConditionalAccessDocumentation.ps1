<#PSScriptInfo

.VERSION 1.6.0

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

#Requires -Module @{ ModuleName = 'Microsoft.Graph.Identity.SignIns'; ModuleVersion = '1.9.2'}, @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '1.9.2'}, @{ ModuleName = 'Microsoft.Graph.Users'; ModuleVersion = '1.9.2'}, @{ ModuleName = 'Microsoft.Graph.Identity.DirectoryManagement'; ModuleVersion = '1.9.2'}, @{ ModuleName = 'Microsoft.Graph.Groups'; ModuleVersion = '1.9.2'}, @{ ModuleName = 'Microsoft.Graph.Applications'; ModuleVersion = '1.9.2'}

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
                $directoryObject = Get-MgDirectoryObject -DirectoryObjectId $InputObject -ErrorAction Stop
                return $directoryObject.AdditionalProperties["displayName"]
            }
            catch {
                Write-Warning "Unable to resolve directory object with ID $InputObject, might have been deleted!"
            }
        }

        return $InputObject
    }
}



if (-not $(Get-MgContext)) {
    Throw "Authentication needed, call 'Connect-Graph -Scopes `"Application.Read.All`", `"Group.Read.All`", `"Policy.Read.All`", `"RoleManagement.Read.Directory`", `"User.Read.All`""
}

# Get Conditional Access Policies
$conditionalAccessPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
#Get Conditional Access Named / Trusted Locations
$namedLocations = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop | Group-Object -Property Id -AsHashTable
if (-not $namedLocations) {$namedLocations = @{}}
# Get Azure AD Directory Role Templates
$directoryRoleTemplates = Get-MgDirectoryRoleTemplate -ErrorAction Stop | Group-Object -Property Id -AsHashTable
# Service Principals
$servicePrincipals = Get-MgServicePrincipal -All -ErrorAction Stop | Group-Object -Property AppId -AsHashTable
# Init report 
$conditionalAccessDocumentation = [System.Collections.Generic.List[Object]]::new()

# Process all Conditional Access Policies
foreach ($conditionalAccessPolicy in $conditionalAccessPolicies) {

    # Display some progress (based on policy count)
    $currentIndex = $conditionalAccessPolicies.indexOf($conditionalAccessPolicy)
    Write-Progress -Activity "Generating Conditional Access Documentation..." -PercentComplete (($currentIndex + 1) / $conditionalAccessPolicies.Count * 100) `
        -CurrentOperation "Processing Policy '$($conditionalAccessPolicy.DisplayName)' ($currentIndex/$($conditionalAccessPolicies.Count))"

    Write-Output "Processing policy `"$($conditionalAccessPolicy.DisplayName)`""
    
    try {
        # Resolve object IDs of included users
        $includeUsers = [System.Collections.Generic.List[Object]]::new()
        $conditionalAccessPolicy.Conditions.Users.IncludeUsers | ForEach-Object {
            $includeUsers.Add((Resolve-MgObject -InputObject $PSItem))
        }
        # Resolve object IDs of excluded users
        $excludeUsers = [System.Collections.Generic.List[Object]]::new()
        $conditionalAccessPolicy.Conditions.Users.ExcludeUsers | ForEach-Object {
            $excludeUsers.Add((Resolve-MgObject -InputObject $PSItem))
        }
        # Resolve object IDs of included groups
        $includeGroups = [System.Collections.Generic.List[Object]]::new()
        $conditionalAccessPolicy.Conditions.Users.IncludeGroups | ForEach-Object {
            $includeGroups.Add((Resolve-MgObject -InputObject $PSItem))
        }
        # Resolve object IDs of excluded groups
        $excludeGroups = [System.Collections.Generic.List[Object]]::new()
        $conditionalAccessPolicy.Conditions.Users.ExcludeGroups | ForEach-Object {
            $excludeGroups.Add((Resolve-MgObject -InputObject $PSItem))
        }
        # Resolve object IDs of included roles
        $includeRoles = [System.Collections.Generic.List[Object]]::new()
        $conditionalAccessPolicy.Conditions.Users.IncludeRoles | ForEach-Object {
            if ($directoryRoleTemplates.ContainsKey($PSItem)) {
                $includeRoles.Add(($directoryRoleTemplates[$PSItem].DisplayName))
            }
            else {
                $includeRoles.Add($PSItem)
            }
        }

        # Resolve object IDs of excluded roles
        $excludeRoles = [System.Collections.Generic.List[Object]]::new()
        $conditionalAccessPolicy.Conditions.Users.ExcludeRoles | ForEach-Object {
            if ($directoryRoleTemplates.ContainsKey($PSItem)) {
                $excludeRoles.Add(($directoryRoleTemplates[$PSItem].DisplayName))
            }
            else {
                $excludeRoles.Add($PSItem)
            }
        }
        # Resolve object IDs of included apps
        $includeApps = [System.Collections.Generic.List[Object]]::new()
        $conditionalAccessPolicy.Conditions.Applications.IncludeApplications | ForEach-Object {
            if ($servicePrincipals.ContainsKey($PSItem)) {
                $includeApps.Add(($servicePrincipals[$PSItem].DisplayName))
            }
            else {
                $includeApps.Add($PSItem)
            }
        }
        # Resolve object IDs of excluded apps
        $excludeApps = [System.Collections.Generic.List[Object]]::new()
        $conditionalAccessPolicy.Conditions.Applications.ExcludeApplications | ForEach-Object {
            if ($servicePrincipals.ContainsKey($PSItem)) {
                $excludeApps.Add(($servicePrincipals[$PSItem].DisplayName))
            }
            else {
                $excludeApps.Add($PSItem)
            }
        }
        # Resolve object IDs of included locations
        $includeLocations = [System.Collections.Generic.List[Object]]::new()
        $conditionalAccessPolicy.conditions.Locations.IncludeLocations | ForEach-Object {
            if ($PSItem -and $namedLocations.ContainsKey($PSItem)) {
                $includeLocations.Add($namedLocations[$PSItem].DisplayName)
            }
            else {
                $includeLocations.Add($PSItem)
            }
        }
        # Resolve object IDs of excluded locations
        $excludeLocations = [System.Collections.Generic.List[Object]]::new()
        $conditionalAccessPolicy.conditions.Locations.ExcludeLocations | ForEach-Object {
            if ($PSItem -and $namedLocations.ContainsKey($PSItem)) {
                $excludeLocations.Add(($namedLocations[$PSItem].DisplayName))
            }
            else {
                $excludeLocations.Add($PSItem)
            }
        }

        # delimiter for arrays in csv report
        $separator = "`r`n"
        if ($conditionalAccessPolicy.GrantControls.TermsOfUse) { $conditionalAccessPolicy.GrantControls.BuiltInControls += "TermsOfUse" }
        $conditionalAccessDocumentation.Add(
            [PSCustomObject]@{
                Name                            = $conditionalAccessPolicy.DisplayName
                State                           = $conditionalAccessPolicy.State

                IncludeUsers                    = $includeUsers -join $separator
                IncludeGroups                   = $includeGroups -join $separator
                IncludeRoles                    = $includeRoles -join $separator

                ExcludeUsers                    = $excludeUsers -join $separator
                ExcludeGroups                   = $excludeGroups -join $separator
                ExcludeRoles                    = $excludeRoles -join $separator

                IncludeApps                     = $includeApps -join $separator
                ExcludeApps                     = $excludeApps -join $separator

                IncludeUserActions              = $conditionalAccessPolicy.Conditions.Applications.IncludeUserActions -join $separator
                ClientAppTypes                  = $conditionalAccessPolicy.Conditions.ClientAppTypes -join $separator

                IncludePlatforms                = $conditionalAccessPolicy.Conditions.Platforms.IncludePlatforms -join $separator
                ExcludePlatforms                = $conditionalAccessPolicy.Conditions.Platforms.ExcludePlatforms -join $separator

                IncludeLocations                = $includeLocations -join $separator
                ExcludeLocations                = $excludeLocations -join $separator

                DeviceFilterMode                = $conditionalAccessPolicy.Conditions.Devices.DeviceFilter.Mode
                DeviceFilterRule                = $conditionalAccessPolicy.Conditions.Devices.DeviceFilter.Rule

                GrantControls                   = $conditionalAccessPolicy.GrantControls.BuiltInControls -join $separator
                GrantControlsOperator           = $conditionalAccessPolicy.GrantControls.Operator

                SignInRiskLevels                = $conditionalAccessPolicy.Conditions.SignInRiskLevels -join $separator
                UserRiskLevels                  = $conditionalAccessPolicy.Conditions.UserRiskLevels -join $separator

                ApplicationEnforcedRestrictions = $conditionalAccessPolicy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled
                CloudAppSecurity                = $conditionalAccessPolicy.SessionControls.CloudAppSecurity.IsEnabled
                PersistentBrowser               = $conditionalAccessPolicy.SessionControls.PersistentBrowser.Mode
                SignInFrequency                 = "$($conditionalAccessPolicy.SessionControls.SignInFrequency.Value) $($conditionalAccessPolicy.SessionControls.SignInFrequency.Type)"
            }
        )
    }
    catch {
        Throw $_
        Write-Error $PSItem
    }
}

# Build export path (script directory)
$exportPath = Join-Path $PSScriptRoot "ConditionalAccessDocumentation.csv"
# Export report as csv
$conditionalAccessDocumentation | Export-Csv -Path $exportPath -NoTypeInformation

Write-Output "Exported Documentation to '$($exportPath)'"
