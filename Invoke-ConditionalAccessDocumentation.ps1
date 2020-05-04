$requiredScopes = @("Application.Read.All", "Group.Read.All", "Policy.Read.All", "RoleManagement.Read.Directory", "User.Read.All")
Connect-Graph -Scopes $requiredScopes


$conditionalAccessDocumentation = @()
$conditionalAccessPolicies = Get-MgConditionalAccessPolicy

$directoryRoleTemplates = Get-MgDirectoryRoleTemplate
$namedLocations = Get-MgConditionalAccessNamedLocation

$servicePrincipals = Get-MgServicePrincipal

foreach ($conditionalAccessPolicy in $conditionalAccessPolicies){

    $conditionalAccessDocumentation += [PSCustomObject]@{

        Name = $conditionalAccessPolicy.DisplayName
        State =  $conditionalAccessPolicy.State

        IncludeUsers = $conditionalAccessPolicy.Conditions.UserIncludeUsers | ForEach-Object {
            try{
                if ([guid]::Parse($_)){
                    Get-MgUser -userId $_ | Select-Object -ExpandProperty DisplayName
                }
            }catch{}
        } | Join-String -Separator "`r`n"

        IncludeGroups = $conditionalAccessPolicy.Conditions.UserIncludeGroups | ForEach-Object {
            Get-MgGroup -groupId $_ | Select-Object -ExpandProperty DisplayName
        } | Join-String -Separator "`r`n"

        IncludeRoles = $conditionalAccessPolicy.Conditions.UserIncludeRoles | ForEach-Object {
            $roleId = $_
            $directoryRoleTemplates | Where-Object {$_.Id -eq $roleId} | Select-Object -ExpandProperty DisplayName
        } | Join-String -Separator "`r`n"

        ExcludeUsers = $conditionalAccessPolicy.Conditions.UserExcludeUsers | ForEach-Object {
            try{
                if ([guid]::Parse($_)){
                    Get-MgUser -userId $_ | Select-Object -ExpandProperty DisplayName
                }
            }catch{}
        } | Join-String -Separator "`r`n"

        ExcludeGroups = $conditionalAccessPolicy.Conditions.UserExcludeGroups | ForEach-Object {
            Get-MgGroup -groupId $_ | Select-Object -ExpandProperty DisplayName 
        } | Join-String -Separator "`r`n"

        ExcludeRoles = $conditionalAccessPolicy.Conditions.UserExcludeRoles | ForEach-Object {
            $roleId = $_
            $directoryRoleTemplates | Where-Object {$_.Id -eq $roleId} | Select-Object -ExpandProperty DisplayName
        } | Join-String -Separator "`r`n"

        IncludeApps = $conditionalAccessPolicy.Conditions.ApplicationIncludeApplications | ForEach-Object {
            try{
                $servicePrincipalId = $_
                if ([guid]::Parse($_)){
                    $servicePrincipals | Where-Object {$_.Id -eq $servicePrincipalId} 
                } else {
                    return $servicePrincipalId
                }
            }catch{}
        } | Join-String -Separator "`r`n"

        ExcludeApps = $conditionalAccessPolicy.Conditions.ApplicationExcludeApplications | ForEach-Object {
            try{
                $servicePrincipalId = $_
                if ([guid]::Parse($_)){
                    $servicePrincipals | Where-Object {$_.Id -eq $servicePrincipalId} | Select-Object -ExpandProperty DisplayName
                }else{
                   return $servicePrincipalId
                }
            }catch{}
        } | Join-String -Separator "`r`n"

        IncludeUserActions = $conditionalAccessPolicy.Conditions.ApplicationIncludeUserActions | Join-String -Separator "`r`n"

        ClientAppTypes = $conditionalAccessPolicy.Conditions.ClientAppTypes | Join-String -Separator "`r`n"

        IncludePlatforms = $conditionalAccessPolicy.Conditions.PlatformIncludePlatforms | Join-String -Separator "`r`n"
        ExcludePlatforms = $conditionalAccessPolicy.Conditions.PlatformExcludePlatforms | Join-String -Separator "`r`n"

        IncludeLocations = $conditionalAccessPolicy.Conditions.LocationIncludeLocations | ForEach-Object {
            try{
                $locationId = $_
                $namedLocations | Where-Object {$_.Id -eq $servicePrincipalId} | Select-Object -ExpandProperty DisplayName
            }catch{
                Write-Output $_
            }
        } | Join-String -Separator "`r`n"

        ExcludeLocations = $conditionalAccessPolicy.Conditions.LocationExcludeLocations | ForEach-Object {
            try{
                $locationId = $_
                $namedLocations | Where-Object {$_.Id -eq $servicePrincipalId} | Select-Object -ExpandProperty DisplayName
            }catch{
                Write-Output $_
            }
        } | Join-String -Separator "`r`n"

        IncludeDeviceStates = $conditionalAccessPolicy.Conditions.DeviceIncludeDeviceStates | Join-String -Separator "`r`n"
        ExcludeDeviceStates = $conditionalAccessPolicy.Conditions.DeviceExcludeDeviceStates | Join-String -Separator "`r`n"

        GrantControls = $conditionalAccessPolicy.GrantControlBuiltInControls | Join-String -Separator "`r`n"
        GrantControlsOperator = $conditionalAccessPolicy.GrantControlOperator
        ApplicationEnforcedRestrictions = $conditionalAccessPolicy.ApplicationEnforcedRestrictionIsEnabled
        CloudAppSecurity = $conditionalAccessPolicy.CloudAppSecurityIsEnabled
        PersistentBrowser = $conditionalAccessPolicy.PersistentBrowserIsEnabled
        SignInFrequency = "$($conditionalAccessPolicy.SignInFrequencyValue) $($conditionalAccessPolicy.SignInFrequencyType)"
    }
}

$exportPath = Join-Path $PSScriptRoot "ConditionalAccessDocumentation.csv"

$conditionalAccessDocumentation | Export-Csv -Path $exportPath

Write-Output "Exported Documentation to '$($exportPath)'"