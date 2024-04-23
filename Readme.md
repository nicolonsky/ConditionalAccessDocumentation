# Document Conditional Access with PowerShell 

[![PSGallery Version](https://img.shields.io/powershellgallery/v/Invoke-ConditionalAccessDocumentation.svg?style=flat-square&label=PSGallery%20Version)](https://www.powershellgallery.com/packages/Invoke-ConditionalAccessDocumentation) [![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/Invoke-ConditionalAccessDocumentation?style=flat-square&label=PSGallery%20Downloads)](https://www.powershellgallery.com/packages/Invoke-ConditionalAccessDocumentation)
![GitHub](https://img.shields.io/github/license/nicolonsky/conditionalaccessdocumentation?style=flat-square)
![GitHub Release Date](https://img.shields.io/github/release-date/nicolonsky/conditionalaccessdocumentation?style=flat-square)


This PowerShell script documents your Entra ID Conditional Access policies while translating directory object IDs of targeted users, groups and apps to readable names. The script exports all data as a csv file which can be pretty formatted as excel workbook.

1. Install this script from the PowerShell gallery (dependent modules are automatically installed):

    * `Install-Script -Name Invoke-ConditionalAccessDocumentation -Scope CurrentUser`
    
2. Connect to Microsoft Graph

    * Grant initial admin consent: `Connect-MgGraph -Scopes "Application.Read.All", "Group.Read.All", "Policy.Read.All", "RoleManagement.Read.Directory", "User.Read.All" -ContextScope Process`
    
    * After initial admin consent has been granted you can connect with: `Connect-MgGraph` for subsequent usage
    
3. Run script via PowerShell dot sourcing
    
    ```powershell
    Invoke-ConditionalAccessDocumentation.ps1
    ```
    
4. (Optional) Pretty format the csv with excel & save it as excel workbook 

    * ![Example](https://raw.githubusercontent.com/nicolonsky/ConditionalAccessDocumentation/master/Example/Example.png)


