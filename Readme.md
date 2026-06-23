# Document Conditional Access with PowerShell 

[![PSGallery Version](https://img.shields.io/powershellgallery/v/Invoke-ConditionalAccessDocumentation.svg?style=flat-square&label=PSGallery%20Version)](https://www.powershellgallery.com/packages/Invoke-ConditionalAccessDocumentation) [![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/Invoke-ConditionalAccessDocumentation?style=flat-square&label=PSGallery%20Downloads)](https://www.powershellgallery.com/packages/Invoke-ConditionalAccessDocumentation)
![GitHub](https://img.shields.io/github/license/nicolonsky/conditionalaccessdocumentation?style=flat-square)
![GitHub Release Date](https://img.shields.io/github/release-date/nicolonsky/conditionalaccessdocumentation?style=flat-square)

This PowerShell script documents your Microsoft Entra Conditional Access policies. The script exports all data as a csv file which can be pretty formatted as excel workbook.
To ensure all policies can be retrieved and documented the script uses the Microsoft Graph Beta API endpoint.

## Installation & Usage

1. Install this script from the PowerShell gallery (dependent `Microsoft.Graph.Authentication` module is automatically installed):

    * `Install-Script -Name Invoke-ConditionalAccessDocumentation -Scope CurrentUser`
    * Script is saved to the user's default script location:
        * Windows : `C:\Users\%USERNAME%\Documents\WindowsPowerShell\Scripts`
        * macOS: `~/.local/share/powershell/scripts`
2. Connect to Microsoft Graph

    * Grant initial admin consent: `Connect-Graph -Scopes "Application.Read.All", "Group.Read.All", "Policy.Read.All", "RoleManagement.Read.Directory", "User.Read.All", "NetworkAccess.Read.All" -ContextScope Process`
    * After initial admin consent has been granted you can connect with: `Connect-Graph` for subsequent usage
    * If you want to connect via Bearer Token from your Browser session you can use the following snippet to connect: ``Connect-MgGraph -AccessToken $((Get-Clipboard -Raw).Replace("Bearer ","").Replace("`n","") | ConvertTo-SecureString -AsPlainText -Force)``
3. Run script via PowerShell dot sourcing

    * ```.\Invoke-ConditionalAccessDocumentation.ps1```
 
4. (Optional) Pretty format the csv with excel & save it as excel workbook

    * ![Example](https://raw.githubusercontent.com/nicolonsky/ConditionalAccessDocumentation/master/Example/Example.png)
