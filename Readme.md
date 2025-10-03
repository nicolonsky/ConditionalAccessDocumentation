# Document Conditional Access with PowerShell 

[![PSGallery Version](https://img.shields.io/powershellgallery/v/Invoke-ConditionalAccessDocumentation.svg?style=flat-square&label=PSGallery%20Version)](https://www.powershellgallery.com/packages/Invoke-ConditionalAccessDocumentation) [![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/Invoke-ConditionalAccessDocumentation?style=flat-square&label=PSGallery%20Downloads)](https://www.powershellgallery.com/packages/Invoke-ConditionalAccessDocumentation)
![GitHub](https://img.shields.io/github/license/nicolonsky/conditionalaccessdocumentation?style=flat-square)
![GitHub Release Date](https://img.shields.io/github/release-date/nicolonsky/conditionalaccessdocumentation?style=flat-square)


This PowerShell script documents your Azure AD Conditional Access policies. The script exports all data as a csv file which can be pretty formatted as excel workbook.

1. Install this script from the PowerShell gallery (dependent modules are automatically installed):

    * `Install-Script -Name Invoke-ConditionalAccessDocumentation -Scope CurrentUser`
    
    * Script is saved to the user's default script lcoation: 
       - Windows : `"C:\Users\%USERNAME%\Documents\WindowsPowerShell\Scripts"`
       - macOS: `~/.local/share/powershell/scripts`
    
2. Connect to Microsoft Graph

    * Grant initial admin consent: `Connect-Graph -Scopes "Application.Read.All", "Group.Read.All", "Policy.Read.All", "RoleManagement.Read.Directory", "User.Read.All" -ContextScope Process`
    
    * You can also connect to Microsoft Graph Beta endpoint with `Select-MgProfile -Name "Beta"`, this will also export policies with preview features like workload identities
    
    * After initial admin consent has been granted you can connect with: `Connect-Graph` for subsequent usage
    
3. Run script via PowerShell dot sourcing
    
    * ```& "C:\Users\$env:USERNAME\Documents\WindowsPowerShell\Scripts\Invoke-ConditionalAccessDocumentation.ps1"```
    
4. (Optional) Pretty format the csv with excel & save it as excel workbook 

    * ![Example](https://raw.githubusercontent.com/nicolonsky/ConditionalAccessDocumentation/master/Example/Example.png)


