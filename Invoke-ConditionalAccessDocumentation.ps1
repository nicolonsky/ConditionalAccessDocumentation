<#PSScriptInfo

.VERSION 1.4.0

.GUID 6c861af7-d12e-4ea2-b5dc-56fee16e0107

.AUTHOR Nicola Suter

.TAGS ConditionalAccess, AzureAD, Identity

.PROJECTURI https://github.com/nicolonsky/ConditionalAccessDocumentation

.ICONURI https://raw.githubusercontent.com/microsoftgraph/g-raph/master/g-raph.png

.DESCRIPTION This script documents Azure AD Conditional Access Policies.

.SYNOPSIS This script retrieves all Conditional Access Policies and translates Azure AD Object ID's to display names for users, groups, directory roles, locations...

.EXAMPLE
    Connect-Graph -Scopes @("Application.Read.All", "Group.Read.All", "Policy.Read.All", "RoleManagement.Read.Directory", "User.Read.All")
    & "C:\Repos\GitHub\ConditionalAccessDocumentation\Invoke-ConditionalAccessDocumentation.ps1"
    Generates the documentation and exports the csv to the script directory.
.NOTES
    Author:           Nicola Suter
    Creation Date:    05.05.2020
#>

#Requires -Module @{ ModuleName = 'Microsoft.Graph.Identity.ConditionalAccess'; RequiredVersion = '0.9.1'}, @{ ModuleName = 'Microsoft.Graph.Authentication'; RequiredVersion = '0.9.1'}, @{ ModuleName = 'Microsoft.Graph.Identity.ServicePrincipal'; RequiredVersion = '0.9.1'}, @{ ModuleName = 'Microsoft.Graph.Identity.DirectoryRoleTemplates'; RequiredVersion = '0.9.1'}, @{ ModuleName = 'Microsoft.Graph.Users.User'; RequiredVersion = '0.9.1'}, @{ ModuleName = 'Microsoft.Graph.Groups.Group'; RequiredVersion = '0.9.1'}

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

if ($null -eq $(Get-MgContext)) {
    Throw "Authentication needed, call 'Connect-Graph -Scopes @(`"Application.Read.All`", `"Group.Read.All`", `"Policy.Read.All`", `"RoleManagement.Read.Directory`", `"User.Read.All`")'."
}

# Lookup table for application ID's
$lookupTable = @{
    "00000004-0000-0ff1-ce00-000000000000" = "Microsoft.Lync"
    "00000006-0000-0ff1-ce00-000000000000" = "Microsoft.Office365Portal"
    "00000003-0000-0ff1-ce00-000000000000" = "Microsoft.SharePoint"
    "00000005-0000-0000-c000-000000000000" = "Microsoft.Azure.Workflow"
    "00000009-0000-0000-c000-000000000000" = "Microsoft.Azure.AnalysisServices"
    "00000002-0000-0ff1-ce00-000000000000" = "Microsoft.Exchange"
    "00000007-0000-0ff1-ce00-000000000000" = "Microsoft.ExchangeOnlineProtection"
    "00000002-0000-0000-c000-000000000000" = "Microsoft.Azure.ActiveDirectory"
    "8fca0a66-c008-4564-a876-ab3ae0fd5cff" = "Microsoft.SMIT"
    "0000000b-0000-0000-c000-000000000000" = "Microsoft.SellerDashboard"
    "0000000f-0000-0000-c000-000000000000" = "Microsoft.Azure.GraphExplorer"
    "0000000c-0000-0000-c000-000000000000" = "MicrosoftAppAccessPanel"
    "00000013-0000-0000-c000-000000000000" = "Microsoft.Azure.Portal"
    "00000010-0000-0000-c000-000000000000" = "Microsoft.Azure.GraphStore"
    "93ee9413-cf4c-4d4e-814b-a91ff20a01bd" = "Workflow"
    "aa9ecb1e-fd53-4aaa-a8fe-7a54de2c1334" = "Microsoft.Office365.Configure"
    "797f4846-ba00-4fd7-ba43-dac1f8f63013" = "WindowsAzureServiceManagementAPI"
    "00000005-0000-0ff1-ce00-000000000000" = "Microsoft.YammerEnterprise"
    "601d4e27-7bb3-4dee-8199-90d47d527e1c" = "Microsoft.Office365.ChangeManagement"
    "6f82282e-0070-4e78-bc23-e6320c5fa7de" = "Microsoft.DiscoveryService"
    "0f698dd4-f011-4d23-a33e-b36416dcb1e6" = "Microsoft.OfficeClientService"
    "67e3df25-268a-4324-a550-0de1c7f97287" = "Microsoft.OfficeWebAppsService"
    "ab27a73e-a3ba-4e43-8360-8bcc717114d8" = "Microsoft.OfficeModernCalendar"
    "aedca418-a84d-430d-ab84-0b1ef06f318f" = "Workflow"
    "595d87a1-277b-4c0a-aa7f-44f8a068eafc" = "Microsoft.SupportTicketSubmission"
    "e3583ad2-c781-4224-9b91-ad15a8179ba0" = "Microsoft.ExtensibleRealUserMonitoring"
    "b645896d-566e-447e-8f7f-e2e663b5d182" = "OpsDashSharePointApp"
    "48229a4a-9f1d-413a-8b96-4c02462c0360" = "OpsDashSharePointApp"
    "48717084-a59c-4306-9dc4-3f618dbecdf9" = "Office365DevelopmentTools"
    "c859ff33-eb41-4ba6-8093-a2c5153bbd7c" = "Workflow"
    "67cad61c-3411-48d7-ab73-561c64f11ed6" = "Workflow"
    "914ed757-9257-4200-b68e-a2bed2f12c5a" = "RbacBackfill"
    "499b84ac-1321-427f-aa17-267ca6975798" = "Microsoft.VisualStudio.Online"
    "b2590339-0887-4e94-93aa-13357eb510d7" = "Workflow"
    "0000001b-0000-0000-c000-000000000000" = "MicrosoftPowerBIInformationService"
    "89f80565-bfac-4c01-9535-9f0eba332ffe" = "PowerBI"
    "433895fb-4ec7-45c3-a53c-c44d10f80d5b" = "CompromisedAccountService"
    "d7c17728-4f1e-4a1e-86cf-7e0adf3fe903" = "Workflow"
    "17ef6d31-381f-4783-b186-7b440a3c85c1" = "Workflow"
    "00000012-0000-0000-c000-000000000000" = "Microsoft.Azure.RMS"
    "81ce94d4-9422-4c0d-a4b9-3250659366ce" = "Workflow"
    "8d3a7d3c-c034-4f19-a2ef-8412952a9671" = "MicrosoftOffice"
    "0469d4cd-df37-4d93-8a61-f8c75b809164" = "MicrosoftPolicyAdministrationService"
    "31d3f3f5-7267-45a8-9549-affb00110054" = "WindowsAzureRemoteAppService"
    "4e004241-32db-46c2-a86f-aaaba29bea9c" = "Workflow"
    "748d098e-7a3b-436d-8b0a-006a58b29647" = "Workflow"
    "dbf08535-1d3b-4f89-bf54-1d48dd613a61" = "Workflow"
    "ed9fe1ef-25a4-482f-9981-2b60f91e2448" = "Workflow"
    "8ad28d50-ee26-42fc-8a29-e41ea38461f2" = "Office365RESTAPIExplorer.Office365App"
    "38285dce-a13d-4107-9b04-3016b941bb3a" = "BasicDataOperationsREST"
    "92bb96c8-321c-47f9-bcc5-8849490c2b07" = "BasicSelfHostedAppREST"
    "488a57a0-00e2-4817-8c8d-cf8a15a994d2" = "WindowsFormsApplication2.Office365App"
    "11c174dc-1945-4a9a-a36b-c79a0f246b9b" = "AzureApplicationInsights"
    "e6acb561-0d94-4287-bd3a-3169f421b112" = "Tutum"
    "7b77b3a2-8490-49e1-8842-207cd0899af9" = "Nearpod"
    "0000000a-0000-0000-c000-000000000000" = "Microsoft.Intune"
    "93625bc8-bfe2-437a-97e0-3d0060024faa" = "SelfServicePasswordReset"
    "dee7ba80-6a55-4f3b-a86c-746a9231ae49" = "MicrosoftAppPlatEMA"
    "803ee9ca-3f7f-4824-bd6e-0b99d720c35c" = "AzureMediaService"
    "2d4d3d8e-2be3-4bef-9f87-7875a61c29de" = "OneNote"
    "8d40666e-5abf-45f6-a5e7-b7192d6d56ed" = "Workflow"
    "262044b1-e2ce-469f-a196-69ab7ada62d3" = "BackupManagementService"
    "087a2c70-c89e-463f-8dd3-e3959eabb1a9" = "MicrosoftProfileServicePlatformService"
    "7cd684f4-8a78-49b0-91ec-6a35d38739ba" = "AzureLogicApps"
    "c5393580-f805-4401-95e8-94b7a6ef2fc2" = "Office365ManagementAPIs"
    "96231a05-34ce-4eb4-aa6a-70759cbb5e83" = "MicrosoftAzureRedisCache"
    "b8340c3b-9267-498f-b21a-15d5547fd85e" = "Hyper-VRecoveryManager"
    "abfa0a7c-a6b6-4736-8310-5855508787cd" = "Microsoft.Azure.WebSites"
    "c44b4083-3bb0-49c1-b47d-974e53cbdf3c" = "IbizaPortal"
    "905fcf26-4eb7-48a0-9ff0-8dcc7194b5ba" = "Sway"
    "b10686fd-6ba8-49f2-a3cd-67e4d2f52ac8" = "NovoEd"
    "c606301c-f764-4e6b-aa45-7caaaea93c9a" = "OfficeStore"
    "569e8598-685b-4ba2-8bff-5bced483ac46" = "Evercontact"
    "20a23a2f-8c32-4de7-8063-8c8f909602c0" = "Workflow"
    "aaf214cc-8013-4b95-975f-13203ae36039" = "PowerBITiles"
    "d88a361a-d488-4271-a13f-a83df7dd99c2" = "IDMLGraphResolverServiceandCAD"
    "dff9b531-6290-4620-afce-26826a62a4e7" = "DocuSign"
    "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9" = "DeviceRegistrationService"
    "3290e3f7-d3ac-4165-bcef-cf4874fc4270" = "Smartsheet"
    "a4ee6867-8640-4495-b1fd-8b26037a5bd3" = "Workflow"
    "aa0e3dd4-df02-478d-869e-fc61dd71b6e8" = "Workflow"
    "0f6edad5-48f2-4585-a609-d252b1c52770" = "AIGraphClient"
    "0c8139b5-d545-4448-8d2b-2121bb242680" = "BillingExtension"
    "475226c6-020e-4fb2-8a90-7a972cbfc1d4" = "KratosAppsService"
    "39624784-6cbe-4a60-afbe-9f46d10fdb27" = "SkypeForBusinessRemotePowershell"
    "8bdebf23-c0fe-4187-a378-717ad86f6a53" = "ResourceHealthRP"
    "c161e42e-d4df-4a3d-9b42-e7a3c31f59d4" = "MicrosoftIntuneAPI"
    "9cb77803-d937-493e-9a3b-4b49de3f5a74" = "MicrosoftIntuneServiceDiscovery"
    "ddbf3205-c6bd-46ae-8127-60eb93363864" = "MicrosoftAzureBatch"
    "80ccca67-54bd-44ab-8625-4b79c4dc7775" = "ComplianceCenter"
    "0a5f63c0-b750-4f38-a71c-4fc0d58b89e2" = "MicrosoftMobileApplicationManagement"
    "e1335bb1-2aec-4f92-8140-0e6e61ae77e5" = "CIWebService"
    "75018fbe-21fe-4a57-b63c-83252b5eaf16" = "TeamImprover-TeamOrganizationChart"
    "a393296b-5695-4463-97cb-9fa8638a494a" = "MySharePointSites"
    "fe217466-5583-431c-9531-14ff7268b7b3" = "MicrosoftEducation"
    "5bfe8a29-054e-4348-9e7a-3981b26b125f" = "BingPlacesforBusiness"
    "eaf8a961-f56e-47eb-9ffd-936e22a554ef" = "DevilFish"
    "4b4b1d56-1f03-47d9-a0a3-87d4afc913c9" = "Wunderlist"
    "00000003-0000-0000-c000-000000000000" = "MicrosoftGraph"
    "60e6cd67-9c8c-4951-9b3c-23c25a2169af" = "ComputeResourceProvider"
    "507bc9da-c4e2-40cb-96a7-ac90df92685c" = "Office365Reports"
    "09abbdfd-ed23-44ee-a2d9-a627aa1c90f3" = "ProjectWorkManagement"
    "28ec9756-deaf-48b2-84d5-a623b99af263" = "OfficePersonalAssistantatWorkService"
    "9e4a5442-a5c9-4f6f-b03f-5b9fcaaf24b1" = "OfficeServicesManager"
    "3138fe80-4087-4b04-80a6-8866c738028a" = "SharePointNotificationService"
    "d2a0a418-0aac-4541-82b2-b3142c89da77" = "MicrosoftAzureOperationalInsights"
    "2cf9eb86-36b5-49dc-86ae-9a63135dfa8c" = "AzureTrafficManagerandDNS"
    "32613fc5-e7ac-4894-ac94-fbc39c9f3e4a" = "OAuthSandbox"
    "925eb0d0-da50-4604-a19f-bd8de9147958" = "GroupiesWebService"
    "e4ab13ed-33cb-41b4-9140-6e264582cf85" = "AzureSQLDatabaseBackupToAzureBackupVault"
    "ad230543-afbe-4bb4-ac4f-d94d101704f8" = "ApiaryforPowerBI"
    "11cd3e2e-fccb-42ad-ad00-878b93575e07" = "AutomatedCallDistribution"
    "de17788e-c765-4d31-aba4-fb837cfff174" = "SkypeforBusinessManagementReportingandAnalytics"
    "65d91a3d-ab74-42e6-8a2f-0add61688c74" = "MicrosoftApprovalManagement"
    "5225545c-3ebd-400f-b668-c8d78550d776" = "OfficeAgentService"
    "1cda9b54-9852-4a5a-96d4-c2ab174f9edf" = "O365Account"
    "4747d38e-36c5-4bc3-979b-b0ef74df54d1" = "PushChannel"
    "b97b6bd4-a49f-4a0c-af18-af507d1da76c" = "OfficeShreddingService"
    "d4ebce55-015a-49b5-a083-c84d1797ae8c" = "MicrosoftIntuneEnrollment"
    "5b20c633-9a48-4a5f-95f6-dae91879051f" = "AzureInformationProtection"
    "441509e5-a165-4363-8ee7-bcf0b7d26739" = "EnterpriseAgentPlatform"
    "e691bce4-6612-4025-b94c-81372a99f77e" = "Boomerang"
    "8edd93e1-2103-40b4-bd70-6e34e586362d" = "WindowsAzureSecurityResourceProvider"
    "94c63fef-13a3-47bc-8074-75af8c65887a" = "OfficeDelve"
    "e95d8bee-4725-4f59-910d-94d415da51b9" = "SkypeforBusinessNameDictionaryService"
    "e3c5dbcd-bb5f-4bda-b943-adc7a5bbc65e" = "Workflow"
    "8602e328-9b72-4f2d-a4ae-1387d013a2b3" = "AzureAPIManagement"
    "8b3391f4-af01-4ee8-b4ea-9871b2499735" = "O365SecureScore"
    "c26550d6-bc82-4484-82ca-ac1c75308ca3" = "Office365YammerOnOls"
    "33be1cef-03fb-444b-8fd3-08ca1b4d803f" = "OneDriveWeb"
    "dcad865d-9257-4521-ad4d-bae3e137b345" = "MicrosoftSharePointOnline-SharePointHome"
    "b2cc270f-563e-4d8a-af47-f00963a71dcd" = "OneProfileService"
    "4660504c-45b3-4674-a709-71951a6b0763" = "MicrosoftInvitationAcceptancePortal"
    "ba23cd2a-306c-48f2-9d62-d3ecd372dfe4" = "OfficeGraph"
    "d52485ee-4609-4f6b-b3a3-68b6f841fa23" = "On-PremisesDataGatewayConnector"
    "996def3d-b36c-4153-8607-a6fd3c01b89f" = "Dynamics365forFinancials"
    "b6b84568-6c01-4981-a80f-09da9a20bbed" = "MicrosoftInvoicing"
    "9d3e55ba-79e0-4b7c-af50-dc460b81dca1" = "MicrosoftAzureDataCatalog"
    "4345a7b9-9a63-4910-a426-35363201d503" = "O365SuiteUX"
    "ac815d4a-573b-4174-b38e-46490d19f894" = "Workflow"
    "bb8f18b0-9c38-48c9-a847-e1ef3af0602d" = "Microsoft.Azure.ActiveDirectoryIUX"
    "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe" = "MicrosoftTeamsServices"
    "5e3ce6c0-2b1f-4285-8d4b-75ee78787346" = "SkypeTeams"
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264" = "MicrosoftTeams"
    "6d32b7f8-782e-43e0-ac47-aaad9f4eb839" = "PermissionServiceO365"
    "cdccd920-384b-4a25-897d-75161a4b74c1" = "SkypeTeamsFirehose"
    "1c0ae35a-e2ec-4592-8e08-c40884656fa5" = "SkypeTeamSubstrateconnector"
    "cf6c77f8-914f-4078-baef-e39a5181158b" = "SkypeTeamsSettingsStore"
    "64f79cb9-9c82-4199-b85b-77e35b7dcbcb" = "MicrosoftTeamsBots"
    "b7912db9-aa33-4820-9d4f-709830fdd78f" = "ConnectionsService"
    "82f77645-8a66-4745-bcdf-9706824f9ad0" = "PowerAppsRuntimeService"
    "6204c1d1-4712-4c46-a7d9-3ed63d992682" = "MicrosoftFlowPortal"
    "7df0a125-d3be-4c96-aa54-591f83ff541c" = "MicrosoftFlowService"
    "331cc017-5973-4173-b270-f0042fddfd75" = "PowerAppsService"
    "0a0e9e37-25e3-47d4-964c-5b8237cad19a" = "CloudSponge"
    "df09ff61-2178-45d8-888c-4210c1c7b0b2" = "O365UAPProcessor"
    "8338dec2-e1b3-48f7-8438-20c30a534458" = "ViewPoint"
    "00000001-0000-0000-c000-000000000000" = "AzureESTSService"
    "394866fc-eedb-4f01-8536-3ff84b16be2a" = "MicrosoftPeopleCardsService"
    "0a0a29f9-0a25-49c7-94bf-c53c3f8fa69d" = "CortanaExperiencewithO365"
    "bb2a2e3a-c5e7-4f0a-88e0-8e01fd3fc1f4" = "CPIMService"
    "0004c632-673b-4105-9bb6-f3bbd2a927fe" = "PowerAppsandFlow"
    "d3ce4cf8-6810-442d-b42e-375e14710095" = "GraphExplorer"
    "3aa5c166-136f-40eb-9066-33ac63099211" = "O365CustomerMonitoring"
    "d6fdaa33-e821-4211-83d0-cf74736489e1" = "MicrosoftServiceTrust"
    "ef4a2a24-4b4e-4abf-93ba-cc11c5bd442c" = "Edmodo"
    "b692184e-b47f-4706-b352-84b288d2d9ee" = "Microsoft.MileIQ.RESTService"
    "a25dbca8-4e60-48e5-80a2-0664fdb5c9b6" = "Microsoft.MileIQ"
    "f7069a8d-9edc-4300-b365-ae53c9627fc4" = "Microsoft.MileIQ.Dashboard"
    "02e3ae74-c151-4bda-b8f0-55fbf341de08" = "ApplicationRegistrationPortal"
    "1f5530b3-261a-47a9-b357-ded261e17918" = "AzureMulti-FactorAuthConnector"
    "981f26a1-7f43-403b-a875-f8b09b8cd720" = "AzureMulti-FactorAuthClient"
    "6ea8091b-151d-447a-9013-6845b83ba57b" = "ADHybridHealth"
    "fc68d9e5-1f76-45ef-99aa-214805418498" = "AzureADIdentityProtection"
    "01fc33a7-78ba-4d2f-a4b7-768e336e890e" = "MS-PIM"
    "a6aa9161-5291-40bb-8c5c-923b567bee3b" = "StorageResourceProvider"
    "4e9b8b9a-1001-4017-8dd1-6e8f25e19d13" = "AdobeAcrobat"
    "159b90bb-bb28-4568-ad7c-adad6b814a2f" = "LastPass"
    "b4bddae8-ab25-483e-8670-df09b9f1d0ea" = "Signup"
    "aa580612-c342-4ace-9055-8edee43ccb89" = "MicrosoftStaffHub"
    "51133ff5-8e0d-4078-bcca-84fb7f905b64" = "MicrosoftTeamsMailhook"
    "ab3be6b7-f5df-413d-ac2d-abf1e3fd9c0b" = "MicrosoftTeamsGraphService"
    "b1379a75-ce5e-4fa3-80c6-89bb39bf646c" = "MicrosoftTeamsChatAggregator"
    "48af08dc-f6d2-435f-b2a7-069abd99c086" = "Connectors"
    "d676e816-a17b-416b-ac1a-05ad96f43686" = "Workflow"
    "cfa8b339-82a2-471a-a3c9-0fc0be7a4093" = "AzureKeyVault"
    "c2f89f53-3971-4e09-8656-18eed74aee10" = "calendly"
    "6da466b6-1d13-4a2c-97bd-51a99e8d4d74" = "ExchangeOfficeGraphClientforAAD-Interactive"
    "0eda3b13-ddc9-4c25-b7dd-2f6ea073d6b7" = "MicrosoftFlowCDSIntegrationService"
    "eacba838-453c-4d3e-8c6a-eb815d3469a3" = "MicrosoftFlowCDSIntegrationServiceTIP1"
    "4ac7d521-0382-477b-b0f8-7e1d95f85ca2" = "SQLServerAnalysisServicesAzure"
    "b4114287-89e4-4209-bd99-b7d4919bcf64" = "OfficeDelve"
    "4580fd1d-e5a3-4f56-9ad1-aab0e3bf8f76" = "CallRecorder"
    "a855a166-fd92-4c76-b60d-a791e0762432" = "MicrosoftTeamsVSTS"
    "c37c294f-eec8-47d2-b3e2-fc3daa8f77d3" = "Workflow"
    "fc75330b-179d-49af-87dd-3b1acf6827fa" = "AzureAutomationAADPatchS2S"
    "766d89a4-d6a6-444d-8a5e-e1a18622288a" = "OneDrive"
    "f16c4a38-5aff-4549-8199-ee7d3c5bd8dc" = "Workflow"
    "4c4f550b-42b2-4a16-93f9-fdb9e01bb6ed" = "TargetedMessagingService"
    "765fe668-04e7-42ba-aec0-2c96f1d8b652" = "ExchangeOfficeGraphClientforAAD-Noninteractive"
    "0130cc9f-7ac5-4026-bd5f-80a08a54e6d9" = "AzureDataWarehousePolybase"
    "a1cf9e0a-fe14-487c-beb9-dd3360921173" = "Meetup"
    "76cd24bf-a9fc-4344-b1dc-908275de6d6d" = "AzureSQLVirtualNetworktoNetworkResourceProvider"
    "9f505dbd-a32c-4685-b1c6-72e4ef704cb0" = "AmazonAlexa"
    "1e2ca66a-c176-45ea-a877-e87f7231e0ee" = "MicrosoftB2BAdminWorker"
    "2634dd23-5e5a-431c-81ca-11710d9079f4" = "MicrosoftStreamService"
    "cf53fce8-def6-4aeb-8d30-b158e7b1cf83" = "MicrosoftStreamPortal"
    "c9a559d2-7aab-4f13-a6ed-e7e9c52aec87" = "MicrosoftForms"
    "978877ea-b2d6-458b-80c7-05df932f3723" = "MicrosoftTeamsAuditService"
    "dbc36ae1-c097-4df9-8d94-343c3d091a76" = "ServiceEncryption"
    "fa7ff576-8e31-4a58-a5e5-780c1cd57caa" = "OneNote"
    "cb4dc29f-0bf4-402a-8b30-7511498ed654" = "PowerBIPremium"
    "f5aeb603-2a64-4f37-b9a8-b544f3542865" = "MicrosoftTeamsRetentionHookService"
    "da109bdd-abda-4c06-8808-4655199420f8" = "GlipContacts"
    "76c7f279-7959-468f-8943-3954880e0d8c" = "AzureSQLManagedInstancetoMicrosoft.Network"
    "3a9ddf38-83f3-4ea1-a33a-ecf934644e2d" = "ProtectedMessageViewer"
    "5635d99c-c364-4411-90eb-764a511b5fdf" = "ResponsiveBannerSlider"
    "a43e5392-f48b-46a4-a0f1-098b5eeb4757" = "Cloudsponge"
    "d73f4b35-55c9-48c7-8b10-651f6f2acb2e" = "MCAPIAuthorizationProd"
    "166f1b03-5b19-416f-a94b-1d7aa2d247dc" = "OfficeHive"
    "b815ce1c-748f-4b1e-9270-a42c1fa4485a" = "Workflow"
    "bd7b778b-4aa8-4cde-8d90-8aeb821c0bd2" = "Workflow"
    "9d06afd9-66c9-49a6-b385-ea7509332b0b" = "O365SBRMService"
    "9ea1ad79-fdb6-4f9a-8bc3-2b70f96e34c7" = "Bing"
    "57fb890c-0dab-4253-a5e0-7188c88b2bb4" = "SharePointOnlineClient"
    "45c10911-200f-4e27-a666-9e9fca147395" = "drawio"
    "b73f62d0-210b-4396-a4c5-ea50c4fab79b" = "SkypeBusinessVoiceFraudDetectionandPrevention"
    "bc59ab01-8403-45c6-8796-ac3ef710b3e3" = "OutlookOnlineAdd-inApp"
    "035f9e1d-4f00-4419-bf50-bf2d87eb4878" = "AzureMonitorRestricted"
    "7c33bfcb-8d33-48d6-8e60-dc6404003489" = "NetworkWatcher"
    "a0be0c72-870e-46f0-9c49-c98333a996f7" = "AzureDnsFrontendApp"
    "1e3e4475-288f-4018-a376-df66fd7fac5f" = "NetworkTrafficAnalyticsService"
    "7557eb47-c689-4224-abcf-aef9bd7573df" = "SkypeforBusiness"
    "c39c9bac-9d1f-4dfb-aa29-27f6365e5cb7" = "AzureAdvisor"
    "2087bd82-7206-4c0a-b305-1321a39e5926" = "MicrosoftTo-Do"
    "f8d98a96-0999-43f5-8af3-69971c7bb423" = "iOSAccounts"
    "c27373d3-335f-4b45-8af9-fe81c240d377" = "P2PServer"
    "5c2ffddc-f1d7-4dc3-926e-3c1bd98e32bd" = "RITSDev"
    "982bda36-4632-4165-a46a-9863b1bbcf7d" = "O365Demeter"
    "98c8388a-4e86-424f-a176-d1288462816f" = "OfficeFeedProcessors"
    "bf9fc203-c1ff-4fd4-878b-323642e462ec" = "JarvisTransactionService"
    "257601fd-462f-4a21-b623-7f719f0f90f4" = "CentralizedDeployment"
    "2a486b53-dbd2-49c0-a2bc-278bdfc30833" = "CortanaatWorkService"
    "22d7579f-06c2-4baa-89d2-e844486adb9d" = "CortanaatWorkBingServices"
    "4c8f074c-e32b-4ba7-b072-0f39d71daf51" = "IPSubstrate"
    "a164aee5-7d0a-46bb-9404-37421d58bdf7" = "MicrosoftTeamsAuthSvc"
    "354b5b6d-abd6-4736-9f51-1be80049b91f" = "MicrosoftMobileApplicationManagementBackend"
    "82b293b2-d54d-4d59-9a95-39c1c97954a7" = "TasksinaBox"
    "fdc83783-b652-4258-a622-66bc85f1a871" = "FedExPackageTracking"
    "d0597157-f0ae-4e23-b06c-9e65de434c4f" = "MicrosoftTeamsTaskService"
    "f5c26e74-f226-4ae8-85f0-b4af0080ac9e" = "ApplicationInsightsAPI"
    "57c0fc58-a83a-41d0-8ae9-08952659bdfd" = "AzureCosmosDBVirtualNetworkToNetworkResourceProvider"
    "744e50be-c4ff-4e90-8061-cd7f1fabac0b" = "LinkedInMicrosoftGraphConnector"
    "823dfde0-1b9a-415a-a35a-1ad34e16dd44" = "MicrosoftTeamsWikiImagesMigration"
    "3ab9b3bc-762f-4d62-82f7-7e1d653ce29f" = "MicrosoftVolumeLicensing"
    "44eb7794-0e11-42b6-800b-dc31874f9f60" = "Alignable"
    "c58637bb-e2e1-4312-8a00-04b5ffcd3403" = "SharePointOnlineClientExtensibility"
    "62b732f7-fc71-40bc-b27d-35efcb0509de" = "MicrosoftTeamsAadSync"
    "07978fee-621a-42df-82bb-3eabc6511c26" = "SurveyMonkey"
    "47ee738b-3f1a-4fc7-ab11-37e4822b007e" = "AzureADApplicationProxy"
    "00000007-0000-0000-c000-000000000000" = "DynamicsCRMOnline"
    "913c6de4-2a4a-4a61-a9ce-945d2b2ce2e0" = "DynamicsLifecycleservices"
    "f217ad13-46b8-4c5b-b661-876ccdf37302" = "AttachOneDrivefilestoAsana"
    "00000008-0000-0000-c000-000000000000" = "Microsoft.Azure.DataMarket"
    "9b06ebd4-9068-486b-bdd2-dac26b8a5a7a" = "Microsoft.DynamicsMarketing"
    "e8ab36af-d4be-4833-a38b-4d6cf1cfd525" = "MicrosoftSocialEngagement"
    "8909aac3-be91-470c-8a0b-ff09d669af91" = "MicrosoftParatureDynamicsCRM"
    "71234da4-b92f-429d-b8ec-6e62652e50d7" = "MicrosoftCustomerEngagementPortal"
    "b861dbcc-a7ef-4219-a005-0e4de4ea7dcf" = "DataExportServiceforMicrosoftDynamics365"
    "2db8cb1d-fb6c-450b-ab09-49b6ae35186b" = "MicrosoftDynamicsCRMLearningPath"
    "2e49aa60-1bd3-43b6-8ab6-03ada3d9f08b" = "DynamicsDataIntegration"
    "d1ddf0e4-d672-4dae-b554-9d5bdfd93547" = "Microsoft Intune Powershell"
}

# Get Conditional Access Policies
$conditionalAccessPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
#Get Conditional Access Named / Trusted Locations
$namedLocations = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop
# Get Azure AD Directory Role Templates
$directoryRoleTemplates = Get-MgDirectoryRoleTemplate -ErrorAction Stop
# Get Azure AD Service Principals
$servicePrincipals = Get-MgServicePrincipal -All -ErrorAction Stop
# Init report
$conditionalAccessDocumentation = @()

# Process all Conditional Access Policies
foreach ($conditionalAccessPolicy in $conditionalAccessPolicies) {

    # Display some progress (based on policy count)
    $currentIndex = $conditionalAccessPolicies.indexOf($conditionalAccessPolicy)
    Write-Progress -Activity "Generating Conditional Access Documentation..." -PercentComplete (($currentIndex + 1) / $conditionalAccessPolicies.Count * 100) `
        -CurrentOperation "Processing Policy '$($conditionalAccessPolicy.DisplayName)' ($currentIndex/$($conditionalAccessPolicies.Count))"

    try {
        # Resolve object ID's of included users
        $includeUsers = @()
        $conditionalAccessPolicy.Conditions.Users.IncludeUsers | ForEach-Object {
            if (Test-Guid $PSItem) {
                $includeUsers += Get-MgUser -userId $PSItem | Select-Object -ExpandProperty DisplayName -ErrorAction Stop
            }
            else {
                $includeUsers += $PSItem
            }
        }
        # Resolve object ID's of excluded users
        $excludeUsers = @()
        $conditionalAccessPolicy.Conditions.Users.ExcludeUsers | ForEach-Object {
            if (Test-Guid $PSItem) {
                $excludeUsers += Get-MgUser -userId $PSItem | Select-Object -ExpandProperty DisplayName -ErrorAction Stop
            }
            else {
                $excludeUsers += $PSItem
            }
        }
        # Resolve object ID's of included groups
        $includeGroups = @()
        $conditionalAccessPolicy.Conditions.Users.IncludeGroups | ForEach-Object {
            $includeGroups += Get-MgGroup -GroupId $PSItem | Select-Object -ExpandProperty DisplayName
        }
        # Resolve object ID's of excluded groups
        $excludeGroups = @()
        $conditionalAccessPolicy.Conditions.Users.ExcludeGroups | ForEach-Object {
            $excludeGroups += Get-MgGroup -GroupId $PSItem | Select-Object -ExpandProperty DisplayName
        }
        # Resolve object ID's of included roles
        $includeRoles = @()
        $conditionalAccessPolicy.Conditions.Users.IncludeRoles | ForEach-Object {
            $roleId = $PSItem
            $includeRoles += $directoryRoleTemplates | Where-Object { $PSItem.Id -eq $roleId } | Select-Object -ExpandProperty DisplayName
        }
        # Replace role display names if all selected
        $maxRoles = 56
        if ($includeRoles.Count -eq $maxRoles) {
            $includeRoles = "All ($maxRoles)"
        }
        # Resolve object ID's of excluded roles
        $excludeRoles = @()
        $conditionalAccessPolicy.Conditions.Users.ExcludeRoles | ForEach-Object {
            $roleId = $PSItem
            $excludeRoles += $directoryRoleTemplates | Where-Object { $PSItem.Id -eq $roleId } | Select-Object -ExpandProperty DisplayName
        }
        # Resolve object ID's of included apps
        $includeApps = @()
        $conditionalAccessPolicy.Conditions.Applications.IncludeApplications | ForEach-Object {
            $servicePrincipalId = $PSItem
            if (Test-Guid $PSItem) {
                $res = $servicePrincipals | Where-Object { $PSItem.AppId -eq $servicePrincipalId } | Select-Object -ExpandProperty DisplayName
                if ($null -ne $res) {
                    $includeApps += $res
                }
                else {

                    $res = $lookupTable[$servicePrincipalId]

                    if ($null -ne $res) {
                        $includeApps += $res
                    }
                    else {
                        $includeApps += $servicePrincipalId
                    }
                }
            }
            else {
                $includeApps += $servicePrincipalId
            }
        }
        # Resolve object ID's of excluded apps
        $excludeApps = @()
        $conditionalAccessPolicy.Conditions.Applications.ExcludeApplications | ForEach-Object {
            $servicePrincipalId = $PSItem
            if (Test-Guid $PSItem) {
                $res = $servicePrincipals | Where-Object { $PSItem.AppId -eq $servicePrincipalId } | Select-Object -ExpandProperty DisplayName
                if ($null -ne $res) {
                    $excludeApps += $res
                }
                else {

                    $res = $lookupTable[$servicePrincipalId]

                    if ($null -ne $res) {
                        $excludeApps += $res
                    }
                    else {
                        $excludeApps += $servicePrincipalId
                    }
                }
            }
            else {
                $excludeApps += $servicePrincipalId
            }
        }
        # Resolve object ID's of included locations
        $includeLocations = @()
        $conditionalAccessPolicy.Conditions.Locations.IncludeLocations | ForEach-Object {
            $locationId = $PSItem
            if (Test-Guid $PSItem) {
                $includeLocations += $namedLocations | Where-Object { $PSItem.Id -eq $locationId } | Select-Object -ExpandProperty DisplayName
            }
            else {
                $includeLocations += $locationId
            }
        }
        # Resolve object ID's of excluded locations
        $excludeLocations = @()
        $conditionalAccessPolicy.Conditions.Locations.ExcludeLocations | ForEach-Object {
            $locationId = $PSItem
            if (Test-Guid $PSItem) {
                $excludeLocations += $namedLocations | Where-Object { $PSItem.Id -eq $locationId } | Select-Object -ExpandProperty DisplayName
            }
            else {
                $excludeLocations += $locationId
            }
        }

        # delimiter for arrays in csv report
        $separator = "`r`n"

        # Build custom object with properties
        $entry = [PSCustomObject]@{

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

            IncludeDeviceStates             = $conditionalAccessPolicy.Conditions.Devices.IncludeDeviceStates -join $separator
            ExcludeDeviceStates             = $conditionalAccessPolicy.Conditions.Devices.ExcludeDeviceStates -join $separator

            GrantControls                   = $conditionalAccessPolicy.GrantControls.BuiltInControls -join $separator
            GrantControlsOperator           = $conditionalAccessPolicy.GrantControls.Operator

            SignInRiskLevels                = $conditionalAccessPolicy.Conditions.SignInRiskLevels -join $separator
            UserRiskLevels                  = $conditionalAccessPolicy.Conditions.UserRiskLevels -join $separator

            ApplicationEnforcedRestrictions = $conditionalAccessPolicy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled
            CloudAppSecurity                = $conditionalAccessPolicy.SessionControls.CloudAppSecurity.IsEnabled
            PersistentBrowser               = $conditionalAccessPolicy.SessionControls.PersistentBrowser.Mode
            SignInFrequency                 = "$($conditionalAccessPolicy.SessionControls.SignInFrequency.Value) $($conditionalAccessPolicy.SessionControls.SignInFrequency.Type)"
        }
        # Add entry to report
        $conditionalAccessDocumentation += $entry
    }
    catch {
        Write-Error $PSItem
    }
}

# Build export path (script directory)
$exportPath = Join-Path $PSScriptRoot "ConditionalAccessDocumentation.csv"
# Export report as csv
$conditionalAccessDocumentation | Export-Csv -Path $exportPath -NoTypeInformation

Write-Output "Exported Documentation to '$($exportPath)'"