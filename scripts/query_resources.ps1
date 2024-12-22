# Authenticate to Azure (GitHub Action already logs in with azure/login)
#$resourceGroupName = "my-resource-group"
#$existingResourceGroup = Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue

# Prepare Terraform variables

#$tfVars = @{
#    resource_group_name = $resourceGroupName
#    resource_group_exists = $false
#}

#if ($existingResourceGroup) {
#    Write-Host "Resource Group '$resourceGroupName' already exists."
#    $tfVars.resource_group_exists = $true
#}

# Save variables to terraform.tfvars.json
#$tfVars | ConvertTo-Json -Depth 10 | Set-Content -Path "./terraform.tfvars.json" -Encoding UTF8
#Write-Host "Generated terraform.tfvars.json."

###########################################################################################################


Set-Location $PSScriptRoot;

#Load needed modules
. .\HelperFunctions.ps1;
Import-Module -Name exec-query -Force #force reloads if it's already loaded
Import-Module -Name New-SqlConnection -Force; #force reloads if it's already loaded
#Import-Module -Name .\CreateSqlServerLogin.ps1 -Force #force reloads if it's already loaded

Import-Module BMQRAuthentication
Import-Module BMQRAuth0
Import-Module SqlServer -WarningAction SilentlyContinue -DisableNameChecking
Import-Module DBAFunctions -force
Import-Module AzureRunbooks -force
#Import-Module Sqlps -WarningAction SilentlyContinue -DisableNameChecking


#######################################
#Variables
#######################################

$customerID = Read-Host "What is the customerID?";
$customerID = $customerID.ToLower()
$customerName = Read-Host "What is the Customer Name?";
$customerSN = Read-Host "Enter the Customer Serial Number"   

$environmentTypes = "PRODUCTION","VALIDATION","DEVELOPMENT","TESTING"
$environmentType = $environmentTypes | Out-GridView -Title "Select the Customer Environment Type" -PassThru
#db mail profiles are called the same as the $environmenttype FYI

$deploymentModes = "BPT","NO_BPT"
$deploymentMode = $deploymentModes | Out-GridView -Title "What deployment mode of R4 are you deploying?" -PassThru

$customertypes = "CLOUD_ESSENTIALS","CLOUD_BP_CONFIG","CLOUD"
$customertype = $customertypes | Out-GridView -Title "Select the Customer Type" -PassThru

$auth0ConnectionName = "coolblue-waad"
#if (($result = Read-Host "Enter the Auth0 Connection name to use for the CLOUD AUTHENTICATION source or press enter to accept default value `"$auth0ConnectionName`"") -eq '') {$auth0ConnectionName} else {$auth0ConnectionName= $result } 

#set cloud essentials to development caption

if($customertype -eq "CLOUD_ESSENTIALS"){
$caption = "DEVELOPMENT"
#$caption = $environmentType 
}else{
$caption = $environmentType}


$applicationEnvironment = $caption
#$applicationEnvironment = "DEMO 1 INSTANCE"
$applicationEnvironmentBackground = "#5e6a71"

$applicationDatabaseName = $customerID + "_RAMDB";
$tenantName = $customerName;
$subDomain = $customerID;

$systemBuildMode = $false;
#$bmqrTenantID = "d6ed1c6e-9709-4bbb-a7bf-e9ec567574bc"

$subscriptionNames = "BMQR-BPT-DEVELOPMENT","BMQR-BPT-PRODUCTION", "OTHER"
$subscriptionName = $subscriptionNames | Out-GridView -Title "Select the Subscription Name" -PassThru
if($subscriptionName -eq "Other")
  {
  $OtherSub = "Y"
  $subscriptionName = Read-Host "Enter the Subscription Name"
  }

$region = "eastus"
if (($result = Read-Host "Which region are your resource groups in? or press enter to accept default value `"$region`"") -eq '') {$region} else {$region= $result }

$regAbbrev = "eus"
if (($result = Read-Host "Enter the region abbrev for $region or press enter to accept default value `"$regAbbrev`"") -eq '') {$regAbbrev} else {$regAbbrev= $result }

<#
$resourceGroups= Get-AzResourceGroup -Location $region | Select-Object ResourceGroupName | Sort-Object ResourceGroupName 
$resourceGroup = $resourceGroups | Out-GridView -Title "Select the Resource Group Name for shared resources (i.e. BMQR)" -PassThru
$resourceGroup = $resourceGroup.ResourceGroupName
#>
$resourceGroup = "BMQR"


Add-BmqrAuthentication($subscriptionName)

Select-AzSubscription -Subscription $subscriptionName -Tenant $azureTenantid
Set-AzContext -Subscription $subscriptionName

$appEnvResourceGroups = Get-AzResourceGroup -Location $region  | Select-Object ResourceGroupName | Sort-Object ResourceGroupName.ResourceGroupName 
$appEnvResourceGroup = $appEnvResourceGroups | Sort-Object ResourceGroupName.ResourceGroupName | Out-GridView -Title "What is the App Environment Resource Group Name? (e.g., 'dev-r4-636-testa-eus-rg-01')" -PassThru 
$appEnvResourceGroup = $appEnvResourceGroup.ResourceGroupName   

$appGatewayName = (Get-AzResource -ResourceType Microsoft.Network/applicationGateways -resourceGroup $appEnvResourceGroup | Select-Object Name).Name | Out-GridView -Title "Select the App Gateway Name (select only one!)" -PassThru

if($subscriptionName -eq "BMQR-BPT-DEVELOPMENT")
    {$DNSZone = "bluemountainsoftware.com"
     $auth0tenant = "bluemountainsoftware.auth0.com"
     $issuer = "https://bluemountainsoftware.auth0.com/"
     $mobileBundleIdentifier = "bluemountain"
     $keyvault = "BMQRKeyVaultDev"
     $subAbbrev = "DEV"
     $isproduction = "0"
     $DNSsubscription = "BMQR-BPT-PRODUCTION"
     $SA = "sharedwebcontent"
     $bmqradminPasswordSecret = "bmqradminDEV"
     $isDevelopmentEnvironment = $true
     $clusterTargetsFile = "`.\ClusterTargetsR4_DEV.txt"
     $tenantDatabaseServer = "r4-01-eus-azsqlserver-bmqrdev.database.windows.net"
     $tenantDBlogin = "bmqrdevadmin"
     $bmqrTenantDBUserPasswordSecret = "bmqrdevTenantDBUserPassword"
     $customError502Url = "https://bmqrtest.blob.core.windows.net/maintenancealert/index.html"
     $apimgtsvcName = "r4-01-eus-apimgtsvc-01" 
     $apimgtsvcURL = "https://r4-01-eus-apimgtsvc-01.azure-api.net"
     $servicebusName = "r4-01-eus-servicebus"
     $automationAccount = "CloudAutomation"
    }
 if($subscriptionName -eq "BMQR-BPT-PRODUCTION")
    {$DNSZone = "coolbluecloud.com"
     $auth0tenant = "coolbluecloud.auth0.com"
     $issuer = "https://coolbluecloud.auth0.com/"
     $mobileBundleIdentifier = "bluemountain"
     $keyvault = "BMQRKeyVault"
     $subAbbrev = "PROD"
     $isproduction = "1"
     $DNSsubscription = "BMQR-BPT-PRODUCTION"
     $SA = "bmqrdatastorage"
     $bmqradminPasswordSecret = "bmqradminPROD"
     $isDevelopmentEnvironment = $false
     $clusterTargetsFile = "`.\ClusterTargetsR4.txt"
     $tenantDatabaseServer = "r4-01-eus-azsqlserver-bmqrprod.database.windows.net"
     $tenantDBlogin = "bmqrprodadmin"
     $bmqrTenantDBUserPasswordSecret = "bmqrprodTenantDBUserPassword"
     $customError502Url = "https://bmqrfiles.blob.core.windows.net/maintenancealert/index.html"
     $apimgtsvcName = "r4-01-eus-apimgtsvc-02" 
     $apimgtsvcURL = "https://r4-01-eus-apimgtsvc-02.azure-api.net"
     $servicebusName = "r4-01-eus-01-servicebus"
     $automationAccount = "CloudAutomationPROD"
    }


$subAbbrevLower = $subAbbrev.ToLower()


#find cluster from bmramcontrol, and the server info

$ControlDatabase = "BMRAMControl"
$access_token = (Get-AzAccessToken -ResourceUrl https://database.windows.net).Token
$query = "select ClusterNamePrefix from tblclusters where ApplicationGroup = 'R4'"
$clusterNames = invoke-sqlcmd -ServerInstance $tenantDatabaseServer -Database $ControlDatabase -AccessToken $access_token -Query $query

$SourceCluster = $clusterNames | Out-GridView -PassThru -Title "What Cluster does the customer reside on?"
$clusterPrefix = "Cluster-" + $SourceCluster.ClusterNamePrefix
$clusterPrefixInfo =  $SourceCluster.ClusterNamePrefix

$storageAccount = Get-AzStorageAccount -ResourceGroupName $resourceGroup -Name $backupDestAccount 
#define variables by reading cluster targets table for R4
$tableName = "ClusterTargets"
$context = $storageAccount.Context
$cloudTable = (Get-AzStorageTable -Name $tableName -Context $context).CloudTable
$row = Get-AzTableRow -Table $cloudTable | Where-Object{$_.ClusterNamePrefix -eq $SourceCluster.ClusterNamePrefix}
$ag = $row.AvailabilityGroup
$primarySvr = $row.PrimarySvr 
$secondarySvr = $row.SecondarySvr 
$listener = $row.ListenerName
$tenantListenerIP = $row.ListenerIP
$targetRptSvrURL = $row.ReportServerURL

Set-Location $PSScriptRoot;

Get-WebConfigApiToken -tenant $auth0tenant -vaultName $keyvault
Get-InstallationApiToken -tenant $auth0tenant -vaultName $keyvault

#Select-AzSubscription -Subscription $subscriptionName -Tenant $azureTenantid
$logDate = Get-Date -UFormat "%d%b%Y_%T" | ForEach-Object  { $_ -replace ":", "_" }
$logfile = "\DeployLog_" + $customerID + "_" + $logDate + ".txt"
Write-Output "R4 deploy logfile name is " $logfile

$LogfileStorageAccountName = $SA
$LogileSharename = "\\$Global:backupDestAccount.file.core.windows.net\$Global:fileShare"
$LogfileFolder = Join-Path -Path "H:\" -ChildPath "CustomerDeployments" | Join-Path -ChildPath $customerID

if( -Not (Test-Path -Path $LogfileFolder ) )
{
    New-Item -ItemType directory -Path $LogfileFolder
}

$LogfileStorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $resourceGroup -AccountName  $LogfileStorageAccountName)| Where-Object {$_.KeyName -eq "key1"}
$LogfileStorageAccountKey  = $LogfileStorageAccountKey.Value

$logfile = $LogfileFolder + $logfile
$logfileDate = Get-date

$domainController="ad-primary-dc"
$subnetName = $clusterPrefixInfo + "SqlSubnet"
$applicationDatabaseServer = $primarySvr
$tenantDatabaseName = "Tenant";
$landingDatabaseName = "Landing";
$managementDatabaseAccountLogin = "bmqradmin"
$managementDatabaseAccountLoginPassword = (Get-AzKeyVaultSecret -VaultName $vaultName -Name $bmqradminPasswordSecret ).SecretValue
$managementDatabaseAccountLoginPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($managementDatabaseAccountLoginPassword)) 
$managementDatabaseAccountLoginDomain = $null;
$TenantDatabaseAccountLoginPassword = (Get-AzKeyVaultSecret -VaultName $vaultName -Name $bmqrTenantDBUserPasswordSecret ).SecretValue
$TenantDatabaseAccountLoginPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($TenantDatabaseAccountLoginPassword)) 
$TenantDatabaseAccountLoginDomain = $null;
$r4AppUser = $clusterPrefixInfo + "_ramapp"
$r4ClusterAppUserPasswordSecret = $clusterPrefixInfo + "R4AppUserPassword"
$r4AppUserPassword = (Get-AzKeyVaultSecret -VaultName $vaultName -Name $r4ClusterAppUserPasswordSecret ).SecretValue
$r4AppUserPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($r4AppUserPassword)) 
$serviceAccountLogin = $r4AppUser;
$serviceAccountLoginPassword = $r4ClusterAppUserPasswordSecret
$serviceAccountLoginDomain = $null;
$databaseOwnerAccountDomain = $null;
$databaseOwnerAccount = "RamDatabaseOwner";
$reportUserLogin = "rpt$(Get-RandomCharacters -length 17 -characters 'abcdefghiklmnoprstuvwxyzABCDEFGHKLMNOPRSTUVWXYZ1234567890')";  #this is the report user on the datasource (SQL authentication)
$reportUserLoginPassword = (Get-AzKeyVaultSecret -VaultName $vaultName -Name ReportUserPassword ).SecretValue
$reportUserLoginPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($reportUserLoginPassword)) 
$loginlessUser = "usr$(Get-RandomCharacters -length 17 -characters 'abcdefghiklmnoprstuvwxyzABCDEFGHKLMNOPRSTUVWXYZ1234567890')";
$tenantApiKey = "$(Get-RandomCharacters -length 64 -characters 'abcdefghiklmnoprstuvwxyzABCDEFGHKLMNOPRSTUVWXYZ1234567890!@#$%^&*()_+~`{}|[]\:;<>?,./')";


$continueOnError = $false;
$ilbname = $clusterPrefixInfo + "-sql-ilb"
$ilbfeip = $clusterPrefixInfo + "-sql-ilbfe1"
$slb = Get-AzLoadBalancer -Name $ilbname -ResourceGroupName $resourcegroup
$connectionStringServerIp = $slb.FrontendIpConfigurations.PrivateIpAddress
$uriScheme = "https"
$uriHost = $servicebusName + ".servicebus.windows.net"
$uriPort = $null;
$uriPath = "messages"
$uriQuerystring = "messagetimeout=60"
$uriFragment = $null;
$httpVerb = "POST";
$requestHeaders = "<headers><header><name>Accept-Encoding</name><value>gzip, deflate</value></header><header><name>Cache-Control</name><value>no-cache</value></header><header><name>ContentType</name><value>application/json</value></header></headers>";
$serviceBusNamespace = $uriHost 
$serviceBusAccessPolicy = "SendSharedAccessKey";
$accessPolicyKey = Get-AzServiceBusKey -ResourceGroupName $resourcegroup -Namespace $servicebusName -Name $serviceBusAccessPolicy 
$accessPolicyKey = $accessPolicyKey.PrimaryKey
$accessTokenLifetime = "600";


$applicationDatabaseConnection=$null;
$tenantDatabaseConnection=$null;
$serverUrl = "https://$($subdomain)" + "." + $DNSZone;
$recordsPerPage = 50;


$BMQRAuthenticationSourceID = "CLOUD AUTHENTICATION"
$BMQRAuthenticationSourceName = "CLOUD AUTHENTICATION"
$BMQRPersonnelID = "BMQRAdmin"
$BMQRPersonnelName ="BMQR Admin User"
$BMQRPersonnelInitialWorkspaceID = "DefaultSystemWorkspace"
$BMQRPersonnelScopeID = "SYSTEM"
$BMQRPersonnelFirstName = "BMQR"
$BMQRPersonnelLastName = "Admin User"
$groupMemberships=$null
$groupMemberships+= ,(@("ADMINISTRATORS","SYSTEM"))
$groupMemberships+= ,(@("bpt_2.BatchUpdateAdministrator","SYSTEM"))
$CustomerAuthenticationSourceID = $customerID.ToUpper() + " CLOUD AUTHENTICATION";
$CustomerAuthenticationSourceName = $customerID.ToUpper() + " CLOUD AUTHENTICATION";
$BMQRPMPersonnelID = "BMQRPM"
$BMQRPMPersonnelName ="BMQR Project Manager"
$BMQRPMPersonnelFirstName = "BMQR"
$BMQRPMPersonnelLastName = "Project Manager"
$authenticationType = "AUTHCLOUD"
$remoteAccessRegistry = $true
$remoteAccessRegistryCustomer = $false
$BMQRAnalystPersonnelID = "BMQRAnalyst"
$BMQRAnalystPersonnelName ="BMQR Analyst"
$BMQRAnalystPersonnelFirstName = "BMQR"
$BMQRAnalystPersonnelLastName = "Analyst"
$BMQRAnalyst2PersonnelID = "BMQRAnalyst2"
$BMQRAnalyst2PersonnelName ="BMQR Analyst 2"
$BMQRAnalyst2PersonnelFirstName = "BMQR"
$BMQRAnalyst2PersonnelLastName = "Analyst2"
$BMQRAnalyst3PersonnelID = "BMQRAnalyst3"
$BMQRAnalyst3PersonnelName ="BMQR Analyst 3"
$BMQRAnalyst3PersonnelFirstName = "BMQR"
$BMQRAnalyst3PersonnelLastName = "Analyst3"
$authenticationPropertyMapsToAdd=$null
$authenticationPropertyMapsToAdd+= ,(@("Email","Email"))
$authenticationPropertyMapsToAdd+= ,(@("Given Name","FirstName"))
$authenticationPropertyMapsToAdd+= ,(@("Family Name","LastName"))
$authenticationPropertyMapsToAdd+= ,(@("Full Name","Name"))


$authGrantEmailMailFormat = "HTML"
$authGrantEmailImportance = "Normal"

$authGrantEmailMessageSubject = $customerName + " (" + $customerID + ") Remote Assistance Request has been Submitted";
$authGrantEmailMessageBody = "
Attention:

$customerName ($customerID) has provided an authorization grant for remote assistance.  

Please review the following details of this request:

Customer Name: $customerName
CustomerID: $customerID
Serial Number:  $customerSN
Customer URL: $serverUrl

Entered By:
Requestor email:
Expiration Date:
Comments:


"
$authGrantEmailRecipients = "BMQRRemoteAssistance@coolblue.com";
$authGrantEmailBCCRecipients = "";





$reportingUserID  = $reportUserLogin; #this is the domain report user that will have browser rights for reports, Windows authentication
$reportingUserDomain = "bmqr.local"
$reportingUserPassword = $reportUserLoginPassword

$URL = "http://$tenantListenerIP/reportserver" 
$reportServer = $URL






$authorizationGrantID = "InitialInstallGrant";
$authorizationGrantName = "Initial Install Grant";
$expirationDate = (Get-Date).AddDays(730).ToString("yyyy-MM-dd") #2 year login grant
$comments = "Authorization Grant to allow BMQR users to access the system following initial installation"


$deployVersion="6.3.6"   #this correlates to a folder in H:\deploymentsource
if (($result = Read-Host "What version of the RAMDB are you deploying or press enter to accept default value `"$deployVersion`"") -eq '') {$deployVersion} else {$deployVersion= $result } 
$bmramDB = "$customerID`_RAMDB"
$deployRootDir = "C:\"
$deployRootDirH = "H:\"
$deploySourceRootDir= Join-Path -Path $deployRootDirH -ChildPath "DeploymentSource"  #changed to H
$deploySourceDir= Join-Path -Path $deployRootDirH -ChildPath "DeploymentSource" | Join-Path -ChildPath $deployVersion\DB  #changed to H:\DeploymentSource\R3SR0\DB
$deployScriptDir= Join-Path -Path $deployRootDir -ChildPath "DeploymentScripts"
$deployReportDir= Join-Path -Path $deployRootDirH -ChildPath "CustomerDeployments"  #changed from C to H
$deployReportSourceDir= Join-Path -Path $deployRootDirH -ChildPath "DeploymentSource" | Join-Path -ChildPath $deployVersion\Reports



$webAppResourceType = "Microsoft.Web/sites"
$ramWebApps = (Get-AzResource -ResourceGroupName $appEnvResourceGroup -ResourceType $webAppResourceType | Where-Object{$_.Name -like "*-ram-*"}).Name
$ramWebApp = $ramWebApps | Out-GridView -Title "Select the Ram Web App for the Customer" -PassThru; Write-Output $ramWebApp

$signalrWebApps = (Get-AzResource -ResourceGroupName $appEnvResourceGroup -ResourceType $webAppResourceType | Where-Object{$_.Name -like "*-signalr-*"}).Name
$signalrWebApp = $signalrWebApps | Out-GridView -Title "Select the SignalR Web App for the Customer" -PassThru; Write-Output $signalrWebApp

$webAPIWebApps = (Get-AzResource -ResourceGroupName $appEnvResourceGroup -ResourceType $webAppResourceType | Where-Object{$_.Name -like "*-webapi-*"}).Name
$webAPIWebApp = $webAPIWebApps | Out-GridView -Title "Select the WebAPI Web App for the Customer" -PassThru; Write-Output $webAPIWebApp

$ramreportsWebApps = (Get-AzResource -ResourceGroupName $appEnvResourceGroup -ResourceType $webAppResourceType | Where-Object{$_.Name -like "*-ramreports-*"}).Name
$ramreportsWebApp = $ramreportsWebApps | Out-GridView -Title "Select the RamReports Web App for the Customer" -PassThru; Write-Output $ramreportsWebApp

$serviceBusTopics = (Get-AzServiceBusTopic -ResourceGroupName $resourceGroup -Namespace $serviceBusName | Where-Object{$_.Name -like "*-automations-*"}).Name
$serviceBusTopic = $serviceBusTopics | Out-GridView -Title "Select the Automation topic to use" -PassThru; Write-Output $serviceBusTopic        

$batchServiceBusTopics = (Get-AzServiceBusTopic -ResourceGroupName $resourceGroup -Namespace $serviceBusName | Where-Object{$_.Name -like "*-batch-*"}).Name
$batchServiceBusTopic = $batchServiceBusTopics | Out-GridView -Title "Select the Batch topic to use" -PassThru; Write-Output $batchServiceBusTopic        

$notificationServiceBusTopics = (Get-AzServiceBusTopic -ResourceGroupName $resourceGroup -Namespace $serviceBusName | Where-Object{$_.Name -like "*-notifications-*"}).Name
$notificationBusTopic = $notificationServiceBusTopics | Out-GridView -Title "Select the Notifications topic to use" -PassThru; Write-Output $notificationBusTopic  
$controlMessageTopic = $notificationBusTopic


$BMQRAdminUser = Read-Host "Enter Your Personal Microsoft username (i.e. user@coolblue.com)"
$DNSTenantID = $azureTenantID
Connect-AzAccount -Identity
Select-AzSubscription -Subscription $DNSSubscription -Tenant $azureTenantid
Set-AzContext -Subscription $DNSSubscription

$aliasGateway = $appGatewayName + "." + $DNSZone

$BMQRPMUser = Read-Host "What is the username (i.e. username@coolblue.com) of the Blue Mountain Project Manager for this customer?"

sleep 5

###############################################

# Passing the variables to tfvars for terraform 

################################################

$tfVars = @{
    customerID                  =       $customerID
    customerName                =       $customerName
    customerSN                  =       $customerSN
    
}

if ($existingResourceGroup) {
    Write-Host "Resource Group '$resourceGroupName' already exists."
    $tfVars.resource_group_exists = $true
}

# Save variables to terraform.tfvars.json
$tfVars | ConvertTo-Json -Depth 10 | Set-Content -Path "./terraform.tfvars.json" -Encoding UTF8
Write-Host "Generated terraform.tfvars.json."