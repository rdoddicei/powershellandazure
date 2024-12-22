# Variables acptured in tfvars will be updated and passed on here
# Defining Variables for Terraform

variable "access_token" {
  description = "The access token"
  type        = string
}

variable "accessPolicyKey" {
  description = "The access policy key"
  type        = string
}

variable "accessTokenLifetime" {
  description = "Lifetime of the access token"
  type        = string
}

variable "ag" {
  description = "AG variable"
  type        = string
}

variable "aliasGateway" {
  description = "Alias Gateway"
  type        = string
}

variable "apimgtsvcName" {
  description = "API Management Service name"
  type        = string
}

variable "apimgtsvcURL" {
  description = "API Management Service URL"
  type        = string
}

variable "appEnvResourceGroup" {
  description = "App Environment Resource Group"
  type        = string
}

variable "appGatewayName" {
  description = "Application Gateway name"
  type        = string
}

variable "applicationDatabaseConnection" {
  description = "Connection string for the application database"
  type        = string
  default     = null
}

variable "applicationDatabaseName" {
  description = "Name of the application database"
  type        = string
}

variable "applicationDatabaseServer" {
  description = "Server for the application database"
  type        = string
}

variable "auth0ConnectionName" {
  description = "Auth0 Connection Name"
  type        = string
}

variable "auth0tenant" {
  description = "Auth0 Tenant"
  type        = string
}

variable "authenticationType" {
  description = "Authentication type"
  type        = string
}

variable "authorizationGrantID" {
  description = "Authorization Grant ID"
  type        = string
}

variable "automationAccount" {
  description = "Automation account"
  type        = string
}

variable "batchServiceBusTopic" {
  description = "Batch Service Bus topic"
  type        = string
}

variable "bmqradminPasswordSecret" {
  description = "BMQR Admin password secret"
  type        = string
  sensitive   = true
}

variable "BMQRAdminUser" {
  description = "BMQR Admin User"
  type        = string
}

variable "bmramDB" {
  description = "BM RAM Database"
  type        = string
}

variable "cloudTable" {
  description = "Cloud table"
  type        = string
}

variable "clusterPrefix" {
  description = "Cluster prefix"
  type        = string
}

variable "clusterNames" {
  description = "Cluster names"
  type        = list(string)
}

variable "customerName" {
  description = "Customer name"
  type        = string
}

variable "customerID" {
  description = "Customer ID"
  type        = string
}

variable "deploymentMode" {
  description = "Deployment mode"
  type        = string
}

variable "deployVersion" {
  description = "Deployment version"
  type        = string
  default     = "6.3.6"
}

variable "DNSsubscription" {
  description = "DNS subscription"
  type        = string
}

variable "keyvault" {
  description = "Keyvault name"
  type        = string
}

variable "logfile" {
  description = "Log file location"
  type        = string
}

variable "primarySvr" {
  description = "Primary server"
  type        = string
}

variable "secondarySvr" {
  description = "Secondary server"
  type        = string
}

variable "resourceGroup" {
  description = "Resource Group name"
  type        = string
}

variable "servicebusName" {
  description = "Service Bus Name"
  type        = string
}

variable "signalrWebApp" {
  description = "SignalR Web App"
  type        = string
}

variable "storageAccount" {
  description = "Storage Account Name"
  type        = string
}

variable "subscriptionName" {
  description = "Subscription Name"
  type        = string
}

variable "tenantDatabaseName" {
  description = "Tenant Database name"
  type        = string
}

variable "tenantDatabaseServer" {
  description = "Tenant Database Server"
  type        = string
}

variable "tenantDBlogin" {
  description = "Tenant Database Login"
  type        = string
}

variable "webAPIWebApp" {
  description = "Web API Web App"
  type        = string
}

variable "authenticationPropertyMapsToAdd" {
  description = "Authentication property maps to add"
  type        = list(string)
  default     = []
}

variable "groupMemberships" {
  description = "Group memberships"
  type        = list(string)
  default     = []
}

variable "isDevelopmentEnvironment" {
  description = "Is the environment development?"
  type        = bool
}

variable "isproduction" {
  description = "Is the environment production?"
  type        = bool
}

variable "logfileDate" {
  description = "Log file date"
  type        = string
}

variable "LogfileFolder" {
  description = "Log file folder"
  type        = string
}

variable "LogfileStorageAccountKey" {
  description = "Log file storage account key"
  type        = string
  sensitive   = true
}

variable "LogfileStorageAccountName" {
  description = "Log file storage account name"
  type        = string
}

variable "LogileSharename" {
  description = "Log file share name"
  type        = string
}

variable "managementDatabaseAccountLogin" {
  description = "Management database account login"
  type        = string
}

variable "managementDatabaseAccountLoginDomain" {
  description = "Management database account login domain"
  type        = string
}

variable "managementDatabaseAccountLoginPassword" {
  description = "Management database account login password"
  type        = string
  sensitive   = true
}

variable "mobileBundleIdentifier" {
  description = "Mobile bundle identifier"
  type        = string
}

variable "notificationBusTopic" {
  description = "Notification service bus topic"
  type        = string
}

variable "primarySvr" {
  description = "Primary server for database"
  type        = string
}

variable "query" {
  description = "Query for database operations"
  type        = string
}

variable "r4AppUser" {
  description = "R4 App User"
  type        = string
}

variable "r4AppUserPassword" {
  description = "R4 App User Password"
  type        = string
  sensitive   = true
}

variable "ramreportsWebApp" {
  description = "RAM Reports Web App"
  type        = string
}

variable "ramWebApp" {
  description = "RAM Web App"
  type        = string
}

variable "recordsPerPage" {
  description = "Records per page"
  type        = number
}

variable "region" {
  description = "Region"
  type        = string
}

variable "resourceGroup" {
  description = "Resource group"
  type        = string
}

variable "SA" {
  description = "Storage account"
  type        = string
}

variable "tenantListenerIP" {
  description = "Tenant listener IP"
  type        = string
}

variable "tenantName" {
  description = "Tenant name"
  type        = string
}

variable "tenantDatabaseConnection" {
  description = "Tenant database connection"
  type        = string
}

variable "tenantDBlogin" {
  description = "Tenant DB login"
  type        = string
}

variable "tenantDatabaseServer" {
  description = "Tenant database server"
  type        = string
}

variable "tenantDatabaseName" {
  description = "Tenant database name"
  type        = string
}

variable "webAPIWebApp" {
  description = "Web API Web App"
  type        = string
}

variable "webAppResourceType" {
  description = "Web App Resource Type"
  type        = string
}

variable "dns_zone" {
  description = "The name of the DNS Zone"
  type        = string
}

variable "subdomain" {
  description = "The subdomain for the CNAME record"
  type        = string
}

variable "alias_gateway" {
  description = "The CNAME target (alias gateway)"
  type        = string
}

variable "ttl" {
  description = "The TTL for the CNAME record"
  type        = number
  default     = 3600
}

variable "subscription_id" {
  description = "Azure Subscription ID"
  type        = string
}

variable "tenant_id" {
  description = "Azure Tenant ID"
  type        = string
}

variable "resource_group" {
  description = "The Azure resource group"
  type        = string
}

variable "apim_service_name" {
  description = "Name of the API Management service"
  type        = string
}

variable "customer_id" {
  description = "Customer ID for the API"
  type        = string
}

variable "vault_name" {
  description = "Key Vault Name"
  type        = string
}

variable "webapi_webapp" {
  description = "Web API Web App name"
  type        = string
}

variable "audience" {
  description = "Audience for the API"
  type        = string
}

variable "issuer" {
  description = "Issuer for the API"
  type        = string
}

# SQL query to execute on the SQL secondary server replica
variable "sql_query" {
  description = "SQL query to execute on the SQL secondary server replica"
  type        = string
  default = "
SELECT N'USE Master; CREATE LOGIN ['+sp.[name]+'] WITH PASSWORD=0x'+
       CONVERT(nvarchar(max), l.password_hash, 2)+N' HASHED, CHECK_POLICY=OFF, '+
       N'SID=0x'+CONVERT(nvarchar(max), sp.[sid], 2)+N'; ALTER LOGIN ['+sp.[name]+'] WITH CHECK_EXPIRATION = OFF;' 
FROM master.sys.server_principals AS sp
INNER JOIN master.sys.sql_logins AS l ON sp.[sid]=l.[sid]
WHERE sp.[type]='S' AND sp.is_disabled=0 and sp.name = '${var.report_user_login}'"
}
