resource "azurerm_dns_cname_record" "dnsrecord" {
  name                = var.subdomain
  zone_name           = var.dns_zone
  resource_group_name = var.resource_group
  ttl                 = var.ttl
  cname               = var.alias_gateway
}

resource "azurerm_api_management" "example" {
  name                = var.apim_service_name
  location            = "East US"  # Update with your location
  resource_group_name = var.resource_group
  sku_name            = "Developer_1"  # Update as necessary
}

resource "azurerm_api_management_api" "mobile_api" {
  name                = "${var.customer_id}_mobile"
  resource_group_name = var.resource_group
  api_management_name = azurerm_api_management.example.name
  revision            = "1"
  display_name        = "${var.customer_id}-mobile"
  path                = "mobile"
  protocols           = ["https"]

  import {
    content_format = "swagger-link-json"  # Or use the content format you need
    content_value  = "https://${var.webapi_webapp}.azurewebsites.net/api/graphql/SYSTEM"
  }
}

resource "azurerm_key_vault_secret" "mobile_api_signing_key" {
  name         = "MobileWEBAPIAuth0SigningSecret"
  value        = "your-signing-key-value"  # Terraform can be used to create or import the secret, adjust as needed
  key_vault_id = azurerm_key_vault.example.id
}

resource "azurerm_api_management_api_operation" "mobile_api_operation" {
  operation_id        = "mobile-api-graph"
  api_name            = azurerm_api_management_api.mobile_api.name
  api_management_name = azurerm_api_management.example.name
  resource_group_name = var.resource_group
  display_name        = "Mobile API Graph Operation"
  method              = "POST"
  url_template        = "/graphql"
  response {
    status = 200
    description = "Successful Response"
  }
}

resource "azurerm_api_management_api_operation_policy" "example" {
  operation_id        = azurerm_api_management_api_operation.mobile_api_operation.operation_id
  api_name            = azurerm_api_management_api.mobile_api.name
  api_management_name = azurerm_api_management.example.name
  resource_group_name = var.resource_group
  xml_content         = <<XML
<policies>
  <inbound>
    <base />
    <set-variable name="signingKey" value="${azurerm_key_vault_secret.mobile_api_signing_key.value}" />
  </inbound>
</policies>
XML
}

variable "sql_server" {
  description = "The SQL Server name"
  type        = string
}

variable "sql_admin_user" {
  description = "The SQL Server admin username"
  type        = string
}

variable "sql_admin_password" {
  description = "The SQL Server admin password"
  type        = string
  sensitive   = true
}

variable "sql_database" {
  description = "The database to run the queries on"
  type        = string
}

variable "report_user_login" {
  description = "The login name of the user"
  type        = string
}

variable "report_user_password" {
  description = "The password of the AD user"
  type        = string
  sensitive   = true
}

variable "management_database_account_login" {
  description = "SQL Server management account username"
  type        = string
}

variable "management_database_account_login_password" {
  description = "SQL Server management account password"
  type        = string
  sensitive   = true
}

variable "management_database_account_login_domain" {
  description = "Domain of SQL Server management account"
  type        = string
}

variable "secondary_svr" {
  description = "The SQL Server secondary replica"
  type        = string
}

variable "secondary_database_connection" {
  description = "The connection string for the SQL Server secondary replica"
  type        = string
}

variable "application_database_connection" {
  description = "The connection string for the SQL Server primary replica"
  type        = string
}

variable "domain_controller" {
  description = "The domain controller for Active Directory tasks"
  type        = string
}

variable "service_account_login" {
  description = "Service account login for SQL Server"
  type        = string
}

variable "loginlessuser" {
  description = "A retryable login if creation fails"
  type        = string
}

variable "reportuser_login_domain" {
  description = "The domain for report user"
  type        = string
  default = "bmqr"
}

variable "DNSZone" {
  description = "DNS zone for URL configuration"
  type        = string
}

variable "customerID" {
  description = "Customer ID for URL and resource naming"
  type        = string
}

variable "webAPIwebapp" {
  description = "Name of the web API webapp"
  type        = string
}

variable "secondarySvr" {
  description = "SQL Server Secondary Replica"
  type        = string
}

variable "continueOnError" {
  description = "Boolean indicating whether to continue on error"
  type        = bool
  default = false
}

resource "null_resource" "create_sql_login" {
  provisioner "local-exec" {
    command = "sqlcmd -S ${var.sql_server} -U ${var.sql_admin_user} -P ${var.sql_admin_password} -d ${var.sql_database} -Q \"${var.create_sql_login_query}\""
  }
}

variable "create_sql_login_query" {
  description = "The SQL query to create the SQL login"
  type        = string
}

# Task: Create SQL Server SQL login for reports
variable "create_sql_login_query" {
  description = "The SQL query to create the SQL login for reports"
  type        = string
  default = "SELECT N'USE Master; CREATE LOGIN ['+sp.[name]+'] WITH PASSWORD=0x'+
       CONVERT(nvarchar(max), l.password_hash, 2)+N' HASHED, CHECK_POLICY=OFF, '+
       N'SID=0x'+CONVERT(nvarchar(max), sp.[sid], 2)+N'; ALTER LOGIN ['+sp.[name]+'] WITH CHECK_EXPIRATION = OFF;' 
FROM master.sys.server_principals AS sp
INNER JOIN master.sys.sql_logins AS l ON sp.[sid]=l.[sid]
WHERE sp.[type]='S' AND sp.is_disabled=0 and sp.name = '${var.report_user_login}'"
}

# Task: Create SQL Server user AD Windows login
resource "null_resource" "create_sql_windows_login" {
  provisioner "local-exec" {
    command = "sqlcmd -S ${var.sql_server} -U ${var.sql_admin_user} -P ${var.sql_admin_password} -d ${var.sql_database} -Q \"CREATE LOGIN [${var.reportuser_login_domain}\\${var.report_user_login}] FROM WINDOWS\""
  }
}

# Task: Create AD User
resource "null_resource" "create_ad_user" {
  provisioner "local-exec" {
    command = "powershell.exe -ExecutionPolicy Bypass -File ./create_ad_user.ps1 -Username ${var.report_user_login} -Password ${var.report_user_password} -DomainController ${var.domain_controller}"
  }
}

# Task: Execute SQL Query on the secondary SQL server replica
resource "null_resource" "exec_sql_on_secondary_replica" {
  provisioner "local-exec" {
    command = "sqlcmd -S ${var.secondary_svr} -U ${var.sql_admin_user} -P ${var.sql_admin_password} -d master -Q \"${var.sql_query}\""
    environment = [
      "sql_admin_user=${var.management_database_account_login}",
      "sql_admin_password=${var.management_database_account_login_password}",
      "sql_server=${var.secondary_svr}"
    ]
  }
}


# Set Service Bus configuration for service bus integrations 
$parameters = $null;
$parameters = @{restClientconfigurationId=$restClientconfigurationId; integrationRestClientconfigurationId=$integrationRestClientconfigurationId; integrationServiceBusNamespace=$integrationServiceBusNamespace; integrationUriHost=$integrationUriHost; integrationAccessPolicyKey=$integrationAccessPolicyKey};

$sql = "

INSERT INTO BMRAM.RestClientConfigurations
SELECT 	@integrationRestClientConfigurationId restClientconfigurationId
		,uriScheme
		,NULLIF(@integrationUriHost,'') urihost
		,uriPort
		,uriPath
		,uriQuerystring
		,uriFragment
		,httpVerb
		,requestHeaders
		,NULLIF(@integrationServiceBusNamespace,'') serviceBusNamespace
		,NULL
		,serviceBusAccessPolicy
		,NULLIF(@integrationAccessPolicyKey,'') accessPolicyKey
		,accessTokenLifetime
		,NULL
FROM	BMRAM.RestClientConfigurations 
WHERE	RestClientConfigurationID = @restClientconfigurationId;";

exec-query -databaseConnection $applicationDatabaseConnection -sql $sql -parameters $parameters -continueOnError $true;

#set Service Bus Registry Keys
exec-query -databaseConnection $applicationDatabaseConnection -sql "USE $($applicationDatabaseName); EXEC BMRAM.setRegistryKeyValue 'DefaultIntegrationHandlerConfiguration', '$($integrationRestClientconfigurationId)'" -continueOnError $continueOnError;

*