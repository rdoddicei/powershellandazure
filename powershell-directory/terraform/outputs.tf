output "cname_record" {
  description = "The CNAME record created"
  value       = azurerm_dns_cname_record.dnsrecord.fqdn
}

output "apim_service_name" {
  value = azurerm_api_management.example.name
}

output "mobile_api_name" {
  value = azurerm_api_management_api.mobile_api.name
}
