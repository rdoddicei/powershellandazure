output "resource_group_name" {
  value = var.resource_group_name
}

output "storage_account_name" {
  value = azurerm_storage_account.example.name
}
