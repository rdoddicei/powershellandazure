provider "azurerm" {
  features {}
}

variable "resource_group_name" {
  type = string
}

variable "resource_group_exists" {
  type = bool
}

# Conditionally create Resource Group
resource "azurerm_resource_group" "new" {
  count    = var.resource_group_exists ? 0 : 1
  name     = var.resource_group_name
  location = "East US"
}

# Example: Create a new Storage Account
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = var.resource_group_name
  location                 = "East US"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
