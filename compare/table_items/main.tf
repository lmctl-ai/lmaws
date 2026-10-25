terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.100.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "run_id" {
  type = string
}

resource "aws_dynamodb_table" "table" {
  name         = "lmaws_${var.run_id}_sample"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  attribute {
    name = "pk"
    type = "S"
  }
  tags = { lmaws_test = var.run_id }
}
resource "aws_dynamodb_table_item" "item" {
  table_name = aws_dynamodb_table.table.name
  hash_key   = "pk"
  item       = jsonencode({ pk = { S = "pk" }, value = { S = "example-item" } })
}

output "example_id" { value = "table_items" }
output "estimated_cost" { value = "$0.0001" }
output "resource_count" { value = "2" }
