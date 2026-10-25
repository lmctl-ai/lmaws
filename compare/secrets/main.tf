terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.100.0"
    }
  }
}
provider "aws" { region = "us-east-1" }

data "aws_secretsmanager_secrets" "all" {}
output "example_id" { value = "secrets" }
output "estimated_cost" { value = "$0.00" }
output "resource_count" { value = length(data.aws_secretsmanager_secrets.all.arns) }

output "comparison" { value = { secrets = length(data.aws_secretsmanager_secrets.all.arns) } }
