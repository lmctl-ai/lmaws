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
output "example_id" { value = "parameters" }
output "estimated_cost" { value = "$0.00" }
output "resource_count" { value = length(data.aws_secretsmanager_secrets.all.arns) }
output "comparison_note" { value = "AWS provider 5.100.0 lacks an SSM parameter-list data source; Secrets Manager metadata is represented." }

output "comparison" { value = { parameters = null, secrets = length(data.aws_secretsmanager_secrets.all.arns) } }
