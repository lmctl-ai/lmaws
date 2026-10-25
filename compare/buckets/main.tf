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
data "aws_dynamodb_tables" "all" {}
output "example_id" { value = "buckets" }
output "estimated_cost" { value = "$0.00" }
output "resource_count" { value = length(data.aws_dynamodb_tables.all.names) }
output "comparison_note" { value = "AWS provider 5.100.0 has no aws_s3_buckets or SSM parameter-list data source; only DynamoDB portion is represented." }

output "comparison" { value = { buckets = null, parameters = null, tables = length(data.aws_dynamodb_tables.all.names) } }
