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
data "aws_lambda_functions" "all" {}
data "aws_cloudwatch_log_groups" "all" {}
output "example_id" { value = "functions" }
output "estimated_cost" { value = "$0.00" }
output "resource_count" { value = length(data.aws_lambda_functions.all.function_names) + length(data.aws_cloudwatch_log_groups.all.log_group_names) }

output "comparison" { value = { functions = length(data.aws_lambda_functions.all.function_names), log_groups = length(data.aws_cloudwatch_log_groups.all.log_group_names) } }
