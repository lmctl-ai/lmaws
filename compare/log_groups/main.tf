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

data "aws_cloudwatch_log_groups" "all" {}
output "example_id" { value = "log_groups" }
output "estimated_cost" { value = "$0.00" }
output "resource_count" { value = length(data.aws_cloudwatch_log_groups.all.log_group_names) }

output "comparison" { value = { alarms = null, log_groups = length(data.aws_cloudwatch_log_groups.all.log_group_names) } }
