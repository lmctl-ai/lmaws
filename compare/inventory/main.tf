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
data "aws_instances" "all" {
  instance_state_names = ["pending", "running", "shutting-down", "stopping", "stopped", "terminated"]
}
data "aws_vpcs" "all" {}
data "aws_security_groups" "all" {}
output "example_id" { value = "inventory" }
output "estimated_cost" { value = "$0.00" }
output "resource_count" { value = length(data.aws_instances.all.ids) + length(data.aws_vpcs.all.ids) + length(data.aws_security_groups.all.ids) }
output "comparison_note" { value = "AWS provider 5.100.0 lacks an aws_s3_buckets inventory data source; S3 portion is explicitly unsupported." }

output "comparison" { value = { buckets = null, instances = length(data.aws_instances.all.ids), security_groups = length(data.aws_security_groups.all.ids), vpcs = length(data.aws_vpcs.all.ids) } }
