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
data "aws_instance" "details" {
  for_each    = toset(data.aws_instances.all.ids)
  instance_id = each.value
}
locals {
  tagged = length([for instance in data.aws_instance.details : instance.id if length(instance.tags) > 0])
}
output "comparison" { value = { tagged = local.tagged, untagged = length(data.aws_instances.all.ids) - local.tagged } }
output "example_id" { value = "tag_compliance" }
output "estimated_cost" { value = "$0.00" }
