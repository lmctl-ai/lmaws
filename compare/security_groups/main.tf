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

data "aws_security_groups" "all" {}
data "aws_security_group" "details" {
  for_each = toset(data.aws_security_groups.all.ids)
  id       = each.value
}
locals {
  public = length([for group in data.aws_security_group.details : group.id if anytrue(flatten([for rule in group.ingress : [contains(rule.cidr_blocks, "0.0.0.0/0"), contains(rule.ipv6_cidr_blocks, "::/0")]]))])
}
output "comparison" { value = { public = local.public, private = length(data.aws_security_groups.all.ids) - local.public } }
output "example_id" { value = "security_groups" }
output "estimated_cost" { value = "$0.00" }
