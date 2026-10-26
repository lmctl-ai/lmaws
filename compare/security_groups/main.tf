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
data "aws_vpc_security_group_rules" "all" {}
data "aws_vpc_security_group_rule" "details" {
  for_each = toset(data.aws_vpc_security_group_rules.all.ids)
  security_group_rule_id = each.value
}
locals {
  public_ids = toset([for rule in data.aws_vpc_security_group_rule.details : rule.security_group_id
    if !rule.is_egress && (rule.cidr_ipv4 == "0.0.0.0/0" || rule.cidr_ipv6 == "::/0")])
  public = length(setintersection(toset(data.aws_security_groups.all.ids), local.public_ids))
}
output "comparison" { value = { public = local.public, private = length(data.aws_security_groups.all.ids) - local.public } }
output "example_id" { value = "security_groups" }
output "estimated_cost" { value = "$0.00" }
