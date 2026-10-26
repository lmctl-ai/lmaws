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
data "aws_ecs_clusters" "all" {}
data "aws_vpcs" "all" {}
data "aws_route53_zones" "all" {}
output "example_id" { value = "regional_posture" }
output "estimated_cost" { value = "$0.00" }
output "resource_count" { value = length(data.aws_ecs_clusters.all.cluster_arns) + length(data.aws_vpcs.all.ids) + length(data.aws_route53_zones.all.ids) }

output "comparison" { value = { clusters = length(data.aws_ecs_clusters.all.cluster_arns), vpcs = length(data.aws_vpcs.all.ids), zones = length(data.aws_route53_zones.all.ids) } }
