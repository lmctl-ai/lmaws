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
data "aws_instances" "all" {
  instance_state_names = ["pending", "running", "shutting-down", "stopping", "stopped", "terminated"]
}
output "example_id" { value = "clusters" }
output "estimated_cost" { value = "$0.00" }
output "resource_count" { value = length(data.aws_ecs_clusters.all.cluster_arns) + length(data.aws_instances.all.ids) }

output "comparison" { value = { clusters = length(data.aws_ecs_clusters.all.cluster_arns), instances = length(data.aws_instances.all.ids) } }
