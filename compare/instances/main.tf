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
output "example_id" { value = "instances" }
output "estimated_cost" { value = "$0.00" }
output "resource_count" { value = length(data.aws_instances.all.ids) }

data "aws_instances" "running" { instance_state_names = ["running"] }
data "aws_instances" "stopped" { instance_state_names = ["stopped"] }
output "comparison" { value = { running = length(data.aws_instances.running.ids), stopped = length(data.aws_instances.stopped.ids) } }
