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
data "aws_sqs_queues" "all" {}
output "example_id" { value = "topics" }
output "estimated_cost" { value = "$0.00" }
output "resource_count" { value = length(data.aws_sqs_queues.all.queue_urls) }
output "comparison_note" { value = "AWS provider 5.100.0 lacks a generic SNS topic-list data source; native SNS topics query is unsupported." }

output "comparison" { value = { queues = length(data.aws_sqs_queues.all.queue_urls), topics = null } }
