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
data "aws_sqs_queues" "all" {}
output "example_id" { value = "resource_graph" }
output "estimated_cost" { value = "$0.00" }
output "resource_count" { value = length(data.aws_lambda_functions.all.function_names) + length(data.aws_sqs_queues.all.queue_urls) }
output "comparison_note" { value = "AWS provider 5.100.0 lacks an S3 bucket inventory data source; Lambda/SQS graph inputs are represented." }

output "comparison" { value = { buckets = null, functions = length(data.aws_lambda_functions.all.function_names), queues = length(data.aws_sqs_queues.all.queue_urls) } }
