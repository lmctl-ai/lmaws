terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.100.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "run_id" {
  type = string
}

resource "aws_sqs_queue" "queue" {
  name = "lmaws_${var.run_id}_pipeline"
  tags = { lmaws_test = var.run_id }
}

output "example_id" { value = "queue_pipeline" }
output "estimated_cost" { value = "$0.0001" }
output "resource_count" { value = "1" }
