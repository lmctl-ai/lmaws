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

resource "aws_ssm_parameter" "parameter" {
  name  = "lmaws_${var.run_id}_lifecycle"
  type  = "String"
  value = "demo"
  tags  = { lmaws_test = var.run_id }
}

output "example_id" { value = "sandbox_lifecycle" }
output "estimated_cost" { value = "$0.00" }
output "resource_count" { value = "1" }
