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

resource "aws_s3_bucket" "bucket" {
  bucket = "lmaws-${var.run_id}-sample"
  tags   = { lmaws_test = var.run_id }
}
resource "aws_s3_object" "object" {
  bucket  = aws_s3_bucket.bucket.id
  key     = "tiny.txt"
  content = "lmaws tiny example object"
}

output "example_id" { value = "bucket_objects" }
output "estimated_cost" { value = "$0.0001" }
output "resource_count" { value = "2" }
