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
output "example_id" { value = "sweeper" }
output "estimated_cost" { value = "$0.00" }
output "resource_count" { value = 0 }
output "comparison_note" { value = "Native sweeper only inspects local ledgers; no provider resource equivalence exists." }

output "comparison" { value = { leftovers = 0 } }
