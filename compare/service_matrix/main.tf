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
data "aws_ecs_clusters" "clusters" {}
data "aws_lambda_functions" "functions" {}
data "aws_instances" "instances" {}
data "aws_cloudwatch_log_groups" "logs" {}
data "aws_sqs_queues" "queues" {}
data "aws_secretsmanager_secrets" "secrets" {}
data "aws_security_groups" "security_groups" {}
data "aws_dynamodb_tables" "tables" {}
data "aws_vpcs" "vpcs" {}
data "aws_route53_zones" "zones" {}
output "example_id" { value = "service_matrix" }
output "estimated_cost" { value = "$0.00" }
output "resource_count" { value = length(data.aws_ecs_clusters.clusters.arns) + length(data.aws_lambda_functions.functions.function_names) + length(data.aws_instances.instances.ids) + length(data.aws_cloudwatch_log_groups.logs.log_group_names) + length(data.aws_sqs_queues.queues.queue_urls) + length(data.aws_secretsmanager.secrets.arns) + length(data.aws_security_groups.security_groups.ids) + length(data.aws_dynamodb_tables.tables.names) + length(data.aws_vpcs.vpcs.ids) + length(data.aws_route53_zones.zones.names) }
output "comparison_note" { value = "S3, SSM and SNS inventory data sources are unavailable in provider 5.100.0; IAM and alarm portions are skipped/unsupported." }
