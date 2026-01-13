provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "zero-trust-compliance"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_iam_session_context" "current" {
  issuer_arn = data.aws_caller_identity.current.arn
}

resource "aws_lambda_function" "compliance_scanner" {
  filename         = var.lambda_zip_path
  function_name    = "${var.project_name}-compliance-scanner"
  description      = "Zero-Trust Compliance Scanner Lambda"
  role             = aws_iam_role.lambda_execution.arn
  handler          = "src.api.lambda_handlers.lambda_handler"
  runtime          = "python3.11"
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size
  source_code_hash = filebase64sha256(var.lambda_zip_path)
  
  environment {
    variables = {
      AWS_REGION             = var.aws_region
      CONFIG_S3_BUCKET       = aws_s3_bucket.config_bucket.bucket
      SNS_TOPIC_ARN          = aws_sns_topic.compliance_alerts.arn
      DYNAMODB_TABLE         = aws_dynamodb_table.scan_results.name
      COMPLIANCE_S3_BUCKET   = aws_s3_bucket.reports_bucket.bucket
    }
  }

  vpc_config {
    subnet_ids         = var.vpc_subnet_ids
    security_group_ids = var.vpc_security_group_ids
  }

  tracing_config {
    mode = "Active"
  }

  tags = var.common_tags
}

resource "aws_lambda_function" "ci_cd_scanner" {
  filename         = var.lambda_zip_path
  function_name    = "${var.project_name}-ci-cd-scanner"
  description      = "Zero-Trust CI/CD Compliance Scanner"
  role             = aws_iam_role.lambda_execution.arn
  handler          = "src.api.lambda_handlers.ci_cd_scan_handler"
  runtime          = "python3.11"
  timeout          = 60
  memory_size      = 512
  source_code_hash = filebase64sha256(var.lambda_zip_path)
  
  environment {
    variables = {
      AWS_REGION           = var.aws_region
      COMPLIANCE_DYNAMODB  = aws_dynamodb_table.scan_results.name
    }
  }

  tags = var.common_tags
}

resource "aws_lambda_function" "terraform_scanner" {
  filename         = var.lambda_zip_path
  function_name    = "${var.project_name}-terraform-scanner"
  description      = "Zero-Trust Terraform Scanner"
  role             = aws_iam_role.lambda_execution.arn
  handler          = "src.api.lambda_handlers.terraform_scan_handler"
  runtime          = "python3.11"
  timeout          = 120
  memory_size      = 1024
  source_code_hash = filebase64sha256(var.lambda_zip_path)
  
  environment {
    variables = {
      AWS_REGION         = var.aws_region
      COMPLIANCE_DYNAMODB = aws_dynamodb_table.scan_results.name
    }
  }

  tags = var.common_tags
}

resource "aws_lambda_permission" "allow_s3_invoke" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_scanner.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.terraform_plans.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scheduled_scan.arn
}

resource "aws_cloudwatch_event_rule" "scheduled_scan" {
  name        = "${var.project_name}-daily-scan"
  description = "Triggers daily compliance scan"
  schedule_expression = "cron(0 2 * * ? *)"
  
  tags = var.common_tags
}

resource "aws_cloudwatch_event_target" "scanner_target" {
  rule      = aws_cloudwatch_event_rule.scheduled_scan.name
  target_id = "ComplianceScanner"
  arn       = aws_lambda_function.compliance_scanner.arn
}

resource "aws_sns_topic" "compliance_alerts" {
  name = "${var.project_name}-compliance-alerts"
  
  tags = var.common_tags
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.compliance_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_s3_bucket" "config_bucket" {
  bucket = "${var.project_name}-config-${data.aws_caller_identity.current.account_id}"
  
  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_key {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.compliance_key.arn
      }
    }
  }

  lifecycle_rule {
    enabled = true
    transition {
      days          = 30
      storage_class = "INTELLIGENT_TIERING"
    }
  }

  tags = var.common_tags
}

resource "aws_s3_bucket" "reports_bucket" {
  bucket = "${var.project_name}-reports-${data.aws_caller_identity.current.account_id}"
  
  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_key {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.compliance_key.arn
      }
    }
  }

  lifecycle_rule {
    enabled = true
    expiration {
      days = 365
    }
  }

  tags = var.common_tags
}

resource "aws_s3_bucket" "terraform_plans" {
  bucket = "${var.project_name}-terraform-plans-${data.aws_caller_identity.current.account_id}"
  
  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_key {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.compliance_key.arn
      }
    }
  }

  lifecycle_rule {
    enabled = true
    expiration {
      days = 30
    }
  }

  tags = var.common_tags
}

resource "aws_s3_bucket_notification" "terraform_plan_notification" {
  bucket = aws_s3_bucket.terraform_plans.bucket

  lambda_function {
    lambda_function_arn = aws_lambda_function.terraform_scanner.arn
    events              = ["s3:ObjectCreated:Put"]
    filter_prefix       = "plans/"
  }
}

resource "aws_dynamodb_table" "scan_results" {
  name         = "${var.project_name}-scan-results"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "scan_id"
  
  attribute {
    name = "scan_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  global_secondary_index {
    name            = "provider-timestamp-index"
    hash_key        = "provider"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  server_side_encryption {
    enabled = true
    kms_key_arn = aws_kms_key.compliance_key.arn
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = var.common_tags
}

resource "aws_kms_key" "compliance_key" {
  description             = "KMS key for Zero-Trust Compliance Scanner"
  enable_key_rotation     = true
  key_usage               = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "Enable IAM policies for key management"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "kms:*"
        Resource = "*"
      },
      {
        Sid = "Allow Lambda to use the key"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount": data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = var.common_tags
}

resource "aws_kms_alias" "compliance_key_alias" {
  name          = "alias/${var.project_name}-compliance-key"
  target_key_id = aws_kms_key.compliance_key.key_id
}

resource "aws_iam_role" "lambda_execution" {
  name = "${var.project_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = var.common_tags
}

resource "aws_iam_policy" "lambda_policy" {
  name = "${var.project_name}-lambda-policy"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "s3:Get*",
          "s3:List*",
          "s3:PutObject",
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:Query",
        ]
        Resource = aws_dynamodb_table.scan_results.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
        ]
        Resource = aws_kms_key.compliance_key.arn
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish",
        ]
        Resource = aws_sns_topic.compliance_alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "securityhub:BatchImportFindings",
          "securityhub:GetFindings",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceAccount": data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "sts:AssumeRole",
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.lambda_execution.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

resource "aws_iam_role_policy_attachment" "xray_attachment" {
  role       = aws_iam_role.lambda_execution.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXrayWriteOnlyAccess"
}

output "lambda_function_arn" {
  value = aws_lambda_function.compliance_scanner.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.compliance_scanner.function_name
}

output "reports_bucket_name" {
  value = aws_s3_bucket.reports_bucket.bucket
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.scan_results.name
}

output "sns_topic_arn" {
  value = aws_sns_topic.compliance_alerts.arn
}
