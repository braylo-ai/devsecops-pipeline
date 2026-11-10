# Fixed infrastructure. Skips carry a written reason; every other check passes.
provider "aws" {
  region = "us-east-1"
}

resource "aws_kms_key" "data" {
  description         = "payments data key"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.kms.json
}

data "aws_caller_identity" "me" {}

data "aws_iam_policy_document" "kms" {
  # In a KMS key policy, "*" means "this key". AWS documents this default policy.
  #checkov:skip=CKV_AWS_111:Key policy resource "*" is scoped to this key by AWS.
  #checkov:skip=CKV_AWS_356:Key policy resource "*" is scoped to this key by AWS.
  #checkov:skip=CKV_AWS_109:Account root admin statement is the AWS default key policy.
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.me.account_id}:root"]
    }
  }
}

resource "aws_s3_bucket" "exports" {
  #checkov:skip=CKV_AWS_144:Cross-region replication is out of scope for a single-region demo.
  #checkov:skip=CKV2_AWS_62:Event notifications are not needed for this bucket.
  bucket = "demo-payments-exports"
}

resource "aws_s3_bucket_versioning" "exports" {
  bucket = aws_s3_bucket.exports.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_logging" "exports" {
  bucket        = aws_s3_bucket.exports.id
  target_bucket = "demo-central-access-logs"
  target_prefix = "exports/"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "exports" {
  bucket = aws_s3_bucket.exports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "exports" {
  bucket = aws_s3_bucket.exports.id
  rule {
    id     = "expire-exports"
    status = "Enabled"
    filter {}
    expiration { days = 90 }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_s3_bucket_public_access_block" "exports" {
  bucket                  = aws_s3_bucket.exports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "app" {
  name        = "app"
  description = "App tier: HTTPS from the internal load balancer only"
  vpc_id      = "vpc-00000000000000000"

  ingress {
    description = "HTTPS from internal LB subnet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
  }

  egress {
    description = "HTTPS to VPC endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_db_instance" "payments" {
  identifier                          = "payments"
  engine                              = "postgres"
  engine_version                      = "16.4"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  username                            = "payments"
  manage_master_user_password         = true
  publicly_accessible                 = false
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.data.arn
  multi_az                            = true
  backup_retention_period             = 7
  deletion_protection                 = true
  iam_database_authentication_enabled = true
  auto_minor_version_upgrade          = true
  copy_tags_to_snapshot               = true
  monitoring_interval                 = 60
  monitoring_role_arn                 = "arn:aws:iam::000000000000:role/rds-monitoring"
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = aws_kms_key.data.arn
  enabled_cloudwatch_logs_exports     = ["postgresql", "upgrade"]
  vpc_security_group_ids              = [aws_security_group.app.id]
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "payments-final"
}
