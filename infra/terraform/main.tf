# PLANTED FINDINGS (main branch): insecure AWS resources. Never applied.
provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "exports" {
  bucket = "demo-payments-exports"
}

resource "aws_s3_bucket_public_access_block" "exports" {
  bucket                  = aws_s3_bucket.exports.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_security_group" "app" {
  name        = "app"
  description = "app"

  ingress {
    description = "ssh from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "payments" {
  identifier          = "payments"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "payments"
  password            = "PLANTED_FAKE_rds_password_0004"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}
