# Create config S3 Bucket
resource "aws_s3_bucket" "compliance_bucket" {
  bucket = "${var.project_name}-compliance-bucket-${var.environment}"

  tags = {
    Name        = "My compliance bucket"
    Environment = var.environment
    Description = "Config files"
  }
}

# Enable versioning
resource "aws_s3_bucket_versioning" "compliance_bucket_versioning" {
  bucket = aws_s3_bucket.compliance_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable server side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "compliance_bucket_encryption" {
  bucket = aws_s3_bucket.compliance_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Disbale public access
resource "aws_s3_bucket_public_access_block" "compliance_bucket_public_access_block" {
  bucket = aws_s3_bucket.compliance_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Bucket policy
resource "aws_s3_bucket_policy" "compliance_bucket_policy" {
  bucket = aws_s3_bucket.compliance_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.compliance_bucket.arn
      },
      {
        Sid    = "AWSConfigBucketExistenceCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.compliance_bucket.arn
      },
      {
        Sid    = "AWSConfigBucketPutObject"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.compliance_bucket.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.compliance_bucket.arn,
          "${aws_s3_bucket.compliance_bucket.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.compliance_bucket_public_access_block]
}
