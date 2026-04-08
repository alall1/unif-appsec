resource "aws_s3_bucket_public_access_block" "pab_incomplete" {
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = false
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "logs_bucket" {
  bucket = "demo-unencrypted-logs-bucket"
  # Intentionally missing server_side_encryption_configuration
}
