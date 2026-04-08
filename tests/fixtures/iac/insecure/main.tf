resource "aws_security_group" "sg_insecure" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket_public_access_block" "pab_insecure" {
  block_public_acls = false
  block_public_policy = true
  ignore_public_acls = false
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "bucket_insecure" {
  # Missing server_side_encryption_configuration
}

