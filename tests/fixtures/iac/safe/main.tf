resource "aws_security_group" "sg_safe" {
  ingress {
    cidr_blocks = ["10.0.0.0/8"]
    ipv6_cidr_blocks = ["2001:db8::/64"]
  }
}

resource "aws_s3_bucket_public_access_block" "pab_safe" {
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "bucket_safe" {
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

