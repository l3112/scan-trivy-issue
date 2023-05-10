resource "aws_s3_bucket" "par-522" {
  bucket = "par-422"
}

resource "aws_s3_bucket_acl" "s3_bucket_acl" {
  bucket = aws_s3_bucket.s3_bucket.bucket
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_bucket_server_side_encryption_configuration" {
  bucket = aws_s3_bucket.s3_bucket.bucket
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
