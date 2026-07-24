# Positive path for the AMI metadata data source used to validate the UDP proof
# runner architecture. The provider Read calls ec2:DescribeImages.

data "aws_ami" "runner" {
  filter {
    name   = "image-id"
    values = ["ami-0123456789abcdef0"]
  }
}
