connection "csv" {
  plugin    = "csv"
  paths     = ["/data/aws/ec2/*.csv", "/data/aws/inspector2/*.csv"]
  separator = ","
  header    = true
}
