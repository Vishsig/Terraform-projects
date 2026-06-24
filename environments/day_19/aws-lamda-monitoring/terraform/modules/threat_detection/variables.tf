variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
}

variable "source_log_group_name" {
  description = "Name of the CloudWatch log group to monitor (image processor Lambda)"
  type        = string
}

variable "source_log_group_arn" {
  description = "ARN of the CloudWatch log group to monitor"
  type        = string
}

variable "threat_detector_zip_path" {
  description = "Path to the threat detector Lambda function zip file"
  type        = string
}

variable "threat_detector_source_hash" {
  description = "Base64-encoded SHA256 hash of the threat detector zip"
  type        = string
}

variable "security_alert_email" {
  description = "Email address for receiving security threat alerts"
  type        = string
  default     = ""
}

variable "security_alert_sms" {
  description = "Phone number for critical security SMS alerts (format: +1234567890)"
  type        = string
  default     = ""
}

variable "security_metric_namespace" {
  description = "CloudWatch metrics namespace for security metrics"
  type        = string
  default     = "ImageProcessor/Security"
}

variable "log_level" {
  description = "Log level for the threat detector Lambda (DEBUG, INFO, WARNING, ERROR)"
  type        = string
  default     = "INFO"
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days for the threat detector"
  type        = number
  default     = 7
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}
