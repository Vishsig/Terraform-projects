output "threat_detector_function_name" {
  description = "Name of the threat detector Lambda function"
  value       = aws_lambda_function.threat_detector.function_name
}

output "threat_detector_function_arn" {
  description = "ARN of the threat detector Lambda function"
  value       = aws_lambda_function.threat_detector.arn
}

output "threat_detector_log_group_name" {
  description = "CloudWatch log group for the threat detector"
  value       = aws_cloudwatch_log_group.threat_detector_logs.name
}

output "security_alerts_topic_arn" {
  description = "ARN of the security alerts SNS topic"
  value       = aws_sns_topic.security_alerts.arn
}

output "security_alerts_topic_name" {
  description = "Name of the security alerts SNS topic"
  value       = aws_sns_topic.security_alerts.name
}

output "subscription_filter_name" {
  description = "Name of the CloudWatch Logs subscription filter"
  value       = aws_cloudwatch_log_subscription_filter.threat_detection_filter.name
}

output "security_alarm_names" {
  description = "List of all security alarm names"
  value = [
    aws_cloudwatch_metric_alarm.threats_detected.alarm_name,
    aws_cloudwatch_metric_alarm.detection_latency.alarm_name,
    aws_cloudwatch_metric_alarm.detector_errors.alarm_name
  ]
}

output "security_alarm_arns" {
  description = "List of all security alarm ARNs"
  value = [
    aws_cloudwatch_metric_alarm.threats_detected.arn,
    aws_cloudwatch_metric_alarm.detection_latency.arn,
    aws_cloudwatch_metric_alarm.detector_errors.arn
  ]
}
