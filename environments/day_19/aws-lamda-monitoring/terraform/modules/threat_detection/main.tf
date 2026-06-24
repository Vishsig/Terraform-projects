# ============================================================================
# THREAT DETECTION MODULE
# Real-time threat detection using CloudWatch Logs Subscription Filters
# and a dedicated Lambda function for sub-60-second detection
# ============================================================================
#
# Architecture:
#   Image Processor Lambda → CloudWatch Logs → Subscription Filter
#     → Threat Detector Lambda → CloudWatch Metrics + SNS Alerts
#
# Why this achieves sub-60-second detection:
#   CloudWatch Logs subscription filters deliver log events to Lambda
#   in near real-time (typically 2-10 seconds), unlike CloudTrail which
#   has a 5-15 minute delay. The threat detector Lambda analyzes events
#   and publishes alerts within milliseconds.
# ============================================================================

# ============================================================================
# SNS TOPIC FOR SECURITY ALERTS
# ============================================================================

resource "aws_sns_topic" "security_alerts" {
  name         = "${var.project_name}-${var.environment}-security-alerts"
  display_name = "Security Threat Alerts - ${var.project_name}"

  tags = merge(
    var.tags,
    {
      Name      = "${var.project_name}-security-alerts"
      AlertType = "Security"
    }
  )
}

# SNS Topic Policy (allows CloudWatch and Lambda to publish)
resource "aws_sns_topic_policy" "security_alerts_policy" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = ["cloudwatch.amazonaws.com", "lambda.amazonaws.com"]
        }
        Action = [
          "SNS:Publish"
        ]
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

# Email subscription for security alerts
resource "aws_sns_topic_subscription" "security_email" {
  count     = var.security_alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.security_alert_email
}

# Optional SMS subscription for critical security alerts
resource "aws_sns_topic_subscription" "security_sms" {
  count     = var.security_alert_sms != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "sms"
  endpoint  = var.security_alert_sms
}

# ============================================================================
# IAM ROLE FOR THREAT DETECTOR LAMBDA
# ============================================================================

resource "aws_iam_role" "threat_detector_role" {
  name = "${var.project_name}-${var.environment}-threat-detector-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name = "${var.project_name}-threat-detector-role"
    }
  )
}

resource "aws_iam_role_policy" "threat_detector_policy" {
  name = "${var.project_name}-${var.environment}-threat-detector-policy"
  role = aws_iam_role.threat_detector_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.security_alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      }
    ]
  })
}

# ============================================================================
# THREAT DETECTOR LAMBDA FUNCTION
# ============================================================================

# CloudWatch Log Group for the threat detector itself
resource "aws_cloudwatch_log_group" "threat_detector_logs" {
  name              = "/aws/lambda/${var.project_name}-${var.environment}-threat-detector"
  retention_in_days = var.log_retention_days

  tags = merge(
    var.tags,
    {
      Name = "${var.project_name}-threat-detector-logs"
    }
  )
}

# Lambda function for threat detection
resource "aws_lambda_function" "threat_detector" {
  filename         = var.threat_detector_zip_path
  function_name    = "${var.project_name}-${var.environment}-threat-detector"
  role             = aws_iam_role.threat_detector_role.arn
  handler          = "threat_detector.lambda_handler"
  source_code_hash = var.threat_detector_source_hash
  runtime          = "python3.12"
  timeout          = 30  # Short timeout - detection should be fast
  memory_size      = 256 # Lightweight - only log analysis

  environment {
    variables = {
      SECURITY_TOPIC_ARN = aws_sns_topic.security_alerts.arn
      METRIC_NAMESPACE   = var.security_metric_namespace
      LOG_LEVEL          = var.log_level
    }
  }

  tags = merge(
    var.tags,
    {
      Name    = "${var.project_name}-threat-detector"
      Purpose = "Real-time threat detection"
    }
  )

  depends_on = [
    aws_cloudwatch_log_group.threat_detector_logs,
    aws_iam_role_policy.threat_detector_policy
  ]
}

# ============================================================================
# CLOUDWATCH LOGS SUBSCRIPTION FILTER
# This is the KEY component that enables sub-60-second detection.
# It forwards log events from the image processor to the threat detector
# in near real-time (typically 2-10 seconds).
# ============================================================================

# Permission for CloudWatch Logs to invoke the threat detector Lambda
resource "aws_lambda_permission" "allow_cloudwatch_logs" {
  statement_id  = "AllowExecutionFromCloudWatchLogs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.threat_detector.function_name
  principal     = "logs.${var.aws_region}.amazonaws.com"
  source_arn    = "${var.source_log_group_arn}:*"
}

# Subscription filter on the image processor's log group
# Filters for ERROR, WARNING, AccessDenied, and security-relevant patterns
resource "aws_cloudwatch_log_subscription_filter" "threat_detection_filter" {
  name            = "${var.project_name}-${var.environment}-threat-detection"
  log_group_name  = var.source_log_group_name
  filter_pattern  = "?ERROR ?WARNING ?AccessDenied ?\"Access Denied\" ?\"403\" ?\"processing failed\" ?\"Large image detected\""
  destination_arn = aws_lambda_function.threat_detector.arn

  depends_on = [aws_lambda_permission.allow_cloudwatch_logs]
}

# ============================================================================
# SECURITY-SPECIFIC CLOUDWATCH ALARMS
# These alarms monitor the threat detector's own metrics
# ============================================================================

# Alarm: Threats Detected (fires when any threat is found)
resource "aws_cloudwatch_metric_alarm" "threats_detected" {
  alarm_name          = "${var.project_name}-${var.environment}-threats-detected"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ThreatsDetected"
  namespace           = var.security_metric_namespace
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Triggers when the threat detector identifies security threats (sub-60s detection)"
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    DetectorFunction = "threat-detector"
  }

  tags = merge(
    var.tags,
    {
      Name     = "${var.project_name}-threats-detected-alarm"
      Type     = "Security"
      Severity = "Critical"
    }
  )
}

# Alarm: High Detection Latency (alert if detection takes too long)
resource "aws_cloudwatch_metric_alarm" "detection_latency" {
  alarm_name          = "${var.project_name}-${var.environment}-detection-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "DetectionLatencyMs"
  namespace           = var.security_metric_namespace
  period              = 60
  statistic           = "Maximum"
  threshold           = 55000  # Alert if detection exceeds 55 seconds (buffer before 60s target)
  alarm_description   = "Triggers when threat detection latency approaches the 60-second target"
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    DetectorFunction = "threat-detector"
  }

  tags = merge(
    var.tags,
    {
      Name     = "${var.project_name}-detection-latency-alarm"
      Type     = "Security"
      Severity = "Warning"
    }
  )
}

# Alarm: Threat Detector Errors (the detector itself is failing)
resource "aws_cloudwatch_metric_alarm" "detector_errors" {
  alarm_name          = "${var.project_name}-${var.environment}-detector-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Triggers when the threat detection Lambda itself encounters errors"
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.threat_detector.function_name
  }

  tags = merge(
    var.tags,
    {
      Name     = "${var.project_name}-detector-errors-alarm"
      Type     = "Security"
      Severity = "Critical"
    }
  )
}
