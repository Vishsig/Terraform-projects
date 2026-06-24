# 🖼️ AWS Lambda Image Processor with Comprehensive Monitoring

A production-ready AWS Lambda function for automated image processing with enterprise-grade CloudWatch monitoring, implemented using modular Terraform.

## 📋 Overview

This project demonstrates AWS serverless best practices by combining:
- **Lambda-based image processing** (resize, compress, format conversion)
- **S3 event-driven architecture** (automatic triggering)
- **Comprehensive CloudWatch monitoring** (metrics, alarms, dashboards)
- **SNS alerting** (email/SMS notifications)
- **Modular Terraform** (reusable, maintainable infrastructure)

### What It Does

1. 📤 Upload an image to S3 upload bucket
2. ⚡ Lambda function automatically triggers
3. 🎨 Processes image (creates 5 variants: compressed, low-quality, WebP, PNG, thumbnail)
4. 📥 Saves processed images to destination bucket
5. 📊 Monitors everything with CloudWatch metrics and alarms
6. 📧 Sends alerts via SNS when issues occur

---

## 🏗️ Architecture

```
┌─────────────────┐
│  S3 Upload      │
│  Bucket         │──────┐
└─────────────────┘      │
                         │ S3 Event
                         ▼
                 ┌───────────────┐
                 │  Lambda       │
                 │  Image        │
                 │  Processor    │
                 └───────┬───────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ S3 Processed│  │ CloudWatch  │  │   SNS       │
│   Bucket    │  │   Logs      │  │  Topics     │
└─────────────┘  └──────┬──────┘  └──────┬──────┘
                        │                 │
              ┌─────────┼─────────┐       ▼
              │         │         │ ┌─────────────┐
              ▼         ▼         │ │   Email/    │
       ┌───────────┐ ┌────────┐   │ │    SMS      │
       │ Metrics & │ │Sub.    │   │ └─────────────┘
       │  Alarms   │ │Filter  │   │
       └───────────┘ └───┬────┘   │
                         │ ~2-10s │
                         ▼        │
                 ┌───────────────┐ │
                 │  Threat       │ │
                 │  Detector     │ │
                 │  Lambda       │ │
                 └───────┬───────┘ │
                         │         │
                    ┌────┴────┐    │
                    ▼         ▼    │
             ┌──────────┐ ┌───────────┐
             │ Security │ │   SNS     │
             │ Metrics  │ │ Security  │
             │ & Alarms │ │  Alert    │
             └──────────┘ └─────┬─────┘
                                │
                                ▼
                          ┌───────────┐
                          │  Email/   │
                          │  SMS      │
                          │ (<60 sec) │
                          └───────────┘
```

---

## 🎯 Key Features

### Image Processing
- ✅ Multiple format support (JPEG, PNG, WebP, BMP, TIFF)
- ✅ Automatic format conversion
- ✅ Quality-based compression (85%, 60%)
- ✅ Thumbnail generation (300x300)
- ✅ Large image resizing (max 4096px)
- ✅ Automatic color space conversion

### 🛡️ Real-Time Threat Detection (Sub-60-Second)
- ✅ **CloudWatch Logs Subscription Filter → Lambda pipeline** for near real-time detection
- ✅ **5 Threat Categories Detected**:
  - Rapid-fire errors (brute force / fuzzing attacks)
  - S3 Access Denied patterns (unauthorized access attempts)
  - Suspicious file extensions (malware upload attempts)
  - Injection attempts (path traversal, command injection, XSS)
  - Abnormal payload sizes (DoS / data exfiltration)
- ✅ **Dedicated Security SNS Topic** with email/SMS alerts
- ✅ **3 Security-Specific Alarms**:
  - Threats detected alarm
  - Detection latency alarm (ensures <60s target is met)
  - Detector health alarm
- ✅ **Security Custom Metrics** (ThreatsDetected, EventsAnalyzed, DetectionLatencyMs)
- ✅ **Detailed Alert Messages** with severity, evidence, and recommended actions

### Monitoring & Observability
- ✅ **15 CloudWatch Alarms** (12 existing + 3 security):
  - Error rate monitoring
  - Duration/timeout warnings
  - Throttle detection
  - Memory usage tracking
  - Concurrent execution limits
  - Log-based error patterns
  - **Threat detection alarms**
  
- ✅ **Custom Metrics**:
  - Image processing time
  - Image sizes processed
  - Success/failure rates
  - Business-level insights
  - **Security threat metrics**
  
- ✅ **Comprehensive Dashboard**:
  - Real-time metrics visualization
  - AWS metrics + custom metrics
  - Log insights integration
  - Performance trends
  
- ✅ **Log-Based Alerts**:
  - Timeout detection
  - Memory errors
  - S3 permission issues
  - Image processing failures
  - Critical application errors

### Infrastructure
- ✅ **Modular Terraform** (7 reusable modules)
- ✅ **Security best practices** (IAM least privilege, S3 encryption)
- ✅ **Real-time security monitoring** (sub-60-second threat detection)
- ✅ **Scalable architecture** (auto-scaling Lambda)
- ✅ **Cost-optimized** (pay per use)
- ✅ **Environment-agnostic** (dev/staging/prod)

---

## 📁 Project Structure

```
aws-lamda-monitoring/
├── lambda/
│   ├── lambda_function.py       # Enhanced Lambda with structured logging
│   ├── threat_detector.py       # 🛡️ Real-time threat detection Lambda
│   └── requirements.txt         # Python dependencies (Pillow)
├── scripts/
│   ├── build_layer_docker.sh   # Build Pillow layer using Docker
│   ├── deploy.sh               # Deployment automation
│   └── destroy.sh              # Cleanup script
├── terraform/
│   ├── main.tf                 # Root module orchestration
│   ├── variables.tf            # Input variables
│   ├── outputs.tf              # Output values
│   ├── provider.tf             # AWS provider configuration
│   ├── terraform.tfvars.example # Configuration template
│   └── modules/
│       ├── lambda_function/    # Lambda + IAM + CloudWatch Logs
│       ├── s3_buckets/         # S3 buckets with security
│       ├── sns_notifications/  # SNS topics + subscriptions
│       ├── cloudwatch_metrics/ # Metrics, filters, dashboard
│       ├── cloudwatch_alarms/  # Standard CloudWatch alarms
│       ├── log_alerts/         # Log-based metric filters + alarms
│       └── threat_detection/   # 🛡️ Real-time threat detection (<60s)
├── DEMO_GUIDE.md               # Video presentation guide
└── README.md                   # This file
```

---

## 🚀 Quick Start

### Prerequisites

- AWS Account with appropriate permissions
- AWS CLI configured (`aws configure`)
- Terraform >= 1.0
- Docker (for building Pillow layer)
- Python 3.12
- Git

### Installation

1. **Clone Repository**
   ```bash
   git clone <repository-url>
   cd aws-lamda-monitoring
   ```

2. **Build Lambda Layer**
   ```bash
   cd scripts
   chmod +x build_layer_docker.sh
   ./build_layer_docker.sh
   ```
   
   This creates `pillow_layer.zip` in the terraform directory.

3. **Configure Variables**
   ```bash
   cd ../terraform
   cp terraform.tfvars.example terraform.tfvars
   nano terraform.tfvars  # Edit with your settings
   ```
   
   **Required changes:**
   ```hcl
   alert_email = "your-email@example.com"  # Change this!
   aws_region = "us-east-1"                # Your preferred region
   ```

4. **Deploy Infrastructure**
   ```bash
   terraform init
   terraform plan    # Review changes
   terraform apply   # Type 'yes' to confirm
   ```
   
   ⏱️ **Deployment time:** ~2-3 minutes
   
   📝 **Resources created:** 40+ AWS resources

5. **Confirm SNS Subscriptions**
   - Check your email inbox
   - Confirm 3 subscription emails from AWS
   - This step is **required** to receive alerts

6. **Capture Outputs**
   ```bash
   terraform output
   ```
   
   Save the bucket names for testing.

---

## 🧪 Testing

### Upload Test Image

```bash
# Get bucket name from Terraform output
UPLOAD_BUCKET=$(terraform output -raw upload_bucket_name)

# Upload an image
aws s3 cp path/to/your/image.jpg s3://$UPLOAD_BUCKET/
```

### Watch Logs in Real-Time

```bash
# Get log group name
LOG_GROUP=$(terraform output -raw lambda_log_group_name)

# Tail logs
aws logs tail $LOG_GROUP --follow
```

### Check Processed Images

```bash
# Get processed bucket name
PROCESSED_BUCKET=$(terraform output -raw processed_bucket_name)

# List processed images
aws s3 ls s3://$PROCESSED_BUCKET/ --recursive
```

Expected output: 5 variants per uploaded image
- `image_compressed_xxx.jpg` (JPEG 85% quality)
- `image_low_xxx.jpg` (JPEG 60% quality)
- `image_webp_xxx.webp` (WebP format)
- `image_png_xxx.png` (PNG format)
- `image_thumbnail_xxx.jpg` (300x300 thumbnail)

### Access CloudWatch Dashboard

```bash
# Get dashboard URL
terraform output cloudwatch_dashboard_url
# Copy and paste in browser
```

Or navigate manually:
**AWS Console → CloudWatch → Dashboards → image-processor-dev-processor-monitoring**

---

## 📊 Monitoring

### CloudWatch Dashboard

The automatically created dashboard includes:

1. **Lambda Invocations & Errors** - Total calls and failures
2. **Duration Metrics** - Avg, Max, P99 execution times
3. **Concurrent Executions** - Simultaneous Lambda instances
4. **Custom Metrics** - Success vs Error counts
5. **Processing Time** - Image processing performance
6. **Image Size** - Size distribution of processed images
7. **Recent Errors** - Live error log viewer

### CloudWatch Alarms

**Standard Alarms (6):**
- `high-error-rate` - Triggers on 3+ errors
- `high-duration` - Warns when approaching timeout (45s)
- `throttles` - Detects concurrent execution limits
- `high-concurrency` - Performance warning
- `log-errors` - ERROR logs detected
- `low-success-rate` - Success rate below threshold

**Log-Based Alarms (6):**
- `timeout-errors` - Lambda timeout detection
- `memory-errors` - Out of memory issues
- `image-processing-errors` - PIL/Pillow failures
- `s3-permission-errors` - Access denied to S3
- `critical-errors` - CRITICAL log level
- `large-images` - Large image performance warning

**🛡️ Security/Threat Detection Alarms (3):**
- `threats-detected` - Fires when any security threat is identified
- `detection-latency` - Warns if detection time approaches 60-second target
- `detector-errors` - Alerts if the threat detector itself fails

### SNS Topics

Four separate topics for different alert severities:
- **Critical Alerts** - Errors, failures, timeouts
- **Performance Alerts** - Duration, memory, throttles
- **Log Alerts** - Pattern-based log alerts
- **🛡️ Security Alerts** - Real-time threat detection alerts (<60s)

### Custom Metrics

Emitted from Lambda code and log filters:
- `ProcessingTime` - Milliseconds per image
- `ImagesProcessed` - Count of images
- `ProcessingSuccess` / `ProcessingFailure` - Success rates
- `LambdaErrors` - From log filter
- `ImageSizeBytes` - From log filter
- `TimeoutErrors` - From log filter
- `MemoryErrors` - From log filter

**🛡️ Security Metrics** (namespace: `ImageProcessor/Security`):
- `ThreatsDetected` - Number of threats identified per invocation
- `EventsAnalyzed` - Number of log events analyzed per invocation
- `DetectionLatencyMs` - Time taken to analyze and detect threats

---

## 🔧 Configuration

### Alarm Thresholds

Edit `terraform.tfvars` to customize:

```hcl
# Error threshold (critical)
error_threshold = 3

# Duration warning (75% of timeout recommended)
duration_threshold_ms = 45000

# Throttle detection
throttle_threshold = 5

# Concurrent execution limit
concurrent_executions_threshold = 50

# Log error threshold
log_error_threshold = 1
```

### Lambda Configuration

```hcl
lambda_timeout     = 60      # Seconds (max 900)
lambda_memory_size = 1024    # MB (128-10240)
log_level          = "INFO"  # DEBUG, INFO, WARNING, ERROR
log_retention_days = 7       # Days (1, 3, 5, 7, 14, 30, etc.)
```

### Enable/Disable Features

```hcl
enable_cloudwatch_dashboard = true   # Create dashboard
enable_no_invocation_alarm  = false  # Alert on no invocations
enable_s3_versioning        = true   # S3 version control
```

---

## 🧪 Testing Alarms

### Manually Trigger Alarm

```bash
aws cloudwatch set-alarm-state \
  --alarm-name image-processor-dev-processor-high-error-rate \
  --state-value ALARM \
  --state-reason "Testing alarm notification"
```

Check your email for notification!

### Trigger Real Error

```bash
# Create invalid image file
echo "This is not an image" > fake-image.jpg

# Upload it
aws s3 cp fake-image.jpg s3://$UPLOAD_BUCKET/

# Watch logs for ERROR
aws logs tail $LOG_GROUP --follow

# Check alarm in ~2 minutes
```

### Generate Load

```bash
# Upload multiple images simultaneously
for i in {1..10}; do
  aws s3 cp image.jpg s3://$UPLOAD_BUCKET/test-$i.jpg &
done
wait
```

Watch concurrent executions and duration metrics.

---

## 📈 Costs

### Estimated Monthly Costs (Light Usage)

| Service | Usage | Cost |
|---------|-------|------|
| Lambda | 1000 invocations, 1GB-s | $0.20 |
| S3 | 10GB storage, 1000 requests | $0.30 |
| CloudWatch Logs | 1GB ingested, 7-day retention | $0.50 |
| CloudWatch Metrics | 12 custom metrics | $3.60 |
| CloudWatch Alarms | 12 alarms | $1.20 |
| SNS | 100 notifications | $0.10 |
| **Total** | | **~$6/month** |

💡 **Tip**: Use `log_retention_days = 3` and reduce alarm count for cost savings.

---

## 🛠️ Troubleshooting

### Lambda Not Triggering

**Check:**
1. S3 event notification configured?
   ```bash
   aws s3api get-bucket-notification-configuration --bucket $UPLOAD_BUCKET
   ```
2. Lambda permission granted?
   ```bash
   aws lambda get-policy --function-name image-processor-dev-processor
   ```

### No Email Notifications

**Check:**
1. SNS subscription confirmed?
   - AWS Console → SNS → Subscriptions
   - Status should be "Confirmed"
2. Check spam folder
3. Resend confirmation from SNS console

### Alarms Not Firing

**Check:**
1. Wait 2-5 minutes for metrics to populate
2. Verify alarm threshold values
3. Check alarm state in CloudWatch console
4. Ensure metric has data:
   ```bash
   aws cloudwatch get-metric-statistics \
     --namespace AWS/Lambda \
     --metric-name Errors \
     --dimensions Name=FunctionName,Value=image-processor-dev-processor \
     --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
     --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
     --period 300 \
     --statistics Sum
   ```

### Terraform Errors

**Common issues:**
1. **Provider initialization**: Run `terraform init`
2. **State lock**: Another process using state? Wait or force unlock
3. **Resource conflicts**: Names already exist? Change `project_name` variable
4. **AWS credentials**: Run `aws sts get-caller-identity` to verify

### Lambda Errors

**Check logs:**
```bash
aws logs tail $LOG_GROUP --follow --filter-pattern ERROR
```

**Common errors:**
- PIL import error → Rebuild layer
- S3 access denied → Check IAM permissions
- Timeout → Increase `lambda_timeout`
- Memory error → Increase `lambda_memory_size`

---

## 🔒 Security

### IAM Least Privilege

Lambda has minimal permissions:
- `s3:GetObject` on upload bucket (read-only)
- `s3:PutObject` on processed bucket (write-only)
- `logs:CreateLogGroup/Stream/PutLogEvents` (logging)
- `cloudwatch:PutMetricData` (custom metrics)

### S3 Security

- ✅ Encryption at rest (AES256)
- ✅ Versioning enabled
- ✅ Public access blocked
- ✅ Bucket policies restricted

### Network

- Lambda runs in AWS-managed VPC
- No public internet access required
- S3 access via AWS internal network

---

## 🚀 Production Deployment

### Recommendations

1. **Separate Environments**
   ```bash
   terraform workspace new prod
   terraform workspace select prod
   terraform apply -var="environment=prod"
   ```

2. **Enable Advanced Monitoring**
   ```hcl
   enable_no_invocation_alarm  = true
   log_retention_days          = 30
   ```

3. **Configure Different Alert Channels**
   ```hcl
   critical_alert_email     = "oncall@company.com"
   performance_alert_email  = "devops@company.com"
   log_alert_email          = "team@company.com"
   critical_alert_sms       = "+1234567890"  # Oncall phone
   ```

4. **Implement CI/CD**
   - Use GitHub Actions / GitLab CI
   - Automated testing before deployment
   - Blue/green deployments with Lambda versions

5. **Enable X-Ray Tracing**
   ```hcl
   tracing_config {
     mode = "Active"
   }
   ```

6. **Use CloudWatch Insights**
   - Create saved queries for common investigations
   - Set up dashboards per environment

---

## 📚 Modules Documentation

Each module is self-contained and reusable:

### Module: `lambda_function`
Creates Lambda function with IAM role, policies, and CloudWatch log group.

**Inputs:** function_name, runtime, timeout, memory_size, bucket ARNs
**Outputs:** function_arn, function_name, log_group_name, role_arn

### Module: `s3_buckets`
Creates upload and processed S3 buckets with security configurations.

**Inputs:** bucket names, versioning, lambda_function_arn
**Outputs:** upload_bucket_id, processed_bucket_id, bucket_arns

### Module: `sns_notifications`
Creates SNS topics and email/SMS subscriptions.

**Inputs:** project_name, alert emails, SMS numbers
**Outputs:** topic_arns, topic_names

### Module: `cloudwatch_metrics`
Creates custom metrics, metric filters, and dashboard.

**Inputs:** function_name, log_group_name, metric_namespace
**Outputs:** dashboard_name, dashboard_arn, metric_filter_names

### Module: `cloudwatch_alarms`
Creates standard CloudWatch alarms for Lambda monitoring.

**Inputs:** function_name, SNS topic ARNs, thresholds
**Outputs:** alarm_arns, alarm_names

### Module: `log_alerts`
Creates log-based metric filters and alarms.

**Inputs:** function_name, log_group_name, SNS topic ARN
**Outputs:** alarm_arns, alarm_names

### Module: `threat_detection` 🛡️
Creates a real-time threat detection pipeline using CloudWatch Logs Subscription Filters and a dedicated Lambda function. Detects threats in under 60 seconds by bypassing the CloudTrail delay.

**Inputs:** project_name, environment, source_log_group_name/arn, threat_detector_zip_path, security_alert_email
**Outputs:** threat_detector_function_arn, security_alerts_topic_arn, security_alarm_names

**Detection Pipeline:** CloudWatch Logs → Subscription Filter → Threat Detector Lambda → SNS Alert

**Threats Detected:**
- Rapid-fire errors (brute force / fuzzing)
- Access Denied patterns (unauthorized access)
- Suspicious file extensions (malware uploads)
- Injection attempts (path traversal, command injection)
- Abnormal payload sizes (DoS / exfiltration)

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see LICENSE file for details.

---

## 🙏 Acknowledgments

- AWS Lambda team for serverless compute
- HashiCorp for Terraform
- Pillow (PIL Fork) for image processing
- CloudWatch for comprehensive monitoring

---

## 📞 Support

- **Issues**: Open a GitHub issue
- **Questions**: Use GitHub Discussions
- **Security**: Email security@yourcompany.com

---

## 🗺️ Roadmap

Future enhancements:
- [ ] Add API Gateway for direct uploads
- [ ] Implement Step Functions for complex workflows
- [ ] Add DynamoDB for processing metadata
- [ ] Create CloudFormation templates
- [ ] Add Lambda Powertools for advanced features
- [ ] Implement dead letter queue (DLQ)
- [ ] Add cost allocation tags
- [ ] Create multi-region deployment
- [ ] Add automated testing suite
- [ ] Implement canary deployments

---

**Built with ❤️ for AWS monitoring enthusiasts**

⭐ Star this repo if you find it helpful!
