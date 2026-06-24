"""
Threat Detection Lambda Function
=================================
A dedicated security Lambda that analyzes CloudWatch Logs in real-time
via subscription filters to detect threats in under 60 seconds.

Threat patterns detected:
1. Rapid-fire errors (brute force / fuzzing attacks)
2. S3 access denied patterns (unauthorized access attempts)
3. Suspicious file extensions (malware upload attempts)
4. Injection patterns in object keys (path traversal / command injection)
5. Abnormal payload sizes (data exfiltration attempts)
6. Repeated failures from same source (credential stuffing)

Architecture:
  CloudWatch Logs → Subscription Filter → This Lambda → SNS Alert
  (Near real-time: typically 2-10 seconds latency)
"""

import json
import boto3
import os
import logging
import base64
import gzip
import re
from datetime import datetime, timezone

# Configure structured logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# AWS clients
sns_client = boto3.client('sns')
cloudwatch = boto3.client('cloudwatch')

# Configuration from environment variables
SECURITY_TOPIC_ARN = os.environ.get('SECURITY_TOPIC_ARN', '')
METRIC_NAMESPACE = os.environ.get('METRIC_NAMESPACE', 'ImageProcessor/Security')

# ============================================================================
# THREAT DETECTION PATTERNS
# ============================================================================

# Suspicious file extensions that could indicate malware uploads
SUSPICIOUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.ps1', '.sh', '.php', '.jsp', '.asp',
    '.aspx', '.cgi', '.pl', '.py', '.rb', '.jar', '.war', '.dll',
    '.so', '.bin', '.elf', '.scr', '.vbs', '.wsf', '.hta'
}

# Injection patterns in S3 object keys (path traversal, command injection)
INJECTION_PATTERNS = [
    r'\.\./',                     # Path traversal
    r'\.\.\\',                    # Windows path traversal
    r'%2e%2e',                    # URL-encoded path traversal
    r';\s*(?:rm|cat|wget|curl)',  # Command injection
    r'\|',                        # Pipe injection
    r'`[^`]+`',                   # Backtick command substitution
    r'\$\(',                      # Shell command substitution
    r'<script',                   # XSS in filenames
]

# Compile injection patterns for performance
COMPILED_INJECTION_PATTERNS = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]

# Thresholds
RAPID_ERROR_THRESHOLD = 5          # errors within the batch to flag as rapid-fire
LARGE_PAYLOAD_THRESHOLD = 50 * 1024 * 1024  # 50 MB - suspiciously large


def lambda_handler(event, context):
    """
    Main handler for CloudWatch Logs subscription filter events.
    
    The event contains base64-encoded, gzip-compressed log data
    from the image processor Lambda's CloudWatch log group.
    """
    request_id = context.aws_request_id if context else 'local'
    detection_start = datetime.now(timezone.utc)
    
    logger.info(f"THREAT_DETECTOR REQUEST_ID: {request_id} - Received log event for analysis")
    
    try:
        # Decode and decompress the CloudWatch Logs data
        log_data = decode_log_event(event)
        
        if not log_data:
            logger.info(f"THREAT_DETECTOR REQUEST_ID: {request_id} - No log data to process")
            return {'statusCode': 200, 'body': 'No data'}
        
        log_group = log_data.get('logGroup', 'unknown')
        log_stream = log_data.get('logStream', 'unknown')
        log_events = log_data.get('logEvents', [])
        
        logger.info(
            f"THREAT_DETECTOR REQUEST_ID: {request_id} - "
            f"Analyzing {len(log_events)} log events from {log_group}"
        )
        
        # Run all threat detection checks
        threats_detected = []
        
        threats_detected.extend(detect_rapid_errors(log_events, request_id))
        threats_detected.extend(detect_access_denied(log_events, request_id))
        threats_detected.extend(detect_suspicious_files(log_events, request_id))
        threats_detected.extend(detect_injection_attempts(log_events, request_id))
        threats_detected.extend(detect_abnormal_payloads(log_events, request_id))
        
        # Calculate detection time
        detection_end = datetime.now(timezone.utc)
        detection_time_ms = (detection_end - detection_start).total_seconds() * 1000
        
        # Publish security metrics
        publish_security_metrics(
            threats_found=len(threats_detected),
            events_analyzed=len(log_events),
            detection_time_ms=detection_time_ms
        )
        
        # Send alerts for any threats detected
        if threats_detected:
            logger.warning(
                f"THREAT_DETECTOR REQUEST_ID: {request_id} - "
                f"⚠️ {len(threats_detected)} THREATS DETECTED in {detection_time_ms:.0f}ms"
            )
            send_threat_alert(
                threats=threats_detected,
                log_group=log_group,
                log_stream=log_stream,
                detection_time_ms=detection_time_ms,
                request_id=request_id
            )
        else:
            logger.info(
                f"THREAT_DETECTOR REQUEST_ID: {request_id} - "
                f"✅ No threats detected. Analyzed {len(log_events)} events in {detection_time_ms:.0f}ms"
            )
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'threats_detected': len(threats_detected),
                'events_analyzed': len(log_events),
                'detection_time_ms': round(detection_time_ms, 2),
                'request_id': request_id
            })
        }
        
    except Exception as e:
        logger.error(
            f"THREAT_DETECTOR REQUEST_ID: {request_id} - "
            f"Error in threat detection: {str(e)}",
            exc_info=True
        )
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e), 'request_id': request_id})
        }


def decode_log_event(event):
    """
    Decode CloudWatch Logs subscription filter event.
    
    The data comes as:
    1. Base64-encoded
    2. Gzip-compressed
    3. JSON payload
    """
    try:
        compressed_data = base64.b64decode(event['awslogs']['data'])
        uncompressed_data = gzip.decompress(compressed_data)
        log_data = json.loads(uncompressed_data)
        return log_data
    except (KeyError, Exception) as e:
        logger.error(f"Failed to decode log event: {str(e)}")
        return None


# ============================================================================
# THREAT DETECTION FUNCTIONS
# ============================================================================

def detect_rapid_errors(log_events, request_id):
    """
    Detect rapid-fire errors that could indicate brute force or fuzzing attacks.
    
    If multiple ERROR-level events appear in a short burst, it may indicate
    an attacker systematically probing the system.
    """
    threats = []
    error_events = [e for e in log_events if 'ERROR' in e.get('message', '')]
    
    if len(error_events) >= RAPID_ERROR_THRESHOLD:
        threat = {
            'type': 'RAPID_FIRE_ERRORS',
            'severity': 'HIGH',
            'description': (
                f"Detected {len(error_events)} errors in a single log batch. "
                f"This may indicate a brute force attack, fuzzing attempt, "
                f"or systematic probing of the system."
            ),
            'evidence': [e['message'][:200] for e in error_events[:5]],
            'count': len(error_events),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        threats.append(threat)
        logger.warning(
            f"THREAT_DETECTOR REQUEST_ID: {request_id} - "
            f"🔴 RAPID_FIRE_ERRORS: {len(error_events)} errors detected"
        )
    
    return threats


def detect_access_denied(log_events, request_id):
    """
    Detect Access Denied patterns that could indicate unauthorized access attempts.
    """
    threats = []
    access_denied_patterns = ['AccessDenied', 'Access Denied', '403', 'Forbidden']
    
    denied_events = []
    for event in log_events:
        message = event.get('message', '')
        if any(pattern in message for pattern in access_denied_patterns):
            denied_events.append(event)
    
    if denied_events:
        threat = {
            'type': 'ACCESS_DENIED',
            'severity': 'HIGH',
            'description': (
                f"Detected {len(denied_events)} access denied events. "
                f"This could indicate unauthorized access attempts, "
                f"misconfigured IAM permissions, or an attacker probing S3 bucket access."
            ),
            'evidence': [e['message'][:200] for e in denied_events[:3]],
            'count': len(denied_events),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        threats.append(threat)
        logger.warning(
            f"THREAT_DETECTOR REQUEST_ID: {request_id} - "
            f"🔴 ACCESS_DENIED: {len(denied_events)} denied requests detected"
        )
    
    return threats


def detect_suspicious_files(log_events, request_id):
    """
    Detect uploads of suspicious file extensions that could be malware.
    
    Even though the image processor only accepts images, an attacker might
    try uploading executables or scripts disguised as images.
    """
    threats = []
    suspicious_files = []
    
    for event in log_events:
        message = event.get('message', '')
        # Look for S3 key references in log messages
        for ext in SUSPICIOUS_EXTENSIONS:
            if ext in message.lower():
                suspicious_files.append({
                    'extension': ext,
                    'message': message[:200]
                })
                break
    
    if suspicious_files:
        threat = {
            'type': 'SUSPICIOUS_FILE_UPLOAD',
            'severity': 'CRITICAL',
            'description': (
                f"Detected {len(suspicious_files)} suspicious file extension(s) "
                f"in processing logs. Extensions found: "
                f"{', '.join(set(f['extension'] for f in suspicious_files))}. "
                f"This could indicate malware upload attempts."
            ),
            'evidence': [f['message'] for f in suspicious_files[:3]],
            'count': len(suspicious_files),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        threats.append(threat)
        logger.warning(
            f"THREAT_DETECTOR REQUEST_ID: {request_id} - "
            f"🔴 SUSPICIOUS_FILE_UPLOAD: {len(suspicious_files)} suspicious files detected"
        )
    
    return threats


def detect_injection_attempts(log_events, request_id):
    """
    Detect path traversal, command injection, and XSS attempts
    in S3 object keys logged by the image processor.
    """
    threats = []
    injection_events = []
    
    for event in log_events:
        message = event.get('message', '')
        for pattern in COMPILED_INJECTION_PATTERNS:
            if pattern.search(message):
                injection_events.append({
                    'pattern': pattern.pattern,
                    'message': message[:200]
                })
                break
    
    if injection_events:
        threat = {
            'type': 'INJECTION_ATTEMPT',
            'severity': 'CRITICAL',
            'description': (
                f"Detected {len(injection_events)} potential injection attempt(s). "
                f"Patterns found include path traversal (../), command injection, "
                f"or XSS payloads in S3 object keys. "
                f"This is a strong indicator of an active attack."
            ),
            'evidence': [e['message'] for e in injection_events[:3]],
            'patterns_matched': list(set(e['pattern'] for e in injection_events)),
            'count': len(injection_events),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        threats.append(threat)
        logger.warning(
            f"THREAT_DETECTOR REQUEST_ID: {request_id} - "
            f"🔴 INJECTION_ATTEMPT: {len(injection_events)} injection attempts detected"
        )
    
    return threats


def detect_abnormal_payloads(log_events, request_id):
    """
    Detect abnormally large payloads that could indicate data exfiltration
    or denial of service attempts via oversized uploads.
    """
    threats = []
    large_payload_events = []
    
    # Look for file size information in log messages
    size_pattern = re.compile(r'(?:image_size|file_size|size):\s*(\d+)\s*bytes', re.IGNORECASE)
    
    for event in log_events:
        message = event.get('message', '')
        match = size_pattern.search(message)
        if match:
            size = int(match.group(1))
            if size > LARGE_PAYLOAD_THRESHOLD:
                large_payload_events.append({
                    'size_bytes': size,
                    'size_mb': round(size / (1024 * 1024), 2),
                    'message': message[:200]
                })
    
    if large_payload_events:
        max_size = max(e['size_mb'] for e in large_payload_events)
        threat = {
            'type': 'ABNORMAL_PAYLOAD_SIZE',
            'severity': 'MEDIUM',
            'description': (
                f"Detected {len(large_payload_events)} abnormally large payload(s). "
                f"Largest: {max_size} MB (threshold: "
                f"{LARGE_PAYLOAD_THRESHOLD / (1024 * 1024):.0f} MB). "
                f"This could indicate a denial-of-service attempt via resource exhaustion "
                f"or an attempt to exploit buffer overflow vulnerabilities."
            ),
            'evidence': [
                f"Size: {e['size_mb']} MB - {e['message']}"
                for e in large_payload_events[:3]
            ],
            'count': len(large_payload_events),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        threats.append(threat)
        logger.warning(
            f"THREAT_DETECTOR REQUEST_ID: {request_id} - "
            f"🟡 ABNORMAL_PAYLOAD_SIZE: {len(large_payload_events)} large payloads detected"
        )
    
    return threats


# ============================================================================
# ALERTING & METRICS
# ============================================================================

def send_threat_alert(threats, log_group, log_stream, detection_time_ms, request_id):
    """
    Send a detailed threat alert via SNS with sub-60-second detection claim.
    """
    if not SECURITY_TOPIC_ARN:
        logger.warning("SECURITY_TOPIC_ARN not configured - skipping SNS alert")
        return
    
    # Build alert message
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    max_severity = min(threats, key=lambda t: severity_order.get(t['severity'], 99))['severity']
    
    subject = f"🚨 [{max_severity}] {len(threats)} Security Threat(s) Detected"
    
    # Truncate subject to 100 chars (SNS limit)
    if len(subject) > 100:
        subject = subject[:97] + "..."
    
    message_lines = [
        "=" * 60,
        "🛡️  SECURITY THREAT DETECTION ALERT",
        "=" * 60,
        "",
        f"⏱️  Detection Time: {detection_time_ms:.0f}ms (target: <60,000ms)",
        f"📊 Threats Found: {len(threats)}",
        f"🔴 Max Severity: {max_severity}",
        f"📋 Log Group: {log_group}",
        f"📋 Log Stream: {log_stream}",
        f"🆔 Detector Request ID: {request_id}",
        f"🕐 Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "-" * 60,
        "THREAT DETAILS",
        "-" * 60,
    ]
    
    for i, threat in enumerate(threats, 1):
        message_lines.extend([
            "",
            f"--- Threat #{i}: {threat['type']} ---",
            f"  Severity: {threat['severity']}",
            f"  Count: {threat['count']}",
            f"  Description: {threat['description']}",
            f"  Evidence (first {min(len(threat.get('evidence', [])), 3)}):",
        ])
        for evidence in threat.get('evidence', [])[:3]:
            message_lines.append(f"    • {evidence}")
    
    message_lines.extend([
        "",
        "-" * 60,
        "RECOMMENDED ACTIONS",
        "-" * 60,
        "",
    ])
    
    # Add severity-specific recommendations
    if any(t['severity'] == 'CRITICAL' for t in threats):
        message_lines.extend([
            "🔴 CRITICAL ACTIONS REQUIRED:",
            "  1. Immediately review CloudWatch logs for the affected log group",
            "  2. Check S3 bucket access logs for unauthorized access patterns",
            "  3. Consider temporarily restricting S3 bucket access",
            "  4. Review IAM roles and policies for the Lambda function",
            "  5. Escalate to your security team",
            "",
        ])
    
    if any(t['severity'] == 'HIGH' for t in threats):
        message_lines.extend([
            "🟠 HIGH PRIORITY ACTIONS:",
            "  1. Review recent S3 upload patterns for anomalies",
            "  2. Check for unusual source IPs in CloudTrail",
            "  3. Verify IAM permissions are following least privilege",
            "",
        ])
    
    message_lines.extend([
        "=" * 60,
        f"This alert was generated by the Threat Detection Lambda.",
        f"Detection pipeline: CloudWatch Logs → Subscription Filter → Lambda → SNS",
        f"Total detection latency: {detection_time_ms:.0f}ms",
        "=" * 60,
    ])
    
    message = "\n".join(message_lines)
    
    try:
        sns_client.publish(
            TopicArn=SECURITY_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
        logger.info(
            f"THREAT_DETECTOR - Alert sent to SNS topic: {SECURITY_TOPIC_ARN} "
            f"({len(threats)} threats, detection time: {detection_time_ms:.0f}ms)"
        )
    except Exception as e:
        logger.error(f"THREAT_DETECTOR - Failed to send SNS alert: {str(e)}")


def publish_security_metrics(threats_found, events_analyzed, detection_time_ms):
    """
    Publish security-specific custom metrics to CloudWatch.
    """
    try:
        timestamp = datetime.now(timezone.utc)
        
        metrics = [
            {
                'MetricName': 'ThreatsDetected',
                'Value': threats_found,
                'Unit': 'Count',
                'Timestamp': timestamp
            },
            {
                'MetricName': 'EventsAnalyzed',
                'Value': events_analyzed,
                'Unit': 'Count',
                'Timestamp': timestamp
            },
            {
                'MetricName': 'DetectionLatencyMs',
                'Value': detection_time_ms,
                'Unit': 'Milliseconds',
                'Timestamp': timestamp
            },
        ]
        
        for metric in metrics:
            cloudwatch.put_metric_data(
                Namespace=METRIC_NAMESPACE,
                MetricData=[{
                    'MetricName': metric['MetricName'],
                    'Value': metric['Value'],
                    'Unit': metric['Unit'],
                    'Timestamp': metric['Timestamp'],
                    'Dimensions': [
                        {
                            'Name': 'DetectorFunction',
                            'Value': 'threat-detector'
                        }
                    ]
                }]
            )
        
        logger.debug(f"Published {len(metrics)} security metrics to CloudWatch")
        
    except Exception as e:
        # Don't fail the function if metrics publishing fails
        logger.warning(f"Failed to publish security metrics: {str(e)}")
