from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Count
from .models import RequestLog, SuspiciousIP
import logging

logger = logging.getLogger(__name__)


@shared_task
def detect_anomalies():
    """
    Detect suspicious IP activity and flag them.
    Runs hourly via Celery Beat.
    
    Flags IPs if:
    1. More than 100 requests in the last hour
    2. Multiple attempts to access sensitive paths (/admin, /login)
    """
    logger.info("Starting anomaly detection...")
    
    one_hour_ago = timezone.now() - timedelta(hours=1)
    flagged_count = 0
    
    # Detection Rule 1: High request volume (>100 requests/hour)
    high_volume_ips = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago
    ).values('ip_address').annotate(
        count=Count('ip_address')
    ).filter(count__gt=100)
    
    for item in high_volume_ips:
        ip = item['ip_address']
        count = item['count']
        
        # Check if already flagged recently
        recent_flag = SuspiciousIP.objects.filter(
            ip_address=ip,
            flagged_at__gte=one_hour_ago
        ).exists()
        
        if not recent_flag:
            SuspiciousIP.objects.create(
                ip_address=ip,
                reason=f'High request volume: {count} requests in last hour',
                request_count=count
            )
            flagged_count += 1
            logger.warning(f"Flagged {ip} for high volume: {count} requests")
    
    # Detection Rule 2: Sensitive path access attempts
    sensitive_paths = ['/admin', '/login', '/api/auth']
    
    for path in sensitive_paths:
        suspicious_ips = RequestLog.objects.filter(
            timestamp__gte=one_hour_ago,
            path__startswith=path
        ).values('ip_address').annotate(
            count=Count('ip_address')
        ).filter(count__gt=10)  # More than 10 attempts to sensitive path
        
        for item in suspicious_ips:
            ip = item['ip_address']
            count = item['count']
            
            recent_flag = SuspiciousIP.objects.filter(
                ip_address=ip,
                flagged_at__gte=one_hour_ago,
                reason__contains=path
            ).exists()
            
            if not recent_flag:
                SuspiciousIP.objects.create(
                    ip_address=ip,
                    reason=f'Multiple attempts to {path}: {count} times in last hour',
                    request_count=count
                )
                flagged_count += 1
                logger.warning(f"Flagged {ip} for suspicious access to {path}: {count} attempts")
    
    logger.info(f"Anomaly detection complete. Flagged {flagged_count} IPs.")
    return flagged_count


@shared_task
def cleanup_old_logs():
    """
    Clean up old logs to prevent database bloat.
    Run daily.
    """
    thirty_days_ago = timezone.now() - timedelta(days=30)
    
    deleted_count = RequestLog.objects.filter(
        timestamp__lt=thirty_days_ago
    ).delete()[0]
    
    logger.info(f"Cleaned up {deleted_count} old log entries")
    return deleted_count


@shared_task
def auto_block_suspicious_ips():
    """
    Automatically block IPs that have been flagged multiple times.
    Run hourly.
    """
    from .models import BlockedIP
    
    # Find IPs flagged more than 3 times
    suspicious_ips = SuspiciousIP.objects.filter(
        is_resolved=False
    ).values('ip_address').annotate(
        flag_count=Count('ip_address')
    ).filter(flag_count__gte=3)
    
    blocked_count = 0
    for item in suspicious_ips:
        ip = item['ip_address']
        
        # Block if not already blocked
        if not BlockedIP.is_blocked(ip):
            BlockedIP.block_ip(
                ip,
                reason='Automatically blocked: Multiple suspicious activity flags',
                blocked_by='System',
                duration_hours=24  # Temporary 24-hour block
            )
            blocked_count += 1
            logger.warning(f"Auto-blocked {ip} due to repeated suspicious activity")
            
            # Mark flags as resolved
            SuspiciousIP.objects.filter(ip_address=ip, is_resolved=False).update(
                is_resolved=True
            )
    
    logger.info(f"Auto-blocked {blocked_count} suspicious IPs")
    return blocked_count