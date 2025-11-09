from django.db import models
from django.utils import timezone


class RequestLog(models.Model):
    """Updated with geolocation fields"""
    ip_address = models.GenericIPAddressField(
        help_text="Client IP address (IPv4 or IPv6)"
    )
    
    timestamp = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text="When the request was made"
    )
    
    path = models.CharField(
        max_length=255,
        db_index=True,
        help_text="URL path requested (e.g., /admin, /login)"
    )
    
    # NEW FIELDS FOR TASK 2
    country = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        db_index=True,
        help_text="Country from IP geolocation"
    )
    
    city = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="City from IP geolocation"
    )
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
        indexes = [
            models.Index(fields=['ip_address', '-timestamp']),
            models.Index(fields=['path', '-timestamp']),
            models.Index(fields=['country', '-timestamp']),  # NEW
        ]
    
    def __str__(self):
        location = f" ({self.country})" if self.country else ""
        return f"{self.ip_address}{location} - {self.path} at {self.timestamp}"


# Keep your BlockedIP and BlockedAttempt models as they are
class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True, db_index=True)
    reason = models.TextField(blank=True)
    blocked_at = models.DateTimeField(auto_now_add=True)
    blocked_by = models.CharField(max_length=100, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-blocked_at']
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
    
    def __str__(self):
        if self.reason:
            return f"{self.ip_address} - {self.reason[:50]}"
        return f"{self.ip_address}"
    
    def is_expired(self):
        if self.expires_at is None:
            return False
        return timezone.now() > self.expires_at
    
    @classmethod
    def is_blocked(cls, ip_address):
        try:
            blocked = cls.objects.get(ip_address=ip_address)
            if blocked.is_expired():
                blocked.delete()
                return False
            return True
        except cls.DoesNotExist:
            return False
    
    @classmethod
    def block_ip(cls, ip_address, reason="", blocked_by="", duration_hours=None):
        from datetime import timedelta
        expires_at = None
        if duration_hours:
            expires_at = timezone.now() + timedelta(hours=duration_hours)
        
        blocked, created = cls.objects.get_or_create(
            ip_address=ip_address,
            defaults={
                'reason': reason,
                'blocked_by': blocked_by,
                'expires_at': expires_at
            }
        )
        
        if not created:
            blocked.reason = reason or blocked.reason
            blocked.blocked_by = blocked_by or blocked.blocked_by
            blocked.expires_at = expires_at
            blocked.save()
        
        return blocked
    
    @classmethod
    def unblock_ip(cls, ip_address):
        try:
            blocked = cls.objects.get(ip_address=ip_address)
            blocked.delete()
            return True
        except cls.DoesNotExist:
            return False


class BlockedAttempt(models.Model):
    blocked_ip = models.ForeignKey(BlockedIP, on_delete=models.CASCADE, related_name='attempts')
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Blocked Attempt"
        verbose_name_plural = "Blocked Attempts"
    
    def __str__(self):
        return f"{self.blocked_ip.ip_address} tried {self.path} at {self.timestamp}"


# NEW FOR TASK 4
class SuspiciousIP(models.Model):
    """Stores IPs flagged by anomaly detection"""
    ip_address = models.GenericIPAddressField(db_index=True)
    reason = models.TextField(help_text="Why this IP was flagged")
    flagged_at = models.DateTimeField(auto_now_add=True)
    request_count = models.IntegerField(default=0)
    is_resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-flagged_at']
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"
    
    def __str__(self):
        return f"{self.ip_address} - {self.reason[:50]}"