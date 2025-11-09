from django.db import models
from django.utils import timezone


class RequestLog(models.Model):
    """
    Logs every incoming request to the application.
    """
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
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
        indexes = [
            models.Index(fields=['ip_address', '-timestamp']),
            models.Index(fields=['path', '-timestamp']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} - {self.path} at {self.timestamp}"