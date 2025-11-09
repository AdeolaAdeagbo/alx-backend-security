"""
ip_tracking/admin.py
Django admin interface for managing IP tracking and blocking

UPDATE: Add BlockedIP admin to your existing admin.py
"""
from django.contrib import admin
from .models import RequestLog, BlockedIP, BlockedAttempt
from django.utils.html import format_html
from django.utils import timezone


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    """Admin interface for request logs (from Task 0)"""
    list_display = ['ip_address', 'path', 'timestamp']
    list_filter = ['timestamp', 'path']
    search_fields = ['ip_address', 'path']
    readonly_fields = ['ip_address', 'path', 'timestamp']
    ordering = ['-timestamp']
    list_per_page = 50


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    """
    Admin interface for managing blocked IPs.
    
    Features:
    - View all blocked IPs
    - Add new blocks with reason
    - Remove blocks (unblock)
    - See when blocks expire
    - Quick actions for bulk operations
    """
    
    # Columns to display in list view
    list_display = [
        'ip_address_colored',  # Custom method for colored display
        'reason_short',         # Custom method to truncate reason
        'blocked_at',
        'expires_at_display',   # Custom method to show expiry
        'status_badge',         # Custom method for visual status
        'attempt_count'         # Custom method to count blocked attempts
    ]
    
    # Filters in right sidebar
    list_filter = [
        'blocked_at',
        'expires_at',
    ]
    
    # Search functionality
    search_fields = ['ip_address', 'reason', 'blocked_by']
    
    # Fields to show when viewing/editing a single blocked IP
    fieldsets = (
        ('IP Information', {
            'fields': ('ip_address',)
        }),
        ('Block Details', {
            'fields': ('reason', 'blocked_by', 'blocked_at')
        }),
        ('Expiration', {
            'fields': ('expires_at',),
            'description': 'Leave empty for permanent block'
        }),
    )
    
    # Make certain fields read-only
    readonly_fields = ['blocked_at']
    
    # Order by newest first
    ordering = ['-blocked_at']
    
    # Number of items per page
    list_per_page = 25
    
    # Bulk actions
    actions = [
        'make_permanent',
        'extend_24h',
        'remove_blocks'
    ]
    
    # Custom methods for display
    
    def ip_address_colored(self, obj):
        """Display IP with color coding based on status"""
        if obj.is_expired():
            # Expired blocks in gray
            color = '#999'
            icon = '⏱'
        else:
            # Active blocks in red
            color = '#d32f2f'
            icon = '🚫'
        
        return format_html(
            '<span style="color: {};">{} {}</span>',
            color, icon, obj.ip_address
        )
    ip_address_colored.short_description = 'IP Address'
    ip_address_colored.admin_order_field = 'ip_address'
    
    def reason_short(self, obj):
        """Truncate long reasons"""
        if obj.reason:
            return obj.reason[:50] + ('...' if len(obj.reason) > 50 else '')
        return '-'
    reason_short.short_description = 'Reason'
    
    def expires_at_display(self, obj):
        """Show time remaining for temporary blocks"""
        if obj.expires_at is None:
            return format_html(
                '<span style="color: #d32f2f; font-weight: bold;">Permanent</span>'
            )
        
        if obj.is_expired():
            return format_html(
                '<span style="color: #999;">Expired</span>'
            )
        
        time_left = obj.expires_at - timezone.now()
        hours = int(time_left.total_seconds() / 3600)
        minutes = int((time_left.total_seconds() % 3600) / 60)
        
        return format_html(
            '<span style="color: #f57c00;">{}h {}m remaining</span>',
            hours, minutes
        )
    expires_at_display.short_description = 'Expiration'
    expires_at_display.admin_order_field = 'expires_at'
    
    def status_badge(self, obj):
        """Visual badge for block status"""
        if obj.is_expired():
            return format_html(
                '<span style="background: #e0e0e0; color: #666; '
                'padding: 3px 8px; border-radius: 3px;">EXPIRED</span>'
            )
        else:
            return format_html(
                '<span style="background: #d32f2f; color: white; '
                'padding: 3px 8px; border-radius: 3px;">ACTIVE</span>'
            )
    status_badge.short_description = 'Status'
    
    def attempt_count(self, obj):
        """Count how many times this IP tried to access while blocked"""
        count = obj.attempts.count()
        if count > 0:
            return format_html(
                '<span style="color: #d32f2f; font-weight: bold;">{} attempts</span>',
                count
            )
        return '-'
    attempt_count.short_description = 'Blocked Attempts'
    
    # Bulk actions
    
    def make_permanent(self, request, queryset):
        """Make selected blocks permanent"""
        count = queryset.update(expires_at=None)
        self.message_user(
            request,
            f'{count} block(s) made permanent.'
        )
    make_permanent.short_description = 'Make selected blocks permanent'
    
    def extend_24h(self, request, queryset):
        """Extend blocks by 24 hours"""
        from datetime import timedelta
        extended = 0
        
        for blocked in queryset:
            if blocked.expires_at:
                blocked.expires_at += timedelta(hours=24)
            else:
                blocked.expires_at = timezone.now() + timedelta(hours=24)
            blocked.save()
            extended += 1
        
        self.message_user(
            request,
            f'Extended {extended} block(s) by 24 hours.'
        )
    extend_24h.short_description = 'Extend selected blocks by 24 hours'
    
    def remove_blocks(self, request, queryset):
        """Unblock selected IPs"""
        count = queryset.count()
        queryset.delete()
        self.message_user(
            request,
            f'Removed {count} block(s).'
        )
    remove_blocks.short_description = 'Unblock selected IPs'


@admin.register(BlockedAttempt)
class BlockedAttemptAdmin(admin.ModelAdmin):
    """
    Admin interface for viewing blocked access attempts.
    
    This helps you monitor:
    - Are attackers still trying?
    - What are they trying to access?
    - Should you report them?
    """
    
    list_display = [
        'blocked_ip_link',  # Custom method with link
        'path',
        'timestamp',
        'attempts_same_path'  # Custom method
    ]
    
    list_filter = [
        'timestamp',
        'path',
    ]
    
    search_fields = [
        'blocked_ip__ip_address',
        'path'
    ]
    
    readonly_fields = ['blocked_ip', 'timestamp', 'path']
    
    ordering = ['-timestamp']
    
    list_per_page = 50
    
    def blocked_ip_link(self, obj):
        """Create clickable link to the BlockedIP entry"""
        url = f'/admin/ip_tracking/blockedip/{obj.blocked_ip.id}/change/'
        return format_html(
            '<a href="{}">{}</a>',
            url, obj.blocked_ip.ip_address
        )
    blocked_ip_link.short_description = 'Blocked IP'
    
    def attempts_same_path(self, obj):
        """Count attempts to same path"""
        count = BlockedAttempt.objects.filter(
            blocked_ip=obj.blocked_ip,
            path=obj.path
        ).count()
        
        if count > 5:
            return format_html(
                '<span style="color: #d32f2f; font-weight: bold;">{} times</span>',
                count
            )
        return f'{count} times'
    attempts_same_path.short_description = 'Attempts to this path'


# Optional: Custom admin site title
admin.site.site_header = "IP Tracking Administration"
admin.site.site_title = "IP Tracking Admin"
admin.site.index_title = "Welcome to IP Tracking Administration"