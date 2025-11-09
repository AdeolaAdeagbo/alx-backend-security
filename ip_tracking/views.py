from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .models import RequestLog, BlockedIP, SuspiciousIP
from django.db.models import Count

@swagger_auto_schema(
    method='get',
    operation_description="Get statistics about IP tracking",
    responses={200: openapi.Response('Statistics retrieved successfully')}
)
@api_view(['GET'])
def ip_statistics(request):
    """
    Get IP tracking statistics
    Returns counts of logs, blocked IPs, and suspicious IPs
    """
    stats = {
        'total_requests': RequestLog.objects.count(),
        'blocked_ips': BlockedIP.objects.count(),
        'suspicious_ips': SuspiciousIP.objects.filter(is_resolved=False).count(),
        'top_countries': list(
            RequestLog.objects.exclude(country__isnull=True)
            .values('country')
            .annotate(count=Count('country'))
            .order_by('-count')[:5]
        )
    }
    return Response(stats)


@swagger_auto_schema(
    method='post',
    operation_description="Block an IP address",
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['ip_address'],
        properties={
            'ip_address': openapi.Schema(type=openapi.TYPE_STRING, description='IP address to block'),
            'reason': openapi.Schema(type=openapi.TYPE_STRING, description='Reason for blocking'),
            'duration_hours': openapi.Schema(type=openapi.TYPE_INTEGER, description='Block duration in hours (optional)'),
        },
    ),
    responses={
        201: openapi.Response('IP blocked successfully'),
        400: openapi.Response('Invalid request'),
    }
)
@api_view(['POST'])
def block_ip_api(request):
    """
    Block an IP address via API
    """
    ip_address = request.data.get('ip_address')
    reason = request.data.get('reason', '')
    duration_hours = request.data.get('duration_hours')
    
    if not ip_address:
        return Response({'error': 'ip_address is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        blocked = BlockedIP.block_ip(
            ip_address=ip_address,
            reason=reason,
            blocked_by=request.user.username if request.user.is_authenticated else 'API',
            duration_hours=duration_hours
        )
        return Response({
            'message': f'Successfully blocked {ip_address}',
            'ip_address': blocked.ip_address,
            'reason': blocked.reason
        }, status=status.HTTP_201_CREATED)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='get',
    operation_description="List all blocked IP addresses",
    responses={200: openapi.Response('Blocked IPs retrieved successfully')}
)
@api_view(['GET'])
def list_blocked_ips(request):
    """
    Get list of all blocked IPs
    """
    blocked_ips = BlockedIP.objects.all()
    data = [{
        'ip_address': ip.ip_address,
        'reason': ip.reason,
        'blocked_at': ip.blocked_at,
        'expires_at': ip.expires_at,
        'is_active': not ip.is_expired()
    } for ip in blocked_ips]
    
    return Response({'blocked_ips': data, 'count': len(data)})


@swagger_auto_schema(
    method='get',
    operation_description="Get list of suspicious IPs flagged by anomaly detection",
    responses={200: openapi.Response('Suspicious IPs retrieved successfully')}
)
@api_view(['GET'])
def list_suspicious_ips(request):
    """
    Get list of suspicious IPs
    """
    suspicious = SuspiciousIP.objects.filter(is_resolved=False)
    data = [{
        'ip_address': ip.ip_address,
        'reason': ip.reason,
        'request_count': ip.request_count,
        'flagged_at': ip.flagged_at
    } for ip in suspicious]
    
    return Response({'suspicious_ips': data, 'count': len(data)})