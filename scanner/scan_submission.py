import logging
from uuid import uuid4

from django.db import transaction
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .access import visible_scans
from .models import Client, Scan
from .realtime_service import publish_event, publish_on_commit
from .scan_queries import scan_summary_queryset
from .serializers import ScanSummarySerializer
from .ssh_scanner import InvalidScanTarget, validate_scan_target
from .tasks import execute_scan

logger = logging.getLogger(__name__)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def scans_list(request):
    if request.method == 'GET':
        scans = scan_summary_queryset(visible_scans(request.user)).order_by('-date_scan')
        search = request.query_params.get('search', '').strip()
        risk = request.query_params.get('risk', '').upper()
        status_filter = request.query_params.get('status', '').upper()
        if search:
            scans = scans.filter(domaine__icontains=search)
        if risk == 'HIGH':
            scans = scans.filter(score_risque_ia__gte=7)
        elif risk == 'MEDIUM':
            scans = scans.filter(score_risque_ia__gte=4, score_risque_ia__lt=7)
        elif risk == 'LOW':
            scans = scans.filter(score_risque_ia__lt=4)
        if status_filter in Scan.Status.values:
            scans = scans.filter(status=status_filter)
        try:
            page = max(int(request.query_params.get('page', 1)), 1)
            page_size = min(max(int(request.query_params.get('page_size', 10)), 1), 100)
        except (TypeError, ValueError):
            return Response({'error': 'Pagination invalide'}, status=status.HTTP_400_BAD_REQUEST)
        total = scans.count()
        start = (page - 1) * page_size
        return Response({
            'results': ScanSummarySerializer(scans[start:start + page_size], many=True).data,
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': max(1, (total + page_size - 1) // page_size),
        })

    raw_targets = request.data.get('urls')
    if raw_targets is None:
        raw_targets = [request.data.get('url')] if request.data.get('url') else []
    if not isinstance(raw_targets, list) or not raw_targets:
        return Response({'error': 'Aucune URL fournie'}, status=status.HTTP_400_BAD_REQUEST)
    if len(raw_targets) > 20:
        return Response({'error': 'Maximum 20 cibles par requête'}, status=status.HTTP_400_BAD_REQUEST)

    client = None
    if request.user.role != 'admin':
        try:
            client = request.user.client_profile
        except Client.DoesNotExist:
            client = None

    queued = []
    for raw in raw_targets:
        try:
            target = validate_scan_target(raw)
        except InvalidScanTarget as exc:
            return Response({'error': f'Cible invalide: {exc}'}, status=status.HTTP_400_BAD_REQUEST)
        task_id = str(uuid4())
        with transaction.atomic():
            scan = Scan.objects.create(
                domaine=target,
                status=Scan.Status.PENDING,
                celery_task_id=task_id,
                created_by=request.user,
                client=client,
            )
            publish_on_commit('scan.queued', scan, {'status': Scan.Status.PENDING})
        try:
            execute_scan.apply_async(
                args=[scan.id, request.data.get('is_production', True),
                      request.data.get('has_financial_data', False),
                      request.data.get('options', {}), request.data.get('email')],
                task_id=task_id,
            )
        except Exception as exc:
            logger.exception('scan_queue_failed scan_id=%s error_type=%s', scan.id, exc.__class__.__name__)
            scan.status = Scan.Status.FAILED
            scan.error_message = 'Mise en file Celery impossible.'
            scan.save(update_fields=['status', 'error_message'])
            publish_event('scan.failed', scan, {'status': Scan.Status.FAILED})
            return Response({'error': scan.error_message, 'scan_id': scan.id}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        queued.append({
            'scan_id': scan.id,
            'task_id': task_id,
            'domaine': target,
            'status': Scan.Status.PENDING,
            'status_url': f'/api/scans/{scan.id}/',
        })

    return Response(
        {'scans': queued, 'tracking_ids': [item['scan_id'] for item in queued]},
        status=status.HTTP_202_ACCEPTED,
    )