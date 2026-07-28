import logging

from celery import shared_task
from django.db import transaction
from django.utils import timezone

from .models import Scan
from .realtime_service import publish_event, publish_on_commit
from .scan_persistence import build_stored_results, replace_scan_cves

logger = logging.getLogger(__name__)


def _run_pipeline(target, is_prod, has_money, options):
    from .views import scan_single_site
    return scan_single_site(target, is_prod=is_prod, has_money=has_money, options=options)



@shared_task(bind=True, name='scanner.execute_scan')
def execute_scan(self, scan_id, is_prod=True, has_money=False, options=None, email_to=None):
    options = options or {}
    updated = Scan.objects.filter(pk=scan_id).update(
        status=Scan.Status.RUNNING,
        started_at=timezone.now(),
        error_message='',
        celery_task_id=self.request.id or '',
    )
    if not updated:
        raise Scan.DoesNotExist(f'Scan {scan_id} introuvable')
    scan = Scan.objects.get(pk=scan_id)
    publish_event('scan.running', scan, {'status': Scan.Status.RUNNING})

    try:
        result = _run_pipeline(scan.domaine, is_prod, has_money, options)
        if not result.get('success'):
            raise RuntimeError(result.get('error') or 'Le scan a échoué')

        completed_at = timezone.now()
        with transaction.atomic():
            scan = Scan.objects.select_for_update().get(pk=scan_id)
            scan.resultats_ssl = build_stored_results(result)
            scan.score_risque_ia = round(float(result.get('score_risque_ia') or 0), 1)
            scan.status = Scan.Status.COMPLETED
            scan.completed_at = completed_at
            scan.error_message = ''
            scan.save(update_fields=[
                'resultats_ssl', 'score_risque_ia', 'status', 'completed_at', 'error_message',
            ])
            replace_scan_cves(scan, result.get('cves', []))
            publish_on_commit('scan.completed', scan, {
                'status': Scan.Status.COMPLETED,
                'score_risque_ia': scan.score_risque_ia,
            })

        # Le scan est déjà visible comme COMPLETED avant les opérations lentes PDF/email.
        try:
            from .notification_service import notify_scan_events
            notify_scan_events(scan)
        except Exception:
            logger.exception('scan_notifications_failed scan_id=%s', scan_id)

        try:
            from .report_pipeline import finalize_scan_report
            report = finalize_scan_report(scan, extra_emails=[email_to] if email_to else None)
            stored = dict(scan.resultats_ssl)
            stored['report'] = report
            Scan.objects.filter(pk=scan_id).update(resultats_ssl=stored)
        except Exception:
            logger.exception('scan_report_pipeline_failed scan_id=%s', scan_id)

        logger.info('scan_completed scan_id=%s duration_status=completed', scan_id)
        return {'scan_id': scan.id, 'status': Scan.Status.COMPLETED}
    except Exception as exc:
        logger.exception('scan_task_failed scan_id=%s error_type=%s', scan_id, exc.__class__.__name__)
        Scan.objects.filter(pk=scan_id).update(
            status=Scan.Status.FAILED,
            error_message=str(exc)[:1000],
            completed_at=timezone.now(),
        )
        failed_scan = Scan.objects.filter(pk=scan_id).first()
        if failed_scan:
            publish_event('scan.failed', failed_scan, {'status': Scan.Status.FAILED})
        raise