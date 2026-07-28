from __future__ import annotations

import logging
from typing import Optional

from .ai_module.chatbot import format_score
from .models import CVE, Notification, Scan
from .cve_data import collect_scan_cves
from .realtime_service import publish_event

logger = logging.getLogger(__name__)


def create_notification(scan, titre, message, type, niveau='info'):
    notification, created = Notification.objects.get_or_create(
        scan=scan, type=type, titre=titre,
        defaults={'message': message, 'niveau': niveau},
    )
    if not created and (notification.message != message or notification.niveau != niveau):
        notification.message = message
        notification.niveau = niveau
        notification.save(update_fields=['message', 'niveau'])
    if created:
        publish_event('notification.created', scan, {
            'notification_id': notification.id,
            'category': type,
            'severity': niveau,
        })
        logger.info('notification_created notification_id=%s type=%s scan_id=%s',
                    notification.id, type, scan.id)
    return notification


def notify_scan_finished(scan):
    return create_notification(
        scan, f'Scan terminé — {scan.domaine}',
        f'Le scan de sécurité sur {scan.domaine} est terminé. Score de risque IA : {format_score(scan.score_risque_ia)}/10.',
        'scan_finished', 'info',
    )


def notify_report_ready(scan, format_rapport='PDF'):
    label = format_rapport.upper()
    return create_notification(
        scan, f'Rapport {label} disponible — {scan.domaine}',
        f'Le rapport {label} pour {scan.domaine} est prêt au téléchargement.',
        'report_ready', 'info',
    )


def notify_critical_cve(scan, cve):
    score = float(cve.get('cvss_score') or 0) if isinstance(cve, dict) else float(cve.cvss_score or 0)
    if score < 7:
        return None
    cve_id = cve.get('cve_id') if isinstance(cve, dict) else cve.cve_id
    description = cve.get('description') if isinstance(cve, dict) else cve.description
    niveau = 'critical' if score >= 9 else 'warning'
    return create_notification(
        scan, f'CVE critique détectée — {cve_id}',
        f'{cve_id} détectée sur {scan.domaine} (CVSS {format_score(score)}/10). {description[:300]}',
        'new_cve', niveau,
    )

def notify_high_risk(scan):
    if float(scan.score_risque_ia or 0) < 9:
        return None
    return create_notification(
        scan, f'Risque élevé — {scan.domaine}',
        f'Le score de risque IA ({format_score(scan.score_risque_ia)}/10) dépasse le seuil critique sur {scan.domaine}.',
        'high_risk', 'critical',
    )


def notify_scan_events(scan, cves: Optional[list] = None):
    notifications = [notify_scan_finished(scan)]
    high = notify_high_risk(scan)
    if high:
        notifications.append(high)
    results = scan.resultats_ssl if isinstance(scan.resultats_ssl, dict) else {}
    selected_cves = cves if cves is not None else collect_scan_cves(scan, results)
    for cve in selected_cves:
        notification = notify_critical_cve(scan, cve)
        if notification:
            notifications.append(notification)
    return notifications