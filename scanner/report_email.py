"""
Envoi d'emails post-scan avec le rapport PDF en pièce jointe.

Gère les erreurs d'envoi sans faire échouer le pipeline de scan.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from django.conf import settings
from django.core.mail import EmailMessage

from .models import Rapport, Scan
from .report_generator import (
    build_report_context,
    risk_level_from_score,
    security_score_from_risk,
    resolve_pdf_absolute_path,
)

logger = logging.getLogger(__name__)


def _notify_email_status(scan, result):
    try:
        from .notification_service import notify_report_emailed, notify_report_email_failed
        if result.get('success'):
            notify_report_emailed(scan, result.get('recipients', []))
        else:
            notify_report_email_failed(scan, result.get('error') or 'Erreur envoi inconnue')
    except Exception:
        logger.warning('email_status_notification_failed scan_id=%s', scan.id, exc_info=True)


def resolve_recipient_emails(scan: Scan, extra_emails: Optional[List[str]] = None) -> List[str]:
    """
    Destinataires par ordre de priorité :
    1. emails explicites (ex. paramètre request)
    2. email du client lié au scan
    3. email de l'utilisateur qui a lancé le scan
    """
    recipients: List[str] = []
    seen = set()

    def add(addr: Optional[str]):
        if not addr:
            return
        email = str(addr).strip()
        if not email or '@' not in email:
            return
        key = email.lower()
        if key in seen:
            return
        seen.add(key)
        recipients.append(email)

    for e in extra_emails or []:
        add(e)

    if scan.client_id and getattr(scan, 'client', None) is not None:
        add(scan.client.email)
    elif scan.client_id:
        try:
            add(scan.client.email)
        except Exception:
            logger.warning('Email client inaccessible pour le scan %s', scan.id, exc_info=True)

    if scan.created_by_id and getattr(scan, 'created_by', None) is not None:
        add(scan.created_by.email)
    elif scan.created_by_id:
        try:
            add(scan.created_by.email)
        except Exception:
            logger.warning('Email createur inaccessible pour le scan %s', scan.id, exc_info=True)

    return recipients


def build_report_url(scan: Scan) -> str:
    site_url = getattr(settings, 'CYBERSCAN_SITE_URL', 'http://localhost:4200').rstrip('/')
    api_base = getattr(settings, 'CYBERSCAN_API_URL', 'http://localhost:8000').rstrip('/')
    return f'{site_url}/scans/{scan.id}/rapport'


def build_api_report_url(scan: Scan) -> str:
    api_base = getattr(settings, 'CYBERSCAN_API_URL', 'http://localhost:8000').rstrip('/')
    return f'{api_base}/api/scans/{scan.id}/rapport/'


def build_email_subject(scan: Scan, context: Optional[dict] = None) -> str:
    ctx = context or build_report_context(scan)
    risk_label = ctx.get('niveau_risque') or risk_level_from_score(scan.score_risque_ia)[0]
    security_score = ctx.get('score_global_securite')
    if security_score is None:
        security_score = security_score_from_risk(scan.score_risque_ia)
    return (
        f"[CyberScan] {scan.domaine} — Risque {risk_label} "
        f"(sécurité {security_score}/10) — Rapport disponible"
    )


def build_email_body(scan: Scan, context: Optional[dict] = None) -> str:
    ctx = context or build_report_context(scan)
    risk_label = ctx.get('niveau_risque') or risk_level_from_score(scan.score_risque_ia)[0]
    security_score = ctx.get('score_global_securite')
    if security_score is None:
        security_score = security_score_from_risk(scan.score_risque_ia)
    date_str = scan.date_scan.strftime('%d/%m/%Y %H:%M UTC') if scan.date_scan else '—'
    resume = ctx.get('resume_executif') or ''
    report_url = build_report_url(scan)
    api_report_url = build_api_report_url(scan)

    return (
        f"Bonjour,\n\n"
        f"Votre scan CyberScan est terminé. Voici le résumé :\n\n"
        f"  Domaine          : {scan.domaine}\n"
        f"  Date             : {date_str}\n"
        f"  Score global     : {security_score}/10\n"
        f"  Niveau de risque : {risk_label}\n"
        f"  Score risque IA  : {scan.score_risque_ia}/10\n\n"
        f"Résumé exécutif :\n"
        f"{resume}\n\n"
        f"Consulter le rapport en ligne :\n"
        f"  {report_url}\n\n"
        f"Télécharger via l'API :\n"
        f"  {api_report_url}\n\n"
        f"Le rapport PDF complet est joint à cet e-mail.\n"
        f"Vous pouvez également exporter le rapport en Excel ou JSON depuis le tableau de bord.\n\n"
        f"Cordialement,\n"
        f"L'équipe CyberScan\n"
    )


def send_scan_report_email(
    scan: Scan,
    rapport: Optional[Rapport] = None,
    extra_emails: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Envoie l'email de rapport avec PDF en pièce jointe.

    Retourne un dict :
      {
        'success': bool,
        'recipients': [...],
        'error': str|None,
        'skipped': bool,   # True si aucun destinataire
      }

    Les erreurs sont capturées et loggées : elles ne remontent pas d'exception
    non gérée vers l'appelant (sauf si on souhaite propager — ici non).
    """
    result: Dict[str, Any] = {
        'success': False,
        'recipients': [],
        'error': None,
        'skipped': False,
    }

    try:
        recipients = resolve_recipient_emails(scan, extra_emails=extra_emails)
        result['recipients'] = recipients

        if not recipients:
            result['skipped'] = True
            result['error'] = 'Aucun destinataire email disponible pour ce scan'
            logger.warning(
                'Email rapport scan #%s non envoyé : aucun destinataire (domaine=%s)',
                scan.id, scan.domaine,
            )
            _notify_email_status(scan, result)
            return result

        if rapport is None:
            rapport = scan.rapports.order_by('-date_generation').first()

        context = build_report_context(scan)
        subject = build_email_subject(scan, context)
        body = build_email_body(scan, context)

        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', None) or settings.EMAIL_HOST_USER
        email = EmailMessage(
            subject=subject,
            body=body,
            from_email=from_email,
            to=recipients,
        )

        # Pièce jointe PDF
        if rapport is not None:
            pdf_path = resolve_pdf_absolute_path(rapport)
            if pdf_path.is_file():
                email.attach_file(str(pdf_path), mimetype='application/pdf')
            else:
                logger.error(
                    'PDF introuvable pour scan #%s (chemin=%s) — email sans pièce jointe',
                    scan.id, rapport.chemin_pdf,
                )
                # On envoie quand même le corps textuel
        else:
            logger.warning('Aucun Rapport PDF pour scan #%s — email sans pièce jointe', scan.id)

        email.send(fail_silently=False)
        result['success'] = True
        logger.info(
            'Email rapport scan #%s envoyé à %s',
            scan.id, ', '.join(recipients),
        )
        _notify_email_status(scan, result)
        return result

    except Exception as exc:
        # Gestion des erreurs d'envoi (SMTP, auth, réseau, etc.)
        error_msg = str(exc).strip() or exc.__class__.__name__
        result['success'] = False
        result['error'] = error_msg
        logger.exception(
            'Échec envoi email rapport scan #%s : %s',
            getattr(scan, 'id', '?'), error_msg,
        )
        _notify_email_status(scan, result)
        return result
