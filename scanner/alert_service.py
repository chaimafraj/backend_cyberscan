from __future__ import annotations

from .ai_module.chatbot import format_score
from .cve_data import collect_scan_cves


def severity_from_score(score):
    value = float(score or 0)
    if value >= 7:
        return 'CRITIQUE'
    if value >= 4:
        return 'MOYEN'
    return 'FAIBLE'


def frontend_type(severity):
    return {'CRITIQUE': 'danger', 'MOYEN': 'warn', 'FAIBLE': 'ok'}[severity]


def _alert(scan, title, message, severity, source, source_id=''):
    return {
        'scan_id': scan.id,
        'domain': scan.domaine,
        'icon': '⚠' if severity == 'CRITIQUE' else '!' if severity == 'MOYEN' else 'i',
        'titre': title,
        'message': message,
        'date': scan.date_scan.isoformat() if scan.date_scan else None,
        'niveau': severity,
        'type': frontend_type(severity),
        'source': source,
        'source_id': source_id,
    }


def build_alerts(scans):
    alerts = []
    for scan in scans:
        results = scan.resultats_ssl if isinstance(scan.resultats_ssl, dict) else {}
        for vulnerability in dict.fromkeys(results.get('vulnerabilities') or []):
            definitions = {
                'TLSv1.0': ('CRITIQUE', 'Protocole obsolète signalé par SSLScan et à désactiver au profit de TLS 1.2 ou 1.3.'),
                'TLSv1.1': ('MOYEN', 'Protocole déprécié à désactiver au profit de TLS 1.2 ou 1.3.'),
                'WEAK_CIPHER': ('CRITIQUE', 'Suite de chiffrement faible 3DES ou RC4 signalée par SSLScan.'),
            }
            if vulnerability in definitions:
                severity, message = definitions[vulnerability]
                alerts.append(_alert(scan, f'{vulnerability} détecté — {scan.domaine}', message,
                                     severity, 'ssl', vulnerability))
        for cve in collect_scan_cves(scan, results):
            severity = severity_from_score(cve['cvss_score'])
            alerts.append(_alert(
                scan, f"{cve['cve_id']} — {scan.domaine}",
                f"{cve['description']} (CVSS {format_score(cve['cvss_score'])}/10)",
                severity, 'cve', cve['cve_id'],
            ))
        for vulnerability in scan.vulnerabilites_manuelles.all():
            severity = {'critical': 'CRITIQUE', 'high': 'CRITIQUE', 'medium': 'MOYEN', 'low': 'FAIBLE'}.get(
                (vulnerability.risk or '').lower(), severity_from_score(vulnerability.cvss_score)
            )
            alerts.append(_alert(
                scan, f'{vulnerability.nom} — {scan.domaine}', vulnerability.description,
                severity, 'manual', str(vulnerability.id),
            ))
        for finding in results.get('nuclei_findings') or []:
            raw = str(finding.get('severity') or 'info').lower()
            severity = {'critical': 'CRITIQUE', 'high': 'CRITIQUE', 'medium': 'MOYEN'}.get(raw, 'FAIBLE')
            name = finding.get('name') or finding.get('template_id') or 'Vulnérabilité Nuclei'
            alerts.append(_alert(scan, f'{name} — {scan.domaine}', finding.get('description') or '',
                                 severity, 'nuclei', str(finding.get('template_id') or '')))
        for finding in results.get('zap_findings') or []:
            raw = str(finding.get('risk') or 'low').split()[0].lower()
            severity = {'critical': 'CRITIQUE', 'high': 'CRITIQUE', 'medium': 'MOYEN'}.get(raw, 'FAIBLE')
            name = finding.get('name') or 'Vulnérabilité ZAP'
            alerts.append(_alert(scan, f'{name} — {scan.domaine}', (finding.get('description') or '')[:300],
                                 severity, 'zap', str(finding.get('pluginid') or '')))
        if not any(item['scan_id'] == scan.id for item in alerts):
            alerts.append(_alert(
                scan, f'Scan terminé — {scan.domaine}',
                f'Aucune vulnérabilité enregistrée. Score IA: {format_score(scan.score_risque_ia)}/10.',
                'FAIBLE', 'scan', str(scan.id),
            ))
    return alerts


def alert_stats(alerts):
    return {
        'critiques': sum(item['niveau'] == 'CRITIQUE' for item in alerts),
        'moyennes': sum(item['niveau'] == 'MOYEN' for item in alerts),
        'faibles': sum(item['niveau'] == 'FAIBLE' for item in alerts),
        'total': len(alerts),
    }