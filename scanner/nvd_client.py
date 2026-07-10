"""Small client for the NVD CVE API v2.0."""

import os

import requests


NVD_CVE_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
NVD_RESULTS_PER_TECHNOLOGY = 10
NVD_PUBLIC_REQUEST_LIMIT = 5


def _description(cve):
    descriptions = cve.get('descriptions', [])
    english = next((item.get('value', '') for item in descriptions if item.get('lang') == 'en'), '')
    return english or (descriptions[0].get('value', '') if descriptions else '')


def _cvss_score(cve):
    metrics = cve.get('metrics', {})
    for metric_name in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        entries = metrics.get(metric_name, [])
        if entries:
            return float(entries[0].get('cvssData', {}).get('baseScore', 0.0))
    return 0.0


def find_cves_for_technologies(technologies):
    """Return de-duplicated NVD CVEs for WhatWeb technology records.

    WhatWeb technology names are not guaranteed to be CPE identifiers, so the
    NVD keyword endpoint is used.  Returned CVEs are candidates and retain the
    detected technology name for report traceability.
    """
    cves = {}
    errors = []
    headers = {}
    api_key = os.getenv('NVD_API_KEY')
    if api_key:
        headers['apiKey'] = api_key
    request_count = 0
    limit_reached = False

    for technology in technologies:
        if limit_reached:
            break
        name = str(technology.get('name', '')).strip()
        if not name:
            continue

        versions = technology.get('version') or ['']
        for version in versions:
            # NVD permits five requests in a rolling 30-second window without
            # an API key. Do not trigger a 429 while scanning a site with many
            # detected technologies; configure NVD_API_KEY for larger scans.
            if not api_key and request_count >= NVD_PUBLIC_REQUEST_LIMIT:
                errors.append('Limite NVD publique atteinte; configurez NVD_API_KEY pour rechercher les autres technologies.')
                limit_reached = True
                break
            query = ' '.join(part for part in (name, str(version).strip()) if part)
            try:
                request_count += 1
                response = requests.get(
                    NVD_CVE_API_URL,
                    params={
                        'keywordSearch': query,
                        'keywordExactMatch': None,
                        'resultsPerPage': NVD_RESULTS_PER_TECHNOLOGY,
                    },
                    headers=headers,
                    timeout=20,
                )
                response.raise_for_status()
                payload = response.json()
            except (requests.RequestException, ValueError) as exc:
                errors.append(f'{query}: {str(exc) or exc.__class__.__name__}')
                continue

            for vulnerability in payload.get('vulnerabilities', []):
                cve = vulnerability.get('cve', {})
                cve_id = cve.get('id')
                if not cve_id:
                    continue
                result = cves.setdefault(cve_id, {
                    'cve_id': cve_id,
                    'description': _description(cve),
                    'cvss_score': _cvss_score(cve),
                    'technologies': [],
                })
                if name not in result['technologies']:
                    result['technologies'].append(name)

    return {
        'success': not errors,
        'cves': list(cves.values()),
        'errors': errors,
    }
