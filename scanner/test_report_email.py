from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from django.core import signing
from django.test import SimpleTestCase, override_settings

from .report_email import (
    REPORT_DOWNLOAD_SALT,
    build_api_report_url,
    build_report_url,
)


class ReportEmailUrlTests(SimpleTestCase):
    def setUp(self):
        self.scan = SimpleNamespace(id=173)

    @override_settings(
        CYBERSCAN_SITE_URL='https://app.cyberscan.example/',
        CYBERSCAN_HISTORY_URL='https://app.cyberscan.example/historique',
    )
    def test_report_url_targets_the_known_history_page(self):
        self.assertEqual(
            build_report_url(self.scan),
            'https://app.cyberscan.example/historique?scan=173',
        )

    @override_settings(
        CYBERSCAN_HISTORY_URL='https://app.cyberscan.example/historique?vue=rapports',
    )
    def test_report_url_preserves_existing_query_parameters(self):
        self.assertEqual(
            build_report_url(self.scan),
            'https://app.cyberscan.example/historique?vue=rapports&scan=173',
        )

    @override_settings(CYBERSCAN_API_URL='https://api.cyberscan.example/')
    def test_api_url_is_a_signed_email_download_link(self):
        url = build_api_report_url(self.scan)
        parts = urlsplit(url)

        self.assertEqual(
            f'{parts.scheme}://{parts.netloc}{parts.path}',
            'https://api.cyberscan.example/api/scans/173/rapport/email-download/',
        )
        token = parse_qs(parts.query)['token'][0]
        self.assertEqual(
            signing.loads(token, salt=REPORT_DOWNLOAD_SALT),
            {'scan_id': 173},
        )