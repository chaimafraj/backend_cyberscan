from types import SimpleNamespace

from django.test import SimpleTestCase

from .ai_module.risk_scorer import RiskScorer
from .report_analysis import build_report_analysis
from .report_data import normalize_results
from .report_fixed import _build_findings
from .risk_policy import level_from_score, priority_from_score
from .test_report_data import FakeCveManager, NMAP, SSL_SCAN, WHATWEB


class RiskAndNarrativeConsistencyTests(SimpleTestCase):
    def test_score_level_and_global_priority_are_consistent(self):
        scorer = RiskScorer()
        cases = [
            (scorer.calculate_scan_score(is_prod=False), "Faible", "P3"),
            (scorer.calculate_scan_score(zap_findings=[{"risk": "medium"}], is_prod=False), "Moyen", "P2"),
            (scorer.calculate_scan_score(security_signals=["TLSv1.0"], is_prod=False), "Élevé", "P1"),
            (scorer.calculate_scan_score(nuclei_findings=[{"severity": "critical"}], is_prod=False), "Critique", "P1"),
        ]
        for score, expected_level, expected_priority in cases:
            self.assertEqual(level_from_score(score), expected_level)
            self.assertEqual(priority_from_score(score)["code"], expected_priority)

    def _scan_and_results(self):
        cve = SimpleNamespace(
            cve_id="CVE-2026-0001", cvss_score=7.5,
            description="Composant vulnérable confirmé", recommandation_ia="Mettre à jour le composant",
        )
        scan = SimpleNamespace(
            id=99, domaine="audit.example", score_risque_ia=8.0,
            cves=FakeCveManager([cve]), started_at=None, completed_at=None,
        )
        results = normalize_results({
            "sslscan": SSL_SCAN, "openssl": "subject=CN=audit.example", "nmap": NMAP,
            "whatweb": WHATWEB, "vulnerabilities": ["TLSv1.0"],
            "nvd_cves": [], "nvd": {"requested": False, "success": True},
            "scan_duration_seconds": 25,
        })
        return scan, results

    def test_every_vulnerability_has_all_required_fields(self):
        scan, results = self._scan_and_results()
        findings = _build_findings(scan, results)
        self.assertTrue(findings)
        required = ("id", "component", "evidence", "score", "severity", "recommendation", "priority", "priority_code")
        for finding in findings:
            for field in required:
                self.assertIn(field, finding)
                self.assertNotIn(finding[field], (None, ""))
            self.assertEqual(finding["severity"], level_from_score(finding["score"]))
            self.assertEqual(finding["priority_code"], priority_from_score(finding["score"])["code"])
            self.assertEqual(finding["priority"], priority_from_score(finding["score"])["label"])

    def test_all_four_sections_only_use_observed_values(self):
        scan, results = self._scan_and_results()
        findings = _build_findings(scan, results)
        analysis = build_report_analysis(scan, results, findings)

        self.assertIn("Score IA 8.0/10 (Élevé)", analysis["summary"])
        self.assertIn(f"{len(findings)} vulnérabilité(s)", analysis["summary"])
        self.assertIn("2 port(s) ouvert(s)", analysis["summary"])
        self.assertEqual(len(analysis["plan"]), len(findings))
        self.assertEqual(analysis["plan"][0]["id"], findings[0]["id"])
        self.assertEqual(analysis["plan"][0]["recommendation"], findings[0]["recommendation"])
        self.assertIn("risque élevé (8.0/10)", analysis["conclusion"])
        self.assertIn(findings[0]["id"], analysis["conclusion"])

        rendered_analysis = " ".join(value for _, value in analysis["ai_rows"])
        self.assertIn(findings[0]["component"], rendered_analysis)
        self.assertIn(findings[0]["recommendation"], rendered_analysis)
        self.assertNotIn("Non disponible", analysis["summary"] + analysis["conclusion"] + rendered_analysis)