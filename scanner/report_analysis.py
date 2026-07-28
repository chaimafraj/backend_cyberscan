"""Sections narratives déterministes construites uniquement depuis le scan."""
from __future__ import annotations

from .report_data import build_report_metrics
from .risk_policy import level_from_score, normalize_score, priority_from_score, recommendation_order


def _joined(values, empty):
    cleaned = [str(value).strip() for value in values if str(value).strip()]
    return ", ".join(dict.fromkeys(cleaned)) if cleaned else empty


def build_report_analysis(scan, results, findings):
    ordered = recommendation_order(findings)
    metrics = build_report_metrics(scan, results, ordered)
    score = normalize_score(scan.score_risque_ia)
    level = level_from_score(score)
    overall_priority = priority_from_score(score)
    severity = metrics["severity"]
    certificate = results.get("certificate") or {}

    observed_parts = [
        f"Score IA {score:.1f}/10 ({level})",
        f"{metrics['findings']} vulnérabilité(s)",
        f"{severity['Critique']} critique(s), {severity['Élevé']} élevée(s), "
        f"{severity['Moyen']} moyenne(s), {severity['Faible']} faible(s)",
        f"{metrics['cves']} CVE",
        f"{metrics['port_count']} port(s) ouvert(s) et {metrics['service_count']} service(s)",
        f"{metrics['technology_count']} technologie(s)",
        f"{metrics['tool_count']} outil(s) avec résultats",
        f"{metrics['tls_count']} version(s) TLS et {metrics['cipher_count']} suite(s) de chiffrement",
    ]
    if certificate:
        certificate_state = "expiré" if certificate.get("expired") is True else "valide" if certificate.get("expired") is False else "présent"
        observed_parts.append(f"certificat {certificate_state}")

    summary = f"Analyse de {scan.domaine} : " + "; ".join(observed_parts) + "."
    top = ordered[:3]
    ai_rows = [
        ("Score et niveau", f"{score:.1f}/10 — {level}"),
        ("Répartition observée", f"Critiques {severity['Critique']} | Élevées {severity['Élevé']} | Moyennes {severity['Moyen']} | Faibles {severity['Faible']}"),
        ("Constats prioritaires", _joined((item["component"] for item in top), "Aucun constat significatif extrait")),
        ("Sources des preuves", _joined((item["type"] for item in ordered), "Aucune source de vulnérabilité")),
        ("Priorité globale", f"{overall_priority['code']} — {overall_priority['label']}"),
    ]
    if top:
        ai_rows.append(("Recommandation principale", top[0]["recommendation"]))

    plan = [
        {
            "priority_code": item["priority_code"],
            "priority": item["priority"],
            "id": item["id"],
            "component": item["component"],
            "recommendation": item["recommendation"],
            "evidence": item["evidence"],
            "score": item["score"],
            "severity": item["severity"],
        }
        for item in ordered
    ]

    if ordered:
        top_ids = _joined((item["id"] for item in top), "")
        conclusion = (
            f"Le scan de {scan.domaine} établit un risque {level.lower()} ({score:.1f}/10) "
            f"à partir de {metrics['findings']} constat(s) documenté(s). "
            f"La priorité {overall_priority['code']} concerne {top_ids}. "
            f"Après application des {len(plan)} action(s) associée(s), un nouveau scan devra mesurer le résultat."
        )
    else:
        conclusion = (
            f"Le scan de {scan.domaine} établit un risque {level.lower()} ({score:.1f}/10) "
            "sans vulnérabilité significative extraite des résultats disponibles."
        )

    return {
        "score": score, "level": level, "overall_priority": overall_priority,
        "metrics": metrics, "summary": summary, "ai_rows": ai_rows,
        "plan": plan, "conclusion": conclusion,
    }