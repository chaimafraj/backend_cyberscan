from django.db import models


class Scan(models.Model):
    domaine = models.CharField(max_length=255)
    date_scan = models.DateTimeField(auto_now_add=True)
    resultats_ssl = models.JSONField(default=dict)
    score_risque_ia = models.FloatField(default=0.0)

    def __str__(self):
        return f"{self.domaine} - {self.date_scan}"


class CVE(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='cves')
    cve_id = models.CharField(max_length=50)
    description = models.TextField()
    cvss_score = models.FloatField(default=0.0)

    def __str__(self):
        return self.cve_id


class Alerte(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='alertes')
    message = models.TextField()
    date_envoi = models.DateTimeField(auto_now_add=True)


class Rapport(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='rapports')
    chemin_pdf = models.CharField(max_length=500)
    date_generation = models.DateTimeField(auto_now_add=True)