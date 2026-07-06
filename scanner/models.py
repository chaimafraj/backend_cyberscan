from django.db import models
from django.contrib.auth.models import AbstractUser
import secrets
import string


class User(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Administrateur'),
        ('analyst', 'Analyste Sécurité'),
        ('viewer', 'Lecteur'),
        ('client', 'Client'),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='viewer')
    email = models.EmailField(unique=True)

    def __str__(self):
        return f"{self.username} ({self.role})"


class Scan(models.Model):
    domaine = models.CharField(max_length=255)
    date_scan = models.DateTimeField(auto_now_add=True)
    resultats_ssl = models.JSONField(default=dict)
    score_risque_ia = models.FloatField(default=0.0)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name='scans'
    )
    client = models.ForeignKey(
        'Client', on_delete=models.CASCADE, null=True, blank=True, related_name='scans_client'
    )

    def __str__(self):
        return f"{self.domaine} - {self.date_scan}"

class CVE(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='cves')
    cve_id = models.CharField(max_length=50)
    description = models.TextField()
    cvss_score = models.FloatField(default=0.0)
    recommandation_ia = models.TextField(null=True, blank=True)

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

def generate_temp_password(length=10):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


class Client(models.Model):
    nom = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='client_profile',
        null=True, blank=True
    )
    must_change_password = models.BooleanField(default=True)
    date_creation = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='clients_created'
    )
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.nom


class Site(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE, related_name='sites')
    domaine = models.CharField(max_length=255)
    date_ajout = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.domaine} ({self.client.nom})"