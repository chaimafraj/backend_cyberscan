from rest_framework import serializers
from .models import Scan, CVE, Alerte


class CVESerializer(serializers.ModelSerializer):
    class Meta:
        model = CVE
        fields = '__all__'


class ScanSerializer(serializers.ModelSerializer):
    cves = CVESerializer(many=True, read_only=True)

    class Meta:
        model = Scan
        fields = '__all__'