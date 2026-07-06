from rest_framework import serializers
from .models import Scan, CVE, User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class CVESerializer(serializers.ModelSerializer):
    class Meta:
        model = CVE
        fields = ['id', 'cve_id', 'description', 'cvss_score', 'recommandation_ia']


class ScanSerializer(serializers.ModelSerializer):
    cves = CVESerializer(many=True, read_only=True)

    class Meta:
        model = Scan
        fields = ['id', 'domaine', 'date_scan', 'resultats_ssl', 'score_risque_ia', 'cves']


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'role', 'is_active']


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'role']

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get('email', ''),
            password=validated_data['password'],
            role=validated_data.get('role', 'viewer'),
        )
        return user


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['role'] = user.role
        token['username'] = user.username
        return token

    def validate(self, attrs):
        data = super().validate(attrs)

        must_change = False
        if hasattr(self.user, 'client_profile'):
            must_change = self.user.client_profile.must_change_password

        data['user'] = {
            'id': self.user.id,
            'username': self.user.username,
            'email': self.user.email,
            'role': self.user.role,
            'must_change_password': must_change,
        }
        return data