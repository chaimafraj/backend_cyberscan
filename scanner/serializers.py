from rest_framework import serializers
from .models import Scan, CVE, User, VulnerabiliteManuelle, Notification
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class ChatbotRequestSerializer(serializers.Serializer):
    question = serializers.CharField(
        required=True, allow_blank=False, trim_whitespace=True, max_length=1000,
    )
    scan_id = serializers.IntegerField(required=False, allow_null=True, min_value=1)


class ChatbotResponseSerializer(serializers.Serializer):
    answer = serializers.CharField()
    question = serializers.CharField()
    scan_id = serializers.IntegerField(min_value=1)
    context_mode = serializers.ChoiceField(choices=('scan', 'latest_scan'))
    sections = serializers.DictField(child=serializers.CharField())

class CVESerializer(serializers.ModelSerializer):
    class Meta:
        model = CVE
        fields = ['id', 'cve_id', 'description', 'cvss_score', 'recommandation_ia']


class ScanSerializer(serializers.ModelSerializer):
    cves = CVESerializer(many=True, read_only=True)
    client_nom = serializers.SerializerMethodField()
    pdf_disponible = serializers.SerializerMethodField()
    has_rapport = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = [
            'id', 'domaine', 'date_scan', 'resultats_ssl', 'score_risque_ia',
            'cves', 'client_nom', 'pdf_disponible', 'has_rapport',
        ]

    def get_client_nom(self, obj):
        return obj.client.nom if obj.client else '—'

    def get_pdf_disponible(self, obj):
        return obj.rapports.exists()

    def get_has_rapport(self, obj):
        return obj.rapports.exists()


class NotificationSerializer(serializers.ModelSerializer):
    title = serializers.CharField(source='titre', read_only=True)
    description = serializers.CharField(source='message', read_only=True)
    timestamp = serializers.DateTimeField(source='date_creation', read_only=True)
    read = serializers.BooleanField(source='lu', read_only=True)
    type = serializers.SerializerMethodField()

    class Meta:
        model = Notification
        fields = ['id', 'type', 'title', 'description', 'timestamp', 'read']
        read_only_fields = fields

    def get_type(self, obj):
        if obj.type == 'scan_finished':
            return 'success'
        if obj.niveau == 'critical':
            return 'alert'
        if obj.niveau == 'warning':
            return 'warning'
        return 'info'


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


class VulnerabiliteManuelleSerializer(serializers.ModelSerializer):
    ajoutee_par_username = serializers.SerializerMethodField()

    class Meta:
        model = VulnerabiliteManuelle
        fields = [
            'id', 'scan', 'type_vuln', 'nom', 'impacted_element', 'description',
            'risk', 'cvss_score', 'cvss_vector', 'priorite', 'complexite',
            'technical_business_risks', 'recommandation', 'proof_of_concept',
            'references', 'date_ajout', 'ajoutee_par_username',
        ]
        read_only_fields = ['date_ajout']

    def get_ajoutee_par_username(self, obj):
        return obj.ajoutee_par.username if obj.ajoutee_par else '—'