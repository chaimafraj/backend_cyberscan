import os
from rest_framework.decorators import api_view, permission_classes
from django.db.models import Count, Avg
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.contrib.auth.models import User
from rest_framework.permissions import AllowAny, IsAuthenticated

from .models import Scan, CVE, Client
from .serializers import ScanSerializer
from .ssh_scanner import run_sslscan, run_nmap, run_openssl, run_whatweb
from .nvd_client import find_cves_for_technologies

from .ai_module.risk_scorer import RiskScorer
from .ai_module.recommender import VulnRecommender

scorer_rf = RiskScorer()
recommender_hf = VulnRecommender()


# =========================================================================
# 0. AUTHENTICATION : REGISTER USER
# =========================================================================
@api_view(['POST'])
@permission_classes([AllowAny])
def register_user(request):
    username = request.data.get('username')
    password = request.data.get('password')
    email = request.data.get('email')
    role = request.data.get('role', 'User')

    if not username or not password:
        return Response({'error': 'Username and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(username=username).exists():
        return Response({'error': 'Nom d’utilisateur déjà existant.'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(username=username, email=email, password=password)

    return Response({'message': 'Utilisateur créé avec succès !'}, status=status.HTTP_201_CREATED)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_stats(request):
    user = request.user

    if user.role == 'admin':
        scans_qs = Scan.objects.all()
    else:
        try:
            client = user.client_profile
            scans_qs = Scan.objects.filter(client=client)
        except Client.DoesNotExist:
            scans_qs = Scan.objects.none()

    total_scans = scans_qs.count()
    avg_risk_score = scans_qs.aggregate(Avg('score_risque_ia'))['score_risque_ia__avg'] or 0

    critical_scans = scans_qs.filter(score_risque_ia__gte=7).count()
    medium_scans = scans_qs.filter(score_risque_ia__gte=4, score_risque_ia__lt=7).count()
    low_scans = scans_qs.filter(score_risque_ia__lt=4).count()

    total_recommandations = CVE.objects.filter(scan__in=scans_qs).count()

    scans_recents = scans_qs.order_by('-date_scan')[:5]
    serializer = ScanSerializer(scans_recents, many=True)

    return Response({
        "total_scans": total_scans,
        "avg_risk_score": round(avg_risk_score, 1),
        "critical_count": critical_scans,
        "medium_count": medium_scans,
        "low_count": low_scans,
        "total_recommandations": total_recommandations,
        "recent_scans": serializer.data
    }, status=status.HTTP_200_OK)


# =========================================================================
# 2. INTERNAL UTILS : PARSER MTA3 EL DATA
# =========================================================================
def parse_sslscan(raw_output):
    protocols = []
    vulnerabilities = []

    for line in raw_output.split('\n'):
        if 'TLSv1.0' in line and 'enabled' in line:
            protocols.append({'name': 'TLSv1.0', 'status': 'vulnerable'})
            vulnerabilities.append('TLSv1.0')

        if 'TLSv1.1' in line and 'enabled' in line:
            protocols.append({'name': 'TLSv1.1', 'status': 'obsolete'})
            vulnerabilities.append('TLSv1.1')

        if 'TLSv1.2' in line and 'enabled' in line:
            protocols.append({'name': 'TLSv1.2', 'status': 'secure'})

        if 'TLSv1.3' in line and 'enabled' in line:
            protocols.append({'name': 'TLSv1.3', 'status': 'secure'})

        if '3DES' in line or 'RC4' in line:
            vulnerabilities.append('WEAK_CIPHER')

    return protocols, list(set(vulnerabilities))


# =========================================================================
# 3. PIPELINE DE SCAN CRÉATION (SINGLE OU MULTI-SITE)
# =========================================================================
def scan_single_site(target, is_prod=True, has_money=False):
    sslscan_result = run_sslscan(target)

    if not sslscan_result['success']:
        return {
            'domaine': target,
            'success': False,
            'error': sslscan_result['error'],
            'score_risque_ia': None,
            'protocols': [],
            'vulnerabilities': [],
            'cves': [],
        }

    nmap_result = run_nmap(target)
    openssl_result = run_openssl(target)
    whatweb_result = run_whatweb(target)
    nvd_result = find_cves_for_technologies(
        whatweb_result.get('technologies', []) if whatweb_result.get('success') else []
    )
    # Nuclei is intentionally disabled for the main scan pipeline.
    nuclei_result = {
        'success': False,
        'error': 'Nuclei scan disabled',
        'findings': [],
        'raw': '',
    }
    print(nuclei_result)
    protocols, vulnerabilities = parse_sslscan(sslscan_result['raw'])
    has_weak_cipher = 'WEAK_CIPHER' in vulnerabilities

    # ─── 🧠 Random Forest ───
    score_ia = scorer_rf.calculate_contextual_score(
        vulnerabilities,
        has_weak_cipher,
        is_prod,
        has_money
    )

    nuclei_findings = nuclei_result.get('findings', []) if nuclei_result.get('success') else []
    nuclei_critical_count = sum(1 for f in nuclei_findings if f.get('severity') in ('critical', 'high'))
    if nuclei_critical_count > 0:
        score_ia = min(10.0, score_ia + (nuclei_critical_count * 0.5))

    # ─── 🧠 Flan-T5 ───
    cves_data = []

    if 'TLSv1.0' in vulnerabilities:
        cve_id = "CVE-2014-3566"
        desc_brute = "The SSL protocol 3.0 and TLS 1.0 use CBC mode ciphers, allowing man-in-the-middle attackers to conduct POODLE attacks."
        try:
            solution = recommender_hf.generate_remediation(cve_id, desc_brute)
        except Exception:
            solution = "Désactiver le protocole TLSv1.0 obsolète et migrer vers TLSv1.2 ou TLSv1.3."

        cves_data.append({
            'cve_id': cve_id,
            'description': "Protocole TLSv1.0 obsolète détecté, vulnérable aux attaques POODLE.",
            'cvss_score': 7.5,
            'recommandation_ia': solution
        })

    if has_weak_cipher:
        cve_id_cipher = "CVE-2016-2183"
        desc_cipher_brute = "The DES and Triple DES ciphers use a block size of 64 bits, making them vulnerable to birthday attacks (Sweet32)."
        try:
            solution_cipher = recommender_hf.generate_remediation(cve_id_cipher, desc_cipher_brute)
        except Exception:
            solution_cipher = "Désactiver les suites de chiffrement 3DES et RC4. Utiliser AES-GCM ou ChaCha20-Poly1305."

        cves_data.append({
            'cve_id': cve_id_cipher,
            'description': "Suites de chiffrement 3DES/RC4 faibles détectées, vulnérables à l'attaque Sweet32.",
            'cvss_score': 7.5,
            'recommandation_ia': solution_cipher
        })

    # NVD CVEs are candidate matches: WhatWeb identifies a product/version,
    # then NVD searches its vulnerability corpus for that technology.
    existing_cve_ids = {cve['cve_id'] for cve in cves_data}
    for nvd_cve in nvd_result['cves']:
        if nvd_cve['cve_id'] in existing_cve_ids:
            continue
        try:
            recommendation = recommender_hf.generate_remediation(
                nvd_cve['cve_id'], nvd_cve['description']
            )
        except Exception:
            recommendation = (
                f"Mettre a jour {', '.join(nvd_cve['technologies'])} vers une version corrigee "
                f"et consulter l'avis NVD pour {nvd_cve['cve_id']}."
            )
        cves_data.append({
            'cve_id': nvd_cve['cve_id'],
            'description': nvd_cve['description'],
            'cvss_score': nvd_cve['cvss_score'],
            'recommandation_ia': recommendation,
        })
        existing_cve_ids.add(nvd_cve['cve_id'])

    for finding in nuclei_findings:
        if finding.get('severity') in ('critical', 'high'):
            cves_data.append({
                'cve_id': finding.get('template_id', 'NUCLEI-UNKNOWN'),
                'description': finding.get('name', 'Vulnérabilité détectée par Nuclei'),
                'cvss_score': 9.0 if finding.get('severity') == 'critical' else 7.0,
                'recommandation_ia': f"Vulnérabilité détectée sur {finding.get('matched_at', target)}. Consulter la documentation Nuclei template: {finding.get('template_id', '')}",
            })

    return {
        'domaine': target,
        'success': True,
        'error': None,
        'score_risque_ia': score_ia,
        'protocols': protocols,
        'vulnerabilities': vulnerabilities,
        'cves': cves_data,
        'sslscan_raw': sslscan_result['raw'],
        'nmap_raw': nmap_result.get('raw', ''),
        'openssl_raw': openssl_result.get('raw', ''),
        'nuclei_findings': nuclei_findings,
        'nuclei_raw': nuclei_result.get('raw', ''),
        'nuclei_success': nuclei_result.get('success', False),
        'nuclei_error': nuclei_result.get('error'),
        'whatweb': whatweb_result,
        'nvd': {
            'success': nvd_result['success'],
            'errors': nvd_result['errors'],
            'cves_count': len(nvd_result['cves']),
        },
    }


# =========================================================================
# 4. MAIN ENDPOINT : LIST & ACTIONS (GET / POST)
# =========================================================================
@api_view(['GET'])
def test_api(request):
    return Response({"message": "API Scanner is running!"}, status=status.HTTP_200_OK)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def scans_list(request):
    user = request.user

    if user.role == 'admin':
        base_qs = Scan.objects.all()
    else:
        try:
            client = user.client_profile
        except Client.DoesNotExist:
            client = None
        base_qs = Scan.objects.filter(client=client) if client else Scan.objects.none()

    if request.method == 'GET':
        scans = base_qs.order_by('-date_scan')
        search = request.GET.get('search', '')
        risk = request.GET.get('risk', '').upper()

        try:
            page = int(request.GET.get('page', 1))
            page_size = int(request.GET.get('page_size', 5))
        except ValueError:
            return Response({'error': 'page et page_size doivent être des nombres'}, status=status.HTTP_400_BAD_REQUEST)

        page = max(page, 1)
        page_size = max(page_size, 1)

        if search:
            scans = scans.filter(domaine__icontains=search)

        if risk == 'HIGH':
            scans = scans.filter(score_risque_ia__gte=7)
        elif risk == 'MEDIUM':
            scans = scans.filter(score_risque_ia__gte=4, score_risque_ia__lt=7)
        elif risk == 'LOW':
            scans = scans.filter(score_risque_ia__lt=4)

        total = scans.count()
        total_pages = max(1, (total + page_size - 1) // page_size)

        start = (page - 1) * page_size
        end = start + page_size

        serializer = ScanSerializer(scans[start:end], many=True)

        return Response({
            'results': serializer.data,
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': total_pages,
        }, status=status.HTTP_200_OK)

    if request.method == 'POST':
        urls = request.data.get('urls')
        single_url = request.data.get('url')
        email_to = request.data.get('email')

        is_prod = request.data.get('is_production', True)
        has_money = request.data.get('has_financial_data', False)

        target_list = urls if urls else ([single_url] if single_url else [])
        if not target_list:
            return Response({'error': 'Aucune URL fournie'}, status=status.HTTP_400_BAD_REQUEST)

        client_for_scan = None
        if user.role != 'admin':
            try:
                client_for_scan = user.client_profile
            except Client.DoesNotExist:
                client_for_scan = None

        rapport_global = []

        for target in target_list:
            target = target.strip()
            if not target:
                continue

            result = scan_single_site(target, is_prod=is_prod, has_money=has_money)

            if result['success']:
                scan = Scan.objects.create(
                    domaine=target,
                    resultats_ssl={
                        'sslscan': result['sslscan_raw'],
                        'nmap': result['nmap_raw'],
                        'openssl': result['openssl_raw'],
                        'protocols': result['protocols'],
                        'vulnerabilities': result['vulnerabilities'],
                        'nuclei_findings': result.get('nuclei_findings', []),
                        'nuclei_raw': result.get('nuclei_raw', ''),
                        # Keep Nuclei diagnostics with the scan.  Previously a
                        # failed SSH command was saved as empty output, which
                        # made it indistinguishable from a scan with no hits.
                        'nuclei_success': result.get('nuclei_success', False),
                        'nuclei_error': result.get('nuclei_error'),
                        # JSONField is supported by PostgreSQL, so no model
                        # migration is required to retain WhatWeb findings.
                        'whatweb': result.get('whatweb', {
                            'success': False,
                            'technologies': [],
                        }),
                        'nvd': result.get('nvd', {
                            'success': True,
                            'errors': [],
                            'cves_count': 0,
                        }),
                    },
                    score_risque_ia=result['score_risque_ia'],
                    created_by=user,
                    client=client_for_scan,
                )

                for c in result['cves']:
                    CVE.objects.create(
                        scan=scan,
                        cve_id=c['cve_id'],
                        description=c['description'],
                        cvss_score=c['cvss_score'],
                        recommandation_ia=c['recommandation_ia'],
                    )

                rapport_global.append({
                    'id': scan.id,
                    'domaine': target,
                    'success': True,
                    'score_risque_ia': result['score_risque_ia'],
                    'protocols': result['protocols'],
                    'vulnerabilities': result['vulnerabilities'],
                    'whatweb': result.get('whatweb', {
                        'success': False,
                        'technologies': [],
                    }),
                    'nvd': result.get('nvd', {
                        'success': True,
                        'errors': [],
                        'cves_count': 0,
                    }),
                    'cves_count': scan.cves.count()
                })
            else:
                rapport_global.append({
                    'id': None,
                    'domaine': target,
                    'success': False,
                    'error': result['error'],
                    'score_risque_ia': None,
                    'protocols': [],
                    'vulnerabilities': [],
                    'cves_count': 0
                })

        if email_to:
            critiques = [r for r in rapport_global if r.get('score_risque_ia') and r['score_risque_ia'] >= 7]
            try:
                corps = f"Bonjour,\n\nVoici le rapport de sécurité CYBERSCAN pour votre demande de flicage de {len(rapport_global)} site(s):\n\n"
                for r in rapport_global:
                    if r['success']:
                        corps += f"🌐 Site: {r['domaine']} -> Score Risque IA: {r['score_risque_ia']}/10\n"
                    else:
                        corps += f"🌐 Site: {r['domaine']} -> ❌ ÉCHEC DE SCAN ({r['error']})\n"

                if critiques:
                    corps += f"\n🚨 ATTENTION: {len(critiques)} site(s) CRITIQUE(S) détecté(s)! Veuillez vous connecter au tableau de bord Angular pour voir les remédiations en Français."

                send_mail(
                    subject=f'🚨 CYBERSCAN : Rapport Global ({len(rapport_global)} site(s))',
                    message=corps,
                    from_email='noreply@cyberapp.com',
                    recipient_list=[email_to],
                    fail_silently=True,
                )
            except Exception:
                pass

        return Response({'rapport': rapport_global}, status=status.HTTP_201_CREATED)


# =========================================================================
# 5. SCAN DETAIL (GET / PUT / DELETE)
# =========================================================================
@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def scan_detail(request, pk):
    user = request.user
    try:
        scan = Scan.objects.get(pk=pk)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan introuvable'}, status=status.HTTP_404_NOT_FOUND)

    if user.role != 'admin':
        try:
            client = user.client_profile
        except Client.DoesNotExist:
            client = None
        if scan.client_id != (client.id if client else None):
            return Response({'error': 'Accès refusé'}, status=status.HTTP_403_FORBIDDEN)

    if request.method == 'GET':
        serializer = ScanSerializer(scan)
        return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'PUT':
        scan.domaine = request.data.get('domaine', scan.domaine)
        scan.save()
        serializer = ScanSerializer(scan)
        return Response(serializer.data, status=status.HTTP_200_OK)

    if request.method == 'DELETE':
        scan.delete()
        return Response({'message': 'Scan supprimé'}, status=status.HTTP_204_NO_CONTENT)
