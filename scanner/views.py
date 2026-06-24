from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import Scan, CVE
from .serializers import ScanSerializer
from .ssh_scanner import run_sslscan, run_nmap, run_openssl


def parse_sslscan(output):
    protocols = []
    vulnerabilities = []
    for line in output.split('\n'):
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
    return protocols, vulnerabilities


def calculate_risk_score(vulnerabilities):
    score = 0.0
    if 'TLSv1.0' in vulnerabilities: score += 3.0
    if 'TLSv1.1' in vulnerabilities: score += 2.0
    if 'WEAK_CIPHER' in vulnerabilities: score += 2.5
    return min(round(score, 1), 10.0)


@api_view(['GET'])
def test_api(request):
    return Response({"message": "API Scanner is running!"})


@api_view(['GET', 'POST'])
def scans_list(request):

    # READ ALL + OPTIONAL FILTERS
    if request.method == 'GET':
        scans = Scan.objects.all().order_by('-date_scan')

        search = request.GET.get('search')
        risk = request.GET.get('risk', '').upper()

        if search:
            scans = scans.filter(domaine__icontains=search)

        if risk == 'HIGH':
            scans = scans.filter(score_risque_ia__gte=7)
        elif risk == 'MEDIUM':
            scans = scans.filter(
                score_risque_ia__gte=4,
                score_risque_ia__lt=7
            )
        elif risk == 'LOW':
            scans = scans.filter(score_risque_ia__lt=4)

        serializer = ScanSerializer(scans, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # CREATE / LANCER SCAN
    if request.method == 'POST':
        target = request.data.get('url')

        if not target:
            return Response(
                {'error': 'URL manquante'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            sslscan_output = run_sslscan(target)
            nmap_output = run_nmap(target)
            openssl_output = run_openssl(target)

            protocols, vulnerabilities = parse_sslscan(sslscan_output)
            score = calculate_risk_score(vulnerabilities)

            scan = Scan.objects.create(
                domaine=target,
                resultats_ssl={
                    'sslscan': sslscan_output,
                    'nmap': nmap_output,
                    'openssl': openssl_output,
                    'protocols': protocols,
                    'vulnerabilities': vulnerabilities,
                },
                score_risque_ia=score
            )

            return Response(
                {
                    'id': scan.id,
                    'domaine': scan.domaine,
                    'protocols': protocols,
                    'vulnerabilities': vulnerabilities,
                    'score_risque_ia': score,
                    'sslscan_output': sslscan_output,
                    'nmap_output': nmap_output,
                    'openssl_output': openssl_output,
                    'date_scan': scan.date_scan,
                },
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            return Response(
                {'error': 'Erreur lors du scan', 'details': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@api_view(['GET', 'PUT', 'DELETE'])
def scan_detail(request, pk):
    try:
        scan = Scan.objects.get(pk=pk)
    except Scan.DoesNotExist:
        return Response({'error': 'Scan introuvable'}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = ScanSerializer(scan)
        return Response(serializer.data)

    if request.method == 'PUT':
        domaine = request.data.get('domaine', scan.domaine)
        scan.domaine = domaine
        scan.save()
        serializer = ScanSerializer(scan)
        return Response(serializer.data)

    if request.method == 'DELETE':
        scan.delete()
        return Response({'message': 'Scan supprimé'}, status=status.HTTP_204_NO_CONTENT)

    @api_view(['GET', 'POST'])
    def scans_list(request):
        if request.method == 'GET':
            scans = Scan.objects.all().order_by('-date_scan')

            search = request.GET.get('search', '')
            risk = request.GET.get('risk', '').upper()
            page = int(request.GET.get('page', 1))
            page_size = int(request.GET.get('page_size', 5))

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

