import paramiko
import requests as req

VM_HOST = "192.168.11.131"
VM_USER = "chaima"
VM_PASS = "chqi;q123"


def get_ssh_client():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(VM_HOST, username=VM_USER, password=VM_PASS, timeout=15)
    return ssh


def classify_error(output, target):
    """Détecte le type d'erreur précis pour le rapport"""
    out = output.lower()
    if 'name or service not known' in out or 'could not resolve' in out or 'unknown host' in out:
        return f"DOMAINE INTROUVABLE: '{target}' n'existe pas (erreur DNS)"
    if 'connection refused' in out:
        return f"PORT FERMÉ: '{target}' refuse la connexion"
    if 'timed out' in out or 'timeout' in out:
        return f"TIMEOUT: '{target}' ne répond pas (injoignable ou pare-feu)"
    if 'no route to host' in out:
        return f"HÔTE INJOIGNABLE: '{target}' n'est pas accessible"
    return None


def run_sslscan(target):
    try:
        ssh = get_ssh_client()
        _, stdout, stderr = ssh.exec_command(f"sslscan --connect-timeout=10 {target}")
        result = stdout.read().decode()
        err = stderr.read().decode()
        ssh.close()

        combined = result + err
        error_type = classify_error(combined, target)
        if error_type or not result.strip():
            return {'success': False, 'error': error_type or 'Aucune réponse du serveur SSL', 'raw': combined}
        return {'success': True, 'error': None, 'raw': result}
    except paramiko.AuthenticationException:
        return {'success': False, 'error': 'Erreur SSH: authentification VM échouée', 'raw': ''}
    except Exception as e:
        return {'success': False, 'error': f'Erreur connexion VM: {str(e)}', 'raw': ''}


def run_nmap(target):
    try:
        ssh = get_ssh_client()
        _, stdout, stderr = ssh.exec_command(
            f"nmap --script ssl-enum-ciphers -p 443 --host-timeout 15s {target}"
        )
        result = stdout.read().decode()
        ssh.close()

        out_lower = result.lower()
        if 'host seems down' in out_lower or '0 hosts up' in out_lower:
            return {'success': False, 'error': f"HÔTE INJOIGNABLE: '{target}' semble injoignable", 'raw': result}
        if 'closed' in out_lower and 'open' not in out_lower:
            return {'success': False, 'error': f"PORT FERMÉ: 443 fermé sur '{target}'", 'raw': result}
        return {'success': True, 'error': None, 'raw': result}
    except Exception as e:
        return {'success': False, 'error': str(e), 'raw': ''}


def run_openssl(target):
    try:
        ssh = get_ssh_client()
        _, stdout, stderr = ssh.exec_command(
            f"timeout 10 openssl s_client -connect {target}:443 -servername {target} </dev/null 2>&1"
        )
        result = stdout.read().decode()
        ssh.close()

        error_type = classify_error(result, target)
        if error_type:
            return {'success': False, 'error': error_type, 'raw': result}
        return {'success': True, 'error': None, 'raw': result}
    except Exception as e:
        return {'success': False, 'error': str(e), 'raw': ''}


def run_ssllabs(target):
    try:
        url = f"https://api.ssllabs.com/api/v3/analyze?host={target}&publish=off&all=done"
        response = req.get(url, timeout=60)
        data = response.json()

        status = data.get('status', 'UNKNOWN')

        if status == 'READY':
            endpoints = data.get('endpoints', [])
            if endpoints:
                grade = endpoints[0].get('grade', 'N/A')
                return {'success': True, 'status': 'ready', 'grade': grade, 'host': target}
            return {'success': False, 'status': 'no_endpoints', 'grade': 'N/A', 'host': target}

        if status == 'IN_PROGRESS':
            return {'success': True, 'status': 'in_progress', 'grade': 'EN COURS...', 'host': target}

        if status == 'ERROR':
            return {'success': False, 'status': 'error', 'grade': 'N/A',
                    'error': f"SSL Labs ne peut analyser '{target}' (domaine introuvable ou injoignable)"}

        return {'success': False, 'status': status.lower(), 'grade': 'N/A', 'host': target}

    except req.exceptions.Timeout:
        return {'success': False, 'status': 'timeout', 'grade': 'N/A', 'error': 'SSL Labs API timeout'}
    except Exception as e:
        return {'success': False, 'status': 'error', 'grade': 'N/A', 'error': str(e)}