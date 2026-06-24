import paramiko
import requests as req

VM_HOST = "192.168.11.131"
VM_USER = "chaima"
VM_PASS = "chqi;q123"


def get_ssh_client():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(VM_HOST, username=VM_USER, password=VM_PASS, timeout=30)
    return ssh


def run_sslscan(target):
    try:
        ssh = get_ssh_client()
        _, stdout, stderr = ssh.exec_command(f"sslscan {target}")
        result = stdout.read().decode()
        ssh.close()
        return result
    except Exception as e:
        return f"ERREUR SSLSCAN: {str(e)}"


def run_nmap(target):
    try:
        ssh = get_ssh_client()
        _, stdout, stderr = ssh.exec_command(
            f"nmap --script ssl-enum-ciphers -p 443 {target}"
        )
        result = stdout.read().decode()
        ssh.close()
        return result
    except Exception as e:
        return f"ERREUR NMAP: {str(e)}"


def run_openssl(target):
    try:
        ssh = get_ssh_client()
        _, stdout, stderr = ssh.exec_command(
            f"echo Q | openssl s_client -connect {target}:443 2>&1"
        )
        result = stdout.read().decode()
        ssh.close()
        return result
    except Exception as e:
        return f"ERREUR OPENSSL: {str(e)}"

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
                    return {
                        'status': 'ready',
                        'grade': grade,
                        'host': target
                    }
            elif status == 'IN_PROGRESS':
                return {
                    'status': 'in_progress',
                    'grade': 'EN COURS...',
                    'host': target
                }
            else:
                return {
                    'status': status.lower(),
                    'grade': 'N/A',
                    'host': target
                }
        except Exception as e:
            return {
                'status': 'error',
                'grade': 'N/A',
                'error': str(e)
            }