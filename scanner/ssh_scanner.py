import paramiko
import requests as req
import json
import re
import shlex

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


def run_whatweb(target):
    """Detect web technologies with WhatWeb running on the scanner VM."""
    technologies = {}

    try:
        clean_target = target.strip()
        if not clean_target:
            return {'success': False, 'error': 'Cible WhatWeb vide', 'technologies': []}

        # WhatWeb accepts either a URL or a hostname.  Quote it before it is
        # passed to the remote shell to keep the SSH command safe.
        url = clean_target if clean_target.startswith(('http://', 'https://')) else f'https://{clean_target}'
        command = (
            '/home/chaima/WhatWeb/whatweb -a 3 --log-json=- --no-errors '
            f'{shlex.quote(url)}'
        )

        ssh = get_ssh_client()
        _, stdout, stderr = ssh.exec_command(command, timeout=120)
        raw_output = stdout.read().decode(errors='replace')
        err = stderr.read().decode(errors='replace')
        exit_status = stdout.channel.recv_exit_status()
        ssh.close()

        if 'not found' in err.lower() or 'command not found' in err.lower():
            return {'success': False, 'error': 'WhatWeb non installe sur la VM', 'technologies': []}

        # --log-json=- outputs JSON records.  Ignore banners or other lines
        # that are not valid JSON, as requested.
        for line in raw_output.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            records = record if isinstance(record, list) else [record]
            for item in records:
                if not isinstance(item, dict):
                    continue
                plugins = item.get('plugins', {})
                if not isinstance(plugins, dict):
                    continue
                for name, data in plugins.items():
                    if not isinstance(data, dict):
                        data = {}
                    technology = technologies.setdefault(name, {
                        'name': name,
                        'version': [],
                        'string': [],
                    })
                    for field in ('version', 'string'):
                        values = data.get(field, [])
                        if not isinstance(values, list):
                            values = [values]
                        for value in values:
                            if value not in (None, '') and value not in technology[field]:
                                technology[field].append(value)

        if exit_status != 0:
            return {
                'success': False,
                'error': err.strip() or f'WhatWeb a termine avec le code {exit_status}',
                'technologies': list(technologies.values()),
            }

        return {'success': True, 'technologies': list(technologies.values())}
    except Exception as e:
        error = str(e).strip() or e.__class__.__name__
        return {'success': False, 'error': f'Erreur execution WhatWeb: {error}', 'technologies': []}


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


def run_nuclei(target):
    def parse_nuclei_output(output):
        findings = []

        # Some older Nuclei versions use -json and emit one JSON array instead
        # of JSONL.  Handle that format before falling back to line-by-line
        # parsing.
        try:
            parsed_output = json.loads(output)
            if isinstance(parsed_output, dict):
                parsed_output = [parsed_output]
            if isinstance(parsed_output, list):
                for finding in parsed_output:
                    if not isinstance(finding, dict):
                        continue
                    findings.append({
                        'template_id': finding.get('template-id', ''),
                        'name': finding.get('info', {}).get('name', ''),
                        'severity': finding.get('info', {}).get('severity', 'info').lower(),
                        'description': finding.get('info', {}).get('description', ''),
                        'matched_at': finding.get('matched-at') or finding.get('host', ''),
                    })
                return findings
        except (TypeError, json.JSONDecodeError):
            pass

        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                finding = json.loads(line)
                findings.append({
                    'template_id': finding.get('template-id', ''),
                    'name': finding.get('info', {}).get('name', ''),
                    'severity': finding.get('info', {}).get('severity', 'info'),
                    'description': finding.get('info', {}).get('description', ''),
                    'matched_at': finding.get('matched-at') or finding.get('host', ''),
                })
                continue
            except json.JSONDecodeError:
                pass

            match = re.match(
                r'^\[(?P<template>[^\]]+)\]\s+\[[^\]]+\]\s+\[(?P<severity>[^\]]+)\]\s+(?P<matched>.+)$',
                line
            )
            if match:
                template_id = match.group('template')
                findings.append({
                    'template_id': template_id,
                    'name': template_id.replace('-', ' ').title(),
                    'severity': match.group('severity').lower(),
                    'description': line,
                    'matched_at': match.group('matched').strip(),
                })

        return findings

    try:
        clean_target = target.strip()
        if not clean_target:
            return {'success': False, 'error': 'Cible Nuclei vide', 'findings': [], 'raw': ''}

        url = clean_target if clean_target.startswith('http') else f'https://{clean_target}'
        quoted_url = shlex.quote(url)
        ssh = get_ssh_client()

        # Run only the HTTP templates needed by this application.  This keeps
        # the scan within the remote timeout instead of running every locally
        # installed Nuclei template.
        base_command = (
            f"timeout 90s nuclei -u {quoted_url} -silent -timeout 5 -no-color "
            f"-t http/technologies/tech-detect.yaml,http/exposures/,http/cves/ "
            f"-severity critical,high,medium -rate-limit 100 -c 25"
        )

        _, stdout, stderr = ssh.exec_command(f"{base_command} -jsonl", timeout=110)
        raw_output = stdout.read().decode()
        err = stderr.read().decode()
        exit_status = stdout.channel.recv_exit_status()

        if 'flag provided but not defined' in err.lower() and 'jsonl' in err.lower():
            _, stdout, stderr = ssh.exec_command(f"{base_command} -json", timeout=110)
            raw_output = stdout.read().decode()
            err = stderr.read().decode()
            exit_status = stdout.channel.recv_exit_status()

        ssh.close()

        combined_output = '\n'.join(part for part in (raw_output, err) if part)
        if 'not found' in err.lower() or 'command not found' in err.lower():
            return {'success': False, 'error': 'Nuclei non installe sur le VM', 'findings': [], 'raw': err}

        # Nuclei normally writes findings to stdout, but collecting both
        # streams preserves findings from wrappers or older installations.
        findings = parse_nuclei_output(combined_output)
        if exit_status == 124:
            return {
                'success': False,
                'error': 'Nuclei a depasse la limite de 90 secondes',
                'findings': findings,
                'raw': combined_output,
            }

        if exit_status != 0 and not findings:
            return {
                'success': False,
                'error': err.strip() or f'Nuclei a termine avec le code {exit_status}',
                'findings': [],
                'raw': combined_output,
            }

        return {'success': True, 'findings': findings, 'raw': combined_output}
    except Exception as e:
        # socket.timeout and a few Paramiko exceptions stringify to an empty
        # string.  Returning the class name makes the failure actionable.
        error = str(e).strip() or e.__class__.__name__
        return {'success': False, 'error': f'Erreur execution Nuclei: {error}', 'findings': [], 'raw': ''}
