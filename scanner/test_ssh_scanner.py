from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from .scan_cancellation import ScanCancelled
from .ssh_scanner import _run_ssh_command


class BufferedChannel:
    def __init__(self, stdout_chunks=None, stderr_chunks=None, exit_code=0):
        self.stdout_chunks = list(stdout_chunks or [])
        self.stderr_chunks = list(stderr_chunks or [])
        self.exit_code = exit_code
        self.events = []
        self.closed = False

    def recv_ready(self):
        return bool(self.stdout_chunks)

    def recv(self, _size):
        self.events.append('stdout')
        return self.stdout_chunks.pop(0)

    def recv_stderr_ready(self):
        return bool(self.stderr_chunks)

    def recv_stderr(self, _size):
        self.events.append('stderr')
        return self.stderr_chunks.pop(0)

    def exit_status_ready(self):
        return not self.stdout_chunks and not self.stderr_chunks

    def recv_exit_status(self):
        if self.stdout_chunks or self.stderr_chunks:
            raise AssertionError('Le code de sortie a été attendu avant de vider les flux')
        self.events.append('status')
        return self.exit_code

    def close(self):
        self.closed = True


class NeverEndingChannel(BufferedChannel):
    def exit_status_ready(self):
        return False


class RunSshCommandTests(SimpleTestCase):
    def test_drains_stdout_and_stderr_before_waiting_for_exit_status(self):
        channel = BufferedChannel(
            stdout_chunks=[b'docker layer 1\n', b'docker layer 2\n'],
            stderr_chunks=[b'warning\n'],
            exit_code=0,
        )
        ssh = Mock()
        ssh.exec_command.return_value = (None, SimpleNamespace(channel=channel), None)

        stdout, stderr, exit_code = _run_ssh_command(ssh, 'docker pull image', timeout=5)

        self.assertEqual(stdout, 'docker layer 1\ndocker layer 2\n')
        self.assertEqual(stderr, 'warning\n')
        self.assertEqual(exit_code, 0)
        self.assertEqual(channel.events[-1], 'status')
        ssh.exec_command.assert_called_once_with('docker pull image', timeout=5)

    @patch('scanner.ssh_scanner.time.sleep')
    @patch('scanner.ssh_scanner.time.monotonic', side_effect=[10.0, 12.0])
    def test_closes_channel_when_command_exceeds_timeout(self, _monotonic, _sleep):
        channel = NeverEndingChannel()
        ssh = Mock()
        ssh.exec_command.return_value = (None, SimpleNamespace(channel=channel), None)

        with self.assertRaisesRegex(TimeoutError, '1 secondes'):
            _run_ssh_command(ssh, 'blocked command', timeout=1)

        self.assertTrue(channel.closed)

    def test_cancel_closes_channel_and_runs_cleanup(self):
        channel = NeverEndingChannel()
        ssh = Mock()
        ssh.exec_command.return_value = (None, SimpleNamespace(channel=channel), None)
        cleanup = Mock()

        with self.assertRaises(ScanCancelled):
            _run_ssh_command(
                ssh,
                'docker run zap',
                timeout=60,
                cancel_check=Mock(return_value=True),
                on_cancel=cleanup,
            )

        cleanup.assert_called_once_with()
        self.assertTrue(channel.closed)

class RunSslscanRetryTests(SimpleTestCase):
    @patch('scanner.ssh_scanner.time.sleep')
    @patch('scanner.ssh_scanner._run_ssh_command')
    @patch('scanner.ssh_scanner.get_ssh_client')
    def test_retries_timeout_then_returns_success(self, get_ssh, run_command, sleep):
        ssh = Mock()
        get_ssh.return_value = ssh
        run_command.side_effect = [
            ('', 'connect timeout', 1),
            ('Version: 2.1.5\nConnected to 196.203.216.18\n', '', 0),
        ]

        from .ssh_scanner import run_sslscan
        result = run_sslscan('esprit.tn')

        self.assertTrue(result['success'])
        self.assertEqual(run_command.call_count, 2)
        sleep.assert_called_once_with(2)
        self.assertEqual(ssh.close.call_count, 2)

    @patch('scanner.ssh_scanner.time.sleep')
    @patch('scanner.ssh_scanner._run_ssh_command')
    @patch('scanner.ssh_scanner.get_ssh_client')
    def test_does_not_retry_non_transient_dns_error(self, get_ssh, run_command, sleep):
        get_ssh.return_value = Mock()
        run_command.return_value = ('', 'Could not resolve hostname', 1)

        from .ssh_scanner import run_sslscan
        result = run_sslscan('missing.example')

        self.assertFalse(result['success'])
        self.assertIn('DOMAINE INTROUVABLE', result['error'])
        run_command.assert_called_once()
        sleep.assert_not_called()

    @patch('scanner.ssh_scanner.time.sleep')
    @patch('scanner.ssh_scanner._run_ssh_command')
    @patch('scanner.ssh_scanner.get_ssh_client')
    def test_returns_timeout_after_three_attempts(self, get_ssh, run_command, sleep):
        get_ssh.return_value = Mock()
        run_command.return_value = ('', 'connection timed out', 1)

        from .ssh_scanner import run_sslscan
        result = run_sslscan('slow.example')

        self.assertFalse(result['success'])
        self.assertIn('TIMEOUT', result['error'])
        self.assertEqual(run_command.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
