import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main as app
import windows_support as win
from test_manager import profile


class WindowsPolicyTests(unittest.TestCase):
    def test_native_ssh_command_line_preserves_paths_and_jump(self):
        found = app.parse_ssh([r"C:\Windows\System32\OpenSSH\ssh.exe", "-NT",
                              "-i", str(Path.home() / "key with spaces"),
                              "-J", "jump-user@203.0.113.10:65422",
                              "-R", "127.0.0.1:18317:127.0.0.1:8317", "user@192.0.2.10"])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["dest_port"], 8317)
        self.assertIn("key with spaces", found[0]["identity_file"])

    def test_windows_never_requests_controlmaster_or_password_prompts(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = app.Manager(directory, discover=False, monitor=False)
            with patch.object(app, "WINDOWS", True):
                p = app.validate_profile(profile(auth_mode="auto"))
                command = manager.build_ssh(p)
                self.assertEqual(p["auth_mode"], "key")
                self.assertIn("BatchMode=yes", command)
                self.assertNotIn("-M", command)
                self.assertNotIn("-S", command)
                env = manager._ssh_env()
                self.assertNotIn("SSH_ASKPASS", env)
                self.assertEqual(env["SSH_ASKPASS_REQUIRE"], "never")

    def test_windows_local_curl_uses_nul_remote_uses_posix_null(self):
        p = app.validate_profile(profile())
        local = app.http_probe_args(p, "127.0.0.1:17897", executable="curl.exe", null_device="nul")
        remote = app.http_probe_args(p, "127.0.0.1:17897")
        self.assertIn("nul", local)
        self.assertNotIn("/dev/null", local)
        self.assertIn("/dev/null", remote)

    def test_task_uses_dedicated_state_and_does_not_pass_web_token(self):
        definition = win.task_definition(Path.cwd() / "folder with spaces", Path.cwd() / "test-state", 17899)
        self.assertIn("--scheduled", definition["TD_ARGUMENTS"])
        self.assertIn("--state-dir", definition["TD_ARGUMENTS"])
        self.assertNotIn("--background", definition["TD_ARGUMENTS"])
        self.assertNotIn("token", definition["TD_ARGUMENTS"])
        self.assertNotEqual(win.task_name("state-a"), win.task_name("state-b"))

    def test_fingerprint_rejects_pid_reuse_and_command_changes(self):
        first = win.process_fingerprint(10, 100.5, ["ssh.exe", "host"])
        self.assertNotEqual(first, win.process_fingerprint(10, 101.5, ["ssh.exe", "host"]))
        self.assertNotEqual(first, win.process_fingerprint(10, 100.5, ["ssh.exe", "other"]))


@unittest.skipUnless(app.WINDOWS, "native Windows integration")
class WindowsNativeTests(unittest.TestCase):
    def test_state_directory_acl_is_private(self):
        with tempfile.TemporaryDirectory() as directory:
            win.secure_state_directory(directory)
            output = win.powershell(r"""
$acl = Get-Acl -LiteralPath $env:TD_STATE
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$entries = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value })
@{protected=$acl.AreAccessRulesProtected; entries=$entries; user=$user} | ConvertTo-Json -Compress
""", {"TD_STATE": directory})
            acl = json.loads(output)
            self.assertTrue(acl["protected"])
            self.assertEqual(set(acl["entries"]), {acl["user"], "S-1-5-18"})

    def test_real_background_start_and_shutdown(self):
        import socket
        import time
        import urllib.request
        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            try:
                result = subprocess.run([sys.executable, str(app.ROOT / "main.py"), "--background",
                                         "--state-dir", directory, "--port", str(port)],
                                        capture_output=True, text=True, encoding="utf-8", timeout=45)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                info = app.existing_server(directory)
                self.assertIsNotNone(info)
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(f"http://127.0.0.1:{info['port']}/", timeout=5) as response:
                    self.assertEqual(response.status, 200)
                backend = win.psutil_module().Process(info["pid"])
                app.shutdown_backend(directory)
                backend.wait(10)
                self.assertIsNone(app.existing_server(directory))
            finally:
                app.shutdown_backend(directory)

    @unittest.skipUnless(os.environ.get("TD_TEST_TASK_SCHEDULER") == "1", "opt-in isolated CI task test")
    def test_scheduled_backend_registration_start_and_removal(self):
        import socket
        import time
        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            try:
                win.secure_state_directory(directory)
                info = app.install_service(directory, port)
                self.assertEqual(info["managed_by"], "task_scheduler")
                self.assertEqual(json.loads(win.task_status(directory))["TaskName"], win.task_name(directory))
                backend = win.psutil_module().Process(info["pid"])
                win.uninstall_task(directory)
                backend.wait(10)
                self.assertEqual(json.loads(win.task_status(directory)), {})
            finally:
                win.uninstall_task(directory)
                app.shutdown_backend(directory)
