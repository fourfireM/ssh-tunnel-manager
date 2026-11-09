import copy
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import plistlib
import shlex
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main as app


def profile(**changes):
    values = dict(name="test", kind="R", target="user@192.0.2.10", ssh_port=22,
                  jump="jump-host", bind_host="127.0.0.1", bind_port=17897,
                  dest_host="127.0.0.1", dest_port=7897, auth_mode="key",
                  auto_reconnect=False, health_type="http_proxy", health_url="https://www.baidu.com")
    values.update(changes)
    return values


class ValidationTests(unittest.TestCase):
    def test_reject_shell_and_option_injection(self):
        for value in ["-oProxyCommand=bad", "host;touch /tmp/x", "host\nother", "$(id)", "host`id`", "host -R 1:2:3"]:
            with self.subTest(value=value), self.assertRaises(app.UserError):
                app.validate_profile(profile(target=value))

    def test_reject_public_bind_and_privileged_ports(self):
        for value in ["0.0.0.0", "*", "192.0.2.10"]:
            with self.assertRaises(app.UserError):
                app.validate_profile(profile(bind_host=value))
        for value in [22, 0, 65536, True, "12.5"]:
            with self.assertRaises(app.UserError):
                app.validate_profile(profile(bind_port=value))

    def test_no_credential_or_arbitrary_source_fields(self):
        for key in ["password", "private_key", "launch_path", "source", "id", "command"]:
            with self.assertRaises(app.UserError):
                app.validate_profile(profile(**{key: "unsafe"}))

    def test_health_url_rejects_credentials_and_non_http(self):
        for url in ["file:///etc/passwd", "http://user:secret@host", "javascript:alert(1)", "https://host/\nheader", "http://host:bad"]:
            with self.assertRaises(app.UserError):
                app.validate_profile(profile(health_url=url))

    def test_ipv6_forward_and_dynamic(self):
        self.assertEqual(app.split_forward("[::1]:12345:[::1]:7897", "R"), ("::1", 12345, "::1", 7897))
        self.assertEqual(app.split_forward("1080", "D"), ("127.0.0.1", 1080, "", None))


class DiscoveryTests(unittest.TestCase):
    def test_import_current_training_command(self):
        found = app.parse_ssh(["ssh", "-fNT", "-J", "user@203.0.113.10:65422", "-p", "22", "-o", "ExitOnForwardFailure=yes", "-R", "127.0.0.1:17897:127.0.0.1:7897", "user@192.0.2.10"])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["bind_port"], 17897)
        self.assertEqual(found[0]["dest_port"], 7897)
        self.assertEqual(found[0]["ssh_port"], 22)

    def test_proxyjump_helper_is_not_an_extra_tunnel(self):
        self.assertEqual(app.parse_ssh(["ssh", "-l", "user", "-p", "65422", "-W", "[192.0.2.10]:22", "203.0.113.10"]), [])

    def test_import_launchd_key_auth(self):
        found = app.parse_ssh(["/usr/bin/ssh", "-NT", "-o", "BatchMode=yes", "-o", "ControlMaster=no", "-R", "127.0.0.1:18317:127.0.0.1:8317", "p6000"])
        self.assertEqual(found[0]["target"], "p6000")
        self.assertEqual(found[0]["auth_mode"], "key")

    def test_discovery_does_not_restart_existing_connections(self):
        existing = app.validate_profile(profile())
        processes = [{"pid": 1234, "ppid": 1, "command": "ssh", "profile": existing}]
        with tempfile.TemporaryDirectory() as directory, patch.object(app, "scan_processes", return_value=(processes, "")), patch.object(app, "read_launch_agents", return_value=[]), patch.object(app, "process_identity", return_value="identity"), patch.object(app.subprocess, "Popen") as popen, patch.object(app, "safe_signal") as stop:
            manager = app.Manager(directory, discover=False, monitor=False)
            self.assertEqual(manager.discover(), 1)
            self.assertEqual(manager.discover(), 0)
            self.assertEqual(len(manager.profiles), 1)
            popen.assert_not_called()
            stop.assert_not_called()

    def test_shared_multi_forward_process_not_independently_imported(self):
        a = app.validate_profile(profile())
        b = app.validate_profile(profile(bind_port=17898))
        processes = [{"pid": 1234, "profile": p} for p in [a, b]]
        with tempfile.TemporaryDirectory() as directory, patch.object(app, "scan_processes", return_value=(processes, "")), patch.object(app, "read_launch_agents", return_value=[]):
            manager = app.Manager(directory, discover=False, monitor=False)
            manager.discover()
            self.assertEqual(manager.profiles, [])


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.manager = app.Manager(self.tmp.name, discover=False, monitor=False)
        self.p = self.manager.save_profile(profile())

    def tearDown(self):
        self.manager.closed.set()
        self.tmp.cleanup()

    def test_pid_reuse_fails_closed(self):
        with patch.object(app, "process_identity", return_value="different"), patch.object(app.os, "kill") as kill:
            with self.assertRaises(app.UserError):
                app.safe_signal(1234, "expected")
            kill.assert_not_called()

    def test_scan_failure_never_starts_or_stops_a_tunnel(self):
        self.manager.scan_error = "denied"
        with patch.object(self.manager, "_refresh"), patch.object(app.subprocess, "Popen") as popen, patch.object(app, "safe_signal") as stop:
            with self.assertRaises(app.UserError):
                self.manager.start(self.p["id"])
            with self.assertRaises(app.UserError):
                self.manager.stop(self.p["id"])
            popen.assert_not_called()
            stop.assert_not_called()

    def test_port_conflicts_are_scoped_to_the_listening_machine(self):
        with patch.object(self.manager, "resolve_host", side_effect=lambda p: {"hostname": p["target"], "port": 22}):
            with self.assertRaises(app.UserError):
                self.manager.save_profile(profile(name="same endpoint"))
            other = self.manager.save_profile(profile(name="different host", target="user@192.0.2.20"))
            self.assertEqual(other["bind_port"], self.p["bind_port"])

    def test_save_configuration_never_restarts_a_running_tunnel(self):
        with patch.object(self.manager, "start") as start, patch.object(self.manager, "stop") as stop:
            self.manager.save_profile({"name": "updated", "dest_port": 7900}, self.p["id"])
            start.assert_not_called()
            stop.assert_not_called()

    def test_background_reconnect_cannot_prompt_for_password(self):
        auto = app.validate_profile(profile(auth_mode="auto"))
        command = self.manager.build_ssh(auto, interactive=False)
        self.assertIn("BatchMode=yes", command)
        self.assertNotIn("BatchMode=no", command)
        with patch.object(app.subprocess, "run", return_value=app.subprocess.CompletedProcess([], 0, "", "")):
            env = self.manager._ssh_env(allow_prompt=False)
        if app.WINDOWS:
            self.assertEqual(env["SSH_ASKPASS_REQUIRE"], "never")
            self.assertNotIn("SSH_ASKPASS", env)
        else:
            self.assertEqual(env["SSH_ASKPASS"], str(self.manager.deny_askpass_path))
            self.assertNotEqual(env["SSH_ASKPASS"], str(self.manager.askpass_path))

    @unittest.skipIf(app.WINDOWS, "launchd is a macOS integration")
    def test_keepalive_launchd_stop_disables_and_unloads_instead_of_kill(self):
        self.p.update(source="launchd", launch_label="test.ssh", launch_path="/unused")
        self.manager.profiles = [self.p]
        calls = []
        def launchctl(*args, **kwargs):
            calls.append(args)
            return app.subprocess.CompletedProcess([], 0, "", "")
        with patch.object(self.manager, "_refresh"), patch.object(self.manager, "_current_process", return_value=None), patch.object(self.manager, "_trusted_launch_agent"), patch.object(self.manager, "_launchctl", side_effect=launchctl), patch.object(app, "safe_signal") as kill:
            self.manager.stop(self.p["id"])
            self.assertEqual([call[0] for call in calls], ["disable", "print", "bootout"])
            kill.assert_not_called()

    def test_untrusted_launch_agent_path_is_rejected(self):
        for path in ["/tmp/not-a-launch-agent.plist", str(Path.home()/"Library/LaunchAgents/../other.plist")]:
            with self.assertRaises(app.UserError):
                self.manager._trusted_launch_agent({"launch_path": path, "launch_label": "bad"})

    def test_launchd_backend_leaves_independent_tunnels_alive(self):
        service = app.service_plist(self.tmp.name, 17899)
        self.assertTrue(service["KeepAlive"])
        self.assertTrue(service["RunAtLoad"])
        self.assertTrue(service["AbandonProcessGroup"])
        self.assertNotIn("--background", service["ProgramArguments"])
        self.assertNotIn("--open", service["ProgramArguments"])
        self.assertNotIn("SSH_AUTH_SOCK", service["EnvironmentVariables"])

    def test_local_authorization_survives_backend_restart_and_is_private(self):
        before = app.access_token(Path(self.tmp.name))
        after = app.access_token(Path(self.tmp.name))
        self.assertEqual(before, after)
        self.assertGreaterEqual(len(before), 40)
        if not app.WINDOWS:
            self.assertEqual((Path(self.tmp.name)/'access-token.json').stat().st_mode & 0o777, 0o600)

    def test_pending_configuration_cannot_probe_the_wrong_endpoint(self):
        live = copy.deepcopy(self.p)
        self.manager._rt(self.p["id"]).update(observed_profile=live, identity="same")
        self.manager.get(self.p["id"])["dest_port"] = 9999
        with patch.object(self.manager, "_refresh"), patch.object(self.manager, "_current_process", return_value={"pid": 100}), patch.object(app.subprocess, "run") as run:
            with self.assertRaises(app.UserError):
                self.manager.check(self.p["id"])
            run.assert_not_called()

    def test_monitor_recognizes_reauthentication_without_browser_polling(self):
        rt = self.manager._rt(self.p["id"])
        rt.update(owned=True, authenticated=False, failures=4)
        with patch.object(self.manager.closed, "wait", side_effect=[False,True]), patch.object(self.manager, "_refresh"), patch.object(self.manager, "_current_process", return_value={"pid":1234}), patch.object(self.manager, "resolve_host", return_value={"hostname":"192.0.2.10"}), patch.object(self.manager, "read_log", return_value='Authenticated to 192.0.2.10 (via proxy) using "publickey".'), patch.object(self.manager, "_save"):
            self.manager._monitor()
        self.assertTrue(rt["authenticated"])
        self.assertEqual(rt["failures"],0)


class HealthCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requests = []

        class GetOnlyAPI(BaseHTTPRequestHandler):
            def do_HEAD(self):
                cls.requests.append(("HEAD", self.path))
                self.send_response(404)
                self.end_headers()

            def do_GET(self):
                cls.requests.append(("GET", self.path))
                path = app.urlsplit(self.path).path
                status = {"/v1/models": 401, "/missing": 404, "/method": 405,
                          "/error": 503, "/blocked": 403, "/ok": 200}[path]
                body = b'{"private_response_body":"must-not-be-logged"}'
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), GetOnlyAPI)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.manager = app.Manager(self.tmp.name, discover=False, monitor=False)
        self.p = self.manager.save_profile(profile(kind="L", bind_port=self.port,
                                                   health_type="http", dest_port=8317,
                                                   health_url=f"http://127.0.0.1:{self.port}/v1/models"))
        self.requests.clear()

    def tearDown(self):
        self.manager.closed.set()
        self.tmp.cleanup()

    def check(self, **changes):
        self.p = self.manager.save_profile(changes, self.p["id"])
        self.manager._rt(self.p["id"]).update(identity="same", observed_profile=copy.deepcopy(self.p))
        real_run = app.subprocess.run

        def execute_probe(command, **kwargs):
            # Execute the generated remote curl command against the real local
            # HTTP fixture, without needing an SSH server in the unit suite.
            if command[0] == "/test/ssh":
                command = shlex.split(command[-1])
                command[0] = app.CURL
                command = [app.os.devnull if arg == "/dev/null" else arg for arg in command]
            return real_run(command, **kwargs)

        with patch.object(self.manager, "_refresh"), patch.object(self.manager, "_current_process", return_value={"pid": 1234}), patch.object(self.manager, "_connection_args", return_value=["/test/ssh"]), patch.object(self.manager, "_ssh_env", return_value=None), patch.object(app.subprocess, "run", side_effect=execute_probe):
            self.manager.check(self.p["id"])
        return self.manager._rt(self.p["id"])["health"]

    def test_get_only_api_is_reachable_locally_and_via_remote_probe(self):
        for kind in ["L", "R"]:
            with self.subTest(kind=kind):
                result = self.check(kind=kind)
                self.assertEqual(self.requests[-1], ("GET", "/v1/models"))
                self.assertTrue(result["ok"])
                self.assertEqual(result["http_status"], 401)
                self.assertEqual(result["level"], "warn")
                self.assertIn("链路已连通", result["message"])
                self.assertIn("接口需要认证", result["message"])
                self.assertNotIn("must-not-be-logged", result["details"])
        self.assertNotIn("HEAD", [method for method, _ in self.requests])

    def test_bad_api_route_or_server_error_does_not_claim_tunnel_is_down(self):
        for path, status in [("/missing", 404), ("/method", 405), ("/error", 503)]:
            with self.subTest(status=status):
                result = self.check(health_url=f"http://127.0.0.1:{self.port}{path}")
                self.assertFalse(result["ok"])
                self.assertEqual(result["level"], "warn")
                self.assertIn("链路已连通", result["message"])
                self.assertEqual(result["http_status"], status)

    def test_proxy_http_error_is_not_counted_as_working_external_access(self):
        result = self.check(health_type="http_proxy", health_url="http://unresolvable.example/blocked")
        self.assertEqual(self.requests[-1], ("GET", "http://unresolvable.example/blocked"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["level"], "bad")
        self.assertIn("代理访问未通过", result["message"])

    def test_successful_api_response_does_not_claim_model_inference(self):
        result = self.check(health_url=f"http://127.0.0.1:{self.port}/ok")
        self.assertTrue(result["ok"])
        self.assertEqual(result["level"], "good")
        self.assertIn("接口响应正常", result["message"])
        self.assertIn("不发起模型调用", result["details"])
        self.assertNotIn("must-not-be-logged", result["details"])


class SecurityHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.manager = app.Manager(cls.tmp.name, discover=False, monitor=False)
        cls.token = "test-token-not-a-real-credential"
        cls.server = app.LocalServer(("127.0.0.1", 0), cls.manager, cls.token)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.manager.closed.set()
        cls.tmp.cleanup()

    def request(self, method, path, body=None, **headers):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=10)
        if body is not None:
            body = json.dumps(body)
            headers.setdefault("Content-Type", "application/json")
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        content = response.read()
        status, result_headers = response.status, dict(response.getheaders())
        connection.close()
        return status, result_headers, content

    def test_api_requires_authorization(self):
        self.assertEqual(self.request("GET", "/api/state")[0], 401)

    def test_authorized_same_origin_works(self):
        status, headers, body = self.request("GET", "/api/state", Authorization="Bearer " + self.token)
        self.assertEqual(status, 200)
        self.assertIn("tunnels", json.loads(body))
        self.assertNotIn(self.token.encode(), body)

    def test_dns_rebinding_host_is_rejected(self):
        self.assertEqual(self.request("GET", "/api/state", Authorization="Bearer " + self.token, Host=f"evil.example:{self.port}")[0], 403)

    def test_cross_origin_requests_are_rejected_even_with_token(self):
        status, _, _ = self.request("POST", "/api/discover", {}, Authorization="Bearer " + self.token, Origin="https://evil.example")
        self.assertEqual(status, 403)

    def test_cookie_is_not_enough_and_no_cross_origin_preflight(self):
        self.assertEqual(self.request("GET", "/api/state", Cookie="td_session=" + self.token)[0], 401)
        status, headers, _ = self.request("OPTIONS", "/api/tunnels")
        self.assertEqual(status, 405)
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_no_directory_traversal_and_no_inline_scripts(self):
        self.assertEqual(self.request("GET", "/../main.py")[0], 404)
        status, headers, _ = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", headers["Content-Security-Policy"])

    def test_web_api_cannot_supply_pid_or_shell_command(self):
        for field in ["pid", "command", "launch_path"]:
            status, _, _ = self.request("POST", "/api/tunnels", profile(**{field: "bad"}), Authorization="Bearer " + self.token)
            self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
