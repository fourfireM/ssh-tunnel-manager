"""Real OpenSSH client against an isolated, key-authenticated SSH test server.

Paramiko is a CI/test dependency only. No production hosts or keys are used.
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import select
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main as app

try:
    import paramiko
except ImportError:
    paramiko = None


def available_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def bridge(left, right):
    try:
        while True:
            readable, _, _ = select.select([left, right], [], [], 1)
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                (right if source is left else left).sendall(data)
    except (OSError, EOFError):
        pass
    finally:
        left.close()
        right.close()


@unittest.skipUnless(paramiko is not None and (app.WINDOWS or os.environ.get("TD_RUN_SSH_INTEGRATION") == "1"),
                     "requires Paramiko and native Windows, or opt-in POSIX run")
class NativeOpenSSHTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="Tunnel Desk test ")
        root = Path(self.tmp.name)
        app.private_directory(root)
        self.host_key = paramiko.RSAKey.generate(2048)
        self.client_key = paramiko.RSAKey.generate(2048)
        self.key_path = root / "client key"
        self.client_key.write_private_key_file(str(self.key_path))
        self.closed = threading.Event()
        self.transports, self.listeners = [], []
        self.ssh_listener = socket.socket()
        self.ssh_listener.bind(("127.0.0.1", 0))
        self.ssh_listener.listen(8)
        self.ssh_listener.settimeout(.2)
        self.ssh_port = self.ssh_listener.getsockname()[1]
        known_hosts = root / "known hosts"
        known_hosts.write_text(f"[127.0.0.1]:{self.ssh_port} {self.host_key.get_name()} {self.host_key.get_base64()}\n")
        self.config = root / "ssh config"
        self.config.write_text('Host *\n  IdentitiesOnly yes\n  UserKnownHostsFile "' + known_hosts.as_posix() + '"\n', encoding="utf-8")

        class HTTPHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"native SSH forwarding works"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), HTTPHandler)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        threading.Thread(target=self.accept_ssh, daemon=True).start()
        self.manager = app.Manager(root / "state", discover=False, monitor=False)

    def accept_ssh(self):
        while not self.closed.is_set():
            try:
                connection, _ = self.ssh_listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.serve_ssh, args=(connection,), daemon=True).start()

    def serve_ssh(self, connection):
        fixture = self
        transport = paramiko.Transport(connection)
        self.transports.append(transport)
        transport.add_server_key(self.host_key)

        class Server(paramiko.ServerInterface):
            def __init__(self):
                self.destinations = {}
                self.channels = []

            def get_allowed_auths(self, username):
                return "publickey"

            def check_auth_publickey(self, username, key):
                return paramiko.AUTH_SUCCESSFUL if username == "test" and key == fixture.client_key else paramiko.AUTH_FAILED

            def check_channel_request(self, kind, channel_id):
                return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_channel_direct_tcpip_request(self, channel_id, origin, destination):
                if destination != ("127.0.0.1", fixture.http.server_port):
                    return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
                self.destinations[channel_id] = destination
                return paramiko.OPEN_SUCCEEDED

            def check_port_forward_request(self, address, port):
                if address != "127.0.0.1":
                    return False
                listener = socket.socket()
                listener.bind((address, port))
                listener.listen(5)
                listener.settimeout(.2)
                fixture.listeners.append(listener)

                def forward():
                    while transport.is_active() and not fixture.closed.is_set():
                        try:
                            peer, origin = listener.accept()
                        except socket.timeout:
                            continue
                        except OSError:
                            return
                        try:
                            channel = transport.open_forwarded_tcpip_channel((address, port), origin)
                            threading.Thread(target=bridge, args=(peer, channel), daemon=True).start()
                        except (OSError, paramiko.SSHException):
                            peer.close()

                threading.Thread(target=forward, daemon=True).start()
                return listener.getsockname()[1]

            def check_channel_exec_request(self, channel, command):
                args = shlex.split(command.decode())
                if not args or args[0] != "curl":
                    return False
                args[0] = app.CURL
                args = [os.devnull if value == "/dev/null" else value for value in args]

                def execute():
                    try:
                        result = app.run_process(args, capture_output=True, timeout=20)
                        if result.stdout:
                            channel.sendall(result.stdout)
                        if result.stderr:
                            channel.sendall_stderr(result.stderr)
                        channel.send_exit_status(result.returncode)
                    finally:
                        channel.close()

                threading.Thread(target=execute, daemon=True).start()
                return True

        server = Server()
        try:
            transport.start_server(server=server)
            while transport.is_active() and not self.closed.is_set():
                channel = transport.accept(.2)
                if channel is None:
                    continue
                server.channels.append(channel)
                destination = server.destinations.pop(channel.get_id(), None)
                if destination:
                    peer = socket.create_connection(destination, timeout=5)
                    threading.Thread(target=bridge, args=(channel, peer), daemon=True).start()
        except (OSError, EOFError, paramiko.SSHException):
            pass
        finally:
            transport.close()

    def tearDown(self):
        self.manager.closed.set()
        for child in self.manager.children.values():
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=10)
        self.closed.set()
        self.ssh_listener.close()
        for listener in self.listeners:
            listener.close()
        for transport in self.transports:
            transport.close()
        self.http.shutdown()
        self.http.server_close()
        self.tmp.cleanup()

    def test_native_client_forward_discover_check_and_stop(self):
        for kind in ["R", "L", "D"]:
            with self.subTest(kind=kind):
                entry = available_port()
                target = self.http.server_port
                profile = self.manager.save_profile({"name": "native-" + kind, "kind": kind,
                    "target": "test@127.0.0.1", "ssh_port": self.ssh_port,
                    "bind_host": "127.0.0.1", "bind_port": entry,
                    "dest_host": "127.0.0.1", "dest_port": target,
                    "identity_file": str(self.key_path), "config_file": str(self.config),
                    "auth_mode": "key", "health_type": "socks5" if kind == "D" else "http",
                    "health_url": f"http://127.0.0.1:{target if kind == 'D' else entry}/ok"})
                self.manager.start(profile["id"])
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    card = next(t for t in self.manager.snapshot()["tunnels"] if t["id"] == profile["id"])
                    if card["status"] == "running":
                        break
                    time.sleep(.2)
                else:
                    self.fail(self.manager.read_log(profile["id"]))
                self.assertTrue(card["pid"])
                self.assertTrue(app.process_identity(card["pid"]))
                self.manager.check(profile["id"])
                health = self.manager._rt(profile["id"])["health"]
                self.assertTrue(health["ok"], health["details"])
                self.assertEqual(health["http_status"], 200)
                self.manager.stop(profile["id"])
                self.assertFalse(app.process_identity(card["pid"]))
