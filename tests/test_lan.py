"""LAN interface selection, changing addresses, and shared-entry probes."""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main as app
from test_manager import profile


def network(address="192.0.2.20", interface="en0"):
    return {"interfaces": [{"interface": interface, "address": address,
                            "label": "Wi-Fi", "physical": True, "recommended": True}], "error": ""}


def lan(**changes):
    return profile(kind="L", access_scope="lan", network_interface="en0", bind_port=18765,
                   health_type="http", health_url="http://127.0.0.1:18765/", **changes)


class InterfaceTests(unittest.TestCase):
    def test_multiple_interfaces_and_vpn_default(self):
        config = '''lo0: flags=8049<UP,LOOPBACK,RUNNING>
    inet 127.0.0.1 netmask 0xff000000
utun4: flags=8051<UP,POINTOPOINT,RUNNING>
    inet 198.18.0.1 --> 198.18.0.1 netmask 0xfffffffc
en0: flags=8863<UP,BROADCAST,RUNNING>
    inet 192.0.2.20 netmask 0xffffff00
    status: active
en7: flags=8863<UP,BROADCAST,RUNNING>
    inet 192.0.2.21 netmask 0xffffff00
    status: active
en8: flags=8863<UP,BROADCAST,RUNNING>
    inet 192.0.2.22 netmask 0xffffff00
    status: inactive
en9: flags=8863<UP,BROADCAST,RUNNING>
    inet 169.254.1.2 netmask 0xffff0000
'''
        hardware = 'Hardware Port: Wi-Fi\nDevice: en0\n\nHardware Port: USB Ethernet\nDevice: en7\n'
        found = app.parse_network_interfaces(config, hardware, "en7")
        self.assertEqual([item["interface"] for item in found], ["en7", "en0", "utun4"])
        self.assertEqual(found[0]["label"], "USB Ethernet")
        self.assertTrue(found[0]["recommended"])
        vpn_default = app.parse_network_interfaces(config, hardware, "utun4")
        self.assertEqual(vpn_default[0]["interface"], "en0")
        self.assertFalse(vpn_default[-1]["physical"])

    def test_old_profiles_remain_local_and_reject_wildcards(self):
        self.assertEqual(app.validate_profile(profile())["access_scope"], "local")
        for kind in ("R", "D"):
            with self.assertRaises(app.UserError):
                app.validate_profile({**lan(), "kind": kind})
        for value in ("0.0.0.0", "*", "192.0.2.20"):
            with self.assertRaises(app.UserError):
                app.validate_profile(profile(kind="L", bind_host=value))

    def test_resolve_only_the_selected_interface_and_fail_closed_when_missing(self):
        with patch.object(app, "network_interfaces", return_value=network()):
            p = app.validate_profile(lan())
        self.assertEqual(p["bind_host"], "192.0.2.20")
        self.assertEqual(app.resolve_lan_profile(p, network("192.0.2.21"))["bind_host"], "192.0.2.21")
        with self.assertRaises(app.UserError):
            app.resolve_lan_profile(p, network(interface="en7"))
        with patch.object(app, "network_interfaces", return_value={"interfaces": [], "error": "no permission"}):
            with self.assertRaisesRegex(app.UserError, "no permission"):
                app.validate_profile(lan())

    def test_discovery_recognizes_shared_listener_even_after_ip_disappears(self):
        command = ["ssh", "-NT", "-L", "192.0.2.20:18765:127.0.0.1:8765", "user@jump"]
        with patch.object(app, "network_interfaces", return_value=network()):
            parsed = app.parse_ssh(command)
        self.assertEqual(parsed[0]["bind_host"], "192.0.2.20")
        self.assertEqual(parsed[0]["network_interface"], "en0")
        with patch.object(app, "network_interfaces", return_value=network("192.0.2.21")):
            parsed = app.parse_ssh(command)
        self.assertEqual(parsed[0]["bind_host"], "192.0.2.20")
        self.assertEqual(parsed[0]["network_interface"], "unavailable")
        self.assertEqual(app.parse_ssh(["ssh", "-NT", "-L", "0.0.0.0:18765:127.0.0.1:8765", "user@jump"]), [])

    def test_probe_uses_entry_address_and_preserves_path_and_query(self):
        p = {**lan(), "health_url": "http://wrong.example:12345/path?x=1"}
        args = app.http_probe_args(p, "192.0.2.20:18765")
        self.assertEqual(args[-1], "http://192.0.2.20:18765/path?x=1")
        self.assertEqual(args[args.index("--proxy") + 1], "")


class LanLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.manager = app.Manager(self.tmp.name, discover=False, monitor=False)
        self.network_patch = patch.object(app, "network_interfaces", return_value=network())
        self.lookup = self.network_patch.start()
        self.p = self.manager.save_profile(lan())

    def tearDown(self):
        self.network_patch.stop()
        self.manager.closed.set()
        self.tmp.cleanup()

    def test_start_resolves_current_ip_without_changing_saved_configuration(self):
        self.lookup.return_value = network("192.0.2.21")
        child = Mock(pid=2345)
        child.poll.return_value = None
        with patch.object(self.manager, "_refresh"), patch.object(self.manager, "_ssh_env", return_value={}), patch.object(app, "process_identity", return_value="same"), patch.object(app.subprocess, "Popen", return_value=child) as popen:
            self.manager.start(self.p["id"])
        self.assertIn("192.0.2.21:18765:127.0.0.1:7897", popen.call_args.args[0])
        self.assertEqual(self.manager.get(self.p["id"])["bind_host"], "192.0.2.20")
        active = self.manager._rt(self.p["id"])["observed_profile"]
        self.assertEqual(active["bind_host"], "192.0.2.21")
        self.assertEqual(app.connection_settings(active), app.connection_settings(self.p))

    def test_changed_or_missing_interface_never_silently_rebinds(self):
        self.manager._rt(self.p["id"])["observed_profile"] = copy.deepcopy(self.p)
        self.lookup.return_value = network("192.0.2.21")
        with patch.object(self.manager, "_refresh"), patch.object(app.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(app.UserError, "手动重启"):
                self.manager.start(self.p["id"], automatic=True)
            self.lookup.return_value = network(interface="en7")
            with self.assertRaisesRegex(app.UserError, "没有可用"):
                self.manager.start(self.p["id"])
            popen.assert_not_called()

    def test_card_uses_actual_running_address_and_reports_drift(self):
        self.manager._rt(self.p["id"]).update(observed_profile=copy.deepcopy(self.p), authenticated=True)
        self.lookup.return_value = network("192.0.2.21")
        with patch.object(self.manager, "_refresh"), patch.object(self.manager, "_current_process", return_value={"pid": 1234}):
            card = self.manager.snapshot()["tunnels"][0]
        self.assertEqual(card["share_url"], "http://192.0.2.20:18765/")
        self.assertIn("IP 已变化", card["network_warning"])
        self.assertFalse(card["pending_changes"])
        self.assertEqual(card["active_connection"]["bind_host"], "192.0.2.20")

    def test_running_edit_preserves_old_entry_until_restart(self):
        self.manager._rt(self.p["id"]).update(observed_profile=copy.deepcopy(self.p), authenticated=True)
        self.lookup.return_value = network("192.0.2.21", "en7")
        with patch.object(self.manager, "start") as start, patch.object(self.manager, "stop") as stop:
            self.manager.save_profile({"network_interface": "en7"}, self.p["id"])
            start.assert_not_called()
            stop.assert_not_called()
        with patch.object(self.manager, "_refresh"), patch.object(self.manager, "_current_process", return_value={"pid": 1234}):
            card = self.manager.snapshot()["tunnels"][0]
        self.assertTrue(card["pending_changes"])
        self.assertEqual(card["share_url"], "http://192.0.2.20:18765/")

    def test_conflict_includes_old_active_address_after_network_change(self):
        self.manager._rt(self.p["id"])["observed_profile"] = copy.deepcopy(self.p)
        self.lookup.return_value = {"interfaces": network()["interfaces"] + network("192.0.2.21", "en7")["interfaces"], "error": ""}
        self.manager.save_profile({"network_interface": "en7"}, self.p["id"])
        other = {**self.p, "id": "other", "network_interface": "en0", "bind_host": "192.0.2.20"}
        with patch.object(self.manager, "_current_process", return_value={"pid": 1234}):
            with self.assertRaisesRegex(app.UserError, "冲突"):
                self.manager._check_conflict(other)


class SharedHTTPTests(unittest.TestCase):
    def test_real_lan_listener_and_probe(self):
        interfaces = app.network_interfaces(fresh=True)["interfaces"]
        physical = next((item for item in interfaces if item["physical"]), None)
        if not physical:
            self.skipTest("no active physical IPv4 interface")
        class Web(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200 if self.path == '/page?check=1' else 404)
                self.end_headers()
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer((physical["address"], 0), Web)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                manager = app.Manager(directory, discover=False, monitor=False)
                p = manager.save_profile({**lan(), "network_interface": physical["interface"],
                                          "bind_port": server.server_port,
                                          "health_url": "http://wrong.example/page?check=1"})
                manager._rt(p["id"]).update(identity="same", observed_profile=copy.deepcopy(p))
                with patch.object(manager, "_refresh"), patch.object(manager, "_current_process", return_value={"pid": 1234}):
                    manager.check(p["id"])
                result = manager._rt(p["id"])["health"]
                self.assertTrue(result["ok"])
                self.assertEqual(result["http_status"], 200)
                self.assertIn("不能验证同事电脑", result["details"])
                manager.closed.set()
        finally:
            server.shutdown()
            server.server_close()
