#!/usr/bin/env python3
"""Tunnel Desk: a loopback-only SSH tunnel manager using the Python standard library."""
from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit
from urllib.request import Request, build_opener, ProxyHandler
import uuid
import webbrowser


ROOT = Path(__file__).resolve().parent
DEFAULT_STATE = ROOT / ".state"
SSH = "/usr/bin/ssh"
LAUNCHCTL = "/bin/launchctl"
SERVICE_LABEL = "local.tunneldesk.manager"
LOOPBACK = {"127.0.0.1", "::1", "localhost"}
TARGET_RE = re.compile(r"^[\w.@:\[\],-]+$", re.UNICODE)
HOST_RE = re.compile(r"^[\w.:[\]-]+$", re.UNICODE)
PROFILE_FIELDS = {
    "name", "description", "kind", "target", "ssh_port", "jump", "bind_host",
    "bind_port", "dest_host", "dest_port", "auth_mode", "auto_reconnect",
    "health_type", "health_url", "identity_file", "config_file",
}


def stamp():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def atomic_json(path: Path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_name(path.name + "." + secrets.token_hex(4) + ".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def read_json(path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return copy.deepcopy(default)


class UserError(Exception):
    pass


def port(value, label, allow_empty=False):
    if allow_empty and value in (None, "", 0):
        return None
    if isinstance(value, bool):
        raise UserError(f"{label}必须是 1–65535 之间的整数")
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise UserError(f"{label}必须是整数")
    if str(value).strip() != str(number) or not 1 <= number <= 65535:
        raise UserError(f"{label}必须是 1–65535 之间的整数")
    return number


def safe_target(value, label, optional=False):
    text = str(value or "").strip()
    if not text and optional:
        return ""
    if not text or len(text) > 240 or not TARGET_RE.fullmatch(text):
        raise UserError(f"{label}请填写 SSH 别名或 user@host，不允许空格和 Shell 符号")
    if any(part.startswith("-") or not part for part in text.split(",")):
        raise UserError(f"{label}格式不正确")
    if label != "跳板机" and "," in text:
        raise UserError(f"{label}只能填写一台主机")
    return text


def validate_profile(data, original=None):
    if not isinstance(data, dict):
        raise UserError("配置必须是 JSON 对象")
    unknown = set(data) - PROFILE_FIELDS
    if unknown:
        raise UserError("不支持的配置字段：" + ", ".join(sorted(unknown)))
    result = copy.deepcopy(original) if original else {"id": uuid.uuid4().hex, "source": "app"}
    result.update(data)
    result["name"] = str(result.get("name", "")).strip()
    if not result["name"] or len(result["name"]) > 64:
        raise UserError("通道名称应为 1–64 个字符")
    result["description"] = str(result.get("description", "")).strip()[:240]
    result["kind"] = result.get("kind", "R")
    if result["kind"] not in {"R", "L", "D"}:
        raise UserError("请选择反向转发、本地转发或 SOCKS 代理")
    result["target"] = safe_target(result.get("target"), "SSH 主机")
    result["jump"] = safe_target(result.get("jump"), "跳板机", optional=True)
    result["ssh_port"] = port(result.get("ssh_port"), "SSH 端口", allow_empty=True)
    result["bind_host"] = result.get("bind_host", "127.0.0.1")
    if result["bind_host"] not in {"127.0.0.1", "::1"}:
        raise UserError("为保护本机和服务器，监听地址仅允许 127.0.0.1 或 ::1")
    result["bind_port"] = port(result.get("bind_port"), "监听端口")
    if result["bind_port"] < 1024:
        raise UserError("请使用 1024 以上的监听端口，无需管理员权限")
    if result["kind"] != "D":
        result["dest_host"] = str(result.get("dest_host", "127.0.0.1")).strip()
        if (not HOST_RE.fullmatch(result["dest_host"]) or result["dest_host"].startswith("-")
                or len(result["dest_host"]) > 240):
            raise UserError("目标地址格式不正确")
        result["dest_port"] = port(result.get("dest_port"), "目标端口")
    else:
        result["dest_host"], result["dest_port"] = "", None
    result["auth_mode"] = result.get("auth_mode", "auto")
    if result["auth_mode"] not in {"auto", "key"}:
        raise UserError("认证方式不正确")
    if result.get("source") == "launchd":
        result["auth_mode"] = "key"
    if not isinstance(result.get("auto_reconnect", False), bool):
        raise UserError("自动重连设置必须为布尔值")
    result["auto_reconnect"] = result.get("auto_reconnect", False)
    result["health_type"] = result.get("health_type", "tcp")
    if result["health_type"] not in {"tcp", "http_proxy", "socks5", "http"}:
        raise UserError("检测类型不正确")
    result["health_url"] = str(result.get("health_url", "https://www.baidu.com")).strip()
    if result["health_type"] != "tcp":
        try:
            parsed = urlsplit(result["health_url"])
            _ = parsed.port
        except ValueError:
            raise UserError("检测 URL 格式不正确")
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username or parsed.password or parsed.fragment
                or len(result["health_url"]) > 1500
                or any(ord(c) < 32 for c in result["health_url"])):
            raise UserError("检测 URL 必须是无密码、无锚点的 HTTP/HTTPS 地址")
    for key in ("identity_file", "config_file"):
        value = str(result.get(key, "")).strip()
        if value and ("\n" in value or "\x00" in value or not Path(value).expanduser().is_absolute()):
            raise UserError("密钥及 SSH 配置路径必须是绝对路径")
        result[key] = value
    return result


def split_forward(text, kind):
    """Parse TCP forward specifications, including bracketed IPv6 addresses."""
    chunks = re.findall(r"\[[^\]]+\]|[^:]+", text)
    chunks = [x[1:-1] if x.startswith("[") and x.endswith("]") else x for x in chunks]
    if kind == "D":
        if len(chunks) == 1:
            return "127.0.0.1", int(chunks[0]), "", None
        if len(chunks) == 2:
            return chunks[0], int(chunks[1]), "", None
    elif len(chunks) == 3:
        return "127.0.0.1", int(chunks[0]), chunks[1], int(chunks[2])
    elif len(chunks) == 4:
        return chunks[0], int(chunks[1]), chunks[2], int(chunks[3])
    raise ValueError("unsupported forward")


def parse_ssh(argv):
    """Discover explicit TCP forwards; never treat a ProxyJump helper as a tunnel."""
    if not argv or Path(argv[0]).name != "ssh":
        return []
    options, forwards, target = {}, [], ""
    value_options = set("BbcDEeFIiJLlmOopQRSWw")
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            if i + 1 < len(argv):
                target = argv[i + 1]
            break
        if not arg.startswith("-"):
            target = arg
            break
        if len(arg) > 1 and arg[1] in value_options:
            key = arg[1]
            if len(arg) > 2:
                value = arg[2:]
            else:
                i += 1
                if i >= len(argv):
                    return []
                value = argv[i]
            if key in "RLD":
                forwards.append((key, value))
            elif key == "o":
                pair = re.split(r"[=\s]+", value, maxsplit=1)
                if len(pair) == 2:
                    options[pair[0].lower()] = pair[1]
            else:
                options[key] = value
        i += 1
    if not target or "W" in options:
        return []
    if options.get("l") and "@" not in target:
        target = options["l"] + "@" + target
    result = []
    for kind, spec in forwards:
        try:
            bind_host, bind_port, dest_host, dest_port = split_forward(spec, kind)
            data = {
                "name": target.split("@")[-1], "description": "从现有 SSH 连接接入",
                "kind": kind, "target": target, "ssh_port": options.get("p"),
                "jump": options.get("J", ""), "bind_host": bind_host,
                "bind_port": bind_port, "dest_host": dest_host, "dest_port": dest_port,
                "auth_mode": "key" if options.get("batchmode", "").lower() == "yes" else "auto",
                "auto_reconnect": False, "health_type": "tcp",
                "health_url": "https://www.baidu.com", "identity_file": options.get("i", ""),
                "config_file": options.get("F", ""),
            }
            result.append(validate_profile(data))
        except (ValueError, UserError):
            continue
    return result


def signature(p):
    return (p["kind"], p["target"], p.get("ssh_port"), p.get("jump", ""),
            p["bind_host"], p["bind_port"], p.get("dest_host", ""), p.get("dest_port"))


def connection_settings(p):
    return tuple((key, p.get(key)) for key in (
        "kind", "target", "ssh_port", "jump", "bind_host", "bind_port", "dest_host",
        "dest_port", "identity_file", "config_file", "auth_mode"))


def http_probe_args(profile, endpoint, executable="curl"):
    # Many APIs register GET routes without supporting HEAD. Discard response
    # bodies so model lists and other API data never enter the diagnostic log.
    args = [executable, "-sS", "--dump-header", "-", "--output", "/dev/null",
            "--connect-timeout", "5", "--max-time", "15", "--noproxy", ""]
    if profile["health_type"] in {"http_proxy", "socks5"} or profile["kind"] == "D":
        scheme = "socks5h" if profile["kind"] == "D" or profile["health_type"] == "socks5" else "http"
        args += ["--proxy", scheme + "://" + endpoint]
    else:
        args += ["--proxy", ""]
    return args + ["-w", "\n__TD_STATUS__:%{http_code}\n", profile["health_url"]]


def scan_processes():
    try:
        result = subprocess.run(["/bin/ps", "-axo", "pid=,ppid=,args="],
                                capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], "无法读取 SSH 进程：" + str(exc)
    if result.returncode:
        return [], "无法读取系统进程，请从本机启动器运行管理器。"
    found = []
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) != 3:
            continue
        try:
            argv = shlex.split(parts[2])
            profiles = parse_ssh(argv)
        except ValueError:
            continue
        if not profiles:
            continue
        pid = int(parts[0])
        for profile in profiles:
            found.append({"pid": pid, "ppid": int(parts[1]), "command": parts[2], "profile": profile})
    return found, ""


def process_identity(pid):
    try:
        out = subprocess.run(["/bin/ps", "-p", str(int(pid)), "-o", "lstart=,args="],
                             capture_output=True, text=True, timeout=3)
        return hashlib.sha256(out.stdout.strip().encode()).hexdigest() if out.returncode == 0 and out.stdout.strip() else ""
    except (ValueError, OSError, subprocess.TimeoutExpired):
        return ""


def safe_signal(pid, expected_identity):
    if not expected_identity or process_identity(pid) != expected_identity:
        raise UserError("进程已发生变化，已取消停止操作。请刷新状态后重试。")
    try:
        os.kill(int(pid), signal.SIGTERM)
    except ProcessLookupError:
        pass


def read_launch_agents():
    found = []
    for path in (Path.home() / "Library/LaunchAgents").glob("*.plist"):
        try:
            if path.is_symlink() or path.stat().st_uid != os.getuid():
                continue
            obj = plistlib.loads(path.read_bytes())
            argv = obj.get("ProgramArguments", [])
            profiles = parse_ssh(argv)
            if profiles and obj.get("Label"):
                found.append({"path": str(path), "label": obj["Label"],
                              "keep_alive": bool(obj.get("KeepAlive")), "profiles": profiles})
        except (OSError, ValueError, plistlib.InvalidFileException):
            continue
    return found


def ssh_aliases():
    aliases, seen = [], set()

    def read(path, depth=0):
        path = Path(path).expanduser()
        if depth > 4 or str(path) in seen or not path.is_file():
            return
        seen.add(str(path))
        try:
            lines = path.read_text().splitlines()
        except OSError:
            return
        for line in lines:
            try:
                chunks = shlex.split(line, comments=True)
            except ValueError:
                continue
            if not chunks:
                continue
            if chunks[0].lower() == "host":
                for alias in chunks[1:]:
                    if not any(c in alias for c in "*?!") and alias not in aliases:
                        aliases.append(alias)
            if chunks[0].lower() == "include":
                import glob
                for value in chunks[1:]:
                    include = Path(value).expanduser()
                    if not include.is_absolute():
                        include = Path.home() / ".ssh" / include
                    for match in glob.glob(str(include)):
                        read(match, depth + 1)

    read(Path.home() / ".ssh/config")
    return aliases


class Manager:
    def __init__(self, state_dir=DEFAULT_STATE, discover=True, monitor=True):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        self.log_dir = self.state_dir / "logs"
        self.log_dir.mkdir(mode=0o700, exist_ok=True)
        self.control_dir = self.state_dir / "sockets"
        self.control_dir.mkdir(mode=0o700, exist_ok=True)
        self.config_path = self.state_dir / "tunnels.json"
        self.runtime_path = self.state_dir / "runtime.json"
        self.lock = threading.RLock()
        self.closed = threading.Event()
        self.profiles = read_json(self.config_path, {"profiles": []}).get("profiles", [])
        self.runtime = read_json(self.runtime_path, {})
        self.jobs = {}
        self.operation_locks = {}
        self.children = {}
        self.aliases = ssh_aliases()
        self.host_cache = {}
        self.scan_error = ""
        self.events = []
        self.last_scan = 0
        self.processes = []
        self.launch_agents = read_launch_agents() if discover else []
        self._write_askpass()
        if discover:
            self.discover()
        if monitor:
            threading.Thread(target=self._monitor, name="tunnel-monitor", daemon=True).start()

    def _write_askpass(self):
        self.askpass_path = self.state_dir / "askpass"
        text = "#!/bin/sh\nexec " + shlex.join([sys.executable, str(ROOT / "askpass.py")]) + ' "$@"\n'
        self.askpass_path.write_text(text)
        os.chmod(self.askpass_path, 0o700)
        self.deny_askpass_path = self.state_dir / "deny-askpass"
        self.deny_askpass_path.write_text("#!/bin/sh\nexit 1\n")
        os.chmod(self.deny_askpass_path, 0o700)

    def _save(self):
        atomic_json(self.config_path, {"schema": 1, "profiles": self.profiles})
        atomic_json(self.runtime_path, self.runtime)

    def _event(self, message, tunnel_id=None):
        self.events.insert(0, {"time": stamp(), "message": message, "tunnel_id": tunnel_id})
        self.events = self.events[:40]

    def _rt(self, profile_id):
        return self.runtime.setdefault(profile_id, {})

    def _operation_lock(self, profile_id):
        with self.lock:
            return self.operation_locks.setdefault(profile_id, threading.RLock())

    def get(self, profile_id):
        for profile in self.profiles:
            if profile["id"] == profile_id:
                return profile
        raise UserError("没有找到这条通道")

    def resolve_host(self, profile):
        key = (profile["target"], profile.get("ssh_port"), profile.get("config_file", ""))
        if key in self.host_cache:
            return self.host_cache[key]
        result = {"hostname": profile["target"].split("@")[-1], "port": profile.get("ssh_port") or 22, "user": ""}
        args = [SSH, "-G"]
        if profile.get("config_file"):
            args += ["-F", str(Path(profile["config_file"]).expanduser())]
        if profile.get("ssh_port"):
            args += ["-p", str(profile["ssh_port"])]
        args += [profile["target"]]
        try:
            out = subprocess.run(args, capture_output=True, text=True, timeout=4)
            if not out.returncode:
                for line in out.stdout.splitlines():
                    fields = line.split(None, 1)
                    if len(fields) == 2 and fields[0] in result:
                        result[fields[0]] = int(fields[1]) if fields[0] == "port" else fields[1]
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
        self.host_cache[key] = result
        return result

    def _default_labels(self, profile):
        if profile["kind"] == "R" and profile["dest_port"] == 7897:
            profile.update(name="训练机 · 网络代理", description="经跳板机使用 Mac 的网络代理，供下载与联网工具使用",
                           health_type="http_proxy", health_url="https://www.baidu.com")
        elif profile["kind"] == "R" and profile["dest_port"] == 8317:
            profile.update(name="p6000 · 模型接口", description="将 Mac 上的 CLIProxyAPI 接口提供给 p6000",
                           health_type="http", health_url=f"http://127.0.0.1:{profile['bind_port']}/v1/models")
        return profile

    def discover(self):
        processes, error = scan_processes()
        agents = read_launch_agents()
        with self.lock:
            self.processes, self.scan_error = processes, error
            self.launch_agents, self.last_scan = agents, time.monotonic()
            added = 0
            for agent in agents:
                # A launchd job may own several forwards. Keep them together to avoid
                # accidentally stopping sibling forwards from an independently shown card.
                if len(agent["profiles"]) != 1:
                    continue
                candidate = agent["profiles"][0]
                existing = next((p for p in self.profiles if p.get("launch_label") == agent["label"]), None)
                if existing is None:
                    existing = next((p for p in self.profiles if signature(p) == signature(candidate)), None)
                if existing is None:
                    existing = self._default_labels(candidate)
                    self.profiles.append(existing)
                    added += 1
                existing.update(source="launchd", launch_label=agent["label"], launch_path=agent["path"])
                existing["auth_mode"] = "key"
                rt = self._rt(existing["id"])
                rt.setdefault("observed_profile", copy.deepcopy(candidate))
            # Multi-forward processes are not imported as independently stoppable tunnels.
            counts = {}
            for found in processes:
                counts[found["pid"]] = counts.get(found["pid"], 0) + 1
            for found in processes:
                if counts[found["pid"]] != 1:
                    continue
                candidate = found["profile"]
                profile = next((p for p in self.profiles if self._rt(p["id"]).get("pid") == found["pid"]
                                and self._rt(p["id"]).get("identity") == process_identity(found["pid"])), None)
                if profile is None:
                    profile = next((p for p in self.profiles if signature(p) == signature(candidate)
                                    or signature(self._rt(p["id"]).get("observed_profile", p)) == signature(candidate)), None)
                if profile is None:
                    profile = self._default_labels(candidate)
                    profile["source"] = "existing"
                    self.profiles.append(profile)
                    added += 1
                rt = self._rt(profile["id"])
                identity = process_identity(found["pid"])
                if rt.get("identity") != identity:
                    rt.pop("health", None)
                    rt["connected_at"] = stamp()
                rt.update(pid=found["pid"], identity=identity, observed_profile=copy.deepcopy(candidate))
                rt.setdefault("desired_running", True)
            self._save()
            if added:
                self._event(f"已接入 {added} 条现有通道，连接保持原样")
            return added

    def _refresh(self):
        if time.monotonic() - self.last_scan < 2:
            return
        processes, error = scan_processes()
        with self.lock:
            self.processes, self.scan_error, self.last_scan = processes, error, time.monotonic()
            for p in self.profiles:
                rt = self._rt(p["id"])
                matched = next((item for item in processes if item["pid"] == rt.get("pid")), None)
                if matched and process_identity(matched["pid"]) == rt.get("identity"):
                    continue
                old = rt.get("observed_profile", p)
                matched = next((item for item in processes if signature(item["profile"]) == signature(p)
                                or signature(item["profile"]) == signature(old)), None)
                if matched:
                    rt.update(pid=matched["pid"], identity=process_identity(matched["pid"]),
                              observed_profile=copy.deepcopy(matched["profile"]), connected_at=stamp())
                    rt.pop("health", None)
            for pid, child in list(self.children.items()):
                if child.poll() is not None:
                    self.children.pop(pid, None)

    def _current_process(self, profile):
        rt = self._rt(profile["id"])
        found = next((p for p in self.processes if p["pid"] == rt.get("pid")), None)
        if found and process_identity(found["pid"]) == rt.get("identity"):
            return found
        return None

    def _target_online(self, profile):
        if profile["kind"] != "R" or profile.get("dest_host") not in LOOPBACK:
            return None
        try:
            with socket.create_connection((profile["dest_host"], profile["dest_port"]), timeout=.3):
                return True
        except OSError:
            return False

    def snapshot(self):
        self._refresh()
        with self.lock:
            cards = []
            for profile in self.profiles:
                rt = self._rt(profile["id"])
                current = self._current_process(profile)
                log = self.read_log(profile["id"], limit=6000)
                status = "running" if current else "stopped"
                if current and rt.get("owned"):
                    target_name = self.resolve_host(profile)["hostname"]
                    # A ProxyJump helper may authenticate before the target.
                    if re.search(r"Authenticated to " + re.escape(target_name) + r"(?:\s|\[)", log):
                        rt["authenticated"] = True
                    if not rt.get("authenticated"):
                        status = "connecting"
                if not current and rt.get("last_error"):
                    status = "error"
                card = copy.deepcopy(profile)
                active = rt.get("observed_profile", profile) if current else profile
                card.update(status=status, pid=current["pid"] if current else None,
                            resolved=self.resolve_host(profile), local_service=self._target_online(active),
                            active_connection={**{key: active.get(key) for key in ("kind", "target", "ssh_port", "jump", "bind_host", "bind_port", "dest_host", "dest_port")}, "resolved": self.resolve_host(active)},
                            pending_changes=bool(current and connection_settings(profile) != connection_settings(rt.get("observed_profile", profile))),
                            connected_at=rt.get("connected_at"), last_error=rt.get("last_error", ""),
                            health=rt.get("health") if current else None,
                            command=shlex.join(self.build_ssh(profile)),
                            busy=any(j["tunnel_id"] == profile["id"] and j["status"] == "running" for j in self.jobs.values()),
                            retry_at=rt.get("retry_at"))
                cards.append(card)
            # Don't return credentials, launchd plist contents, or environment variables.
            return {"tunnels": cards, "aliases": self.aliases, "scan_error": self.scan_error,
                    "events": self.events[:12], "jobs": list(self.jobs.values())[-30:],
                    "updated_at": stamp(), "platform": sys.platform,
                    "backend": {"managed_by": "launchd" if os.environ.get("TUNNEL_DESK_LAUNCHD") == "1" else "process",
                                "pid": os.getpid(), "service_label": SERVICE_LABEL},
                    "security": {"bind": "127.0.0.1", "credentials": "macOS 系统弹窗 / ssh-agent"}}

    def _check_conflict(self, profile):
        for other in self.profiles:
            if other["id"] == profile["id"]:
                continue
            if profile["bind_host"] != other["bind_host"] or profile["bind_port"] != other["bind_port"]:
                continue
            same_side = (profile["kind"] == "R") == (other["kind"] == "R")
            if not same_side:
                continue
            if profile["kind"] == "R":
                a, b = self.resolve_host(profile), self.resolve_host(other)
                if (a["hostname"], a["port"]) != (b["hostname"], b["port"]):
                    continue
            raise UserError(f"监听端口与「{other['name']}」冲突。同一台机器上的入口端口需要不同。")

    def save_profile(self, data, profile_id=None):
        with self.lock:
            original = self.get(profile_id) if profile_id else None
            if original and any(j["tunnel_id"] == profile_id and j["status"] == "running" for j in self.jobs.values()):
                raise UserError("该通道正在操作，请稍后再编辑")
            profile = validate_profile(data, original)
            self._check_conflict(profile)
            if original:
                self.profiles[self.profiles.index(original)] = profile
                if connection_settings(original) != connection_settings(profile):
                    self._rt(profile_id).pop("health", None)
            else:
                self.profiles.append(profile)
            self._save()
            self._event(f"已保存「{profile['name']}」；运行中的连接保持原样", profile["id"])
            return copy.deepcopy(profile)

    def delete_profile(self, profile_id):
        self._refresh()
        with self.lock:
            profile = self.get(profile_id)
            if self._current_process(profile):
                raise UserError("请先关闭通道，再移除配置")
            if any(j["tunnel_id"] == profile_id and j["status"] == "running" for j in self.jobs.values()):
                raise UserError("操作尚未结束，请稍后移除")
            if profile.get("source") == "launchd":
                raise UserError("这是已有的系统任务。可以关闭通道；管理器不会删除原有 LaunchAgent 文件。")
            self.profiles.remove(profile)
            self.runtime.pop(profile_id, None)
            self._save()
            self._event(f"已移除「{profile['name']}」的管理配置")

    def control_path(self, profile):
        # macOS Unix sockets have a short path limit. Hash the app path and id.
        return self.control_dir / (profile["id"][:12] + ".sock")

    def _connection_args(self, profile, interactive=False, control=True):
        args = [SSH]
        if profile.get("config_file"):
            args += ["-F", str(Path(profile["config_file"]).expanduser())]
        if profile.get("identity_file"):
            args += ["-i", str(Path(profile["identity_file"]).expanduser())]
        if profile.get("jump"):
            args += ["-J", profile["jump"]]
        if profile.get("ssh_port"):
            args += ["-p", str(profile["ssh_port"])]
        args += ["-o", "BatchMode=" + ("no" if interactive and profile["auth_mode"] == "auto" else "yes"),
                 "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
                 "-o", "ConnectTimeout=12", "-o", "ConnectionAttempts=1", "-o", "NumberOfPasswordPrompts=1"]
        if control and self.control_path(profile).exists():
            args += ["-S", str(self.control_path(profile)), "-o", "ControlMaster=no"]
        return args

    @staticmethod
    def _address(value):
        return f"[{value}]" if ":" in value and not value.startswith("[") else value

    def build_ssh(self, profile, interactive=True):
        args = self._connection_args(profile, interactive, control=False)
        args += ["-NT", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30",
                 "-o", "ServerAliveCountMax=3"]
        if profile.get("source") == "launchd":
            args += ["-o", "ControlMaster=no", "-o", "ControlPath=none"]
        else:
            args += ["-M", "-S", str(self.control_path(profile)), "-o", "ControlPersist=no"]
        spec = f"{self._address(profile['bind_host'])}:{profile['bind_port']}"
        if profile["kind"] != "D":
            spec += f":{self._address(profile['dest_host'])}:{profile['dest_port']}"
        args += ["-" + profile["kind"], spec, profile["target"]]
        return args

    def _ssh_env(self, allow_prompt=True):
        env = os.environ.copy()
        # BatchMode on the target does not propagate to ProxyJump helpers.
        # Enforce no prompts in the inherited environment as well.
        env.update(SSH_ASKPASS=str(self.askpass_path if allow_prompt else self.deny_askpass_path), SSH_ASKPASS_REQUIRE="force")
        env.setdefault("DISPLAY", ":0")
        if not env.get("SSH_AUTH_SOCK"):
            try:
                result = subprocess.run([LAUNCHCTL, "getenv", "SSH_AUTH_SOCK"],
                                        capture_output=True, text=True, timeout=2)
                candidate = result.stdout.strip()
                if candidate and Path(candidate).exists():
                    env["SSH_AUTH_SOCK"] = candidate
            except (OSError, subprocess.TimeoutExpired):
                pass
        return env

    def _log_path(self, profile_id):
        if not re.fullmatch(r"[a-f0-9]{32}", profile_id):
            raise UserError("通道标识不正确")
        return self.log_dir / (profile_id + ".log")

    def read_log(self, profile_id, limit=24000):
        path = self._log_path(profile_id)
        try:
            with path.open("rb") as stream:
                stream.seek(0, 2)
                size = stream.tell()
                stream.seek(max(0, size - limit))
                text = stream.read().decode("utf-8", "replace")
            text = re.sub(r"(?i)(authorization:\s*bearer\s+|api[_-]?key[=:]\s*)\S+", r"\1[已隐藏]", text)
            return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
        except OSError:
            return "尚无本应用日志。接入已有进程不会重启它；下次通过管理器启动后开始记录。"

    def _append_log(self, profile_id, message):
        path = self._log_path(profile_id)
        if path.exists() and path.stat().st_size > 512_000:
            path.replace(path.with_suffix(".previous.log"))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as stream:
            stream.write(f"\n[{stamp()}] {message}\n")

    def _trusted_launch_agent(self, profile):
        path = Path(profile.get("launch_path", "")).expanduser()
        directory = (Path.home() / "Library/LaunchAgents").resolve()
        if path.is_symlink() or path.parent.resolve() != directory or path.suffix != ".plist":
            raise UserError("系统任务路径不可信，已取消操作")
        try:
            if path.stat().st_uid != os.getuid():
                raise UserError("系统任务不属于当前用户")
            obj = plistlib.loads(path.read_bytes())
        except (OSError, ValueError, plistlib.InvalidFileException) as exc:
            raise UserError("无法读取系统任务：" + str(exc))
        if obj.get("Label") != profile.get("launch_label") or len(parse_ssh(obj.get("ProgramArguments", []))) != 1:
            raise UserError("系统任务内容已变化，请重新发现后再操作")
        return path, obj

    def _launchctl(self, *args, check=True):
        result = subprocess.run([LAUNCHCTL, *args], capture_output=True, text=True, timeout=15)
        if check and result.returncode:
            raise UserError("系统任务操作失败：" + (result.stderr or result.stdout).strip()[-600:])
        return result

    def _apply_launch_agent(self, profile):
        path, obj = self._trusted_launch_agent(profile)
        parsed = parse_ssh(obj["ProgramArguments"])[0]
        if connection_settings(parsed) == connection_settings(profile):
            return
        backup = self.state_dir / "backups"
        backup.mkdir(mode=0o700, exist_ok=True)
        filename = profile["id"] + "-" + str(time.time_ns()) + ".plist"
        fd = os.open(backup / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(path.read_bytes())
        obj["ProgramArguments"] = self.build_ssh(profile, interactive=False)
        temp = path.with_name(path.name + ".tunneldesk.tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                plistlib.dump(obj, stream)
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)
        self._event("原系统任务已备份，新的连接配置将在启动时应用", profile["id"])

    def start(self, profile_id, automatic=False):
        self._refresh()
        if self.scan_error:
            raise UserError("无法确认已有进程状态，已取消启动以避免重复连接。请从本机启动器运行管理器。")
        with self.lock:
            profile = copy.deepcopy(self.get(profile_id))
            rt = self._rt(profile_id)
            rt.update(desired_running=True, last_error="")
            if self._current_process(profile):
                return "通道已经在运行"
            self._check_conflict(profile)
        if profile.get("source") == "launchd":
            path, _ = self._trusted_launch_agent(profile)
            job = f"gui/{os.getuid()}/{profile['launch_label']}"
            # If edited, unload before replacing the persisted job definition.
            parsed = parse_ssh(plistlib.loads(path.read_bytes())["ProgramArguments"])[0]
            changed = connection_settings(parsed) != connection_settings(profile)
            loaded = self._launchctl("print", job, check=False).returncode == 0
            if changed and loaded:
                self._launchctl("bootout", job)
                loaded = False
            self._apply_launch_agent(profile)
            self._launchctl("enable", job)
            if loaded:
                self._launchctl("kickstart", job)
            else:
                self._launchctl("bootstrap", f"gui/{os.getuid()}", str(path))
            self._event(f"已开启系统托管通道「{profile['name']}」", profile_id)
        else:
            interactive = not automatic
            # Remove only this profile's private stale socket, after verifying
            # that its recorded process is no longer running.
            self.control_path(profile).unlink(missing_ok=True)
            args = self.build_ssh(profile, interactive=interactive)
            path = self._log_path(profile_id)
            self._append_log(profile_id, "启动 SSH；" + ("自动恢复仅使用密钥，不弹出密码窗口" if automatic else "如需密码，将使用 macOS 系统弹窗"))
            # Keep diagnostics in a private file. Never send credentials through HTTP.
            args[1:1] = ["-v", "-E", str(path)]
            with path.open("ab", buffering=0) as log_stream:
                child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                         stderr=log_stream, start_new_session=True,
                                         env=self._ssh_env(allow_prompt=interactive and profile["auth_mode"] == "auto"))
            with self.lock:
                self.children[child.pid] = child
                rt.update(pid=child.pid, identity=process_identity(child.pid), owned=True, authenticated=False,
                          observed_profile=copy.deepcopy(profile), started_at=time.time(), connected_at=stamp())
                self.get(profile_id)["source"] = "app"
                rt.pop("health", None)
                self._save()
            time.sleep(.4)
            if child.poll() is not None:
                raise UserError(self._friendly_error(self.read_log(profile_id)))
            self._event(f"已启动「{profile['name']}」", profile_id)
        self.last_scan = 0
        self._refresh()
        with self.lock:
            self._save()
        return "连接已启动；若出现系统认证窗口，请在窗口中完成登录"

    @staticmethod
    def _friendly_error(log):
        patterns = [
            ("Permission denied", "认证失败：请检查账户、SSH 密钥或密码"),
            ("Host key verification failed", "主机指纹尚未受信任或已变化。请先在终端 SSH 登录并核对指纹"),
            ("REMOTE HOST IDENTIFICATION HAS CHANGED", "服务器主机指纹发生变化，请先人工核实"),
            ("Address already in use", "监听端口已被占用"),
            ("remote port forwarding failed", "远端端口转发失败：检查端口占用和服务器转发权限"),
            ("administratively prohibited", "服务器拒绝了 TCP 转发请求"),
            ("Connection refused", "SSH 连接被拒绝，请检查主机地址、端口和网络"),
            ("Operation timed out", "SSH 连接超时，请检查公司网络或 VPN"),
            ("Could not resolve hostname", "无法解析 SSH 主机名，请检查地址或 SSH 别名"),
        ]
        for needle, message in patterns:
            if needle in log:
                return message
        return "SSH 进程已退出，请查看通道日志"

    def stop(self, profile_id):
        self._refresh()
        if self.scan_error:
            raise UserError("无法核实进程身份，已取消停止操作。请刷新后重试。")
        with self.lock:
            profile = copy.deepcopy(self.get(profile_id))
            rt = self._rt(profile_id)
            current = self._current_process(profile)
            rt.update(desired_running=False, last_error="", retry_at=None, failures=0)
            rt.pop("health", None)
            self._save()
        if profile.get("source") == "launchd":
            self._trusted_launch_agent(profile)
            job = f"gui/{os.getuid()}/{profile['launch_label']}"
            # A KeepAlive job would respawn after kill; disable and unload it instead.
            self._launchctl("disable", job)
            if self._launchctl("print", job, check=False).returncode == 0:
                self._launchctl("bootout", job)
        elif current:
            safe_signal(current["pid"], rt.get("identity"))
        deadline = time.monotonic() + 3
        while current and time.monotonic() < deadline and process_identity(current["pid"]) == rt.get("identity"):
            time.sleep(.1)
        if current and process_identity(current["pid"]) == rt.get("identity"):
            raise UserError("SSH 尚未退出，已停止发送信号。请查看日志后重试。")
        self.last_scan = 0
        self._event(f"已关闭「{profile['name']}」", profile_id)
        self._append_log(profile_id, "用户关闭通道")
        return "通道已关闭"

    def check(self, profile_id):
        self._refresh()
        with self.lock:
            profile = copy.deepcopy(self.get(profile_id))
            current = self._current_process(profile)
            identity = self._rt(profile_id).get("identity")
        if not current:
            raise UserError("请先开启通道，再检测链路")
        with self.lock:
            if connection_settings(profile) != connection_settings(self._rt(profile_id).get("observed_profile", profile)):
                raise UserError("连接配置已修改，请先重启通道，再按新配置检测")
        if profile["kind"] == "R":
            endpoint = f"{self._address(profile['bind_host'])}:{profile['bind_port']}"
            if profile["health_type"] == "tcp":
                # Query a fixed port with Python when installed; no user shell text is evaluated.
                code = "import socket; s=socket.create_connection((" + repr(profile["bind_host"]) + "," + str(profile["bind_port"]) + "),4); s.close(); print('TCP_OK')"
                remote = shlex.join(["python3", "-c", code])
            else:
                remote = shlex.join(http_probe_args(profile, endpoint))
            command = self._connection_args(profile, interactive=True)
            command += [profile["target"], remote]
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=145,
                                        stdin=subprocess.DEVNULL, start_new_session=True,
                                        env=self._ssh_env(allow_prompt=profile["auth_mode"] == "auto"))
            except subprocess.TimeoutExpired:
                raise UserError("检测超时；请检查认证窗口、远端 curl/python3 和网络")
        else:
            endpoint = f"{self._address(profile['bind_host'])}:{profile['bind_port']}"
            if profile["health_type"] == "tcp":
                try:
                    with socket.create_connection((profile["bind_host"], profile["bind_port"]), timeout=4):
                        pass
                    result = subprocess.CompletedProcess([], 0, "TCP_OK", "")
                except OSError as exc:
                    result = subprocess.CompletedProcess([], 1, "", str(exc))
            else:
                command = http_probe_args(profile, endpoint, executable="/usr/bin/curl")
                result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        output = (result.stdout + "\n" + result.stderr).strip()[-7000:]
        status_matches = re.findall(r"__TD_STATUS__:(\d{3})", output)
        http_status = int(status_matches[-1]) if status_matches else None
        tcp_ok = profile["health_type"] == "tcp" and result.returncode == 0 and "TCP_OK" in output
        responded = result.returncode == 0 and http_status is not None and 100 <= http_status <= 599
        is_api = profile["health_type"] == "http" and profile["kind"] != "D"
        requires_auth = is_api and responded and http_status in {401, 403}
        success = tcp_ok or (responded and (200 <= http_status < 400 or requires_auth))
        level = "good" if success else "bad"
        if tcp_ok:
            message = "入口 TCP 可连接"
        elif is_api and responded:
            if http_status >= 400:
                level = "warn"
            explanation = {401: "接口需要认证", 403: "接口拒绝访问", 404: "检测路径不存在", 405: "检测方法不受支持"}.get(http_status)
            message = (f"链路已连通 · HTTP {http_status}，{explanation}" if explanation else
                       f"接口响应正常 · HTTP {http_status}" if success else
                       f"链路已连通 · 接口返回 HTTP {http_status}")
        elif success:
            message = f"代理访问正常 · HTTP {http_status}"
        elif responded:
            message = f"代理访问未通过 · HTTP {http_status}，请查看检测详情"
        else:
            message = "链路检测失败，请查看检测详情"
        method = "TCP" if profile["health_type"] == "tcp" else "GET"
        details = ("检测方式：TCP\n\n" if method == "TCP" else
                   f"检测方式：GET\n检测地址：{profile['health_url']}\n\n") + output
        if is_api and responded:
            details += "\n\n已收到接口响应；此检测不携带接口密钥，也不发起模型调用。"
        check_result = {"ok": success, "level": level, "message": message, "time": stamp(),
                        "http_status": http_status, "method": method, "details": details,
                        "pid": current["pid"]}
        with self.lock:
            if self._rt(profile_id).get("identity") == identity:
                self._rt(profile_id)["health"] = check_result
                self._save()
        self._event(f"「{profile['name']}」{message}", profile_id)
        return message

    def submit(self, profile_id, action):
        if action not in {"start", "stop", "restart", "check"}:
            raise UserError("未知操作")
        with self.lock:
            self.get(profile_id)
            if any(j["tunnel_id"] == profile_id and j["status"] == "running" for j in self.jobs.values()):
                raise UserError("这条通道已有操作正在进行")
            job_id = uuid.uuid4().hex
            job = {"id": job_id, "tunnel_id": profile_id, "action": action, "status": "running", "time": stamp(), "message": "处理中"}
            self.jobs[job_id] = job

        def work():
            try:
                with self._operation_lock(profile_id):
                    if action == "restart":
                        self.stop(profile_id)
                        message = self.start(profile_id)
                    else:
                        message = getattr(self, action)(profile_id)
                with self.lock:
                    job.update(status="done", message=message)
            except Exception as exc:
                message = str(exc) if isinstance(exc, (UserError, OSError)) else "操作失败，请查看管理器日志"
                with self.lock:
                    job.update(status="error", message=message)
                    if action in {"start", "restart"}:
                        self._rt(profile_id)["last_error"] = message
                        self._rt(profile_id)["desired_running"] = False
                        self._save()
                self._event(message, profile_id)
        threading.Thread(target=work, name="tunnel-" + action, daemon=True).start()
        return copy.deepcopy(job)

    def _monitor(self):
        while not self.closed.wait(5):
            try:
                self._refresh()
                candidates = []
                with self.lock:
                    for p in self.profiles:
                        rt = self._rt(p["id"])
                        if self._current_process(p):
                            if rt.get("owned") and not rt.get("authenticated"):
                                target_name = self.resolve_host(p)["hostname"]
                                log = self.read_log(p["id"], limit=6000)
                                if re.search(r"Authenticated to " + re.escape(target_name) + r"(?:\s|\[)", log):
                                    rt["authenticated"] = True
                            if not rt.get("owned") or rt.get("authenticated"):
                                rt["failures"] = 0
                            continue
                        if rt.get("owned") and rt.get("desired_running") and not rt.get("last_error"):
                            rt["last_error"] = self._friendly_error(self.read_log(p["id"]))
                        busy = any(j["tunnel_id"] == p["id"] and j["status"] == "running" for j in self.jobs.values())
                        if (p.get("auto_reconnect") and p.get("source") != "launchd"
                                and rt.get("desired_running") and not busy):
                            failures = rt.get("failures", 0)
                            if failures < 5 and time.time() >= (rt.get("retry_at") or 0):
                                rt["failures"] = failures + 1
                                rt["retry_at"] = time.time() + min(300, 15 * (2 ** failures))
                                candidates.append(p["id"])
                    self._save()
                for profile_id in candidates:
                    operation_lock = self._operation_lock(profile_id)
                    if not operation_lock.acquire(blocking=False):
                        continue
                    try:
                        if self._rt(profile_id).get("desired_running"):
                            self.start(profile_id, automatic=True)
                    except Exception as exc:
                        with self.lock:
                            self._rt(profile_id)["last_error"] = str(exc)
                        self._event("自动重连未成功；必要时请手动开启以完成认证", profile_id)
                    finally:
                        operation_lock.release()
            except Exception:
                # A transient ps or file error must not terminate tunnel monitoring.
                continue


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, manager, token):
        super().__init__(address, Handler)
        self.manager, self.token = manager, token


class Handler(BaseHTTPRequestHandler):
    server_version = "TunnelDesk/1.0"
    sys_version = ""

    def log_message(self, fmt, *args):
        # Never log URL fragments, auth headers, cookies, or request bodies.
        if args and isinstance(args[0], str) and args[0].startswith("GET /api/state"):
            return
        sys.stderr.write(f"[{stamp()}] {self.command} {urlsplit(self.path).path} {args[1] if len(args) > 1 else ''}\n")

    def _host_valid(self):
        port_number = self.server.server_address[1]
        return self.headers.get("Host", "") in {f"127.0.0.1:{port_number}", f"localhost:{port_number}"}

    def _origin_valid(self):
        origin = self.headers.get("Origin")
        port_number = self.server.server_address[1]
        return not origin or origin in {f"http://127.0.0.1:{port_number}", f"http://localhost:{port_number}"}

    def _authorized(self, bootstrap=False):
        if not self._host_valid() or not self._origin_valid():
            return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            return False
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and hmac.compare_digest(auth[7:], self.server.token):
            return True
        # Cookies are shared between ports on localhost. Use an origin-scoped
        # bearer token instead, so another local service never receives it.
        return False

    def _send(self, status, body, mime="application/json; charset=utf-8", extra=None):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self):
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            raise UserError("请求必须使用 application/json")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise UserError("请求长度无效")
        if not 0 < length <= 65536:
            raise UserError("请求内容为空或过大")
        try:
            data = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            raise UserError("JSON 内容无效")
        if not isinstance(data, dict):
            raise UserError("请求必须是 JSON 对象")
        return data

    def do_GET(self):
        if not self._host_valid():
            return self._send(403, {"error": "只允许从本机地址访问"})
        path = unquote(urlsplit(self.path).path)
        if path.startswith("/api/"):
            if not self._authorized():
                return self._send(401, {"error": "请通过本机启动器打开管理页面"})
            try:
                if path == "/api/state":
                    return self._send(200, self.server.manager.snapshot())
                if path == "/api/ping":
                    return self._send(200, {"app": "tunnel-desk", "version": 1})
                match = re.fullmatch(r"/api/tunnels/([a-f0-9]{32})/logs", path)
                if match:
                    self.server.manager.get(match[1])
                    return self._send(200, {"text": self.server.manager.read_log(match[1])})
            except UserError as exc:
                return self._send(400, {"error": str(exc)})
            return self._send(404, {"error": "没有这个接口"})
        assets = {"/": ("index.html", "text/html; charset=utf-8"),
                  "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                  "/style.css": ("style.css", "text/css; charset=utf-8"),
                  "/favicon.svg": ("favicon.svg", "image/svg+xml")}
        if path not in assets:
            return self._send(404, {"error": "没有这个页面"})
        filename, mime = assets[path]
        self._send(200, (ROOT / "web" / filename).read_bytes(), mime)

    def do_POST(self):
        path = urlsplit(self.path).path
        if not self._authorized(bootstrap=path == "/api/session"):
            return self._send(403, {"error": "本机认证失败，或请求来源不受信任"})
        try:
            data = self._json()
            if path == "/api/session":
                return self._send(200, {"ok": True})
            if path == "/api/tunnels":
                return self._send(201, self.server.manager.save_profile(data))
            if path == "/api/discover":
                return self._send(200, {"added": self.server.manager.discover()})
            match = re.fullmatch(r"/api/tunnels/([a-f0-9]{32})/(start|stop|restart|check)", path)
            if match:
                return self._send(202, self.server.manager.submit(match[1], match[2]))
            if path == "/api/shutdown":
                self._send(200, {"ok": True, "message": "管理页面后台已退出，SSH 通道继续运行"})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
        except UserError as exc:
            return self._send(400, {"error": str(exc)})
        except Exception:
            return self._send(500, {"error": "操作失败，请检查管理器日志"})
        return self._send(404, {"error": "没有这个接口"})

    def do_PUT(self):
        if not self._authorized():
            return self._send(403, {"error": "请求未授权"})
        match = re.fullmatch(r"/api/tunnels/([a-f0-9]{32})", urlsplit(self.path).path)
        if not match:
            return self._send(404, {"error": "没有这个接口"})
        try:
            self._send(200, self.server.manager.save_profile(self._json(), match[1]))
        except UserError as exc:
            self._send(400, {"error": str(exc)})

    def do_DELETE(self):
        if not self._authorized():
            return self._send(403, {"error": "请求未授权"})
        match = re.fullmatch(r"/api/tunnels/([a-f0-9]{32})", urlsplit(self.path).path)
        if not match:
            return self._send(404, {"error": "没有这个接口"})
        try:
            self.server.manager.delete_profile(match[1])
            self._send(200, {"ok": True})
        except UserError as exc:
            self._send(400, {"error": str(exc)})

    def do_OPTIONS(self):
        self._send(405, {"error": "不接受跨站调用"})


def existing_server(state_dir):
    info = read_json(Path(state_dir) / "server.json", {})
    if not info.get("token") or not isinstance(info.get("port"), int):
        return None
    try:
        opener = build_opener(ProxyHandler({}))
        request = Request(f"http://127.0.0.1:{info['port']}/api/ping", headers={"Authorization": "Bearer " + info["token"]})
        with opener.open(request, timeout=2) as response:
            if json.load(response).get("app") == "tunnel-desk":
                return info
    except Exception:
        pass
    return None


def access_token(state_dir):
    path = Path(state_dir) / "access-token.json"
    if path.is_symlink():
        raise UserError("本机访问令牌路径不可信")
    saved = read_json(path, {})
    value = saved.get("token") if isinstance(saved, dict) else None
    if not value:
        previous = read_json(Path(state_dir) / "server.json", {})
        value = previous.get("token") if isinstance(previous, dict) else None
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{40,128}", value):
        value = secrets.token_urlsafe(36)
    atomic_json(path, {"token": value})
    return value


def open_page(info):
    webbrowser.open(f"http://127.0.0.1:{info['port']}/#token={info['token']}")


def service_plist(state_dir, port_number):
    return {
        "Label": SERVICE_LABEL,
        "ProgramArguments": [sys.executable, str(ROOT / "main.py"), "--port", str(port_number), "--state-dir", str(Path(state_dir).resolve())],
        "WorkingDirectory": str(ROOT),
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "ProcessType": "Background",
        "LimitLoadToSessionType": "Aqua",
        # SSH children have their own session and deliberately outlive the UI.
        "AbandonProcessGroup": True,
        "EnvironmentVariables": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin", "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1", "TUNNEL_DESK_LAUNCHD": "1"},
        "StandardOutPath": str(Path(state_dir).resolve() / "server.log"),
        "StandardErrorPath": str(Path(state_dir).resolve() / "server.log"),
    }


def install_service(state_dir, port_number):
    """Install only the current user's manager job; never alter tunnel jobs."""
    if sys.platform != "darwin":
        raise UserError("launchd 托管仅适用于 macOS")
    state_dir = Path(state_dir).resolve()
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    agents = Path.home() / "Library/LaunchAgents"
    agents.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = agents / (SERVICE_LABEL + ".plist")
    domain, job = f"gui/{os.getuid()}", f"gui/{os.getuid()}/{SERVICE_LABEL}"
    desired = service_plist(state_dir, port_number)
    changed = not path.exists()
    if path.exists():
        if path.is_symlink() or path.stat().st_uid != os.getuid():
            raise UserError("管理后台的 LaunchAgent 路径不可信")
        old = plistlib.loads(path.read_bytes())
        if old.get("Label") != SERVICE_LABEL:
            raise UserError("发现同名的其他系统任务，已取消覆盖")
        changed = old != desired
        if changed:
            backup = state_dir / "backups"
            backup.mkdir(mode=0o700, exist_ok=True)
            fd = os.open(backup / ("manager-" + str(time.time_ns()) + ".plist"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(path.read_bytes())
    loaded = subprocess.run([LAUNCHCTL, "print", job], capture_output=True).returncode == 0
    running_info = existing_server(state_dir)
    if running_info and running_info.get("managed_by") == "process":
        # Migrate an earlier manually started manager, leaving its SSH children alive.
        opener = build_opener(ProxyHandler({}))
        request = Request(f"http://127.0.0.1:{running_info['port']}/api/shutdown", data=b"{}", method="POST",
                          headers={"Authorization": "Bearer " + running_info["token"], "Content-Type": "application/json"})
        with opener.open(request, timeout=5):
            pass
        for _ in range(30):
            if not existing_server(state_dir):
                break
            time.sleep(.1)
    if changed and loaded:
        result = subprocess.run([LAUNCHCTL, "bootout", job], capture_output=True, text=True)
        if result.returncode:
            raise UserError("无法重新加载管理后台：" + result.stderr.strip())
        loaded = False
    if changed:
        temp = path.with_suffix(".plist.tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                plistlib.dump(desired, stream)
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)
    log_fd = os.open(state_dir / "server.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.close(log_fd)
    result = subprocess.run([LAUNCHCTL, "enable", job], capture_output=True, text=True)
    if result.returncode:
        raise UserError("无法启用管理后台：" + result.stderr.strip())
    command = [LAUNCHCTL, "kickstart", job] if loaded else [LAUNCHCTL, "bootstrap", domain, str(path)]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        raise UserError("无法启动管理后台：" + result.stderr.strip())
    for _ in range(100):
        info = existing_server(state_dir)
        if info:
            return info
        time.sleep(.15)
    raise UserError("系统任务已安装，但网页后台尚未就绪。请查看 .state/server.log")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Tunnel Desk · 本机 SSH 隧道管理")
    parser.add_argument("--open", action="store_true", help="在默认浏览器中打开")
    parser.add_argument("--background", action="store_true", help="后台启动管理页面")
    parser.add_argument("--install-service", action="store_true", help="安装或启动当前用户的 launchd 后台")
    parser.add_argument("--port", type=int, default=17899)
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= 65535:
        parser.error("端口必须在 1024–65535 之间")
    if args.install_service:
        try:
            info = install_service(args.state_dir, args.port)
            if args.open:
                open_page(info)
            print(f"launchd 后台已就绪：http://127.0.0.1:{info['port']}")
            return 0
        except (UserError, OSError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
    info = existing_server(args.state_dir)
    if info:
        if args.open:
            open_page(info)
        print(f"管理器已运行：http://127.0.0.1:{info['port']}")
        return 0
    args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.state_dir, 0o700)
    if args.background:
        log_path = args.state_dir / "server.log"
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "ab") as log:
            child = subprocess.Popen([sys.executable, str(ROOT / "main.py"), "--port", str(args.port), "--state-dir", str(args.state_dir)],
                                     stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        for _ in range(80):
            time.sleep(.15)
            info = existing_server(args.state_dir)
            if info:
                if args.open:
                    open_page(info)
                print(f"管理器已启动：http://127.0.0.1:{info['port']}")
                return 0
            if child.poll() is not None:
                break
        print("启动未完成，请查看 " + str(log_path), file=sys.stderr)
        return 1
    os.umask(0o077)
    manager = Manager(args.state_dir)
    token = access_token(args.state_dir)
    server = None
    for candidate in range(args.port, min(args.port + 10, 65536)):
        try:
            server = LocalServer(("127.0.0.1", candidate), manager, token)
            break
        except OSError:
            continue
    if server is None:
        print("没有可用的本机端口", file=sys.stderr)
        return 1
    info = {"pid": os.getpid(), "port": server.server_address[1], "token": token, "started_at": stamp(),
            "managed_by": "launchd" if os.environ.get("TUNNEL_DESK_LAUNCHD") == "1" else "process"}
    atomic_json(args.state_dir / "server.json", info)
    print(f"Tunnel Desk：http://127.0.0.1:{info['port']}（仅本机访问）", flush=True)
    if args.open:
        open_page(info)
    try:
        server.serve_forever(poll_interval=.3)
    except KeyboardInterrupt:
        pass
    finally:
        manager.closed.set()
        server.server_close()
        saved = read_json(args.state_dir / "server.json", {})
        if saved.get("token") == token:
            (args.state_dir / "server.json").unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
