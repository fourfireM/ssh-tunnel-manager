"""Windows process, ACL and Task Scheduler integration.

No passwords or API credentials are accepted by this module. PowerShell programs
are fixed strings; paths are passed through the child environment, never code.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def executable(name):
    system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    relative = {"ssh": "OpenSSH/ssh.exe", "curl": "curl.exe",
                "powershell": "WindowsPowerShell/v1.0/powershell.exe"}[name]
    native = system / relative
    return str(native) if native.is_file() else (shutil.which(name + ".exe") or name + ".exe")


def psutil_module():
    try:
        import psutil
        return psutil
    except ImportError as exc:
        raise RuntimeError("缺少 psutil，请先运行：py -3 -m pip install -r requirements.txt") from exc


def default_state_dir():
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local"))) / "TunnelDesk"


def detached_options():
    # These flags detach from a terminal, not from a supervisor's Windows Job.
    return {"creationflags": subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP}


def powershell(script, variables=None, timeout=30):
    preamble = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
    encoded = base64.b64encode((preamble + script).encode("utf-16-le")).decode("ascii")
    env = os.environ.copy()
    env.update({key: str(value) for key, value in (variables or {}).items()})
    result = subprocess.run([executable("powershell"), "-NoLogo", "-NoProfile", "-NonInteractive",
                             "-EncodedCommand", encoded], env=env, capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=timeout,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode:
        raise RuntimeError("Windows 操作失败：" + (result.stderr.strip() or result.stdout.strip())[-1800:])
    return result.stdout.strip()


_secured = set()


def secure_state_directory(path):
    path = Path(path).absolute()
    if path in _secured:
        return
    if path == Path.home().resolve() or path == Path(path.anchor):
        raise RuntimeError("请选择专门的应用数据目录，不能把用户目录或磁盘根目录作为状态目录")
    path.mkdir(parents=True, exist_ok=True)
    # ACL inheritance protects subsequently created files, including atomic
    # replacement files and logs. Apply only to the dedicated application folder.
    powershell(r"""
$item = Get-Item -LiteralPath $env:TD_STATE -Force
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'State directory cannot be a link' }
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
foreach ($identity in @($sid, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
  $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', $inherit, 'None', 'Allow')
  $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $env:TD_STATE -AclObject $acl
""", {"TD_STATE": path})
    _secured.add(path)


def process_fingerprint(pid, created, argv):
    return hashlib.sha256(json.dumps([pid, created, argv], ensure_ascii=False).encode()).hexdigest()


def _record(process, owner):
    with process.oneshot():
        if process.username().casefold() != owner.casefold():
            return None
        if process.name().casefold() != "ssh.exe":
            return None
        argv = process.cmdline()
        if not argv:
            return None
        return {"pid": process.pid, "ppid": process.ppid(), "argv": argv,
                "identity": process_fingerprint(process.pid, process.create_time(), argv),
                "command": subprocess.list2cmdline(argv)}


def ssh_processes():
    psutil = psutil_module()
    owner = psutil.Process().username()
    records = []
    for process in psutil.process_iter(["name"]):
        try:
            if (process.info["name"] or "").casefold() != "ssh.exe":
                continue
            record = _record(process, owner)
            if record:
                records.append(record)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return records


def process_identity(pid):
    psutil = psutil_module()
    try:
        record = _record(psutil.Process(int(pid)), psutil.Process().username())
        return record["identity"] if record else ""
    except (ValueError, psutil.NoSuchProcess, psutil.AccessDenied):
        return ""


def terminate_ssh(pid, identity):
    psutil = psutil_module()
    try:
        process = psutil.Process(int(pid))
        record = _record(process, psutil.Process().username())
        if not identity or not record or record["identity"] != identity:
            raise RuntimeError("SSH 进程身份已变化，已取消停止")
        # psutil's terminate also checks that the PID still has its original
        # creation time. Never use taskkill /IM or terminate a process tree.
        process.terminate()
    except psutil.NoSuchProcess:
        pass


def task_name(state_dir):
    key = str(Path(state_dir).resolve()).casefold()
    return "TunnelDesk-" + hashlib.sha256(key.encode()).hexdigest()[:12]


def task_definition(root, state_dir, port):
    python = Path(sys.executable)
    windowless = python.with_name("pythonw.exe")
    if windowless.is_file():
        python = windowless
    return {"TD_TASK": task_name(state_dir), "TD_EXECUTABLE": str(python),
            "TD_DIRECTORY": str(Path(root).resolve()),
            "TD_ARGUMENTS": subprocess.list2cmdline([str(Path(root).resolve() / "main.py"),
                "--state-dir", str(Path(state_dir).resolve()), "--port", str(port), "--scheduled"])}


def install_task(root, state_dir, port):
    variables = task_definition(root, state_dir, port)
    powershell(r"""
$user = [Security.Principal.WindowsIdentity]::GetCurrent()
$existing = Get-ScheduledTask -TaskName $env:TD_TASK -ErrorAction SilentlyContinue
if ($existing) {
  $owner = $existing.Principal.UserId
  if ($owner -notmatch '^S-1-') { $owner = [Security.Principal.NTAccount]::new($owner).Translate([Security.Principal.SecurityIdentifier]).Value }
  if ($owner -ne $user.User.Value) { throw 'An existing task with this name belongs to another user' }
}
$action = New-ScheduledTaskAction -Execute $env:TD_EXECUTABLE -Argument $env:TD_ARGUMENTS -WorkingDirectory $env:TD_DIRECTORY
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user.User.Value
$principal = New-ScheduledTaskPrincipal -UserId $user.User.Value -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $env:TD_TASK -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $env:TD_TASK
""", variables)
    return variables["TD_TASK"]


def task_status(state_dir):
    return powershell(r"""
$task = Get-ScheduledTask -TaskName $env:TD_TASK -ErrorAction SilentlyContinue
if ($task) { $task | Select-Object TaskName,State | ConvertTo-Json -Compress } else { '{}' }
""", {"TD_TASK": task_name(state_dir)})


def uninstall_task(state_dir):
    powershell(r"""
$task = Get-ScheduledTask -TaskName $env:TD_TASK -ErrorAction SilentlyContinue
if ($task) {
  $user = [Security.Principal.WindowsIdentity]::GetCurrent()
  $owner = $task.Principal.UserId
  if ($owner -notmatch '^S-1-') { $owner = [Security.Principal.NTAccount]::new($owner).Translate([Security.Principal.SecurityIdentifier]).Value }
  if ($owner -ne $user.User.Value) { throw 'Task belongs to another user' }
  Disable-ScheduledTask -TaskName $env:TD_TASK | Out-Null
  Stop-ScheduledTask -TaskName $env:TD_TASK
  Unregister-ScheduledTask -TaskName $env:TD_TASK -Confirm:$false
}
""", {"TD_TASK": task_name(state_dir)})


def check_requirements():
    if sys.version_info < (3, 10):
        raise RuntimeError("请安装 Python 3.10 或更新版本")
    psutil_module()
    for name in ("ssh", "curl", "powershell"):
        path = executable(name)
        if not Path(path).is_file() and not shutil.which(path):
            raise RuntimeError("缺少 " + name + "，请按 README 安装 Windows OpenSSH 客户端和系统工具")
