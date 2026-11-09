# Tunnel Desk · Windows 分支

在 Windows 浏览器中管理本机发起的 SSH 隧道：发现已有连接、新建、编辑、开关、重启、日志和链路检测。

- **Windows 使用 `windows` 分支。** macOS 使用 [`main`](https://github.com/fourfireM/ssh-tunnel-manager/tree/main)，其后台由 launchd 托管。
- 需要 Windows 10 / 11、Python **3.10+**、Windows OpenSSH **客户端**、系统 `curl.exe` 和 Windows PowerShell 5.1。
- Windows 后台使用 **SSH 密钥 / ssh-agent** 认证，暂不支持网页密码弹窗。首次使用请完成下面的免交互登录配置。
- 网页只监听 `127.0.0.1`。Windows 无需安装 SSH 服务端，也无需为网页开放防火墙端口。
- 远端链路检测目前针对 Linux / POSIX 服务器：HTTP 检测需要远端有 `curl`，TCP 检测需要 `python3`。Windows 作为远端的检测命令尚未适配。

## 1. 下载 Windows 分支

以下命令在 **Windows PowerShell** 中执行，先进入准备保存项目的目录：

```powershell
git clone --branch windows --single-branch https://github.com/fourfireM/ssh-tunnel-manager.git
cd ssh-tunnel-manager
```

也可在 GitHub 切换到 `windows` 分支，选择 **Code → Download ZIP**，解压后在该目录打开 PowerShell。

## 2. 安装运行环境

安装 [python.org 的 Windows Python](https://www.python.org/downloads/windows/)，建议包含 Python Launcher，然后检查：

```powershell
py -3 --version
ssh -V
curl.exe --version
```

没有 `py` 时，后续命令可将 `py -3` 换成 `python`。没有 `ssh` 时，在 Windows“可选功能”中安装 **OpenSSH 客户端**；也可以由管理员在管理员 PowerShell 中运行：

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```

回到普通 PowerShell，在项目目录安装依赖：

```powershell
py -3 -m pip install -r requirements.txt
```

Windows 版用 `psutil` 识别当前用户的 SSH 进程，关闭前核对 PID、创建时间和命令。其余后台使用 Python 标准库，无需 npm。

## 3. 先验证 SSH 密钥登录

以下 `user`、`jump.example.com`、`training.example.com` 和端口均是示例，请替换成自己的。

已有密钥时，验证下面的命令能执行完成，且不要求输入密码：

```powershell
ssh -o BatchMode=yes -p 65422 user@jump.example.com exit
ssh -o BatchMode=yes -J user@jump.example.com:65422 -p 22 user@training.example.com exit
```

首次连接提示主机指纹时，请先用普通 `ssh` 登录，核实并接受指纹，再执行上述验证。应用不会自动信任陌生或变更的指纹。

### 尚未配置密钥

1. 在 Windows 生成密钥。已有同名文件时不要覆盖，可跳过或换一个文件名：

   ```powershell
   ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\id_ed25519"
   ```

2. 把**公钥**追加到 Linux 跳板机的授权文件。这一步允许在终端输入服务器密码：

   ```powershell
   Get-Content "$env:USERPROFILE\.ssh\id_ed25519.pub" | ssh -p 65422 user@jump.example.com 'umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys'
   ```

3. 训练机也要授权，可经跳板机追加公钥：

   ```powershell
   Get-Content "$env:USERPROFILE\.ssh\id_ed25519.pub" | ssh -J user@jump.example.com:65422 -p 22 user@training.example.com 'umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys'
   ```

4. 私钥有口令时，先在管理员 PowerShell 中启用 Windows `ssh-agent`：

   ```powershell
   Set-Service ssh-agent -StartupType Automatic
   Start-Service ssh-agent
   ```

   再在日常使用的用户 PowerShell 中加载密钥：

   ```powershell
   ssh-add "$env:USERPROFILE\.ssh\id_ed25519"
   ```

5. 重新执行本节开头的 `BatchMode=yes` 验证。跳板机和目标主机都应能免交互登录。非默认私钥路径可在网页高级选项中填写；SSH 配置默认读取 `%USERPROFILE%\.ssh\config`。

仅能使用密码时，可以先在 PowerShell 手动建立隧道，再在网页发现和关闭它；网页的开启、重启及远端检测仍需要密钥。

## 4. 启动网页

双击 **`start-windows.cmd`**，或在项目目录执行：

```powershell
py -3 main.py --background --open
```

默认地址为 **http://127.0.0.1:17899**。端口被占用时会尝试后续九个端口，以启动器打开的地址为准。

- 首次使用、新浏览器或清空浏览器数据后，通过启动器打开，才能建立本机网页授权。
- 已有后台会被复用，不会重复创建隧道。关闭浏览器后后台继续运行。
- 双击失败时窗口会保留错误。也可执行 `py -3 main.py --open` 在前台排查。
- Windows 休眠、注销、重启、断网会影响连接。

## 5. 页面参数怎么填

“本地”是运行项目的 **Windows 电脑**；“远端”是 SSH 连接的服务器。

### A. 服务器使用 Windows 的网络代理：反向转发

假设 Windows 的 HTTP/Mixed 代理确实监听在 `127.0.0.1:7897`：

| 字段 | 填写内容 |
| --- | --- |
| 通道名称 | 跳板机 · 网络代理 |
| 远端主机 | `user@jump.example.com` |
| SSH 端口 | `65422` |
| 跳板机 | 留空，直接连接这台主机 |
| 转发类型 | 反向转发 |
| 远端监听端口 | `17897` |
| 监听地址 | `127.0.0.1` |
| 目标地址 | `127.0.0.1` |
| 目标端口 | `7897`，以 Windows 代理实际端口为准 |
| 认证方式 | SSH 密钥 / ssh-agent |
| 链路检测 | HTTP 代理 |
| 检测 URL | `https://www.baidu.com`，也可换成需要访问的网站 |

保存 → 开启 → 检测链路。路径如下：

```text
服务器程序 → 服务器 17897 → SSH → Windows 代理 7897 → 外网
```

给训练机使用时，将“远端主机”改成 `user@training.example.com`，SSH 端口填写训练机实际端口，例如 `22`，“跳板机”填写 `user@jump.example.com:65422`，其余参数相同。本机代理只有 SOCKS 接口时，应选择 SOCKS5 检测。

随后在**使用该通道的 Linux 服务器**中配置，而不是在 Windows PowerShell 配置：

```bash
export http_proxy=http://127.0.0.1:17897
export https_proxy=http://127.0.0.1:17897
export no_proxy="localhost,127.0.0.1,::1"
export NO_PROXY="$no_proxy"
```

支持这些变量的 `curl`、`wget`、`pip` 等会使用代理。每次登录生效时，将四行加入该服务器的 `~/.bashrc`，执行 `source ~/.bashrc`，重新启动相关工具。`no_proxy` 避免本机模型接口也被送入外网代理，出现 502。

### B. 服务器使用 Windows 的模型接口：反向转发

假设模型接口确实运行在**这台 Windows 电脑**的 `127.0.0.1:8317`，复制示例 A 并修改：

| 字段 | 内容 |
| --- | --- |
| 通道名称 | 跳板机 · 模型接口 |
| 远端监听端口 | `18317` |
| 目标端口 | `8317` |
| 链路检测 | HTTP 接口 |
| 检测 URL | `http://127.0.0.1:18317/v1/models` |

服务器上 OpenAI 兼容工具的 Base URL 填 `http://127.0.0.1:18317/v1`，API Key 使用模型接口自身的密钥；其他协议按对应工具要求填写。

检测 `401` 表示接口可达但测试没带密钥，不代表完整模型调用成功；`404` 表示检测路径不匹配。模型密钥不需要填入隧道管理器。

**Mac 上的 `8317` 不会因启动 Windows 版而搬到 Windows。** 目标地址必须从 Windows 可访问。Mac 和 Windows 同时运行管理器时，同一服务器上的同一个监听端口只能由一条连接占用。

### C. Windows 浏览器访问服务器的 Jupyter：本地转发

假设服务器的 Jupyter 监听 `127.0.0.1:8888`：

| 字段 | 内容 |
| --- | --- |
| 转发类型 | 本地转发 |
| 本机监听端口 | `18888` |
| 监听地址 | `127.0.0.1` |
| 目标地址、端口 | `127.0.0.1`、`8888` |
| 链路检测 | TCP；或 HTTP 接口，URL 填 `http://127.0.0.1:18888` |

SSH 主机、端口、跳板机按实际填写。开启后在 **Windows 浏览器**打开 `http://127.0.0.1:18888`；Jupyter 的认证仍然有效。

### D. Windows 借服务器访问不同目标：动态 SOCKS

选择动态 SOCKS，本机监听地址 `127.0.0.1`、端口 `1080`，SSH 主机和跳板机按实际填写；目标地址和端口无需填写。检测选择 SOCKS5，填写服务器能访问的网站。

Windows 程序随后使用 SOCKS5 代理 `127.0.0.1:1080`：

```powershell
curl.exe --proxy socks5h://127.0.0.1:1080 https://www.baidu.com
```

出口是**服务器**。服务器无外网时，此模式不会替服务器提供外网；要让服务器借 Windows 上网，使用示例 A。

## 6. 登录自启动、停止和卸载

普通启动正常后，在**项目目录**运行：

```powershell
py -3 main.py --install-service --open
```

后台注册为当前用户的计划任务，登录后运行，异常退出后按任务设置尝试恢复。任务名类似 `TunnelDesk-xxxxxxxxxxxx`，由状态目录决定。默认不需管理员权限，不保存 Windows 登录密码；公司策略限制注册任务时可用普通启动模式。

任务记录了 Python 和项目的绝对路径，移动目录或更换 Python 后重新执行安装命令。它是**用户登录后启动**，不是无人登录时运行的系统服务。需要自动恢复的 SSH 通道应在页面勾选“断开后自动重连”；已关闭的通道不会自动开启。

```powershell
# 查看计划任务状态
py -3 main.py --service-status

# 停止网页后台（不会删除自启动配置）
py -3 main.py --stop-backend

# 停用并删除本应用的自启动任务
py -3 main.py --uninstall-service
```

**停止计划任务可能同时终止其创建的 SSH 连接。** 卸载前建议先在网页关闭隧道。配置仍会保留，以后可双击启动器手动运行。

## 7. 配置与日志位置

默认保存到 `%LOCALAPPDATA%\TunnelDesk`，位于项目目录之外：

| 文件 | 用途 |
| --- | --- |
| `tunnels.json` | 隧道配置 |
| `runtime.json` | 进程身份、运行状态、检测结果 |
| `access-token.json` | 本机网页访问令牌，不要分享或提交 Git |
| `server.log` | 网页后台日志 |
| `logs\` | 每条隧道的 SSH 日志 |

应用为专用数据目录设置当前用户和 SYSTEM 的访问权限。`.state/`、`output/` 仍受项目 `.gitignore` 排除。

可加 `--state-dir "D:\TunnelDeskData"` 指定专门目录，后续启动、注册任务、查看状态和卸载必须使用同一个目录。不要指定用户主目录、磁盘根目录或存放其他文件的目录。

## 8. 常见问题与限制

| 现象 | 检查方法 |
| --- | --- |
| 缺少 `psutil` | 用启动应用的 Python 执行 `py -3 -m pip install -r requirements.txt` |
| `Permission denied (publickey)` | 验证 `ssh -o BatchMode=yes ... exit`，检查公钥、私钥路径和 agent |
| 跳板机连接失败 | 跳板机和目标主机都需要有效密钥和已核实的指纹 |
| `Host key verification failed` | 在终端普通登录并核实指纹；应用不会自动接受变化的指纹 |
| 远端转发失败 | 检查远端端口占用和 SSH 服务端 `AllowTcpForwarding` 等设置 |
| SSH 运行但下载失败 | 检查 Windows 本机代理实际端口和目标网站的检测结果 |
| 模型接口返回 502 | 本机地址通过 `no_proxy` 绕过通用代理，再检查模型接口上游 |
| 网页要求授权 | 重新双击启动器，不要公开复制访问令牌 |
| 发现不到隧道 | 只发现当前用户原生 `ssh.exe` 的单条显式 TCP 转发；不接管 WSL、PuTTY/plink、其他用户或一个进程里的多条转发 |

本分支按**原生 Windows Python + Windows OpenSSH**设计，请使用 PowerShell。Windows 不使用 Unix `ControlMaster` 套接字，每次远端检测都会新建 SSH 会话。若已有连接由其他服务或任务保活，要先用原管理器停用它，避免关闭后被重新拉起；本项目不会接管任意外部计划任务。

## 9. 验证与支持范围

```powershell
py -3 -m unittest discover -s tests -v
```

Windows 原生 CI 会验证进程管理、文件 ACL、HTTP 检测，并用临时 SSH 服务测试 OpenSSH 的 L/R/D 转发；另有计划任务注册、启动、卸载检查。CI 仅使用临时测试密钥和临时服务器，不访问真实训练机。各次结果见仓库 Actions 页面。

CI 通过表示测试环境内验证通过；Windows 10/11 实际桌面的休眠恢复、企业安全策略及各类第三方代理客户端仍需在真实环境验证。网页密码认证暂不支持。
