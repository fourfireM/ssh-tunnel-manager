# Tunnel Desk

仅在 Mac 本机访问的 SSH 隧道管理页面。使用系统 OpenSSH 和 Python 标准库，不需要安装 npm 或 Python 依赖。

## 启动

双击 **启动隧道管理.command**。也可以在此目录执行：

```bash
python3 main.py --install-service --open
```

默认地址为 `http://127.0.0.1:17899`；端口被占用时会在后续九个端口中选择。启动器将带本机访问令牌的链接交给默认浏览器，页面随后移除地址中的令牌。令牌只用于本应用，不是 SSH 密码或模型 API 密钥；它保存在私有状态目录，并在后台重启后复用，浏览器无需重新授权。

启动器会安装或启用当前用户的 launchd 服务 `local.tunneldesk.manager`，登录后自动运行，异常退出后恢复。无需 sudo。再次运行启动器会打开已有后台，不会重复创建隧道。关闭浏览器后，后台和 SSH 连接继续运行。后台退出也不会自动杀掉已有 SSH 连接；重新启动后可再次识别。

后台任务文件位于 `~/Library/LaunchAgents/local.tunneldesk.manager.plist`。如需手动管理：

```bash
# 查看后台
launchctl print gui/$(id -u)/local.tunneldesk.manager

# 重启网页后台（已有独立 SSH 隧道继续运行）
launchctl kickstart -k gui/$(id -u)/local.tunneldesk.manager

# 停用网页后台；不会关闭已有 SSH 隧道
launchctl disable gui/$(id -u)/local.tunneldesk.manager
launchctl bootout gui/$(id -u)/local.tunneldesk.manager
```

再次运行启动器即可重新启用。如果只想临时运行，不安装系统任务，可以使用 `python3 main.py --background --open`。

## 首次接入

- 读取当前用户的 SSH 进程，以及 `~/Library/LaunchAgents` 中明确配置了单条 TCP 转发的 SSH 任务。
- 接入不会重启现有连接，不会改写 `~/.ssh/config`、`authorized_keys`、系统代理或路由。
- ProxyJump 的 `ssh -W` 辅助进程不会被误当成另一条通道。
- 一个进程里配置了多条转发时，不会将它们拆成可独立停止的通道，以免误断其他连接。

以下是两类常见配置示例，主机名可替换为自己的 SSH 别名：

| 用途 | 远端入口 | Mac 目标 |
| --- | --- | --- |
| 训练机网络代理 | `training-server` 上的 `127.0.0.1:17897` | `127.0.0.1:7897` |
| 模型接口 | `model-server` 上的 `127.0.0.1:18317` | `127.0.0.1:8317` |

端口属于各自监听的机器。不同机器使用相同端口不会因此冲突。CLIProxyAPI 接口端口和通用 HTTP/SOCKS 代理端口用途不同。

## 开关与配置

- 开关会真正控制对应 SSH 连接。
- 现有 launchd 保活任务会使用 `launchctl disable + bootout` 关闭，避免被系统立即重启；开启时 `enable + bootstrap/kickstart`。
- 保存编辑不会重启现有连接，卡片会显示待生效提示。手动重启后才使用新线路。
- 修改原有 LaunchAgent 的连接参数时，会在启动/重启时应用，并在 `.state/backups/` 保存原始 plist。其他任务设置会保留。没有线路修改时，不改写原文件。
- 本应用新建的连接以独立进程运行。停止前重新核实 PID、启动时间和命令，防止 PID 复用误杀。
- 入口只允许 `127.0.0.1` 或 `::1`，不提供公共监听开关。

## 密码与 SSH 密钥

优先使用已有 SSH 密钥和 ssh-agent。不保存密码；需要时通过 macOS 原生弹窗输入，答案只通过 OpenSSH askpass 的私有管道返回，不经过网页、配置文件或日志。

已有系统保活任务保持仅密钥认证，以免在登录或网络故障时反复弹出密码窗口。应用自动重连也只使用密钥；连续失败会退避，最多尝试五次。需要密码时请手动开启。

首次连接新的主机，请先在终端执行普通 SSH 登录，核对主机指纹。应用使用 `StrictHostKeyChecking=yes`，不会自动信任未知或变更的指纹。

## 状态与检测

页面分别显示：

1. SSH 进程是否运行；
2. Mac 上的目标端口是否可连接；
3. 手动检测的端到端结果。

检测支持 TCP、HTTP 代理、SOCKS5 和 HTTP 接口。反向转发的检测在远端执行固定的 curl/python3 命令，需要远端有对应工具和正常 SSH 认证。已有会话可能需要重新认证；应用新建的会话尽量复用私有 SSH 控制套接字。

HTTP 检测使用 GET，丢弃响应正文，仅记录响应头与状态码，避免只支持 GET 的接口被 HEAD 请求误判。HTTP 接口返回 401/403 时，以黄色提示“链路已连通，接口需要认证 / 拒绝访问”；这只验证链路和接口响应，不代表模型调用成功。404/405 会提示检测路径不存在或检测方法不受支持，不会笼统地说隧道断开。代理检测需收到目标站点的成功响应。

“通道总览”统一提供开关、新建与编辑配置，不再重复设置相同内容的配置页面。点击卡片底部的检测结果可直接查看详情。

## 本机网页的安全边界

- 后台仅绑定 `127.0.0.1`。
- API 使用本机随机 Bearer 令牌，检查 Host/Origin，拒绝跨站调用。
- 不使用 Cookie 认证，避免 localhost 不同端口共享 Cookie。
- 页面使用严格 CSP，不加载第三方资源；文本均转义显示。
- 调用 SSH 使用参数数组，不将表单输入拼接给 Shell。远端检测命令也逐参数引用。
- `.state` 权限为 700，配置、日志、令牌和运行状态文件为当前用户私有。

回环端口仍可被同一服务器上的其他用户或进程访问。模型接口应保留自己的 API 密钥；代理应按需限制访问目标。管理器不会替代远端账户和代理服务的权限控制。

## 验证

```bash
PYTHONPYCACHEPREFIX=/tmp/tunnel-desk-pycache python3 -m unittest discover -s tests -v
node --check web/app.js
```

测试覆盖参数注入、端口作用域、PID 身份验证、系统保活任务停止逻辑、配置保存不中断连接，以及本机 API 的认证和来源校验。浏览器 QA 产物位于 `output/playwright/`。
