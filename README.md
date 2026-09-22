# ProxySentry

面向 macOS、Clash Verge Rev 和 mihomo 内核的保守型节点故障切换守卫。它不是常驻代理，也不接管配置；它只通过本机 Unix socket 观察并切换一个 Selector。

完整状态和恢复规则见 [`docs/DESIGN.md`](docs/DESIGN.md)。

## 行为概览

- 每 60 秒检查 `主代理` 当前选择。
- 同一具体节点连续 2 次探活失败后，先复检当前节点，再检查本机直连网络。
- 本机在线时，并行探测组内具体节点，跳过策略组和处于隔离期的节点。
- 按延迟取前 3 名，逐个临时切换并下载 1 MiB：必须读满且平均速度不低于 0.5 MiB/s 才采用。
- 0.3–0.5 MiB/s 的临界结果额外复测一次；下载超时、HTTP 错误、代理错误、未读满和吞吐不达标分别记录。
- 验证失败的节点隔离 30 分钟；同一节点再次失败时 TTL 翻倍，最多 4 小时。隔离记录持久化，24 小时未再失败后遗忘。
- 活跃隔离达到 3 个或候选全部失败时，切回 `自动选择` URLTest 组止血，并以最长 30 分钟的指数退避持续寻找恢复节点。
- 只有具体节点和 URLTest 兜底都不可用的 `OUTAGE` 会发送 macOS 通知，持续故障最多每 30 分钟提醒一次。
- 本机离线期间不新增或刷新任何节点隔离。
- 用户手动选择具体节点时，重新进入观察期；用户手动选择策略组时，脚本完全不干预。

## 吞吐验证前提

脚本通过 `http://127.0.0.1:7897` 下载 Cloudflare 的 1 MiB 测试对象。这个代理入口的路由必须经过被守护的 `主代理`，否则测速结果不能代表刚切换的候选节点。

如果本机 HTTP 代理端口不同，通过 `CLASH_GUARD_PROXY` 修改。故障切换期间会短暂依次选中候选节点，现有连接可能瞬断；这是 mihomo API 无法在不切换 Selector 的情况下让流量指定走某个候选节点所决定的。

## 安全设计

- `fcntl` 非阻塞进程锁阻止 LaunchAgent、循环壳和手动运行重叠。
- PUT 前后都读取当前选择，目标必须是 Selector 的直接成员；发现用户改选立即停止。
- 切换意图先写入状态，进程在 PUT 后崩溃时可以继续验证，而不会直接把临时节点当成成功。
- API 响应限制为 4 MiB；节点名严格 URL 编码；日志清洗控制字符。
- 状态原子更新，日志和状态权限固定为 `0600`，工作目录应为 `0700`。
- 日志保留最近 500 行。

mihomo 的 Unix socket 控制接口不使用 `secret` 鉴权。安全边界是 socket 及其父目录的本机文件权限；不要让其他本机用户拥有连接或替换该 socket 的权限。脚本不上传配置、节点名或日志。探活会访问 Google、Cloudflare 和 Apple 的固定测试地址，故障吞吐验证会经代理访问 Cloudflare；这些服务会像普通网络请求一样看到出口 IP、时间和 HTTP 元数据。

## 要求

- macOS
- `/usr/bin/python3`（仅用标准库）
- `/usr/bin/curl`
- Clash Verge Rev/mihomo Unix 控制接口，默认 `/tmp/verge/verge-mihomo.sock`
- 被守护 Selector 默认名为 `主代理`
- URLTest 兜底组默认名为 `自动选择`，且是 `主代理` 的成员

## 安装

```sh
mkdir -p ~/.workbuddy/bin ~/.workbuddy/logs
chmod 700 ~/.workbuddy ~/.workbuddy/bin ~/.workbuddy/logs
install -m 600 clash-guard.py ~/.workbuddy/bin/clash-guard.py
sed "s|__HOME__|$HOME|g; s|com.example.clash-guard|com.$USER.clash-guard|g" \
  com.example.clash-guard.plist > ~/Library/LaunchAgents/com.$USER.clash-guard.plist
chmod 600 ~/Library/LaunchAgents/com.$USER.clash-guard.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.$USER.clash-guard.plist
```

LaunchAgent 已负责每分钟调度。正常安装不需要 `clash-guard-loop.sh`；循环壳只用于不使用 launchd 的兼容场景。

卸载：

```sh
launchctl bootout gui/$(id -u)/com.$USER.clash-guard
```

## 可选环境变量

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `CLASH_GUARD_SOCKET` | `/tmp/verge/verge-mihomo.sock` | Unix socket 路径 |
| `CLASH_GUARD_SELECTOR` | `主代理` | 被守护的 Selector |
| `CLASH_GUARD_FALLBACK` | `自动选择` | URLTest 兜底组 |
| `CLASH_GUARD_PROXY` | `http://127.0.0.1:7897` | 吞吐测试使用的本地 HTTP 代理入口 |

LaunchAgent 中可通过 `EnvironmentVariables` 字典配置这些值。

## 测试

```sh
PYTHONPYCACHEPREFIX="$PWD/.pycache" /usr/bin/python3 -m unittest discover -s tests -v
/bin/bash -n clash-guard-loop.sh
plutil -lint com.example.clash-guard.plist
```

## 设计参考

本项目吸收了 [mihomo-smart-controller](https://github.com/AlexWhite1111/mihomo-smart-controller) 的稳定优先和故障分类思路，以及 [clash-switch](https://github.com/1deaaa/clash-switch) 的小型本地控制器经验；本实现针对 macOS LaunchAgent、Unix socket、手动选择保护和低流量吞吐验证重新设计。

## License

MIT
