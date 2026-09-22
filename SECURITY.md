# Security

## 本地信任边界

`clash-guard` 通过 mihomo Unix socket 执行读取和 Selector PUT。Unix socket 模式不依赖 mihomo `secret`；请确保 socket 及其父目录仅受当前用户或可信系统进程控制。

建议检查：

```sh
ls -ld /tmp/verge /tmp/verge/verge-mihomo.sock
```

不要以 root 运行本项目。LaunchAgent 应以登录用户身份启动，`~/.workbuddy`、状态、日志和脚本不应允许其他用户写入。

## 数据与网络

项目没有遥测、账号或上传接口。它会访问固定的 Google、Cloudflare、Apple 连通性地址；Cloudflare 还用于故障时的 1 MiB 吞吐验证。远端服务可观察普通请求元数据和出口 IP，但不会收到 mihomo 配置、节点名称、状态文件或日志。

## 报告问题

公开发布后，请使用仓库的 GitHub Security Advisory 私下报告可导致任意文件写入、命令执行、绕过手动选择保护或非预期 PUT 的问题。报告中请删除真实节点名、订阅地址、日志中的网络标识和个人路径。
