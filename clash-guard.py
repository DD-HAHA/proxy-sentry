#!/usr/bin/env python3
"""Fail-safe health guard for a mihomo selector on macOS."""

import concurrent.futures as cf
import errno
import fcntl
import http.client
import json
import math
import os
import pwd
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import urllib.parse
from collections import deque
from datetime import datetime
from pathlib import Path


SOCK = os.environ.get("CLASH_GUARD_SOCKET", "/tmp/verge/verge-mihomo.sock")
HOST = "localhost"
SELECTOR = os.environ.get("CLASH_GUARD_SELECTOR", "主代理")
FALLBACK = os.environ.get("CLASH_GUARD_FALLBACK", "自动选择")
TEST_URLS = (
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
)
PROBE_TIMEOUT_MS = 3000
API_TIMEOUT = 6
MAX_API_BODY = 4 * 1024 * 1024
FAIL_LIMIT = 2
PROBE_WORKERS = 10
RETRY_COOLDOWN = 2 * 60
MAX_RECOVERY_BACKOFF = 30 * 60
OUTAGE_NOTIFY_INTERVAL = 30 * 60
MIN_SWITCH_INTERVAL = 60
MAX_VALIDATION_CANDIDATES = 3
MAX_ACTIVE_QUARANTINE = 3
QUARANTINE_TTL = 10 * 60  # 2026-09-22 调整：原 30min。实测被隔离节点可能在 5 分钟内自愈为全场最优，30min 会让可用节点闲置过久；10min 起步 + strikes 指数退避（10/20/40min…上限 4h）仍能拦住持续失败的坏节点
QUARANTINE_TTL_MAX = 4 * 60 * 60
QUARANTINE_FORGET_AFTER = 24 * 60 * 60
SPEED_PROXY = os.environ.get("CLASH_GUARD_PROXY", "http://127.0.0.1:7897")
SPEED_BYTES = 1024 * 1024
MIN_SPEED_BPS = 512 * 1024
BORDERLINE_SPEED_BPS = 300 * 1024
SPEED_CONNECT_TIMEOUT = 4
SPEED_MAX_TIME = 10
SPEED_URL = f"https://speed.cloudflare.com/__down?bytes={SPEED_BYTES}"
DIRECT_TESTS = (
    ("https://www.apple.com/library/test/success.html", "200"),
    ("https://cp.cloudflare.com/generate_204", "204"),
)
LOG_KEEP = 500

USER_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
WORK_DIR = USER_HOME / ".workbuddy"
STATE_FILE = WORK_DIR / "clash-guard.state"
LOG_FILE = WORK_DIR / "clash-guard.log"
LOCK_FILE = WORK_DIR / "clash-guard.lock"

GROUP_TYPES = {
    "Selector",
    "URLTest",
    "Fallback",
    "LoadBalance",
    "Relay",
    "Smart",
    "Direct",
    "Reject",
    "Compatible",
    "Pass",
    "RejectDrop",
    "Dns",
}


class GuardError(RuntimeError):
    pass


class SelectionChanged(GuardError):
    pass


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, timeout=API_TIMEOUT):
        super().__init__(HOST, timeout=timeout)
        self._sock_path = SOCK

    def connect(self):
        info = os.stat(self._sock_path, follow_symlinks=False)
        if not stat.S_ISSOCK(info.st_mode):
            raise GuardError(f"控制接口不是 Unix socket: {self._sock_path}")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._sock_path)
        self.sock = sock


def _ensure_work_dir():
    WORK_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = os.stat(str(WORK_DIR), follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise OSError(errno.EPERM, "工作目录必须是当前用户拥有的真实目录", str(WORK_DIR))
    if stat.S_IMODE(info.st_mode) != 0o700:
        os.chmod(str(WORK_DIR), 0o700)


def _api_request(method, path, payload=None):
    headers = {}
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    conn = UnixHTTPConnection()
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        raw = response.read(MAX_API_BODY + 1)
        if len(raw) > MAX_API_BODY:
            raise GuardError("控制接口响应过大")
        if not 200 <= response.status < 300:
            detail = raw[:200].decode("utf-8", errors="replace")
            raise GuardError(f"控制接口返回 HTTP {response.status}: {detail}")
    finally:
        conn.close()

    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise GuardError("控制接口返回了无效 JSON") from exc
    return data


def api_get(path):
    return _api_request("GET", path)


def api_put_selector(name):
    path = "/proxies/" + urllib.parse.quote(SELECTOR, safe="")
    _api_request("PUT", path, {"name": name})


def _clean(value, limit=240):
    text = str(value)
    pieces = []
    for char in text[:limit]:
        if char == "\n":
            pieces.append("\\n")
        elif char == "\r":
            pieces.append("\\r")
        elif char == "\t":
            pieces.append("\\t")
        elif unicodedata.category(char).startswith("C"):
            pieces.append(f"\\u{ord(char):04x}")
        else:
            pieces.append(char)
    if len(text) > limit:
        pieces.append("…")
    return "".join(pieces)


def _atomic_write(path, text):
    _ensure_work_dir()
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(WORK_DIR))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as file_obj:
            file_obj.write(text)
            file_obj.flush()
            os.fsync(file_obj.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def log(message):
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} | {_clean(message)}\n"
    try:
        _ensure_work_dir()
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(LOG_FILE), flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(errno.EPERM, "日志路径不是普通文件", str(LOG_FILE))
            os.fchmod(fd, 0o600)
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)

        lines = deque(maxlen=LOG_KEEP)
        count = 0
        with LOG_FILE.open("r", encoding="utf-8", errors="replace") as file_obj:
            for count, old_line in enumerate(file_obj, start=1):
                lines.append(old_line)
        if count > LOG_KEEP:
            _atomic_write(LOG_FILE, "".join(lines))
    except OSError:
        pass


def _default_state():
    return {
        "node": "",
        "fails": 0,
        "last": "HEALTHY",
        "phase": "HEALTHY",
        "last_switch": 0.0,
        "last_attempt": 0.0,
        "next_retry_at": 0.0,
        "recovery_backoff": float(RETRY_COOLDOWN),
        "last_outage_notice": 0.0,
        "controller_selected": "",
        "manual_accepted": "",
        "pending_target": "",
        "pending_from": "",
        "fallback_owned": False,
        "quarantine": {},
    }


def read_state():
    state = _default_state()
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(STATE_FILE), flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(errno.EPERM, "状态路径不是普通文件", str(STATE_FILE))
            raw = os.read(fd, 65537)
        finally:
            os.close(fd)
        if len(raw) > 65536:
            raise ValueError("state file too large")
        loaded = json.loads(raw.decode("utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError("state is not an object")
        for key in (
            "node",
            "last",
            "phase",
            "controller_selected",
            "manual_accepted",
            "pending_target",
            "pending_from",
        ):
            if isinstance(loaded.get(key), str):
                state[key] = loaded[key][:512]
        fails = loaded.get("fails")
        if isinstance(fails, int) and not isinstance(fails, bool):
            state["fails"] = min(max(fails, 0), FAIL_LIMIT)
        for key in (
            "last_switch",
            "last_attempt",
            "next_retry_at",
            "recovery_backoff",
            "last_outage_notice",
        ):
            value = loaded.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                value = float(value)
                if math.isfinite(value) and value >= 0:
                    state[key] = value
        if isinstance(loaded.get("fallback_owned"), bool):
            state["fallback_owned"] = loaded["fallback_owned"]

        quarantine = loaded.get("quarantine")
        if isinstance(quarantine, dict):
            cleaned = {}
            for name, entry in list(quarantine.items())[:100]:
                if not isinstance(name, str) or not isinstance(entry, dict):
                    continue
                until = entry.get("until")
                last_failure = entry.get("last_failure")
                strikes = entry.get("strikes")
                if not isinstance(until, (int, float)) or isinstance(until, bool):
                    continue
                if not isinstance(last_failure, (int, float)) or isinstance(last_failure, bool):
                    continue
                if not isinstance(strikes, int) or isinstance(strikes, bool):
                    continue
                until = float(until)
                last_failure = float(last_failure)
                if not math.isfinite(until) or not math.isfinite(last_failure):
                    continue
                last_speed = entry.get("last_speed_bps", 0)
                if (
                    not isinstance(last_speed, (int, float))
                    or isinstance(last_speed, bool)
                    or not math.isfinite(float(last_speed))
                ):
                    last_speed = 0
                cleaned[name] = {
                    "until": max(0.0, until),
                    "last_failure": max(0.0, last_failure),
                    "strikes": min(max(strikes, 1), 16),
                    "reason": str(entry.get("reason", "UNKNOWN"))[:40],
                    "last_speed_bps": max(0.0, float(last_speed)),
                }
            state["quarantine"] = cleaned
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        pass
    return state


def save_state(state):
    try:
        _atomic_write(STATE_FILE, json.dumps(state, ensure_ascii=False) + "\n")
    except OSError:
        pass


def get_snapshot():
    data = api_get("/proxies")
    if not isinstance(data, dict) or not isinstance(data.get("proxies"), dict):
        raise GuardError("控制接口缺少 proxies 对象")
    proxies = data["proxies"]
    selector = proxies.get(SELECTOR)
    if not isinstance(selector, dict):
        raise GuardError(f"找不到组「{SELECTOR}」")
    if selector.get("type") != "Selector":
        raise GuardError(f"「{SELECTOR}」不是 Selector 组")
    current = selector.get("now")
    if not isinstance(current, str) or not current:
        raise GuardError(f"「{SELECTOR}」没有有效的当前选择")
    return proxies, selector, current


def _delay_path(name, test_url, expected="204"):
    encoded_name = urllib.parse.quote(name, safe="")
    query = urllib.parse.urlencode(
        {"timeout": PROBE_TIMEOUT_MS, "url": test_url, "expected": expected}
    )
    return f"/proxies/{encoded_name}/delay?{query}"


def probe(name):
    for test_url in TEST_URLS:
        try:
            data = api_get(_delay_path(name, test_url))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        delay = data.get("delay")
        if isinstance(delay, int) and not isinstance(delay, bool) and delay > 0:
            return delay
    return None


def local_network_status(proxies):
    """Return True/False for direct Internet, or None when DIRECT is unavailable."""
    direct_names = [
        name
        for name, proxy in proxies.items()
        if isinstance(name, str)
        and isinstance(proxy, dict)
        and proxy.get("type") == "Direct"
    ]
    if not direct_names:
        return None
    for name in direct_names:
        for test_url, expected in DIRECT_TESTS:
            try:
                data = api_get(_delay_path(name, test_url, expected=expected))
            except Exception:
                continue
            delay = data.get("delay") if isinstance(data, dict) else None
            if isinstance(delay, int) and not isinstance(delay, bool) and delay > 0:
                return True
    return False


def _is_group(proxy):
    if not isinstance(proxy, dict):
        return True
    return proxy.get("type") in GROUP_TYPES or isinstance(proxy.get("all"), list)


def probe_candidates(proxies, selector, current, excluded=None):
    members = selector.get("all")
    if not isinstance(members, list):
        raise GuardError(f"「{SELECTOR}」缺少候选列表")
    excluded = set(excluded or ())
    candidates = []
    for name in members:
        if not isinstance(name, str) or name == current or name in excluded:
            continue
        proxy = proxies.get(name)
        if proxy is not None and not _is_group(proxy):
            candidates.append(name)

    results = []
    if not candidates:
        return results
    with cf.ThreadPoolExecutor(max_workers=min(PROBE_WORKERS, len(candidates))) as executor:
        future_names = {executor.submit(probe, name): name for name in candidates}
        for future in cf.as_completed(future_names):
            name = future_names[future]
            try:
                delay = future.result()
            except Exception:
                delay = None
            if delay is not None:
                results.append((delay, name))
    results.sort(key=lambda item: (item[0], item[1]))
    return results


def _active_quarantine(state, now=None):
    now = time.time() if now is None else now
    quarantine = state.setdefault("quarantine", {})
    active = set()
    for name, entry in list(quarantine.items()):
        last_failure = float(entry.get("last_failure", 0) or 0)
        if last_failure and now - last_failure > QUARANTINE_FORGET_AFTER:
            del quarantine[name]
            continue
        if float(entry.get("until", 0) or 0) > now:
            active.add(name)
    return active


def _quarantine_node(state, name, result, now=None):
    now = time.time() if now is None else now
    quarantine = state.setdefault("quarantine", {})
    previous = quarantine.get(name, {})
    last_failure = float(previous.get("last_failure", 0) or 0)
    previous_strikes = int(previous.get("strikes", 0) or 0)
    if not last_failure or now - last_failure > QUARANTINE_FORGET_AFTER:
        previous_strikes = 0
    strikes = min(previous_strikes + 1, 16)
    ttl = min(QUARANTINE_TTL * (2 ** (strikes - 1)), QUARANTINE_TTL_MAX)
    quarantine[name] = {
        "until": now + ttl,
        "last_failure": now,
        "strikes": strikes,
        "reason": result.get("status", "UNKNOWN"),
        "last_speed_bps": float(result.get("speed_bps", 0) or 0),
    }
    return ttl


def _clear_quarantine(state, name):
    state.setdefault("quarantine", {}).pop(name, None)


def speed_test():
    """Download exactly 1 MiB through the managed proxy and classify the result."""
    command = [
        "/usr/bin/curl",
        "-q",
        "--silent",
        "--show-error",
        "--fail",
        "--output",
        "/dev/null",
        "--connect-timeout",
        str(SPEED_CONNECT_TIMEOUT),
        "--max-time",
        str(SPEED_MAX_TIME),
        "--proxy",
        SPEED_PROXY,
        "--write-out",
        "%{http_code}\t%{size_download}\t%{speed_download}",
        SPEED_URL,
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SPEED_MAX_TIME + 2,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "TIMEOUT_PARTIAL",
            "http_code": 0,
            "bytes": 0,
            "speed_bps": 0.0,
            "detail": "curl 子进程超时",
        }
    except OSError as exc:
        return {
            "status": "PROXY_ERROR",
            "http_code": 0,
            "bytes": 0,
            "speed_bps": 0.0,
            "detail": str(exc),
        }

    http_code, downloaded, speed = 0, 0, 0.0
    fields = completed.stdout.strip().split("\t")
    if len(fields) == 3:
        try:
            http_code = int(fields[0])
            downloaded = int(float(fields[1]))
            speed = float(fields[2])
            if not math.isfinite(speed) or speed < 0:
                speed = 0.0
        except (TypeError, ValueError):
            http_code, downloaded, speed = 0, 0, 0.0

    detail = completed.stderr.strip()[:200]
    if completed.returncode == 28:
        status = "TIMEOUT_PARTIAL"
    elif completed.returncode == 22 or http_code >= 400:
        status = "HTTP_ERROR"
    elif completed.returncode != 0:
        status = "PROXY_ERROR"
    elif downloaded < SPEED_BYTES:
        status = "INCOMPLETE"
    elif speed < MIN_SPEED_BPS:
        status = "LOW_THROUGHPUT"
    else:
        status = "PASS"
    return {
        "status": status,
        "http_code": http_code,
        "bytes": max(downloaded, 0),
        "speed_bps": speed,
        "detail": detail,
    }


def _speed_summary(result):
    mib = result.get("bytes", 0) / 1048576
    speed_mib = result.get("speed_bps", 0) / 1048576
    summary = f"{result.get('status')}，收到 {mib:.2f} MiB，平均 {speed_mib:.2f} MiB/s"
    if result.get("http_code"):
        summary += f"，HTTP {result['http_code']}"
    if result.get("detail"):
        summary += f"，{_clean(result['detail'])}"
    return summary


def _notify_outage(state, now=None):
    now = time.time() if now is None else now
    last_notice = float(state.get("last_outage_notice", 0) or 0)
    if now - last_notice < OUTAGE_NOTIFY_INTERVAL:
        return False
    state["last_outage_notice"] = now
    save_state(state)
    script = (
        'display notification "具体节点与 URLTest 兜底均不可用，请检查网络或机场状态。" '
        'with title "clash-guard：网络中断"'
    )
    try:
        completed = subprocess.run(
            ["/usr/bin/osascript", "-e", script],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log(f"OUTAGE 通知发送失败: {exc}")
        return False
    if completed.returncode != 0:
        log(f"OUTAGE 通知发送失败: {_clean(completed.stderr)}")
        return False
    return True


def _fallback_is_valid(proxies, selector):
    members = selector.get("all")
    fallback = proxies.get(FALLBACK)
    return (
        isinstance(members, list)
        and FALLBACK in members
        and isinstance(fallback, dict)
        and fallback.get("type") == "URLTest"
    )


def switch_selector(expected, target):
    _, selector, current = get_snapshot()
    if current != expected:
        raise SelectionChanged(
            f"选择已由用户或其他程序改为「{_clean(current)}」，取消自动切换"
        )
    members = selector.get("all")
    if not isinstance(members, list) or target not in members:
        raise GuardError(f"目标「{_clean(target)}」不是「{SELECTOR}」的成员")
    api_put_selector(target)
    _, _, selected = get_snapshot()
    if selected != target:
        raise GuardError(
            f"切换验证失败：期望「{_clean(target)}」，实际为「{_clean(selected)}」"
        )


def _set_healthy(state, node, last="HEALTHY"):
    state.update(
        {
            "node": node,
            "fails": 0,
            "last": last,
            "phase": "HEALTHY",
            "next_retry_at": 0.0,
            "recovery_backoff": float(RETRY_COOLDOWN),
            "pending_target": "",
            "pending_from": "",
            "fallback_owned": False,
        }
    )
    save_state(state)


def _schedule_retry(state, phase, now=None, initial=None):
    now = time.time() if now is None else now
    backoff = float(state.get("recovery_backoff", RETRY_COOLDOWN) or RETRY_COOLDOWN)
    if initial is not None:
        backoff = float(initial)
    backoff = min(max(backoff, 60.0), float(MAX_RECOVERY_BACKOFF))
    state.update(
        {
            "phase": phase,
            "last": phase,
            "next_retry_at": now + backoff,
            "recovery_backoff": min(backoff * 2, float(MAX_RECOVERY_BACKOFF)),
        }
    )
    save_state(state)
    return int(backoff)


def _accept_manual_selection(state, current, is_group):
    phase = "MANUAL_GROUP" if is_group else "MANUAL_PROBATION"
    state.update(
        {
            "node": current,
            "fails": 0,
            "last": phase,
            "phase": phase,
            "manual_accepted": current,
            "controller_selected": "",
            "pending_target": "",
            "pending_from": "",
            "fallback_owned": False,
            "next_retry_at": 0.0,
        }
    )
    save_state(state)


def _finalize_fallback(state):
    proxies, _, current = get_snapshot()
    if current != FALLBACK:
        raise SelectionChanged(f"兜底切换后当前选择变为「{_clean(current)}」")
    now = time.time()
    fallback = proxies.get(FALLBACK, {})
    phase = "OUTAGE" if fallback.get("alive") is False else "URLTEST_FALLBACK"
    state.update(
        {
            "node": FALLBACK,
            "fails": 0,
            "last": phase,
            "phase": phase,
            "last_switch": now,
            "controller_selected": FALLBACK,
            "manual_accepted": "",
            "pending_target": "",
            "pending_from": "",
            "fallback_owned": True,
            "recovery_backoff": float(RETRY_COOLDOWN),
            "next_retry_at": now + RETRY_COOLDOWN,
        }
    )
    save_state(state)
    if phase == "OUTAGE":
        log(f"已切回「{_clean(FALLBACK)}」，但兜底组当前也无活节点，进入退避恢复")
        _notify_outage(state)
    else:
        log(f"已切回「{_clean(FALLBACK)}」止血；后台将继续寻找可验证的具体节点")


def _switch_to_fallback(state, expected, reason):
    proxies, selector, current = get_snapshot()
    if current != expected:
        raise SelectionChanged(f"选择已变为「{_clean(current)}」，取消兜底切换")
    if not _fallback_is_valid(proxies, selector):
        delay = _schedule_retry(state, "OUTAGE")
        log(f"{reason}；URLTest 兜底不可用，{delay} 秒后重试")
        _notify_outage(state)
        return
    state.update(
        {
            "phase": "URLTEST_FALLBACK",
            "last": "SWITCHING_FALLBACK",
            "pending_target": FALLBACK,
            "pending_from": expected,
            "last_attempt": time.time(),
        }
    )
    save_state(state)
    log(f"{reason}；准备切回「{_clean(FALLBACK)}」")
    switch_selector(expected, FALLBACK)
    _finalize_fallback(state)


def _validate_selected_candidate(state, target, index, total):
    log(f"候选 {index}/{total} 已临时切换至 {_clean(target)}，开始 1 MiB 吞吐验证")
    time.sleep(0.5)
    result = speed_test()
    log(f"吞吐验证 {_clean(target)}：{_speed_summary(result)}")

    if (
        result["status"] == "LOW_THROUGHPUT"
        and result["speed_bps"] >= BORDERLINE_SPEED_BPS
    ):
        log(f"{_clean(target)} 处于临界区间，追加一次 1 MiB 复检")
        result = speed_test()
        log(f"吞吐复检 {_clean(target)}：{_speed_summary(result)}")

    latest_proxies, _, latest_current = get_snapshot()
    if latest_current != target:
        raise SelectionChanged(
            f"吞吐验证期间选择已变为「{_clean(latest_current)}」，取消自动流程"
        )

    if result["status"] == "PASS":
        now = time.time()
        _clear_quarantine(state, target)
        state.update(
            {
                "node": target,
                "fails": 0,
                "last": "HEALTHY",
                "phase": "HEALTHY",
                "last_switch": now,
                "controller_selected": target,
                "manual_accepted": "",
                "pending_target": "",
                "pending_from": "",
                "fallback_owned": False,
                "next_retry_at": 0.0,
                "recovery_backoff": float(RETRY_COOLDOWN),
            }
        )
        save_state(state)
        log(
            f"正式采用 主代理 → {_clean(target)}"
            f"（1 MiB，{result['speed_bps'] / 1048576:.2f} MiB/s）"
        )
        return "ACCEPTED"

    local_status = local_network_status(latest_proxies)
    if local_status is False:
        state.update({"node": target, "last": "LOCAL_OFFLINE", "phase": "LOCAL_OFFLINE"})
        delay = _schedule_retry(state, "LOCAL_OFFLINE", initial=60)
        log(f"吞吐验证失败后发现本机直连离线；不隔离节点，{delay} 秒后复检")
        return "LOCAL_OFFLINE"

    ttl = _quarantine_node(state, target, result)
    state.update(
        {
            "node": target,
            "last": "QUARANTINED",
            "phase": "CANDIDATE_SCAN",
            "pending_target": "",
            "pending_from": "",
        }
    )
    save_state(state)
    log(f"{_clean(target)} 已隔离 {ttl // 60} 分钟（{result['status']}）")
    return "REJECTED"


def _run_candidate_validation(state, expected, resume_target=None):
    proxies, selector, current = get_snapshot()
    if current != expected:
        raise SelectionChanged(f"选择已变为「{_clean(current)}」，取消候选验证")

    if resume_target:
        outcome = _validate_selected_candidate(state, resume_target, 1, MAX_VALIDATION_CANDIDATES)
        if outcome in ("ACCEPTED", "LOCAL_OFFLINE"):
            return
        expected = resume_target
        proxies, selector, current = get_snapshot()

    now = time.time()
    excluded = _active_quarantine(state, now)
    save_state(state)
    if len(excluded) >= MAX_ACTIVE_QUARANTINE:
        _switch_to_fallback(state, expected, "活跃隔离节点已达到 3 个")
        return

    results = probe_candidates(proxies, selector, expected, excluded=excluded)
    top = results[:MAX_VALIDATION_CANDIDATES]
    if not top:
        _switch_to_fallback(state, expected, "没有可用的具体候选节点")
        return

    summary = ", ".join(f"{_clean(name)}({delay}ms)" for delay, name in top)
    log("待验证候选: " + summary)
    total = len(top)
    for index, (delay, target) in enumerate(top, start=1):
        if len(_active_quarantine(state)) >= MAX_ACTIVE_QUARANTINE:
            break
        state.update(
            {
                "phase": "VALIDATING",
                "last": "SWITCHING_CANDIDATE",
                "pending_target": target,
                "pending_from": expected,
                "last_attempt": time.time(),
            }
        )
        save_state(state)
        log(
            f"候选 {index}/{total}：准备从 {_clean(expected)} 临时切换到"
            f" {_clean(target)}（延迟 {delay}ms）"
        )
        switch_selector(expected, target)
        outcome = _validate_selected_candidate(state, target, index, total)
        if outcome in ("ACCEPTED", "LOCAL_OFFLINE"):
            return
        expected = target

    _switch_to_fallback(state, expected, "延迟前 3 名均未通过最低吞吐验证")


def _handle_owned_fallback(state, proxies, selector):
    now = time.time()
    if now < state.get("next_retry_at", 0):
        return 0

    local_status = local_network_status(proxies)
    if local_status is False:
        delay = _schedule_retry(state, "LOCAL_OFFLINE")
        log(f"兜底恢复巡检发现本机仍离线；不隔离节点，{delay} 秒后复检")
        return 0

    excluded = _active_quarantine(state, now)
    if len(excluded) >= MAX_ACTIVE_QUARANTINE:
        active_until = [
            float(state["quarantine"][name]["until"])
            for name in excluded
            if name in state["quarantine"]
        ]
        delay = _schedule_retry(state, "URLTEST_FALLBACK")
        if active_until:
            state["next_retry_at"] = min(state["next_retry_at"], min(active_until))
            save_state(state)
        log(f"仍有 3 个活跃隔离节点；保持 URLTest 兜底，约 {delay} 秒后复检")
        return 0

    results = probe_candidates(proxies, selector, FALLBACK, excluded=excluded)
    if not results:
        delay = _schedule_retry(state, "OUTAGE")
        log(f"兜底恢复巡检仍无具体节点可用；{delay} 秒后重试")
        _notify_outage(state)
        return 0

    state.update({"phase": "CANDIDATE_SCAN", "last": "RECOVERY_SCAN"})
    save_state(state)
    _run_candidate_validation(state, FALLBACK)
    return 0


def main_once():
    try:
        proxies, selector, current = get_snapshot()
    except Exception as exc:
        log(f"读取控制接口失败: {exc}，跳过")
        return 0

    state = read_state()
    _active_quarantine(state)

    pending_target = state.get("pending_target")
    pending_from = state.get("pending_from")
    if pending_target:
        if current == pending_target == FALLBACK:
            _finalize_fallback(state)
            return 0
        if current == pending_target and not _is_group(proxies.get(current)):
            local_status = local_network_status(proxies)
            if local_status is False:
                delay = _schedule_retry(state, "LOCAL_OFFLINE", initial=60)
                log(f"恢复未完成的候选验证时发现本机离线；{delay} 秒后重试")
                return 0
            try:
                _run_candidate_validation(state, current, resume_target=current)
            except SelectionChanged as exc:
                log(str(exc))
            except Exception as exc:
                log(f"恢复候选验证失败: {exc}")
            return 0
        if current == pending_from:
            state.update({"pending_target": "", "pending_from": ""})
            save_state(state)
        else:
            log(f"检测到外部改选 主代理 → {_clean(current)}，取消未完成的自动切换")
            _accept_manual_selection(state, current, _is_group(proxies.get(current)))

    if (
        current == FALLBACK
        and state.get("fallback_owned")
        and state.get("controller_selected") == FALLBACK
    ):
        try:
            return _handle_owned_fallback(state, proxies, selector)
        except SelectionChanged as exc:
            log(str(exc))
            return 0
        except Exception as exc:
            delay = _schedule_retry(state, "OUTAGE")
            log(f"兜底恢复巡检失败: {exc}；{delay} 秒后重试")
            return 0

    expected = (
        state.get("controller_selected")
        or state.get("manual_accepted")
        or state.get("node")
    )
    if not expected:
        state["manual_accepted"] = current
        state["node"] = current
        save_state(state)
    elif current != expected:
        log(f"检测到用户或其他程序改选 主代理 → {_clean(current)}")
        _accept_manual_selection(state, current, _is_group(proxies.get(current)))

    current_proxy = proxies.get(current)
    if _is_group(current_proxy):
        if state.get("phase") != "MANUAL_GROUP" or state.get("node") != current:
            log(f"当前选择为策略组「{_clean(current)}」，尊重手动选择，不干预")
        _accept_manual_selection(state, current, True)
        return 0

    delay = probe(current)
    if delay is not None:
        if state.get("node") == current and state.get("phase") not in (
            "HEALTHY",
            "MANUAL_PROBATION",
        ):
            log(f"恢复：{_clean(current)} 延迟 {delay}ms，失败计数已复位")
        last = (
            "MANUAL_ACCEPTED"
            if state.get("manual_accepted") == current
            and not state.get("controller_selected")
            else "HEALTHY"
        )
        _set_healthy(state, current, last)
        return 0

    previous_phase = state.get("phase")
    previous_retry_at = state.get("next_retry_at", 0)
    previous_fails = state.get("fails", 0) if state.get("node") == current else 0
    fails = min(previous_fails + 1, FAIL_LIMIT)
    state.update({"node": current, "fails": fails, "last": "SUSPECT", "phase": "SUSPECT"})
    if fails < FAIL_LIMIT:
        log(f"探活失败 {fails}/{FAIL_LIMIT}：{_clean(current)}")
        save_state(state)
        return 0

    now = time.time()
    if previous_phase == "LOCAL_OFFLINE" and now < previous_retry_at:
        state.update(
            {
                "last": "LOCAL_OFFLINE",
                "phase": "LOCAL_OFFLINE",
                "next_retry_at": previous_retry_at,
            }
        )
        save_state(state)
        return 0
    if now - state.get("last_attempt", 0) < MIN_SWITCH_INTERVAL:
        state["next_retry_at"] = state.get("last_attempt", 0) + MIN_SWITCH_INTERVAL
        save_state(state)
        return 0

    log(f"确认 {_clean(current)} 连续 {fails} 次探活失败，开始故障判断")
    state.update({"last": "LOCAL_CHECK", "phase": "LOCAL_CHECK", "last_attempt": now})
    save_state(state)

    try:
        fresh_proxies, _, fresh_current = get_snapshot()
        if fresh_current != current:
            raise SelectionChanged(f"选择已变为「{_clean(fresh_current)}」，取消本轮自动切换")
        recovered_delay = probe(current)
        if recovered_delay is not None:
            log(f"切换前复检已恢复：{_clean(current)} 延迟 {recovered_delay}ms")
            _set_healthy(state, current)
            return 0

        local_status = local_network_status(fresh_proxies)
        if local_status is False:
            delay = _schedule_retry(state, "LOCAL_OFFLINE", initial=60)
            log(f"本机直连不可用；禁止隔离节点，{delay} 秒后复检")
            return 0
        if local_status is None:
            log("未找到可用于直连检查的 DIRECT 出站，继续保守候选扫描")

        state.update({"phase": "CANDIDATE_SCAN", "last": "CANDIDATE_SCAN"})
        save_state(state)
        _run_candidate_validation(state, current)
    except SelectionChanged as exc:
        log(str(exc))
        state["last"] = "USER_CHANGED"
        save_state(state)
    except Exception as exc:
        delay = _schedule_retry(state, "OUTAGE")
        log(f"自动恢复流程出错: {exc}；{delay} 秒后重试")
    return 0


def acquire_process_lock():
    _ensure_work_dir()
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(LOCK_FILE), flags, 0o600)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError(errno.EPERM, "进程锁不是普通文件", str(LOCK_FILE))
    os.fchmod(fd, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        return None
    os.ftruncate(fd, 0)
    os.write(fd, f"{os.getpid()}\n".encode("ascii"))
    return fd


def main():
    try:
        lock_fd = acquire_process_lock()
    except OSError as exc:
        print(f"clash-guard: 无法创建进程锁: {exc}", file=sys.stderr)
        return 1
    if lock_fd is None:
        return 0
    try:
        return main_once()
    except Exception as exc:
        log(f"未处理异常: {type(exc).__name__}: {exc}")
        return 1
    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    raise SystemExit(main())
