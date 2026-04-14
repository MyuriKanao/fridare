"""Frida session manager — handles device/process/session lifecycle + pcap capture."""

from __future__ import annotations

import os
import platform
import random
import struct
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

import frida


@dataclass
class SessionState:
    device: frida.core.Device | None = None
    session: frida.core.Session | None = None
    script: frida.core.Script | None = None
    scripts: list[frida.core.Script] = field(default_factory=list)
    _max_scripts: int = 50
    pid: int | None = None
    package: str | None = None
    messages: list[dict] = field(default_factory=list)
    pcap_file: Any = None
    pcap_path: str | None = None
    _max_messages: int = 500

    def add_message(self, msg: dict, data: bytes | None = None):
        entry = {"message": msg}
        if data:
            entry["data_len"] = len(data)
            entry["data_hex"] = data[:256].hex()
            entry["data_raw"] = data
        self.messages.append(entry)
        # Write to pcap if capturing
        if self.pcap_file and data:
            payload = msg.get("payload", {}) if msg.get("type") == "send" else {}
            if isinstance(payload, dict) and payload.get("function") in (
                "SSL_read", "SSL_write", "HTTP_send", "HTTP_recv",
            ):
                _write_pcap_packet(self.pcap_file, payload, data)
        if len(self.messages) > self._max_messages:
            self.messages = self.messages[-self._max_messages:]

    @property
    def is_alive(self) -> bool:
        """Check if session is still valid."""
        if not self.session:
            return False
        try:
            return not self.session.is_detached
        except Exception:
            return False

    def _unload_all_scripts(self):
        for s in self.scripts:
            try:
                s.unload()
            except Exception:
                pass
        self.scripts.clear()
        self.script = None

    def clear(self):
        self._unload_all_scripts()
        if self.session:
            try:
                self.session.detach()
            except Exception:
                pass
        self.stop_pcap()
        self.session = None
        self.pid = None
        self.package = None
        self.messages.clear()

    def start_pcap(self, path: str):
        self.stop_pcap()
        self.pcap_path = path
        self.pcap_file = open(path, "wb", 0)
        # PCAP global header
        for fmt, val in (
            ("=I", 0xa1b2c3d4), ("=H", 2), ("=H", 4),
            ("=i", 0), ("=I", 0), ("=I", 65535), ("=I", 228),  # LINKTYPE_IPV4
        ):
            self.pcap_file.write(struct.pack(fmt, val))

    def stop_pcap(self):
        if self.pcap_file:
            try:
                self.pcap_file.flush()
                self.pcap_file.close()
            except Exception:
                pass
            self.pcap_file = None
            self.pcap_path = None


# ── PCAP writer ────────────────────────────────────────

_ssl_sessions: dict[str, tuple[int, int]] = {}


def _ip_to_int(ip: str) -> int:
    if not ip or ip == "?" or ":" in ip:
        return 0
    try:
        parts = ip.split(".")
        return sum(int(p) << (8 * i) for i, p in enumerate(parts)) & 0xFFFFFFFF
    except Exception:
        return 0


def _write_pcap_packet(f, payload: dict, data: bytes):
    t = time.time()
    func = payload.get("function", "")
    src_addr = _ip_to_int(str(payload.get("src_addr", "0")))
    src_port = int(payload.get("src_port", 0)) & 0xFFFF
    dst_addr = _ip_to_int(str(payload.get("dst_addr", "0")))
    dst_port = int(payload.get("dst_port", 0)) & 0xFFFF
    sid = str(payload.get("ssl_session_id", ""))

    if sid not in _ssl_sessions:
        _ssl_sessions[sid] = (random.randint(0, 0xFFFFFFFF), random.randint(0, 0xFFFFFFFF))

    client_sent, server_sent = _ssl_sessions[sid]
    if func in ("SSL_read", "HTTP_recv"):
        seq, ack = server_sent, client_sent
    else:
        seq, ack = client_sent, server_sent

    pkt_len = 40 + len(data)
    for fmt, val in (
        ("=I", int(t)), ("=I", int((t * 1e6) % 1e6)),
        ("=I", pkt_len), ("=i", pkt_len),
        (">B", 0x45), (">B", 0), (">H", pkt_len), (">H", 0),
        (">H", 0x4000), (">B", 0xFF), (">B", 6), (">H", 0),
        (">I", src_addr), (">I", dst_addr),
        (">H", src_port), (">H", dst_port),
        (">I", seq), (">I", ack),
        (">H", 0x5018), (">H", 0xFFFF), (">H", 0), (">H", 0),
    ):
        f.write(struct.pack(fmt, val))
    f.write(data)

    if func in ("SSL_read", "HTTP_recv"):
        server_sent += len(data)
    else:
        client_sent += len(data)
    _ssl_sessions[sid] = (client_sent, server_sent)


# ── Global singleton ───────────────────────────────────

_state = SessionState()


def get_state() -> SessionState:
    return _state


def _on_message(message: dict, data: bytes | None):
    _state.add_message(message, data)


# ── Device ──────────────────────────────────────────────

def list_devices() -> list[dict]:
    devices = []
    for d in frida.enumerate_devices():
        if d.type in ("usb", "remote", "local"):
            devices.append({"id": d.id, "name": d.name, "type": d.type})
    return devices


def get_device(device_id: str | None = None) -> frida.core.Device:
    if device_id:
        return frida.get_device(device_id, timeout=5)
    return frida.get_usb_device(timeout=5)


# ── Process ─────────────────────────────────────────────

def list_processes(device_id: str | None = None) -> list[dict]:
    dev = get_device(device_id)
    return [{"pid": p.pid, "name": p.name} for p in dev.enumerate_processes()]


# ── Attach / Spawn ──────────────────────────────────────

def attach(target: str | int, device_id: str | None = None) -> dict:
    _state.clear()
    dev = get_device(device_id)
    _state.device = dev

    if isinstance(target, int):
        pid = target
    else:
        pid = None
        for p in dev.enumerate_processes():
            if p.name == target or str(p.pid) == target:
                pid = p.pid
                _state.package = p.name
                break
        if pid is None:
            for p in dev.enumerate_processes():
                if target in p.name:
                    pid = p.pid
                    _state.package = p.name
                    break
        if pid is None:
            raise ValueError(f"Process not found: {target}")

    _state.session = dev.attach(pid)
    _state.pid = pid
    return {"pid": pid, "package": _state.package or str(pid)}


def spawn(package: str, device_id: str | None = None, wait_ms: int = 3000) -> dict:
    _state.clear()
    dev = get_device(device_id)
    _state.device = dev
    _state.package = package
    pid = dev.spawn([package])
    _state.session = dev.attach(pid)
    _state.pid = pid
    time.sleep(wait_ms / 1000)
    dev.resume(pid)
    return {"pid": pid, "package": package}


def detach() -> dict:
    pkg = _state.package
    _state.clear()
    return {"status": "detached", "package": pkg}


# ── Script execution ────────────────────────────────────

def exec_js(code: str, keep_previous: bool = False, wait: float = 0.2) -> Any:
    """Execute JavaScript in the target process.

    Args:
        code: Frida JavaScript to execute.
        keep_previous: If True, don't unload the previous script (avoids access violations
                       when previous hooks are still active). Default False for backwards compat.
        wait: Seconds to wait for synchronous messages before returning. Default 0.2.
    """
    if not _state.session:
        raise RuntimeError("Not attached. Call frida_attach() or frida_spawn() first.")
    if not _state.is_alive:
        raise RuntimeError("Session is dead (app crashed or detached). Re-attach needed.")

    if not keep_previous:
        _state._unload_all_scripts()
        _state.messages.clear()

    start_index = len(_state.messages)
    script = _state.session.create_script(code)
    script.on("message", _on_message)
    script.load()
    _state.script = script
    _state.scripts.append(script)
    # Evict oldest scripts when limit exceeded
    while len(_state.scripts) > _state._max_scripts:
        old = _state.scripts.pop(0)
        try:
            old.unload()
        except Exception:
            pass
    time.sleep(wait)
    new_messages = list(_state.messages[start_index:])
    return {"status": "ok", "messages": new_messages}


def rpc_call(method: str, args: list | None = None) -> Any:
    if not _state.script:
        raise RuntimeError("No script loaded.")
    args = args or []
    fn = getattr(_state.script.exports_sync, method, None)
    if fn is None:
        raise ValueError(f"RPC method not found: {method}")
    return fn(*args)


def load_script(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        code = f.read()
    return exec_js(code)


def get_messages(clear: bool = False) -> list[dict]:
    msgs = list(_state.messages)
    if clear:
        _state.messages.clear()
    return msgs


def status() -> dict:
    """Return current session state."""
    return {
        "attached": _state.session is not None,
        "alive": _state.is_alive,
        "pid": _state.pid,
        "package": _state.package,
        "scripts_loaded": len(_state.scripts),
        "messages_buffered": len(_state.messages),
        "pcap_active": _state.pcap_file is not None,
        "pcap_path": _state.pcap_path,
    }


# ── PCAP control ────────────────────────────────────────

def start_pcap(path: str) -> dict:
    _state.start_pcap(path)
    return {"status": "capturing", "path": path}


def stop_pcap() -> dict:
    path = _state.pcap_path
    _state.stop_pcap()
    return {"status": "stopped", "path": path}


# ── Frida server management ────────────────────────────

def _adb_shell(cmd: str) -> str:
    """Run adb shell command, cross-platform (Win/Linux/Mac)."""
    if platform.system() == "Windows":
        full = ["adb", "shell", f"su -c \"{cmd}\""]
    else:
        full = ["adb", "shell", f"su -c '{cmd}'"]
    env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
    r = subprocess.run(full, capture_output=True, text=True, timeout=10, env=env)
    return r.stdout.strip()


def restart_frida_server(
    server_path: str = "",
    device_id: str | None = None,
) -> dict:
    """Kill and restart frida-server on device.
    If server_path is empty, auto-detects by scanning /data/local/tmp/ for frida-server binaries."""

    if not server_path:
        # Auto-detect: find frida-server binary on device
        ls_out = _adb_shell("ls /data/local/tmp/")
        candidates = []
        for name in ls_out.split():
            name = name.strip()
            if name and ("frida" in name.lower() or name in (
                "rusda", "hluda", "server", "fs", "re.frida.server"
            )):
                candidates.append(name)
        # Also check by running process name
        if not candidates:
            ps_out = _adb_shell("ps -A | grep -i frida || ps -A | grep rusda || ps -A | grep hluda")
            for line in ps_out.split("\n"):
                parts = line.strip().split()
                if parts:
                    candidates.append(parts[-1])

        if not candidates:
            return {"status": "error", "error": "No frida-server found in /data/local/tmp/. Provide server_path."}

        server_name = candidates[0]
        server_path = f"/data/local/tmp/{server_name}"
    else:
        server_name = server_path.split("/")[-1]

    # Kill all known frida-server variants
    _adb_shell(f"killall -9 {server_name} 2>/dev/null")
    _adb_shell("killall -9 frida-server 2>/dev/null")
    time.sleep(1)

    _adb_shell(f"{server_path} -D &")
    time.sleep(2)

    try:
        dev = get_device(device_id)
        count = len(dev.enumerate_processes())
        return {"status": "ok", "server": server_path, "process_count": count}
    except Exception as e:
        return {"status": "error", "error": str(e)}
