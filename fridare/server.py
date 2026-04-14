"""Fridare MCP Server — expose Frida operations as MCP tools."""

from __future__ import annotations

import json
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from fridare import session, builtins

mcp = FastMCP(
    "fridare",
    instructions=(
        "Fridare provides interactive Android reverse engineering through Frida. "
        "Typical workflow: frida_devices → frida_attach/frida_spawn → introspect/hook/capture → frida_detach. "
        "Sessions persist across tool calls — attach once, then run unlimited commands. "
        "Use frida_exec for custom JavaScript when built-in tools are insufficient."
    ),
)


def _error(e: Exception) -> dict:
    """Format an exception as a standardized error response."""
    return {"error": type(e).__name__, "message": str(e)}


# ── Device & Process ────────────────────────────────────


@mcp.tool()
def frida_devices() -> dict:
    """List connected Frida-compatible devices (USB, remote, local).

    Call this first to discover available devices before attaching to a process.
    """
    try:
        devices = session.list_devices()
        return {"count": len(devices), "devices": devices}
    except Exception as e:
        return _error(e)


@mcp.tool()
def frida_ps(
    device_id: Annotated[str, Field(description="Device ID to query. Empty string for default USB device.")] = "",
    filter: Annotated[str, Field(description="Filter processes by name substring (case-insensitive).")] = "",
) -> dict:
    """List running processes on a connected device. Optionally filter by name substring."""
    try:
        procs = session.list_processes(device_id or None)
        if filter:
            procs = [p for p in procs if filter.lower() in p["name"].lower()]
        return {"count": len(procs), "processes": procs}
    except Exception as e:
        return _error(e)


@mcp.tool()
def frida_restart_server(
    server_path: Annotated[str, Field(description="Path to frida-server binary on device. Empty to auto-detect.")] = "",
) -> dict:
    """Kill and restart frida-server on the Android device.

    Auto-detects the server binary in /data/local/tmp/ if path is not provided.
    """
    try:
        return session.restart_frida_server(server_path)
    except Exception as e:
        return _error(e)


# ── Session ─────────────────────────────────────────────


@mcp.tool()
def frida_attach(
    target: Annotated[str, Field(description="Process name, package name, or PID to attach to.")],
    device_id: Annotated[str, Field(description="Device ID. Empty string for default USB device.")] = "",
) -> dict:
    """Attach to a running process. Session persists across subsequent tool calls.

    Accepts process name (fuzzy match), exact package name, or numeric PID.
    """
    try:
        t: str | int = int(target) if target.isdigit() else target
        return session.attach(t, device_id or None)
    except Exception as e:
        return _error(e)


@mcp.tool()
def frida_spawn(
    package: Annotated[str, Field(description="Application package name to spawn (e.g. 'com.example.app').")],
    device_id: Annotated[str, Field(description="Device ID. Empty string for default USB device.")] = "",
    wait_ms: Annotated[int, Field(description="Milliseconds to wait after spawn before resuming.", ge=0)] = 3000,
) -> dict:
    """Spawn (cold-start) an app, attach, and resume. Creates a fresh session."""
    try:
        return session.spawn(package, device_id or None, wait_ms)
    except Exception as e:
        return _error(e)


@mcp.tool()
def frida_detach() -> dict:
    """Detach from the current process and clean up all resources (session, script, PCAP)."""
    try:
        return session.detach()
    except Exception as e:
        return _error(e)


@mcp.tool()
def frida_status() -> dict:
    """Show current session state: attached, alive, PID, scripts loaded, messages buffered, PCAP status."""
    try:
        return session.status()
    except Exception as e:
        return _error(e)


# ── Code execution ──────────────────────────────────────


@mcp.tool()
def frida_exec(
    js_code: Annotated[str, Field(description="Frida JavaScript code to execute. Use send() to emit results.")],
    keep_previous: Annotated[bool, Field(description="Keep previous script alive (avoids crash from dangling hooks). Default false.")] = False,
    wait: Annotated[float, Field(description="Seconds to wait for messages before returning. Default 0.2. Increase for async callbacks.", ge=0, le=30)] = 0.2,
) -> dict:
    """Execute arbitrary JavaScript in the attached process.

    Use `send(payload)` to emit results. Set keep_previous=true when you need hooks
    from a previous frida_exec to stay active (prevents access violations).
    Increase wait for scripts with async callbacks (e.g. setTimeout).
    """
    try:
        return session.exec_js(js_code, keep_previous=keep_previous, wait=wait)
    except Exception as e:
        return _error(e)


@mcp.tool()
def frida_rpc(
    method: Annotated[str, Field(description="RPC export method name to call.")],
    args: Annotated[str, Field(description="JSON array string of arguments to pass.")] = "[]",
) -> dict:
    """Call an RPC export on the currently loaded script.

    The script must define `rpc.exports` with the target method.
    """
    try:
        parsed_args = json.loads(args)
        result = session.rpc_call(method, parsed_args)
        return {"status": "ok", "result": result}
    except Exception as e:
        return _error(e)


@mcp.tool()
def frida_load_script(
    path: Annotated[str, Field(description="Absolute or relative path to a .js Frida script file.")],
) -> dict:
    """Load a Frida JavaScript script from a file. Replaces the previously loaded script."""
    try:
        return session.load_script(path)
    except Exception as e:
        return _error(e)


@mcp.tool()
def frida_messages(
    clear: Annotated[bool, Field(description="If true, clear the message buffer after reading.")] = False,
) -> dict:
    """Read accumulated send() messages from the running script.

    Messages are buffered in memory (max 500). Use clear=true to reset the buffer.
    """
    try:
        msgs = session.get_messages(clear)
        return {"count": len(msgs), "messages": msgs}
    except Exception as e:
        return _error(e)


# ── Java ────────────────────────────────────────────────


@mcp.tool()
def frida_list_classes(
    filter: Annotated[str, Field(description="Filter classes by substring (case-sensitive). Empty for all.")] = "",
) -> dict:
    """List loaded Java classes in the attached process. Optionally filter by substring.

    Returns up to 200 matching class names. Use a filter to narrow results.
    """
    try:
        classes = builtins.list_classes(filter)
        return {"count": len(classes), "classes": classes[:200]}
    except Exception as e:
        return _error(e)


@mcp.tool()
def frida_list_methods(
    class_name: Annotated[str, Field(description="Fully qualified Java class name (e.g. 'com.example.MyClass').")],
    include_inherited: Annotated[bool, Field(description="Walk superclass chain to include inherited methods. Useful for classes with 0 own methods.")] = False,
) -> dict:
    """List methods of a Java class. Set include_inherited=true for classes that inherit all methods."""
    try:
        methods = builtins.list_methods(class_name, include_inherited=include_inherited)
        return {"class": class_name, "count": len(methods), "methods": methods}
    except Exception as e:
        return _error(e)


@mcp.tool()
def frida_list_fields(
    class_name: Annotated[str, Field(description="Fully qualified Java class name.")],
) -> dict:
    """List all declared fields of a Java class."""
    try:
        fields = builtins.list_fields(class_name)
        return {"class": class_name, "count": len(fields), "fields": fields}
    except Exception as e:
        return _error(e)


@mcp.tool()
def frida_hook(
    class_name: Annotated[str, Field(description="Fully qualified Java class name to hook.")],
    method_name: Annotated[str, Field(description="Method name to hook. All overloads are hooked.")],
    backtrace: Annotated[bool, Field(description="If true, capture Java stack trace on each invocation.")] = False,
) -> dict:
    """Hook a Java method to log arguments, return values, and thread name.

    All overloads of the method are hooked. Results accumulate in the message
    buffer — read them with frida_messages().
    """
    try:
        return builtins.hook_method(class_name, method_name, backtrace)
    except Exception as e:
        return _error(e)


# ── Network & Security ─────────────────────────────────


@mcp.tool()
def frida_ssl_capture(
    duration: Annotated[int, Field(description="Capture duration in seconds.", ge=1, le=300)] = 10,
) -> dict:
    """Capture decrypted SSL/TLS + plaintext HTTP traffic for N seconds.

    Based on r0capture. Returns connection info, payload previews, and Java stack traces.
    Combine with frida_pcap_start/stop for Wireshark-compatible PCAP export.
    """
    try:
        msgs = builtins.ssl_capture(duration)
        summary = []
        for m in msgs:
            msg = m.get("message", {})
            if msg.get("type") == "send":
                p = msg.get("payload", {})
                if isinstance(p, dict) and p.get("function") in (
                    "SSL_read", "SSL_write", "HTTP_send", "HTTP_recv",
                ):
                    summary.append({
                        "function": p["function"],
                        "dst": f"{p.get('dst_addr', '?')}:{p.get('dst_port', '?')}",
                        "src": f"{p.get('src_addr', '?')}:{p.get('src_port', '?')}",
                        "length": p.get("length", 0),
                        "data_preview": m.get("data_hex", "")[:128],
                    })
        return {"captured": len(summary), "traffic": summary[:100]}
    except Exception as e:
        return _error(e)


@mcp.tool()
def frida_cert_dump() -> dict:
    """Dump client certificates as PKCS12 (.p12) files and detect SSL pinning.

    Monitors KeyStore operations, TrustManager creation, and custom keystores.
    Exported certs are saved to /sdcard/Download/ on the device.
    """
    try:
        return builtins.cert_dump()
    except Exception as e:
        return _error(e)


@mcp.tool()
def frida_ssl_unpin() -> dict:
    """Bypass SSL certificate pinning (OkHttp, Conscrypt, WebView, universal).

    Injects a permissive TrustManager and hooks common pinning implementations.
    """
    try:
        return builtins.ssl_unpin()
    except Exception as e:
        return _error(e)


@mcp.tool()
def frida_pcap_start(
    path: Annotated[str, Field(description="Output file path for the PCAP file (e.g. 'capture.pcap').")],
) -> dict:
    """Start saving captured traffic to a PCAP file (Wireshark-compatible).

    Use with frida_ssl_capture — all intercepted SSL/HTTP packets are auto-written.
    Call frida_pcap_stop when done.
    """
    try:
        return session.start_pcap(path)
    except Exception as e:
        return _error(e)


@mcp.tool()
def frida_pcap_stop() -> dict:
    """Stop PCAP capture, flush, and close the file."""
    try:
        return session.stop_pcap()
    except Exception as e:
        return _error(e)


# ── Native ──────────────────────────────────────────────


@mcp.tool()
def frida_list_modules() -> dict:
    """List loaded native modules (.so libraries) with base addresses and sizes."""
    try:
        modules = builtins.list_modules()
        return {"count": len(modules), "modules": modules}
    except Exception as e:
        return _error(e)


@mcp.tool()
def frida_list_exports(
    module_name: Annotated[str, Field(description="Native module name (e.g. 'libc.so').")],
) -> dict:
    """List exported functions of a native module. Returns up to 100 entries."""
    try:
        exports = builtins.list_exports(module_name)
        return {"module": module_name, "count": len(exports), "exports": exports[:100]}
    except Exception as e:
        return _error(e)


# ── Entry ───────────────────────────────────────────────


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
