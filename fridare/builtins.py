"""Built-in Frida operations — common reverse engineering tasks."""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from fridare.session import get_state, exec_js, load_script, get_messages

SCRIPTS_DIR = Path(__file__).parent / "scripts"

# Java identifier: letters, digits, $, _ (dots for FQN)
_JAVA_IDENT_RE = re.compile(r"^[\w.$]+$")


def _validate_java_name(name: str, label: str = "name") -> str:
    """Validate a Java class or method name to prevent JS injection."""
    if not name or not _JAVA_IDENT_RE.match(name):
        raise ValueError(f"Invalid Java {label}: {name!r}")
    return name


def _require_session():
    s = get_state()
    if not s.session:
        raise RuntimeError("Not attached. Call frida_attach() or frida_spawn() first.")
    return s


def _extract_payload(messages: list[dict], payload_type: str) -> Any:
    """Extract the first matching payload from exec_js messages."""
    for msg in messages:
        m = msg.get("message", {})
        if m.get("type") == "send" and isinstance(m.get("payload"), dict):
            p = m["payload"]
            if p.get("type") == payload_type:
                return p.get("data")
            if p.get("type") == "error":
                raise ValueError(p["data"])
    return None


# ── Java introspection ──────────────────────────────────


def list_classes(filter: str = "") -> list[str]:
    """List loaded Java classes, optionally filtered by substring."""
    _require_session()
    # Sanitize filter for safe JS string interpolation
    safe_filter = filter.replace("\\", "\\\\").replace("'", "\\'") if filter else ""
    code = f"""
    var results = [];
    Java.perform(function() {{
        Java.enumerateLoadedClasses({{
            onMatch: function(name) {{
                {"if (name.indexOf('" + safe_filter + "') !== -1)" if safe_filter else ""}
                results.push(name);
            }},
            onComplete: function() {{
                send({{type: 'classes', data: results}});
            }}
        }});
    }});
    """
    result = exec_js(code)
    return _extract_payload(result.get("messages", []), "classes") or []


def list_methods(class_name: str) -> list[str]:
    """List all declared methods of a Java class."""
    _validate_java_name(class_name, "class name")
    code = f"""
    Java.perform(function() {{
        var found = false;
        Java.enumerateClassLoaders({{
            onMatch: function(loader) {{
                if (found) return;
                try {{
                    var clz = Java.ClassFactory.get(loader).use("{class_name}");
                    found = true;
                    var methods = clz.class.getDeclaredMethods();
                    var result = [];
                    for (var i = 0; i < methods.length; i++) {{
                        result.push(methods[i].toString());
                    }}
                    send({{type: 'methods', data: result}});
                }} catch(e) {{}}
            }},
            onComplete: function() {{
                if (!found) send({{type: 'error', data: 'Class not found: {class_name}'}});
            }}
        }});
    }});
    """
    result = exec_js(code)
    return _extract_payload(result.get("messages", []), "methods") or []


def list_fields(class_name: str) -> list[str]:
    """List all declared fields of a Java class."""
    _validate_java_name(class_name, "class name")
    code = f"""
    Java.perform(function() {{
        var found = false;
        Java.enumerateClassLoaders({{
            onMatch: function(loader) {{
                if (found) return;
                try {{
                    var clz = Java.ClassFactory.get(loader).use("{class_name}");
                    found = true;
                    var fields = clz.class.getDeclaredFields();
                    var result = [];
                    for (var i = 0; i < fields.length; i++) {{
                        result.push(fields[i].toString());
                    }}
                    send({{type: 'fields', data: result}});
                }} catch(e) {{}}
            }},
            onComplete: function() {{
                if (!found) send({{type: 'error', data: 'Class not found: {class_name}'}});
            }}
        }});
    }});
    """
    result = exec_js(code)
    return _extract_payload(result.get("messages", []), "fields") or []


def hook_method(class_name: str, method_name: str, backtrace: bool = False) -> dict:
    """Hook a Java method — logs args, return value, and thread name."""
    _validate_java_name(class_name, "class name")
    _validate_java_name(method_name, "method name")

    bt_code = ""
    if backtrace:
        bt_code = """
                var stack = Java.use('android.util.Log').getStackTraceString(
                    Java.use('java.lang.Throwable').$new());
                info.stack = stack.substring(0, 800);
        """
    code = f"""
    Java.perform(function() {{
        var found = false;
        Java.enumerateClassLoaders({{
            onMatch: function(loader) {{
                if (found) return;
                try {{
                    var clz = Java.ClassFactory.get(loader).use("{class_name}");
                    var method = clz.{method_name};
                    if (!method || !method.overloads) return;
                    found = true;
                    method.overloads.forEach(function(overload) {{
                        overload.implementation = function() {{
                            var args = [];
                            for (var i = 0; i < arguments.length; i++) {{
                                var a = arguments[i];
                                args.push(a !== null && a !== undefined ? String(a).substring(0, 200) : 'null');
                            }}
                            var info = {{
                                type: 'hook',
                                cls: '{class_name}'.split('.').pop(),
                                method: '{method_name}',
                                args: args,
                                thread: Java.use('java.lang.Thread').currentThread().getName()
                            }};
                            {bt_code}
                            var ret = overload.apply(this, arguments);
                            info.ret = ret !== null && ret !== undefined ? String(ret).substring(0, 300) : 'null';
                            send(info);
                            return ret;
                        }};
                    }});
                    send({{type: 'hooked', data: '{class_name}.{method_name}'}});
                }} catch(e) {{}}
            }},
            onComplete: function() {{
                if (!found) send({{type: 'error', data: 'Method not found'}});
            }}
        }});
    }});
    """
    return exec_js(code)


# ── SSL / Network ──────────────────────────────────────


def ssl_capture(duration: int = 10) -> list[dict]:
    """Capture SSL + HTTP traffic for N seconds."""
    _require_session()
    load_script(str(SCRIPTS_DIR / "ssl_capture.js"))
    time.sleep(duration)
    return get_messages()


def cert_dump() -> dict:
    """Dump client certificates and detect SSL pinning."""
    _require_session()
    return load_script(str(SCRIPTS_DIR / "cert_dump.js"))


def ssl_unpin() -> dict:
    """Bypass SSL certificate pinning."""
    _require_session()
    return load_script(str(SCRIPTS_DIR / "ssl_unpin.js"))


# ── Native ─────────────────────────────────────────────


def list_modules() -> list[dict]:
    """List loaded native modules."""
    code = """
    var mods = Process.enumerateModules();
    var result = [];
    for (var i = 0; i < mods.length; i++) {
        result.push({name: mods[i].name, base: mods[i].base.toString(), size: mods[i].size});
    }
    send({type: 'modules', data: result});
    """
    result = exec_js(code)
    return _extract_payload(result.get("messages", []), "modules") or []


def list_exports(module_name: str) -> list[dict]:
    """List exported functions of a native module."""
    # Sanitize module name for JS string
    safe_name = module_name.replace("\\", "\\\\").replace('"', '\\"')
    code = f"""
    var exports = Module.enumerateExports("{safe_name}");
    var result = [];
    for (var i = 0; i < Math.min(exports.length, 500); i++) {{
        result.push({{name: exports[i].name, address: exports[i].address.toString(), type: exports[i].type}});
    }}
    send({{type: 'exports', data: result, total: exports.length}});
    """
    result = exec_js(code)
    return _extract_payload(result.get("messages", []), "exports") or []
