<div align="center">

# Fridare

**Interactive Android Reverse Engineering through Frida x MCP**

Attach once, explore forever. No scripts to restart, no context lost.

[English](#features) | [中文](#功能)

</div>

---

## Features

- **Persistent sessions** — attach once, run unlimited commands
- **22 MCP tools** — full Frida lifecycle from any MCP-compatible client
- **r0capture integration** — universal SSL/HTTP traffic capture with PCAP export
- **SSL unpinning** — OkHttp / Conscrypt / WebView / universal bypass
- **Certificate dump** — auto-export client certs as P12
- **Cross-platform** — Windows, Linux, macOS. Uses your system Frida — no version conflicts

## Install

Requires `frida` and `frida-tools` to be available in your active Python environment.

### From GitHub

```bash
pip install git+https://github.com/MyuriKanao/fridare.git
```

Or install it as a standalone tool:

```bash
uv tool install git+https://github.com/MyuriKanao/fridare.git
```

### For local development

```bash
pip install -e .
```

## Publishing

For maintainers, build and publish the package with standard Python packaging tools:

```bash
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
python -m twine upload dist/*
```

If you want to test the release flow first, upload to TestPyPI before publishing to PyPI.

### GitHub Actions release flow

This repository also includes `.github/workflows/pypi-publish.yml`:

- pull requests / pushes to `main` build the package and run `twine check`
- pushes of tags matching `v*` publish to PyPI automatically

Typical release flow:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Before the first automated release, configure a **PyPI Trusted Publisher** for:

- PyPI project: `fridare`
- GitHub owner: `MyuriKanao`
- Repository: `fridare`
- Workflow file: `.github/workflows/pypi-publish.yml`
- Environment: `pypi`

If the PyPI project does not exist yet, create a **pending publisher** first and let the first tagged release create it.

## Configure

Fridare is a standard **stdio** MCP server. Add it to any MCP-compatible client:

### Claude Code (CLI / Desktop / Web)

```bash
claude mcp add fridare -- fridare
```

Or manually in `~/.claude.json`:

```json
{
  "mcpServers": {
    "fridare": {
      "type": "stdio",
      "command": "fridare"
    }
  }
}
```

### Claude Desktop

Add to `claude_desktop_config.json` (Settings > Developer > Edit Config):

```json
{
  "mcpServers": {
    "fridare": {
      "command": "fridare"
    }
  }
}
```

If installed in a virtualenv, use the full path:

```json
{
  "mcpServers": {
    "fridare": {
      "command": "/path/to/venv/bin/fridare"
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json` in your project root (or global settings):

```json
{
  "mcpServers": {
    "fridare": {
      "command": "fridare"
    }
  }
}
```

### VS Code (GitHub Copilot)

Add to `.vscode/mcp.json`:

```json
{
  "servers": {
    "fridare": {
      "type": "stdio",
      "command": "fridare"
    }
  }
}
```

### Windsurf

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "fridare": {
      "command": "fridare"
    }
  }
}
```

### Codex CLI (OpenAI)

Add to `~/.codex/config.json`:

```json
{
  "mcpServers": {
    "fridare": {
      "type": "stdio",
      "command": "fridare"
    }
  }
}
```

### Gemini CLI

Add to `~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "fridare": {
      "command": "fridare",
      "args": []
    }
  }
}
```

### Any MCP Client (Generic)

Fridare speaks **stdio** transport. To integrate with any MCP-compatible client:

```
command: fridare
transport: stdio
```

No arguments, no environment variables required. Just ensure `fridare` is on your `PATH` (i.e., `pip install -e .` was run in the active Python environment).

## Tools

### Device & Process

| Tool | Description |
|------|-------------|
| `frida_devices` | List connected devices (USB/remote) |
| `frida_ps` | List processes with optional name filter |
| `frida_restart_server` | Kill & restart frida-server on device |

### Session

| Tool | Description |
|------|-------------|
| `frida_attach` | Attach to process by name/PID (persists) |
| `frida_spawn` | Cold-start app + attach |
| `frida_detach` | Detach and cleanup |
| `frida_status` | Show session state (alive, PID, scripts, PCAP) |

### Execution

| Tool | Description |
|------|-------------|
| `frida_exec` | Run arbitrary JS (supports `keep_previous` and `wait`) |
| `frida_rpc` | Call RPC exports on loaded script |
| `frida_load_script` | Load JS script from file |
| `frida_messages` | Read accumulated `send()` messages |

### Java Introspection

| Tool | Description |
|------|-------------|
| `frida_list_classes` | Enumerate loaded classes (with filter) |
| `frida_list_methods` | List methods (supports `include_inherited`) |
| `frida_list_fields` | List fields of a class |
| `frida_hook` | Hook method — args, retval, optional backtrace |

### Network & Security

| Tool | Description |
|------|-------------|
| `frida_ssl_capture` | Capture SSL + HTTP traffic (r0capture) |
| `frida_ssl_unpin` | Universal SSL pinning bypass |
| `frida_cert_dump` | Dump client certs + detect pinning |
| `frida_pcap_start` | Start saving traffic to PCAP file |
| `frida_pcap_stop` | Stop PCAP capture |

### Native

| Tool | Description |
|------|-------------|
| `frida_list_modules` | List loaded .so modules + base addr |
| `frida_list_exports` | List native exports of a module |

## Usage

```
> Attach to Damai app
→ frida_attach("大麦")

> Search Mtop classes
→ frida_list_classes("Mtop")

> Hook setRetCode with stack trace
→ frida_hook("mtopsdk.mtop.domain.MtopResponse", "setRetCode", backtrace=true)

> Capture SSL traffic for 10s and save to pcap
→ frida_pcap_start("capture.pcap")
→ frida_ssl_capture(10)
→ frida_pcap_stop()

> Execute custom JS
→ frida_exec("Java.perform(function() { send({result: 'hello'}); })")

> Read hook output
→ frida_messages()
```

## Architecture

```
fridare/
├── server.py          MCP tool definitions (22 tools)
├── session.py         Device/process/session lifecycle + PCAP writer
├── builtins.py        Built-in ops (class enum, hooking, SSL capture)
└── scripts/
    ├── ssl_capture.js  Universal traffic capture (SSL + HTTP + stack traces)
    ├── ssl_unpin.js    SSL pinning bypass
    └── cert_dump.js    Certificate dump + pinning locator
```

## Design

- **System Frida** — uses whatever `frida` version is installed. No bundled binaries, no version conflicts
- **Session persistence** — one attach, unlimited operations. No reconnecting between commands
- **Message accumulation** — hook output buffers in memory, read anytime with `frida_messages()`
- **PCAP export** — `frida_pcap_start/stop` wraps traffic into Wireshark-compatible pcap files
- **Cross-platform** — handles Windows/Linux/Mac quoting differences for adb commands

## Credits

- SSL capture based on [r0capture](https://github.com/r0ysue/r0capture) by r0ysue
- Built on [Frida](https://frida.re) by Ole Andre V. Ravnas
- MCP protocol by [Anthropic](https://modelcontextprotocol.io)

---

<a id="功能"></a>

## 功能

- **持久会话** — attach 一次，无限执行
- **22 个 MCP 工具** — 在任何 MCP 兼容客户端中完整操控 Frida
- **r0capture 集成** — 通杀 SSL/HTTP 抓包 + PCAP 导出
- **SSL Pinning 绕过** — OkHttp / Conscrypt / WebView 通杀
- **证书导出** — 自动 dump 客户端证书为 P12
- **跨平台** — Windows / Linux / macOS，使用系统已装的 Frida，无版本冲突

## 安装

需要先在当前 Python 环境中准备好 `frida` 和 `frida-tools`。

### 从 GitHub 安装

```bash
pip install git+https://github.com/MyuriKanao/fridare.git
```

或者安装成独立命令行工具：

```bash
uv tool install git+https://github.com/MyuriKanao/fridare.git
```

### 本地开发安装

```bash
pip install -e .
```

## 发布

维护者可使用标准 Python 打包流程发布：

```bash
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
python -m twine upload dist/*
```

如果想先验证发布流程，建议先上传到 TestPyPI，再发布到正式 PyPI。

### GitHub Actions 自动发布

仓库已包含 `.github/workflows/pypi-publish.yml`：

- PR / 推送到 `main` 时自动构建并执行 `twine check`
- 推送符合 `v*` 的 tag 时自动发布到 PyPI

典型发布流程：

```bash
git tag v0.1.0
git push origin v0.1.0
```

首次自动发布前，需要在 PyPI 中配置 **Trusted Publisher**：

- PyPI 项目名：`fridare`
- GitHub Owner：`MyuriKanao`
- 仓库名：`fridare`
- Workflow 文件：`.github/workflows/pypi-publish.yml`
- Environment：`pypi`

如果 PyPI 项目还不存在，先创建 **pending publisher**，再用第一次带 tag 的发布自动创建项目。

## 配置

Fridare 是标准 **stdio** MCP 服务器，可接入任何 MCP 兼容客户端：

### Claude Code (CLI / 桌面 / Web)

```bash
claude mcp add fridare -- fridare
```

或手动编辑 `~/.claude.json`：

```json
{
  "mcpServers": {
    "fridare": {
      "type": "stdio",
      "command": "fridare"
    }
  }
}
```

### Claude Desktop

Settings > Developer > Edit Config，编辑 `claude_desktop_config.json`：

```json
{
  "mcpServers": {
    "fridare": {
      "command": "fridare"
    }
  }
}
```

### Cursor

项目根目录 `.cursor/mcp.json`：

```json
{
  "mcpServers": {
    "fridare": {
      "command": "fridare"
    }
  }
}
```

### VS Code (GitHub Copilot)

`.vscode/mcp.json`：

```json
{
  "servers": {
    "fridare": {
      "type": "stdio",
      "command": "fridare"
    }
  }
}
```

### Windsurf

`~/.codeium/windsurf/mcp_config.json`：

```json
{
  "mcpServers": {
    "fridare": {
      "command": "fridare"
    }
  }
}
```

### Codex CLI (OpenAI)

`~/.codex/config.json`：

```json
{
  "mcpServers": {
    "fridare": {
      "type": "stdio",
      "command": "fridare"
    }
  }
}
```

### Gemini CLI

`~/.gemini/settings.json`：

```json
{
  "mcpServers": {
    "fridare": {
      "command": "fridare",
      "args": []
    }
  }
}
```

### 通用 MCP 客户端

Fridare 使用 **stdio** 传输协议，无需额外参数或环境变量。确保 `fridare` 在 `PATH` 中即可（即在当前 Python 环境中执行过 `pip install -e .`）。

## 使用示例

```
你: attach 大麦 APP
→ frida_attach("大麦")

你: 搜 Mtop 相关的类
→ frida_list_classes("Mtop")

你: hook setRetCode，带堆栈
→ frida_hook("mtopsdk.mtop.domain.MtopResponse", "setRetCode", backtrace=true)

你: 抓 10 秒流量并存 pcap
→ frida_pcap_start("capture.pcap")
→ frida_ssl_capture(10)
→ frida_pcap_stop()

你: 拿 hook 产生的消息
→ frida_messages()
```
