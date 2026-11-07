# OpenAssist

A minimal, self-hosted remote-assistance tool for Windows — operator console + agent, built with Win32 + SChannel TLS, cross-compiled from Linux with MinGW-w64.

> **Status: prototype.** Works for shell / file transfer / screenshot / sysinfo over a TLS 1.2 channel. UI is rough, code is minimal, no auth layer, no session approval beyond the agent requiring a click on "Connect". **Do not expose to the internet as-is.**

## Why it exists

Self-hosted alternative to TeamViewer/AnyDesk for lab, homelab, and research use, where you want:
- No third-party relay
- No account, no subscription
- Plain TLS between two peers you control

## What it does

| Feature | Status |
|---|---|
| TLS 1.2 transport (SChannel, no OpenSSL) | ✅ |
| Remote `cmd.exe` shell | ✅ |
| File listing / download / upload | ✅ |
| System info | ✅ |
| Full-screen screenshot (BMP) | ✅ |
| Cross-compile from Linux → Windows | ✅ |
| Visible agent UI (no stealth) | ✅ |
| Authentication / session approval | ❌ |
| Compressed transport | ❌ |
| Multi-monitor cursor-aware screenshot | ❌ |

## Architecture
┌─────────────┐ TLS 1.2 (SChannel) ┌──────────────┐
│ panel.exe │◄─────────────────────────►│ agent.exe │
│ (operator) │ msg = u32 len, u16 cmd, │ (host user) │
└─────────────┘ payload └──────────────┘

- `common/proto.h` — framing, command enum, plain sockets
- `common/tls.h` — ~200-line SChannel wrapper (client + server)
- `panel/panel.cpp` — Win32 GUI: session list, shell/files/info/shot windows
- `agent/agent.cpp` — Win32 GUI: address box, connect/disconnect, log

## Build (from Linux)

Requires `mingw-w64`:

```bash
sudo apt install mingw-w64
