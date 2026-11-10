# SUCKLESS-RAT

A minimal, self-hosted remote administration tool for Windows. Win32 UI + SChannel TLS 1.2, cross-compiled with MinGW-w64.

**Status:** educational prototype. There is no authentication layer. Run it only on machines you own or have explicit permission to access.

## Features

| Feature | Status |
|---|---|
| TLS 1.2 transport (SChannel) | yes |
| Remote `cmd.exe` shell | yes |
| File manager (list / get / put) | yes |
| System info | yes |
| Full-screen screenshot | yes |
| Hidden background agent | yes |
| Agent auto-reconnect after panel restart | yes |

## Architecture

```
panel.exe (operator) <----- TLS 1.2 -----> agent.exe (target)
```

- `common/proto.h` - frame format, command IDs
- `common/tls.h` - SChannel wrapper (client + server)
- `panel/panel.cpp` - operator GUI
- `agent/agent.cpp` - background client

The agent retries every 3 seconds if the panel is closed or restarted. It exits only when the operator explicitly sends `C_BYE` ("Disconnect client").

## Build

### Linux -> Windows (cross-compile)

```sh
sudo apt install mingw-w64
make clean && make
```

### Windows (MinGW-w64)

If `make` is not installed, build directly:

```bat
x86_64-w64-mingw32-g++ -std=c++17 -Os -s -Wall -Wno-unused-value -DNOMINMAX ^
  -ffunction-sections -fdata-sections -fno-exceptions -fno-rtti ^
  panel/panel.cpp -o panel.exe -static -mwindows -Wl,--gc-sections ^
  -lws2_32 -lsecur32 -lcrypt32 -lcomctl32 -lgdi32
```

Use the same command with `agent/agent.cpp -o agent.exe` to build the agent.

Outputs: `panel.exe`, `agent.exe`.

## Certificate

The panel needs a TLS server certificate. Generate a self-signed one:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 3650 -subj "/CN=OpenAssistPanel"
openssl pkcs12 -export -out cert.pfx -inkey key.pem -in cert.pem -passout pass:
```

Put `cert.pfx` next to `panel.exe`. Certificates and keys are git-ignored - never commit them.

## Usage

1. Operator: run `panel.exe`, click **Start listening** (default port `8443`).
2. Target: run `agent.exe 192.168.1.100:8443`.
3. Right-click the session to open shell, files, system info or a screenshot.

## Security

- Traffic is encrypted, but the agent currently accepts **any** server certificate and there is **no authentication**. Do not expose the panel to the internet.
- Before using this outside a lab: pin the panel certificate fingerprint in the agent, add a shared secret, and set socket receive timeouts.

## Disclaimer

Research and educational project only. Use only on machines you own or have explicit permission to access. The authors are not responsible for any misuse.
