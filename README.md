# sRAT

A minimal, self-hosted remote administration tool for Windows. Win32 UI + SChannel TLS 1.2, cross-compiled with MinGW-w64.

**Status:** educational prototype. Run it only on machines you own or have explicit permission to access.

## Features

| Feature | Status |
|---|---|
| TLS 1.2 transport (SChannel) | yes |
| Client authentication (shared secret, challenge-response) | yes |
| Remote `cmd.exe` shell | yes |
| File manager (list / get / put) | yes |
| System info | yes |
| Full-screen screenshot | yes |
| Hidden background agent | yes |
| Agent auto-reconnect after panel restart | yes |
| Client list shows Windows version and country (public IP) | yes |
| Start/stop listening without restarting the panel | yes |

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
x86_64-w64-mingw32-g++ -std=c++17 -Os -s -Wall -Wno-unused-value -Wno-misleading-indentation -DNOMINMAX ^
  -ffunction-sections -fdata-sections -fno-exceptions -fno-rtti ^
  panel/panel.cpp -o panel.exe -static -mwindows -Wl,--gc-sections ^
  -lws2_32 -lsecur32 -lcrypt32 -lcomctl32 -lgdi32 -lwininet -ladvapi32 -liphlpapi
```

Use the same command with `agent/agent.cpp -o agent.exe` to build the agent.

Outputs: `panel.exe`, `agent.exe`.

## Certificate

The panel needs a TLS server certificate. Generate a self-signed one:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 3650 -subj "/CN=sRATPanel"
openssl pkcs12 -export -out cert.pfx -inkey key.pem -in cert.pem -passout pass:
```

Put `cert.pfx` next to `panel.exe`. Certificates and keys are git-ignored - never commit them.

## Usage

1. Operator: run `panel.exe`, click **Start listening** (default port `8443`). The button becomes **Stop listening**: it closes the port to new clients but leaves connected sessions running, and the same button starts listening again on the same port.
2. Target: set the panel address in `kServer` at the top of `agent/agent.cpp` (`"192.168.1.100:8443"`), rebuild, then just run `agent.exe`. A `host:port` argument still overrides it for testing.
3. Right-click the session to open shell, files, system info or a screenshot.

## Security

- Traffic is encrypted with SChannel TLS 1.2. The agent pins the panel certificate: it accepts only the exact certificate whose SHA-256 is in `kPin` in `agent/agent.cpp`. If you regenerate `cert.pem`/`cert.pfx`, update that constant, otherwise the agent will refuse to connect.
- Every connection is authenticated with a shared secret. Right after the TLS handshake the panel sends a random 16-byte nonce and the agent must reply with `SHA-256(secret || nonce)`; anything else is dropped before it can send a command. The secret is `kPsk` in `common/proto.h` - the value in the repository is a public placeholder, **change it before building** for your own deployment (both binaries embed it).
- Do not expose the panel to the internet. There is still no per-user identity, no rate limiting and no audit log.
- Downloaded files are written to `downloads\` under a sanitised base name; the agent reports unreadable or oversized (> 64 MB) files instead of failing silently.
- On start the agent makes one HTTPS request to `api.country.is` to learn the public IP and country; no other traffic leaves the machine outside the panel connection.
- Idle connections use TCP keepalive (10 s idle time, 3 s probes). A peer that stops responding is dropped after roughly 20 seconds, while a quiet but live session is left alone.
- Before using this outside a lab: set your own `kPsk`, keep the panel off the internet, and add rate limiting.

## Disclaimer

Research and educational project only. Use only on machines you own or have explicit permission to access. The authors are not responsible for any misuse.
