#pragma once
#include <cstdint>
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <mstcpip.h>
#include <string.h>
enum Cmd : uint16_t {
  C_HELLO = 1, C_SYSINFO, C_SHELL_START, C_SHELL_CLOSE, C_SHELL_DATA,
  C_FS_LIST, C_FS_LIST_RESP, C_FS_GET, C_FS_PUT, C_FS_FILE,
  C_SCREEN, C_SCREEN_IMG, C_BYE, C_AUTH,
};
static const uint32_t MAX_MSG = 64u * 1024 * 1024;
static const char kPsk[] = "sRAT-change-me-psk";
inline bool AuthProof(const unsigned char* nonce, uint32_t n, unsigned char out[32]) {
  unsigned char buf[sizeof(kPsk) + 32]; size_t sl = sizeof(kPsk) - 1; DWORD hl = 32; if (sl + n > sizeof(buf)) return false;
  memcpy(buf, kPsk, sl); memcpy(buf + sl, nonce, n); return CryptHashCertificate(0, CALG_SHA_256, 0, buf, (DWORD)(sl + n), out, &hl) && hl == 32;
}
inline void TuneSocket(SOCKET s) {
  int one = 1; setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char*)&one, sizeof(one));
  tcp_keepalive ka = { 1, 10000, 3000 }; DWORD r = 0; WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), NULL, 0, &r, NULL, NULL);
}
inline bool SendFull(SOCKET s, const void* p, uint32_t n) {
  const char* q = (const char*)p;
  while (n) {
    int r = send(s, q, (int)n, 0);
    if (r <= 0) return false;
    q += r; n -= (uint32_t)r;
  }
  return true;
}
