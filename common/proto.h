#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <cstring>
#include <cstdio>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// One message = [u32 payload_len][u16 cmd][payload]. Max payload 64 MB.
enum Cmd : uint16_t {
  C_HELLO = 1,
  C_SYSINFO,
  C_SHELL_START,
  C_SHELL_CLOSE,
  C_SHELL_DATA,
  C_FS_LIST,
  C_FS_LIST_RESP,
  C_FS_GET,
  C_FS_PUT,
  C_FS_FILE,
  C_SCREEN,
  C_SCREEN_IMG,
  C_BYE,
};

static const uint32_t MAX_MSG = 64u * 1024 * 1024;

inline bool RecvFull(SOCKET s, void* p, uint32_t n) {
  char* q = (char*)p;
  while (n) {
    int r = recv(s, q, (int)n, 0);
    if (r <= 0) return false;
    q += r; n -= (uint32_t)r;
  }
  return true;
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

inline bool SendMsg(SOCKET s, uint16_t cmd, const void* p, uint32_t n) {
  uint32_t hdr[2] = { n, cmd };
  return SendFull(s, hdr, 8) && (n == 0 || SendFull(s, p, n));
}

inline bool RecvMsg(SOCKET s, uint16_t& cmd, std::string& out) {
  uint32_t hdr[2];
  if (!RecvFull(s, hdr, 8)) return false;
  if (hdr[0] > MAX_MSG) return false;
  cmd = (uint16_t)hdr[1];
  out.resize(hdr[0]);
  return hdr[0] == 0 || RecvFull(s, out.data(), hdr[0]);
}