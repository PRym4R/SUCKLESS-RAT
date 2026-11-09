#pragma once
#include <cstdint>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

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

inline bool SendFull(SOCKET s, const void* p, uint32_t n) {
  const char* q = (const char*)p;
  while (n) {
    int r = send(s, q, (int)n, 0);
    if (r <= 0) return false;
    q += r; n -= (uint32_t)r;
  }
  return true;
}