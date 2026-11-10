#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>

static inline void WriteFileAll(const char* p, const void* d, uint32_t n) {
  HANDLE f = CreateFileA(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
  if (f == INVALID_HANDLE_VALUE) return;
  DWORD w; WriteFile(f, d, n, &w, NULL); CloseHandle(f);
}

static inline char* ReadFileAll(const char* p, uint32_t* outLen) {
  *outLen = 0;
  HANDLE f = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  if (f == INVALID_HANDLE_VALUE) return NULL;
  DWORD sz = GetFileSize(f, NULL);
  char* buf = (char*)malloc(sz ? sz : 1);
  DWORD n = 0;
  if (buf) ReadFile(f, buf, sz, &n, NULL);
  CloseHandle(f);
  *outLen = buf ? n : 0;
  return buf;
}
