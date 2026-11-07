// Minimal SChannel TLS 1.2 wrapper (client + server). Zero external deps.
#pragma once
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <string>
#include <cstring>
#include <cstdlib>

#pragma pack(push,1)
struct WireHdr { uint32_t len; uint16_t cmd; };
#pragma pack(pop)

struct TlsCtx {
  SOCKET sock = INVALID_SOCKET;
  CredHandle hcred; CtxtHandle hctx;
  bool haveCred = false, haveCtx = false, server = false;
  SecPkgContext_StreamSizes sz{};
  std::string raw;                     // undecrypted leftover
  std::string dec; size_t decPos = 0;  // decrypted leftover
  ~TlsCtx() {
    if (haveCtx) DeleteSecurityContext(&hctx);
    if (haveCred) FreeCredentialsHandle(&hcred);
  }
};

static bool TlsAcquire(TlsCtx& t, PCCERT_CONTEXT cert) {
  SCHANNEL_CRED sc{};
  sc.dwVersion = SCHANNEL_CRED_VERSION;
  sc.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
  sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_2_SERVER;
  if (cert) { sc.cCreds = 1; sc.paCred = &cert; }
  else { sc.cCreds = 0; }
  TimeStamp ts;
  SECURITY_STATUS st = AcquireCredentialsHandleW(
      nullptr, (SEC_WCHAR*)UNISP_NAME_W,
      cert ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND,
      nullptr, &sc, nullptr, nullptr, &t.hcred, &ts);
  t.haveCred = (st == SEC_E_OK);
  t.server = (cert != nullptr);
  return t.haveCred;
}

static int RawRecv(TlsCtx& t) {
  char buf[16384];
  int r = recv(t.sock, buf, sizeof(buf), 0);
  if (r <= 0) return -1;
  t.raw.append(buf, (size_t)r);
  return r;
}

// Returns: 1 established, 0 need more data, -1 fatal.
static int HandshakeStep(TlsCtx& t, bool& moreWork) {
  moreWork = false;
  SecBufferDesc in, out;
  SecBuffer bin[2]{}, bout[1]{};
  bin[0].pvBuffer = t.raw.empty() ? nullptr : (void*)t.raw.data();
  bin[0].cbBuffer = (unsigned long)t.raw.size();
  bin[0].BufferType = SECBUFFER_TOKEN;
  bin[1].BufferType = SECBUFFER_EMPTY;
  bout[0].BufferType = SECBUFFER_TOKEN;
  DWORD outLen = 12288;
  bout[0].pvBuffer = malloc(outLen);
  bout[0].cbBuffer = outLen;
  in.ulVersion = SECBUFFER_VERSION; in.cBuffers = 2; in.pBuffers = bin;
  out.ulVersion = SECBUFFER_VERSION; out.cBuffers = 1; out.pBuffers = bout;
  DWORD attr = 0; TimeStamp ts;
  SECURITY_STATUS st;
  if (t.server) {
    st = AcceptSecurityContext(&t.hcred, t.haveCtx ? &t.hctx : nullptr, &in, 0,
                               SECURITY_NATIVE_DREP, &t.hctx, &out, &attr, &ts);
  } else {
    if (t.haveCtx) {
      st = InitializeSecurityContextW(&t.hcred, &t.hctx, nullptr,
          ISC_REQ_STREAM | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT |
          ISC_REQ_CONFIDENTIALITY | ISC_REQ_MANUAL_CRED_VALIDATION,
          0, SECURITY_NATIVE_DREP, &in, 0, &t.hctx, &out, &attr, &ts);
    } else {
      st = InitializeSecurityContextW(&t.hcred, nullptr, nullptr,
          ISC_REQ_STREAM | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT |
          ISC_REQ_CONFIDENTIALITY | ISC_REQ_MANUAL_CRED_VALIDATION,
          0, SECURITY_NATIVE_DREP, nullptr, 0, &t.hctx, &out, &attr, &ts);
    }
  }
  if (bout[0].cbBuffer > 0 && st != SEC_E_INCOMPLETE_MESSAGE) {
    if (!SendFull(t.sock, bout[0].pvBuffer, bout[0].cbBuffer)) {
      free(bout[0].pvBuffer); return -1;
    }
  }
  free(bout[0].pvBuffer);

  if (st == SEC_E_OK) { t.haveCtx = true; t.raw.clear(); return 1; }

  if (st == SEC_I_CONTINUE_NEEDED) {
    // consume handled bytes, keep extra
    size_t extra = 0;
    for (int i = 0; i < 2; i++)
      if (bin[i].BufferType == SECBUFFER_EXTRA) extra = bin[i].cbBuffer;
    t.raw.erase(0, t.raw.size() - extra);
    t.haveCtx = true;
    moreWork = true;
    return 0;
  }
  if (st == SEC_E_INCOMPLETE_MESSAGE) {
    // keep everything
    return 0;
  }
  // Opportunistic mode: agent accepts self-signed panel cert.
  if (!t.server && (st == SEC_E_UNTRUSTED_ROOT || st == SEC_E_WRONG_PRINCIPAL ||
                    st == CERT_E_CN_NO_MATCH || st == CERT_E_UNTRUSTEDROOT)) {
    t.haveCtx = true;
    return 1;
  }
  return -1;
}

static bool TlsHandshake(TlsCtx& t) {
  for (;;) {
    bool moreWork = false;
    int r = HandshakeStep(t, moreWork);
    if (r == 1) break;
    if (r < 0) return false;
    if (!moreWork || t.raw.empty()) {
      if (RawRecv(t) < 0) return false;
    }
  }
  QueryContextAttributesW(&t.hctx, SECPKG_ATTR_STREAM_SIZES, &t.sz);
  return true;
}

// Decrypt buffered record data into t.dec.
static bool TlsPump(TlsCtx& t) {
  for (;;) {
    SecBuffer bufs[4]{};
    bufs[0].pvBuffer = (void*)t.raw.data();
    bufs[0].cbBuffer = (unsigned long)t.raw.size();
    bufs[0].BufferType = SECBUFFER_DATA;
    bufs[1].BufferType = bufs[2].BufferType = bufs[3].BufferType = SECBUFFER_EMPTY;
    SecBufferDesc d{ SECBUFFER_VERSION, 4, bufs };
    SECURITY_STATUS st = DecryptMessage(&t.hctx, &d, 0, nullptr);
    if (st == SEC_E_INCOMPLETE_MESSAGE) return RawRecv(t) > 0;
    if (st == SEC_I_RENEGOTIATE) return false;
    if (st != SEC_E_OK) return false;

    size_t extra = 0;
    for (int i = 0; i < 4; i++)
      if (bufs[i].BufferType == SECBUFFER_EXTRA) extra = bufs[i].cbBuffer;
    for (int i = 0; i < 4; i++)
      if (bufs[i].BufferType == SECBUFFER_DATA)
        t.dec.append((char*)bufs[i].pvBuffer, bufs[i].cbBuffer);
    t.raw.erase(0, t.raw.size() - extra);
    if (extra == 0) return true;
  }
}

static bool TlsRecv(TlsCtx& t, void* p, uint32_t n) {
  char* q = (char*)p;
  while (n) {
    size_t avail = t.dec.size() - t.decPos;
    if (avail == 0) {
      t.dec.clear(); t.decPos = 0;
      if (t.raw.empty() && RawRecv(t) < 0) return false;
      if (!TlsPump(t) || t.dec.size() == t.decPos) return false;
      continue;
    }
    size_t take = avail < n ? avail : (size_t)n;
    memcpy(q, t.dec.data() + t.decPos, take);
    t.decPos += take; q += take; n -= (uint32_t)take;
    if (t.decPos == t.dec.size()) { t.dec.clear(); t.decPos = 0; }
  }
  return true;
}

static bool TlsSend(TlsCtx& t, const void* p, uint32_t n) {
  const char* q = (const char*)p;
  while (n) {
    uint32_t chunk = (uint32_t)(n < 60 * 1024 ? n : 60 * 1024);
    size_t total = t.sz.cbHeader + chunk + t.sz.cbTrailer;
    std::string buf(total, 0);
    memcpy(buf.data() + t.sz.cbHeader, q, chunk);
    SecBuffer bufs[4]{};
    bufs[0].cbBuffer = t.sz.cbHeader;
    bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
    bufs[0].pvBuffer = buf.data();
    bufs[1].cbBuffer = chunk;
    bufs[1].BufferType = SECBUFFER_DATA;
    bufs[1].pvBuffer = buf.data() + t.sz.cbHeader;
    bufs[2].cbBuffer = t.sz.cbTrailer;
    bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
    bufs[2].pvBuffer = buf.data() + t.sz.cbHeader + chunk;
    bufs[3].BufferType = SECBUFFER_EMPTY;
    SecBufferDesc d{ SECBUFFER_VERSION, 4, bufs };
    if (EncryptMessage(&t.hctx, 0, &d, 0) != SEC_E_OK) return false;
    if (!SendFull(t.sock, buf.data(), bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer))
      return false;
    q += chunk; n -= chunk;
  }
  return true;
}

static bool TlsSendMsg(TlsCtx& t, uint16_t cmd, const void* p, uint32_t n) {
  WireHdr h{ n, cmd };
  return TlsSend(t, &h, 8) && (n == 0 || TlsSend(t, p, n));
}

static bool TlsRecvMsg(TlsCtx& t, uint16_t& cmd, std::string& out) {
  WireHdr h;
  if (!TlsRecv(t, &h, 8) || h.len > MAX_MSG) return false;
  cmd = h.cmd; out.resize(h.len);
  return h.len == 0 || TlsRecv(t, out.data(), h.len);
}