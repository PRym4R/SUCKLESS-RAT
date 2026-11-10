#pragma once
#include "proto.h"
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <windows.h>
#include <string.h>
#include <stdlib.h>
struct WireHdr { uint32_t len; uint32_t cmd; };
struct TlsCtx {
  SOCKET sock;
  CredHandle hcred; CtxtHandle hctx;
  bool haveCred, haveCtx, server;
  SecPkgContext_StreamSizes sz;
  char* raw; size_t rawLen; size_t rawCap;
  char* dec; size_t decLen; size_t decPos;
  CRITICAL_SECTION sendCs;
};
static void InitTlsCtx(TlsCtx* t, SOCKET s) {
  memset(t, 0, sizeof(TlsCtx)); t->sock = s;
  InitializeCriticalSection(&t->sendCs);
}
static void FreeTlsCtx(TlsCtx* t) {
  if (t->haveCtx) DeleteSecurityContext(&t->hctx);
  if (t->haveCred) FreeCredentialsHandle(&t->hcred);
  if (t->raw) free(t->raw);
  if (t->dec) free(t->dec);
  DeleteCriticalSection(&t->sendCs);
}
static bool RawAppend(TlsCtx* t, const char* buf, size_t len) {
  if (t->rawLen + len > t->rawCap) {
    t->rawCap = (t->rawCap + len) * 2 + 1024;
    char* p = (char*)realloc(t->raw, t->rawCap); if (!p) return false;
    t->raw = p;
  }
  memcpy(t->raw + t->rawLen, buf, len); t->rawLen += len; return true;
}
static void RawErase(TlsCtx* t, size_t count) {
  if (count >= t->rawLen) { t->rawLen = 0; return; }
  memmove(t->raw, t->raw + count, t->rawLen - count); t->rawLen -= count;
}
static size_t ExtraLen(const SecBuffer* b, int n) {
  for (int i = 0; i < n; i++) if (b[i].BufferType == SECBUFFER_EXTRA) return b[i].cbBuffer;
  return 0;
}
static bool TlsAcquire(TlsCtx* t, PCCERT_CONTEXT cert) {
  SCHANNEL_CRED sc; memset(&sc, 0, sizeof(sc));
  sc.dwVersion = SCHANNEL_CRED_VERSION;
  sc.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
  sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_2_SERVER;
  if (cert) { sc.cCreds = 1; sc.paCred = &cert; }
  TimeStamp ts;
  SECURITY_STATUS st = AcquireCredentialsHandleW(NULL, (SEC_WCHAR*)UNISP_NAME_W,
      cert ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND, NULL, &sc, NULL, NULL, &t->hcred, &ts);
  t->haveCred = (st == SEC_E_OK); t->server = (cert != NULL);
  return t->haveCred;
}
static int RawRecv(TlsCtx* t) {
  char buf[16384];
  int r = recv(t->sock, buf, sizeof(buf), 0);
  if (r <= 0) return -1;
  return RawAppend(t, buf, r) ? r : -1;
}
static int HandshakeStep(TlsCtx* t, bool* moreWork) {
  *moreWork = false;
  SecBufferDesc in, out; SecBuffer bin[2], bout[1];
  memset(bin, 0, sizeof(bin)); memset(bout, 0, sizeof(bout));
  bin[0].pvBuffer = t->rawLen ? t->raw : NULL; bin[0].cbBuffer = (unsigned long)t->rawLen; bin[0].BufferType = SECBUFFER_TOKEN;
  bin[1].BufferType = SECBUFFER_EMPTY;
  bout[0].BufferType = SECBUFFER_TOKEN; bout[0].cbBuffer = 12288; bout[0].pvBuffer = malloc(12288);
  if (!bout[0].pvBuffer) return -1;
  in.ulVersion = SECBUFFER_VERSION; in.cBuffers = 2; in.pBuffers = bin;
  out.ulVersion = SECBUFFER_VERSION; out.cBuffers = 1; out.pBuffers = bout;
  DWORD attr = 0; TimeStamp ts; SECURITY_STATUS st;
  if (t->server) {
    st = AcceptSecurityContext(&t->hcred, t->haveCtx ? &t->hctx : NULL, &in, 0,
                               SECURITY_NATIVE_DREP, &t->hctx, &out, &attr, &ts);
  } else {
    st = InitializeSecurityContextW(&t->hcred, t->haveCtx ? &t->hctx : NULL, NULL,
        ISC_REQ_STREAM | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT |
        ISC_REQ_CONFIDENTIALITY | ISC_REQ_MANUAL_CRED_VALIDATION,
        0, SECURITY_NATIVE_DREP, t->haveCtx ? &in : NULL, 0, &t->hctx, &out, &attr, &ts);
  }
  if (bout[0].cbBuffer > 0 && st != SEC_E_INCOMPLETE_MESSAGE &&
      !SendFull(t->sock, bout[0].pvBuffer, bout[0].cbBuffer)) { free(bout[0].pvBuffer); return -1; }
  free(bout[0].pvBuffer);
  if (st == SEC_E_OK) { RawErase(t, t->rawLen - ExtraLen(bin, 2)); t->haveCtx = true; return 1; }
  if (st == SEC_I_CONTINUE_NEEDED) {
    RawErase(t, t->rawLen - ExtraLen(bin, 2));
    t->haveCtx = true; *moreWork = true; return 0;
  }
  if (st == SEC_E_INCOMPLETE_MESSAGE) return 0;
  if (!t->server && (st == SEC_E_UNTRUSTED_ROOT || st == SEC_E_WRONG_PRINCIPAL ||
                     st == CERT_E_CN_NO_MATCH || st == CERT_E_UNTRUSTEDROOT)) {
    t->haveCtx = true; return 1;
  }
  return -1;
}
static bool TlsPinOk(TlsCtx* t, const unsigned char* pin) {
  PCCERT_CONTEXT rc = NULL; if (QueryContextAttributesW(&t->hctx, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &rc) != SEC_E_OK || !rc) return false;
  unsigned char h[32]; DWORD hl = sizeof(h);
  bool ok = CryptHashCertificate(0, CALG_SHA_256, 0, rc->pbCertEncoded, rc->cbCertEncoded, h, &hl) && hl == 32 && !memcmp(h, pin, 32);
  CertFreeCertificateContext(rc); return ok;
}
static bool TlsHandshake(TlsCtx* t, const unsigned char* pin = NULL) {
  for (;;) {
    bool moreWork = false; int r = HandshakeStep(t, &moreWork);
    if (r == 1) break;
    if (r < 0) return false;
    if (!moreWork || t->rawLen == 0) if (RawRecv(t) < 0) return false;
  }
  if (QueryContextAttributesW(&t->hctx, SECPKG_ATTR_STREAM_SIZES, &t->sz) != SEC_E_OK) return false;
  return !pin || TlsPinOk(t, pin);
}
static bool TlsPump(TlsCtx* t) {
  for (;;) {
    if (t->rawLen == 0 && RawRecv(t) <= 0) return false;
    SecBuffer bufs[4]; memset(bufs, 0, sizeof(bufs));
    bufs[0].pvBuffer = t->raw; bufs[0].cbBuffer = (unsigned long)t->rawLen; bufs[0].BufferType = SECBUFFER_DATA;
    SecBufferDesc d = { SECBUFFER_VERSION, 4, bufs };
    SECURITY_STATUS st = DecryptMessage(&t->hctx, &d, 0, NULL);
    if (st == SEC_E_INCOMPLETE_MESSAGE) { if (RawRecv(t) <= 0) return false; continue; }
    if (st != SEC_E_OK) return false;
    size_t extra = ExtraLen(bufs, 4);
    for (int i = 0; i < 4; i++) {
      if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].cbBuffer > 0) {
        size_t oldLen = t->decLen - t->decPos;
        if (oldLen > 0) memmove(t->dec, t->dec + t->decPos, oldLen);
        char* p = (char*)realloc(t->dec, oldLen + bufs[i].cbBuffer); if (!p) return false;
        t->dec = p; memcpy(t->dec + oldLen, bufs[i].pvBuffer, bufs[i].cbBuffer);
        t->decLen = oldLen + bufs[i].cbBuffer; t->decPos = 0;
      }
    }
    RawErase(t, t->rawLen - extra);
    if (extra == 0) return true;
  }
}
static bool TlsRecv(TlsCtx* t, void* p, size_t n) {
  char* q = (char*)p;
  while (n) {
    size_t avail = t->decLen - t->decPos;
    if (avail == 0) {
      if (t->dec) { free(t->dec); t->dec = NULL; }
      t->decLen = 0; t->decPos = 0;
      if (!TlsPump(t) || t->decLen == 0) return false;
      continue;
    }
    size_t take = (avail < n) ? avail : n;
    memcpy(q, t->dec + t->decPos, take); t->decPos += take; q += take; n -= take;
  }
  return true;
}
static bool TlsSend(TlsCtx* t, const void* p, size_t n) {
  const char* q = (const char*)p;
  size_t maxChunk = t->sz.cbMaximumMessage ? t->sz.cbMaximumMessage : 16384;
  bool ok = true;
  EnterCriticalSection(&t->sendCs);
  while (n) {
    size_t chunk = (n < maxChunk) ? n : maxChunk;
    char* buf = (char*)malloc(t->sz.cbHeader + chunk + t->sz.cbTrailer);
    if (!buf) { ok = false; break; }
    memcpy(buf + t->sz.cbHeader, q, chunk);
    SecBuffer bufs[4]; memset(bufs, 0, sizeof(bufs));
    bufs[0].cbBuffer = t->sz.cbHeader; bufs[0].BufferType = SECBUFFER_STREAM_HEADER; bufs[0].pvBuffer = buf;
    bufs[1].cbBuffer = chunk; bufs[1].BufferType = SECBUFFER_DATA; bufs[1].pvBuffer = buf + t->sz.cbHeader;
    bufs[2].cbBuffer = t->sz.cbTrailer; bufs[2].BufferType = SECBUFFER_STREAM_TRAILER; bufs[2].pvBuffer = buf + t->sz.cbHeader + chunk;
    bufs[3].BufferType = SECBUFFER_EMPTY;
    SecBufferDesc d = { SECBUFFER_VERSION, 4, bufs };
    ok = EncryptMessage(&t->hctx, 0, &d, 0) == SEC_E_OK &&
         SendFull(t->sock, buf, bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer);
    free(buf);
    if (!ok) break;
    q += chunk; n -= chunk;
  }
  LeaveCriticalSection(&t->sendCs);
  return ok;
}
static bool TlsSendMsg(TlsCtx* t, uint16_t cmd, const void* p, uint32_t n) {
  WireHdr h; h.len = n; h.cmd = cmd;
  EnterCriticalSection(&t->sendCs);
  bool ok = TlsSend(t, &h, sizeof(h)) && (n == 0 || TlsSend(t, p, n));
  LeaveCriticalSection(&t->sendCs); return ok;
}
static bool TlsRecvMsg(TlsCtx* t, uint16_t* cmd, char** out, uint32_t* outLen) {
  WireHdr h;
  if (!TlsRecv(t, &h, sizeof(h))) return false;
  *cmd = (uint16_t)h.cmd; *outLen = h.len;
  if (h.len > MAX_MSG) return false;
  if (h.len == 0) { *out = NULL; return true; }
  *out = (char*)malloc(h.len + 1); if (!*out) return false;
  if (!TlsRecv(t, *out, h.len)) { free(*out); *out = NULL; return false; }
  (*out)[h.len] = 0;
  return true;
}
