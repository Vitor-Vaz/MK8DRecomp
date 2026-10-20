// Small services: parental control, add-on content, and other mostly-stubbed interfaces.
#include <string.h>

#include "../hle.h"
#include "../ipc.h"

static void ok_logger(Service *s, IpcReq *req, IpcResp *resp) {
    LOG("[svc] %s cmd %u (ok)\n", s->name, req->cmd);
    resp_size(resp, 0x10);
}

static uint32_t new_event_handle(void) {
    uint32_t w, r;
    kernel_create_event_pair(&w, &r);
    return r;
}

// ------------------------------------------------------------------ pctl
static void pctl_service(Service *s, IpcReq *req, IpcResp *resp) {
    (void)s;
    switch (req->cmd) {
    case 1031: case 1035: case 1018: OUT(uint8_t, 0) = 0; resp_size(resp, 1); break;  // restrictions off
    case 1032: OUT(uint32_t, 0) = 0; resp_size(resp, 4); break;
    default: LOG("[pctl] IParentalControlService cmd %u (ok)\n", req->cmd); resp_size(resp, 0x10);
    }
}

static void pctl_root(Service *s, IpcReq *req, IpcResp *resp) {
    (void)s;
    if (req->cmd == 0 || req->cmd == 1)
        ipc_return_object(resp, service_new("IParentalControlService", pctl_service, NULL));
}
SERVICE("pctl", pctl) { pctl_root(s, req, resp); }
SERVICE("pctl:s", pctl_s) { pctl_root(s, req, resp); }
SERVICE("pctl:a", pctl_a) { pctl_root(s, req, resp); }
SERVICE("pctl:r", pctl_r) { pctl_root(s, req, resp); }

// ------------------------------------------------------------------ aoc:u (no DLC)
SERVICE("aoc:u", aoc_u) {
    (void)s;
    switch (req->cmd) {
    case 2: OUT(uint32_t, 0) = 0; resp_size(resp, 4); break;   // CountAddOnContent
    case 3: OUT(uint32_t, 0) = 0; resp_size(resp, 4); break;   // ListAddOnContent
    case 5: OUT(uint64_t, 0) = 0x0100152000023000ull; resp_size(resp, 8); break;  // GetAddOnContentBaseId (MK8D)
    case 8: resp->copy_handles[resp->ncopy++] = new_event_handle(); break;
    default: ok_logger(s, req, resp);
    }
}

// ------------------------------------------------------------------ mii:e / mii:u
static void mii_db_service(Service *s, IpcReq *req, IpcResp *resp) {
    (void)s;
    switch (req->cmd) {
    case 0: case 1: OUT(uint8_t, 0) = 0; resp_size(resp, 1); break;  // IsUpdated, IsFullDatabase
    case 2: case 3: case 4: case 5: OUT(uint32_t, 0) = 0; resp_size(resp, 4); break;  // GetCount, Get, Get1, UpdateLatest
    default: LOG("[mii] IDatabaseService cmd %u (ok)\n", req->cmd); resp_size(resp, 0x58); break;
    }
}

static void mii_root(Service *s, IpcReq *req, IpcResp *resp) {
    (void)s;
    if (req->cmd == 0)
        ipc_return_object(resp, service_new("IDatabaseService", mii_db_service, NULL));
    else
        ok_logger(s, req, resp);
}
SERVICE("mii:e", mii_e) { mii_root(s, req, resp); }
SERVICE("mii:u", mii_u) { mii_root(s, req, resp); }

// ------------------------------------------------------------------ nn::crypto::detail bignum asm helpers (STT_NOTYPE in sdk)
HLE_FUNC("nndetailCryptoBignumMulAddWords", crypto_bn_mul_add_words) {
    uint32_t *rp = (uint32_t *)(uintptr_t)c->x[0];
    const uint32_t *ap = (const uint32_t *)(uintptr_t)c->x[1];
    int num = (int)c->x[2];
    uint64_t w = (uint32_t)c->x[3], carry = 0;
    for (int i = 0; i < num; i++) {
        uint64_t t = (uint64_t)rp[i] + (uint64_t)ap[i] * w + carry;
        rp[i] = (uint32_t)t;
        carry = t >> 32;
    }
    c->x[0] = carry;
}

HLE_FUNC("nndetailCryptoBignumMulWords", crypto_bn_mul_words) {
    uint32_t *rp = (uint32_t *)(uintptr_t)c->x[0];
    const uint32_t *ap = (const uint32_t *)(uintptr_t)c->x[1];
    int num = (int)c->x[2];
    uint64_t w = (uint32_t)c->x[3], carry = 0;
    for (int i = 0; i < num; i++) {
        uint64_t t = (uint64_t)ap[i] * w + carry;
        rp[i] = (uint32_t)t;
        carry = t >> 32;
    }
    c->x[0] = carry;
}

HLE_FUNC("nndetailCryptoBignumAddWords", crypto_bn_add_words) {
    uint32_t *rp = (uint32_t *)(uintptr_t)c->x[0];
    const uint32_t *ap = (const uint32_t *)(uintptr_t)c->x[1];
    const uint32_t *bp = (const uint32_t *)(uintptr_t)c->x[2];
    int num = (int)c->x[3];
    uint64_t carry = 0;
    for (int i = 0; i < num; i++) {
        uint64_t t = (uint64_t)ap[i] + (uint64_t)bp[i] + carry;
        rp[i] = (uint32_t)t;
        carry = t >> 32;
    }
    c->x[0] = carry;
}

HLE_FUNC("nndetailCryptoBignumSubWords", crypto_bn_sub_words) {
    uint32_t *rp = (uint32_t *)(uintptr_t)c->x[0];
    const uint32_t *ap = (const uint32_t *)(uintptr_t)c->x[1];
    const uint32_t *bp = (const uint32_t *)(uintptr_t)c->x[2];
    int num = (int)c->x[3];
    uint64_t borrow = 0;
    for (int i = 0; i < num; i++) {
        uint64_t a = ap[i], b = (uint64_t)bp[i] + borrow;
        rp[i] = (uint32_t)(a - b);
        borrow = a < b ? 1 : 0;
    }
    c->x[0] = borrow;
}

HLE_FUNC("nndetailCryptoBignum_mul_comba8", crypto_bn_mul_comba8) {
    uint32_t *r = (uint32_t *)(uintptr_t)c->x[0];
    const uint32_t *a = (const uint32_t *)(uintptr_t)c->x[1];
    const uint32_t *b = (const uint32_t *)(uintptr_t)c->x[2];
    uint64_t acc[16] = {0};
    for (int i = 0; i < 8; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t t = acc[i + j] + (uint64_t)a[i] * (uint64_t)b[j] + carry;
            acc[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        acc[i + 8] = carry;
    }
    for (int i = 0; i < 16; i++) r[i] = (uint32_t)acc[i];
}

HLE_FUNC("nndetailCryptoBignum_sqr_comba8", crypto_bn_sqr_comba8) {
    uint32_t *r = (uint32_t *)(uintptr_t)c->x[0];
    const uint32_t *a = (const uint32_t *)(uintptr_t)c->x[1];
    uint64_t acc[16] = {0};
    for (int i = 0; i < 8; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t t = acc[i + j] + (uint64_t)a[i] * (uint64_t)a[j] + carry;
            acc[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        acc[i + 8] = carry;
    }
    for (int i = 0; i < 16; i++) r[i] = (uint32_t)acc[i];
}
