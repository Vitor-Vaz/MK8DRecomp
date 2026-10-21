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
static void make_mii_char_info(uint8_t *ci, int idx, const char *name) {
    memset(ci, 0, 0x58);
    // create_id: 16 bytes UUID
    ci[0] = 0x12; ci[1] = 0x34; ci[2] = 0x56; ci[3] = 0x78 + (uint8_t)idx;
    ci[15] = (uint8_t)(idx + 1);
    // Nickname UTF-16LE (up to 10 chars at +0x10)
    for (int i = 0; name[i] && i < 10; i++) {
        ((uint16_t *)(ci + 0x10))[i] = (uint16_t)name[i];
    }
    ci[0x26] = 0;   // font_region
    ci[0x27] = (uint8_t)(idx % 12);  // favorite_color
    ci[0x28] = (idx == 2) ? 1 : 0;   // gender (0=male, 1=female)
    ci[0x29] = 64;  // height
    ci[0x2A] = 64;  // build
    ci[0x2B] = 0;   // type
    ci[0x2C] = 0;   // region_move
    ci[0x2D] = 0;   // faceline_type
    ci[0x2E] = 0;   // faceline_color
    ci[0x2F] = 0;   // faceline_wrinkle
    ci[0x30] = 0;   // faceline_make
    ci[0x31] = (uint8_t)(idx % 6);    // hair_type
    ci[0x32] = 8;   // hair_color
    ci[0x33] = 0;   // hair_flip
    ci[0x34] = 0;   // eye_type
    ci[0x35] = 8;   // eye_color
    ci[0x36] = 4;   // eye_scale
    ci[0x37] = 3;   // eye_aspect
    ci[0x38] = 4;   // eye_rotate
    ci[0x39] = 2;   // eye_x
    ci[0x3A] = 12;  // eye_y
    ci[0x3B] = 0;   // eyebrow_type
    ci[0x3C] = 8;   // eyebrow_color
    ci[0x3D] = 4;   // eyebrow_scale
    ci[0x3E] = 3;   // eyebrow_aspect
    ci[0x3F] = 4;   // eyebrow_rotate
    ci[0x40] = 2;   // eyebrow_x
    ci[0x41] = 10;  // eyebrow_y
    ci[0x42] = 0;   // nose_type
    ci[0x43] = 4;   // nose_scale
    ci[0x44] = 9;   // nose_y
    ci[0x45] = 0;   // mouth_type
    ci[0x46] = 19;  // mouth_color
    ci[0x47] = 4;   // mouth_scale
    ci[0x48] = 3;   // mouth_aspect
    ci[0x49] = 13;  // mouth_y
    ci[0x4A] = (idx == 0 || idx == 1) ? 1 : 0; // mustache_type
    ci[0x4B] = 0;   // beard_type
    ci[0x4C] = 8;   // beard_color
    ci[0x4D] = 4;   // mustache_scale
    ci[0x4E] = 10;  // mustache_y
    ci[0x4F] = 0;   // glass_type
    ci[0x50] = 0;   // glass_color
    ci[0x51] = 4;   // glass_scale
    ci[0x52] = 10;  // glass_y
    ci[0x53] = 0;   // mole_type
    ci[0x54] = 4;   // mole_scale
    ci[0x55] = 2;   // mole_x
    ci[0x56] = 20;  // mole_y
}

static void mii_db_service(Service *s, IpcReq *req, IpcResp *resp) {
    (void)s;
    const char *names[] = { "Mario", "Luigi", "Peach", "Toad" };
    switch (req->cmd) {
    case 0: case 1: // IsUpdated, IsFullDatabase
        OUT(uint8_t, 0) = 0;
        resp_size(resp, 1);
        LOG("[mii] cmd %u (%s) -> 0\n", req->cmd, req->cmd == 0 ? "IsUpdated" : "IsFullDatabase");
        break;
    case 2: // GetCount
        OUT(uint32_t, 0) = 4;
        resp_size(resp, 4);
        LOG("[mii] GetCount -> 4\n");
        break;
    case 3: { // Get(SourceFlag flag, out int count, OutArray<CharInfoElement> elements)
        IpcBuf *b = out_buf(req, 0);
        uint32_t count = 4;
        if (b && b->addr && b->size >= 4 * 0x5C) {
            for (uint32_t i = 0; i < 4; i++) {
                uint8_t *elem = (uint8_t *)(uintptr_t)(b->addr + i * 0x5C);
                make_mii_char_info(elem, i, names[i]);
                *(uint32_t *)(elem + 0x58) = 0; // Source: 0 (Database)
            }
        } else if (b && b->addr && b->size >= 0x5C) {
            count = b->size / 0x5C;
            for (uint32_t i = 0; i < count; i++) {
                uint8_t *elem = (uint8_t *)(uintptr_t)(b->addr + i * 0x5C);
                make_mii_char_info(elem, i, names[i % 4]);
                *(uint32_t *)(elem + 0x58) = 0;
            }
        }
        OUT(uint32_t, 0) = count;
        resp_size(resp, 4);
        LOG("[mii] Get -> %u elements\n", count);
        break;
    }
    case 4: { // Get1(SourceFlag flag, out int count, OutArray<CharInfo> elements)
        IpcBuf *b = out_buf(req, 0);
        uint32_t count = 4;
        if (b && b->addr && b->size >= 4 * 0x58) {
            for (uint32_t i = 0; i < 4; i++) {
                uint8_t *ci = (uint8_t *)(uintptr_t)(b->addr + i * 0x58);
                make_mii_char_info(ci, i, names[i]);
            }
        } else if (b && b->addr && b->size >= 0x58) {
            count = b->size / 0x58;
            for (uint32_t i = 0; i < count; i++) {
                uint8_t *ci = (uint8_t *)(uintptr_t)(b->addr + i * 0x58);
                make_mii_char_info(ci, i, names[i % 4]);
            }
        }
        OUT(uint32_t, 0) = count;
        resp_size(resp, 4);
        LOG("[mii] Get1 -> %u elements\n", count);
        break;
    }
    case 5: // UpdateLatest
        OUT(uint32_t, 0) = 0;
        resp_size(resp, 4);
        LOG("[mii] UpdateLatest -> ok\n");
        break;
    case 6: // BuildRandom(gender, age, race) -> CharInfo (0x58 bytes)
    case 7: { // BuildDefault(index) -> CharInfo (0x58 bytes)
        int32_t idx = req->data_size >= 4 ? IN(int32_t, 0) : 0;
        uint8_t *ci = resp->data;
        const char *name = (idx >= 0 && idx < 4) ? names[idx] : "Player";
        make_mii_char_info(ci, idx, name);
        resp_size(resp, 0x58);
        LOG("[mii] %s index %d -> created '%s'\n", req->cmd == 6 ? "BuildRandom" : "BuildDefault", idx, name);
        break;
    }
    default:
        LOG("[mii] IDatabaseService cmd %u (ok)\n", req->cmd);
        resp_size(resp, 0x58);
        break;
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
