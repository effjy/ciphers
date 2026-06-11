/*
 * crypto.c - Ciphers core encryption engine.
 *
 * File format (all integers little-endian):
 *
 *   offset  size  field
 *   ------  ----  -----------------------------------------------------------
 *   0       8     magic  "CIPHERS\0"
 *   8       1     format_version (currently 1)
 *   9       1     cipher_id
 *   10      1     kdf_id (1 = Argon2id)
 *   11      1     kdf_level (informational)
 *   12      4     argon2 t_cost (iterations)
 *   16      4     argon2 m_cost (KiB)
 *   20      4     argon2 parallelism (lanes/threads)
 *   24      16    salt
 *   40      N     base nonce (N = cipher nonce length)
 *   ...           sequence of frames
 *
 * Each frame: [uint32 clen][clen bytes AEAD ciphertext+tag].
 * The plaintext is split into 64 KiB chunks. Per-chunk nonce = base nonce
 * with a 64-bit little-endian counter XORed into its trailing 8 bytes.
 * Associated data per chunk = counter(8) || final_flag(1), which
 * authenticates chunk ordering and detects truncation of the stream.
 */
#include "crypto.h"

#include <sodium.h>
#include <argon2.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#define MAGIC          "CIPHERS\0"
#define MAGIC_LEN      8
#define FORMAT_VERSION 1
#define KDF_ID_ARGON2ID 1
#define SALT_LEN       16
#define CHUNK_SIZE     65536
#define MAX_NONCE_LEN  24
#define MAX_TAG_LEN    16

/* Upper bounds on KDF parameters accepted from a file header on decryption.
 * A header is untrusted input; without these limits a malicious file could
 * request a multi-terabyte Argon2id allocation (instant OOM) or an absurd
 * iteration/lane count that hangs the process. The ceilings comfortably
 * cover the STRONG preset (4 GiB / t=4 / 8 lanes). */
#define MAX_KDF_M_COST    (4u * 1024u * 1024u)  /* KiB = 4 GiB */
#define MAX_KDF_T_COST    16u
#define MAX_KDF_PARALLEL  16u

/* ----- Cipher registry -------------------------------------------------- */

typedef int (*aead_encrypt_fn)(unsigned char *c, unsigned long long *clen,
                               const unsigned char *m, unsigned long long mlen,
                               const unsigned char *ad, unsigned long long adlen,
                               const unsigned char *nonce, const unsigned char *key);

typedef int (*aead_decrypt_fn)(unsigned char *m, unsigned long long *mlen,
                               const unsigned char *c, unsigned long long clen,
                               const unsigned char *ad, unsigned long long adlen,
                               const unsigned char *nonce, const unsigned char *key);

/* Adapters to give both AEADs a uniform signature (drop the unused
 * nsec argument that libsodium's combined-mode functions expose). */
static int aes_enc(unsigned char *c, unsigned long long *clen,
                   const unsigned char *m, unsigned long long mlen,
                   const unsigned char *ad, unsigned long long adlen,
                   const unsigned char *n, const unsigned char *k) {
    return crypto_aead_aes256gcm_encrypt(c, clen, m, mlen, ad, adlen, NULL, n, k);
}
static int aes_dec(unsigned char *m, unsigned long long *mlen,
                   const unsigned char *c, unsigned long long clen,
                   const unsigned char *ad, unsigned long long adlen,
                   const unsigned char *n, const unsigned char *k) {
    return crypto_aead_aes256gcm_decrypt(m, mlen, NULL, c, clen, ad, adlen, n, k);
}
static int xchacha_enc(unsigned char *c, unsigned long long *clen,
                       const unsigned char *m, unsigned long long mlen,
                       const unsigned char *ad, unsigned long long adlen,
                       const unsigned char *n, const unsigned char *k) {
    return crypto_aead_xchacha20poly1305_ietf_encrypt(c, clen, m, mlen, ad, adlen, NULL, n, k);
}
static int xchacha_dec(unsigned char *m, unsigned long long *mlen,
                       const unsigned char *c, unsigned long long clen,
                       const unsigned char *ad, unsigned long long adlen,
                       const unsigned char *n, const unsigned char *k) {
    return crypto_aead_xchacha20poly1305_ietf_decrypt(m, mlen, NULL, c, clen, ad, adlen, n, k);
}
static int chacha_ietf_enc(unsigned char *c, unsigned long long *clen,
                           const unsigned char *m, unsigned long long mlen,
                           const unsigned char *ad, unsigned long long adlen,
                           const unsigned char *n, const unsigned char *k) {
    return crypto_aead_chacha20poly1305_ietf_encrypt(c, clen, m, mlen, ad, adlen, NULL, n, k);
}
static int chacha_ietf_dec(unsigned char *m, unsigned long long *mlen,
                           const unsigned char *c, unsigned long long clen,
                           const unsigned char *ad, unsigned long long adlen,
                           const unsigned char *n, const unsigned char *k) {
    return crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen, NULL, c, clen, ad, adlen, n, k);
}

typedef struct {
    cipher_id_t      id;
    const char      *name;
    size_t           key_len;
    size_t           nonce_len;
    size_t           tag_len;
    aead_encrypt_fn  encrypt;
    aead_decrypt_fn  decrypt;
} cipher_t;

/* To add a new cipher later (e.g. Serpent), append an entry here and a
 * matching id in crypto.h. Nothing else needs to change. */
static const cipher_t g_ciphers[] = {
    { CIPHER_AES_256_GCM, "AES-256-GCM",
      crypto_aead_aes256gcm_KEYBYTES, crypto_aead_aes256gcm_NPUBBYTES,
      crypto_aead_aes256gcm_ABYTES, aes_enc, aes_dec },
    { CIPHER_XCHACHA20_POLY1305, "XChaCha20-Poly1305",
      crypto_aead_xchacha20poly1305_ietf_KEYBYTES, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
      crypto_aead_xchacha20poly1305_ietf_ABYTES, xchacha_enc, xchacha_dec },
    { CIPHER_CHACHA20_POLY1305_IETF, "ChaCha20-Poly1305",
      crypto_aead_chacha20poly1305_ietf_KEYBYTES, crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
      crypto_aead_chacha20poly1305_ietf_ABYTES, chacha_ietf_enc, chacha_ietf_dec },
};
static const size_t g_ciphers_n = sizeof(g_ciphers) / sizeof(g_ciphers[0]);

static const cipher_t *find_cipher(cipher_id_t id) {
    for (size_t i = 0; i < g_ciphers_n; i++)
        if (g_ciphers[i].id == id) return &g_ciphers[i];
    return NULL;
}

const char *ciphers_cipher_name(cipher_id_t id) {
    const cipher_t *c = find_cipher(id);
    return c ? c->name : NULL;
}

int ciphers_cipher_available(cipher_id_t id) {
    if (id == CIPHER_AES_256_GCM)
        return crypto_aead_aes256gcm_is_available() ? 1 : 0;
    return find_cipher(id) != NULL;
}

/* ----- KDF -------------------------------------------------------------- */

typedef struct {
    uint32_t t_cost;
    uint32_t m_cost;       /* KiB */
    uint32_t parallelism;
} kdf_params_t;

static void kdf_params_for_level(kdf_level_t level, kdf_params_t *p) {
    switch (level) {
    case KDF_BASIC:
        p->t_cost = 3;  p->m_cost = 256u * 1024u;  p->parallelism = 4; /* 256 MiB */
        break;
    case KDF_STRONG:
        p->t_cost = 4;  p->m_cost = 4u * 1024u * 1024u; p->parallelism = 8; /* 4 GiB */
        break;
    case KDF_MEDIUM:
    default:
        p->t_cost = 3;  p->m_cost = 1u * 1024u * 1024u; p->parallelism = 4; /* 1 GiB */
        break;
    }
}

static int derive_key(const char *password, const uint8_t *salt,
                      const kdf_params_t *p, uint8_t *key, size_t key_len) {
    int rc = argon2id_hash_raw(p->t_cost, p->m_cost, p->parallelism,
                               password, strlen(password),
                               salt, SALT_LEN, key, key_len);
    return rc == ARGON2_OK ? 0 : -1;
}

/* ----- Little-endian helpers ------------------------------------------- */

static void put_u32(uint8_t *b, uint32_t v) {
    b[0] = v & 0xff; b[1] = (v >> 8) & 0xff;
    b[2] = (v >> 16) & 0xff; b[3] = (v >> 24) & 0xff;
}
static uint32_t get_u32(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

/* Build per-chunk nonce: base nonce XOR counter into trailing 8 bytes. */
static void chunk_nonce(uint8_t *out, const uint8_t *base, size_t nlen, uint64_t ctr) {
    memcpy(out, base, nlen);
    for (int i = 0; i < 8; i++)
        out[nlen - 8 + i] ^= (uint8_t)((ctr >> (8 * i)) & 0xff);
}

static void seterr(char *err, size_t errlen, const char *msg) {
    if (err && errlen) { snprintf(err, errlen, "%s", msg); }
}

/* Returns 1 if the two paths refer to the same existing file (same device
 * and inode, so symlinks/hardlinks are caught too). Prevents the output
 * from clobbering the input, which "wb" would otherwise truncate. */
static int same_file(const char *a, const char *b) {
    struct stat sa, sb;
    if (stat(a, &sa) != 0 || stat(b, &sb) != 0) return 0;
    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

/* Build a sibling temporary path "<out_path>.ciphers-tmp" into buf. We write
 * output here and rename() onto out_path only on success, so a pre-existing
 * output file is never truncated or deleted by a failed/cancelled operation
 * (e.g. a wrong decryption password). Returns 0 on success, -1 if the name
 * would not fit. */
static int make_tmp_path(const char *out_path, char *buf, size_t buflen) {
    int n = snprintf(buf, buflen, "%s.ciphers-tmp", out_path);
    return (n < 0 || (size_t)n >= buflen) ? -1 : 0;
}

/* ----- Public API ------------------------------------------------------- */

int ciphers_init(void) {
    if (sodium_init() < 0) return -1;

    /* Keep secrets off disk. Core dumps can contain the derived key, the
     * password and plaintext, so disable them; on Linux also clear the
     * dumpable flag (blocks ptrace and /proc-based core capture). Locked
     * pages (sodium_mlock, used per-operation below) cover the swap file:
     * mlock pins them in RAM and marks them MADV_DONTDUMP. */
    struct rlimit rl = { 0, 0 };
    setrlimit(RLIMIT_CORE, &rl);
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
    return 0;
}

int ciphers_encrypt_file(const char *in_path, const char *out_path,
                         const char *password, cipher_id_t cipher_id,
                         kdf_level_t level,
                         ciphers_progress_cb cb, void *cb_user,
                         char *err, size_t errlen) {
    if (!password || !*password) {
        seterr(err, errlen, "A password is required."); return -1;
    }
    const cipher_t *cph = find_cipher(cipher_id);
    if (!cph) { seterr(err, errlen, "Unknown cipher."); return -1; }
    if (!ciphers_cipher_available(cipher_id)) {
        seterr(err, errlen, "Cipher not supported on this CPU (AES-256-GCM needs hardware AES).");
        return -1;
    }

    if (same_file(in_path, out_path)) {
        seterr(err, errlen, "Input and output must be different files.");
        return -1;
    }

    char tmp_path[4096 + 16];
    if (make_tmp_path(out_path, tmp_path, sizeof(tmp_path)) != 0) {
        seterr(err, errlen, "Output path is too long."); return -1;
    }

    FILE *in = fopen(in_path, "rb");
    if (!in) { seterr(err, errlen, "Cannot open input file."); return -1; }
    FILE *out = fopen(tmp_path, "wb");
    if (!out) { seterr(err, errlen, "Cannot open output file."); fclose(in); return -1; }

    int ret = -1;
    uint8_t key[64]; /* >= any key_len */
    uint8_t salt[SALT_LEN];
    uint8_t base_nonce[MAX_NONCE_LEN];
    /* Pin the key (and, below, the plaintext) in RAM so they cannot be
     * written to swap, and mark them non-dumpable. munlock at 'done' also
     * zeroes them. */
    sodium_mlock(key, sizeof(key));
    kdf_params_t kp;
    kdf_params_for_level(level, &kp);

    randombytes_buf(salt, SALT_LEN);
    randombytes_buf(base_nonce, cph->nonce_len);

    if (derive_key(password, salt, &kp, key, cph->key_len) != 0) {
        seterr(err, errlen, "Key derivation failed (insufficient memory for this KDF level?).");
        goto done;
    }

    /* Header */
    uint8_t hdr[40];
    memcpy(hdr, MAGIC, MAGIC_LEN);
    hdr[8]  = FORMAT_VERSION;
    hdr[9]  = (uint8_t)cipher_id;
    hdr[10] = KDF_ID_ARGON2ID;
    hdr[11] = (uint8_t)level;
    put_u32(hdr + 12, kp.t_cost);
    put_u32(hdr + 16, kp.m_cost);
    put_u32(hdr + 20, kp.parallelism);
    memcpy(hdr + 24, salt, SALT_LEN);
    if (fwrite(hdr, 1, sizeof(hdr), out) != sizeof(hdr) ||
        fwrite(base_nonce, 1, cph->nonce_len, out) != cph->nonce_len) {
        seterr(err, errlen, "Write error."); goto done;
    }

    /* Determine total size for progress. */
    uint64_t total = 0;
    if (fseek(in, 0, SEEK_END) == 0) { long t = ftell(in); if (t > 0) total = (uint64_t)t; }
    rewind(in);

    uint8_t  plain[CHUNK_SIZE];
    uint8_t  ct[CHUNK_SIZE + MAX_TAG_LEN];
    uint8_t  nonce[MAX_NONCE_LEN];
    uint8_t  ad[9];
    uint8_t  lenbuf[4];
    uint64_t ctr = 0, done_bytes = 0;
    sodium_mlock(plain, sizeof(plain));   /* holds cleartext */

    for (;;) {
        size_t n = fread(plain, 1, CHUNK_SIZE, in);
        if (n == 0 && !feof(in)) { seterr(err, errlen, "Read error."); goto done; }
        int final = feof(in) ? 1 : 0;

        put_u32(ad, (uint32_t)(ctr & 0xffffffff));
        ad[4] = (uint8_t)((ctr >> 32) & 0xff);
        ad[5] = (uint8_t)((ctr >> 40) & 0xff);
        ad[6] = (uint8_t)((ctr >> 48) & 0xff);
        ad[7] = (uint8_t)((ctr >> 56) & 0xff);
        ad[8] = (uint8_t)final;

        chunk_nonce(nonce, base_nonce, cph->nonce_len, ctr);

        unsigned long long clen = 0;
        if (cph->encrypt(ct, &clen, plain, n, ad, sizeof(ad), nonce, key) != 0) {
            seterr(err, errlen, "Encryption failed."); goto done;
        }
        put_u32(lenbuf, (uint32_t)clen);
        if (fwrite(lenbuf, 1, 4, out) != 4 ||
            fwrite(ct, 1, (size_t)clen, out) != (size_t)clen) {
            seterr(err, errlen, "Write error."); goto done;
        }

        done_bytes += n;
        if (cb && cb(done_bytes, total, cb_user) != 0) {
            seterr(err, errlen, "Cancelled."); goto done;
        }
        ctr++;
        if (final) break;
    }

    ret = 0;
done:
    /* munlock zeroes the buffers before unpinning them. (Safe to call even
     * if we jumped here before mlocking 'plain'.) */
    sodium_munlock(key, sizeof(key));
    sodium_munlock(plain, sizeof(plain));
    fclose(in);
    /* Flush and confirm the temp file is intact before promoting it. */
    if (ret == 0 && (fflush(out) != 0 || ferror(out))) {
        seterr(err, errlen, "Write error."); ret = -1;
    }
    fclose(out);
    if (ret == 0 && rename(tmp_path, out_path) != 0) {
        seterr(err, errlen, "Could not write output file."); ret = -1;
    }
    /* Only ever remove our own temp file, never a pre-existing output. */
    if (ret != 0) remove(tmp_path);
    return ret;
}

int ciphers_decrypt_file(const char *in_path, const char *out_path,
                         const char *password,
                         ciphers_progress_cb cb, void *cb_user,
                         char *err, size_t errlen) {
    if (same_file(in_path, out_path)) {
        seterr(err, errlen, "Input and output must be different files.");
        return -1;
    }

    char tmp_path[4096 + 16];
    if (make_tmp_path(out_path, tmp_path, sizeof(tmp_path)) != 0) {
        seterr(err, errlen, "Output path is too long."); return -1;
    }

    FILE *in = fopen(in_path, "rb");
    if (!in) { seterr(err, errlen, "Cannot open input file."); return -1; }

    int ret = -1;
    FILE *out = NULL;
    uint8_t key[64];
    /* Pin the key (and, below, the recovered plaintext) in RAM: no swap,
     * non-dumpable, zeroed on munlock at 'done'. */
    sodium_mlock(key, sizeof(key));

    uint8_t hdr[40];
    if (fread(hdr, 1, sizeof(hdr), in) != sizeof(hdr) ||
        memcmp(hdr, MAGIC, MAGIC_LEN) != 0) {
        seterr(err, errlen, "Not a Ciphers file (bad magic)."); goto done;
    }
    if (hdr[8] != FORMAT_VERSION) {
        seterr(err, errlen, "Unsupported file format version."); goto done;
    }
    cipher_id_t cipher_id = (cipher_id_t)hdr[9];
    const cipher_t *cph = find_cipher(cipher_id);
    if (!cph) { seterr(err, errlen, "Unknown cipher in file."); goto done; }
    if (!ciphers_cipher_available(cipher_id)) {
        seterr(err, errlen, "Cipher in file not supported on this CPU."); goto done;
    }
    if (hdr[10] != KDF_ID_ARGON2ID) {
        seterr(err, errlen, "Unknown KDF in file."); goto done;
    }

    kdf_params_t kp;
    kp.t_cost = get_u32(hdr + 12);
    kp.m_cost = get_u32(hdr + 16);
    kp.parallelism = get_u32(hdr + 20);

    /* The header is untrusted: reject parameters that would make Argon2id
     * exhaust memory or hang. Legitimate files never exceed these bounds. */
    if (kp.t_cost == 0 || kp.t_cost > MAX_KDF_T_COST ||
        kp.m_cost < 8u || kp.m_cost > MAX_KDF_M_COST ||
        kp.parallelism == 0 || kp.parallelism > MAX_KDF_PARALLEL) {
        seterr(err, errlen, "Invalid or unsafe KDF parameters in file."); goto done;
    }

    uint8_t base_nonce[MAX_NONCE_LEN];
    if (fread(base_nonce, 1, cph->nonce_len, in) != cph->nonce_len) {
        seterr(err, errlen, "Truncated header."); goto done;
    }

    if (derive_key(password, hdr + 24, &kp, key, cph->key_len) != 0) {
        seterr(err, errlen, "Key derivation failed."); goto done;
    }

    out = fopen(tmp_path, "wb");
    if (!out) { seterr(err, errlen, "Cannot open output file."); goto done; }

    /* total = remaining file size for progress. done_bytes (below) counts
     * each frame's 4-byte length prefix plus its ciphertext so the fraction
     * tracks the actual bytes consumed and reaches 100% at the end. */
    uint64_t total = 0;
    long cur = ftell(in);
    if (cur >= 0 && fseek(in, 0, SEEK_END) == 0) {
        long e = ftell(in);
        if (e > cur) total = (uint64_t)(e - cur);
        fseek(in, cur, SEEK_SET);   /* only restore if we actually moved */
    }

    uint8_t  ct[CHUNK_SIZE + MAX_TAG_LEN];
    uint8_t  plain[CHUNK_SIZE + MAX_TAG_LEN];
    uint8_t  nonce[MAX_NONCE_LEN];
    uint8_t  ad[9];
    uint8_t  lenbuf[4];
    uint64_t ctr = 0, done_bytes = 0;
    int saw_final = 0;
    sodium_mlock(plain, sizeof(plain));   /* holds recovered cleartext */

    for (;;) {
        size_t r = fread(lenbuf, 1, 4, in);
        if (r == 0 && feof(in)) break;          /* clean end of frames */
        if (r != 4) { seterr(err, errlen, "Truncated file."); goto done; }
        uint32_t clen = get_u32(lenbuf);
        if (clen > sizeof(ct) || clen < cph->tag_len) {
            seterr(err, errlen, "Corrupt frame length."); goto done;
        }
        if (fread(ct, 1, clen, in) != clen) {
            seterr(err, errlen, "Truncated file."); goto done;
        }

        /* Peek whether another frame follows to know if this is final. */
        int final = 0;
        int ch = fgetc(in);
        if (ch == EOF) final = 1; else ungetc(ch, in);

        put_u32(ad, (uint32_t)(ctr & 0xffffffff));
        ad[4] = (uint8_t)((ctr >> 32) & 0xff);
        ad[5] = (uint8_t)((ctr >> 40) & 0xff);
        ad[6] = (uint8_t)((ctr >> 48) & 0xff);
        ad[7] = (uint8_t)((ctr >> 56) & 0xff);
        ad[8] = (uint8_t)final;

        chunk_nonce(nonce, base_nonce, cph->nonce_len, ctr);

        unsigned long long mlen = 0;
        if (cph->decrypt(plain, &mlen, ct, clen, ad, sizeof(ad), nonce, key) != 0) {
            seterr(err, errlen, "Decryption failed: wrong password or corrupted/tampered file.");
            goto done;
        }
        if (mlen && fwrite(plain, 1, (size_t)mlen, out) != (size_t)mlen) {
            seterr(err, errlen, "Write error."); goto done;
        }

        done_bytes += (uint64_t)clen + 4u;   /* ciphertext + length prefix */
        if (cb && cb(done_bytes, total, cb_user) != 0) {
            seterr(err, errlen, "Cancelled."); goto done;
        }
        ctr++;
        if (final) { saw_final = 1; break; }
    }

    if (!saw_final) { seterr(err, errlen, "File is truncated (missing final block)."); goto done; }
    ret = 0;
done:
    /* munlock zeroes the buffers before unpinning them. (Safe to call even
     * if we jumped here before mlocking 'plain'.) */
    sodium_munlock(key, sizeof(key));
    sodium_munlock(plain, sizeof(plain));
    if (in) fclose(in);
    if (out) {
        if (ret == 0 && (fflush(out) != 0 || ferror(out))) {
            seterr(err, errlen, "Write error."); ret = -1;
        }
        fclose(out);
        if (ret == 0 && rename(tmp_path, out_path) != 0) {
            seterr(err, errlen, "Could not write output file."); ret = -1;
        }
        /* Only ever remove our own temp file, never a pre-existing output. */
        if (ret != 0) remove(tmp_path);
    }
    return ret;
}
