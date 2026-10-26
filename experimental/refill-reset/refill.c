/* Experimental D110_M 4.31 extension. See VALIDATION.md for hardware results.
 * Compile for Cortex-M0; all stock firmware entry points are hash-pinned
 * by build.py. No global/static RAM allocations or external C runtime.
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
#define PTR8(a) ((volatile u8 *)(a))
#define PTR16(a) ((volatile u16 *)(a))
#define PTR32(a) ((volatile u32 *)(a))
#define FN(a, t) ((t)(0x01010001u + (a)))
#define INLINE static __attribute__((always_inline)) inline
typedef void (*VoidFn)(void);
typedef u32 (*CrcFn)(const void *, u32);
typedef int (*CmpFn)(const void *, const void *, u32);
typedef int (*AuthFn)(u32, void *, u8 *);
typedef int (*PageFn)(u32, u32, void *);
typedef void (*CryptoFn)(const void *, void *);
typedef void (*PowerFn)(u32, u32);
typedef int (*FlashFn)(u32, const void *, u32);
typedef int (*DispatchFn)(const u8 *, u8 *, u8 *);
typedef void (*SendFn)(const u8 *, u32, u32);
#define RESTART_COOKIE 0x31524652u
#define RESTART_MARKER PTR32(0x000fab20) /* MLPM.BAKEUP_REG2/3 */

/* Reply status: 0 success; 1 malformed; 2 busy; 3 read/authentication;
 * 4 bad CRC; 5 wrong identity; 6 write failed (rollback verified);
 * 7 readback failed (rollback verified); 8 settings save failed;
 * 9 rollback could not be verified; 10 restart marker failed;
 * 0x10 capability query.
 */
INLINE int equal(const void *a, const void *b, u32 n) {
    return FN(0x204, CmpFn)(a, b, n) == 0;
}
INLINE u32 crc(const void *p, u32 n) {
    return FN(0xb76c, CrcFn)(p, n);
}
INLINE void power(u32 mode) { FN(0x7252, PowerFn)(0, mode); }
INLINE int select_tag(void *uid, u8 *uid_len) {
    /* WUPA/anticollision must start from a fresh tag state, including when
     * reselecting after authenticated reads or before rollback. Stock field
     * control includes its settling delay. No foreground worker runs here.
     */
    power(0);
    power(3);
    return FN(0x533c, AuthFn)(0, uid, uid_len);
}
INLINE void feed(void) { FN(0x2100, VoidFn)(); }
INLINE int page_read(u32 p, void *out) {
    feed();
    return FN(0x541c, PageFn)(0, p, out);
}
INLINE int page_write(u32 p, void *in) {
    feed();
    return FN(0x556a, PageFn)(0, p, in);
}
INLINE int restore_counter(u32 *old, u32 *readback, const u8 *expected_uid) {
    u32 uid[3];
    u8 uid_len = 0;
    if (select_tag(uid, &uid_len) != 0 || uid_len != 8 ||
        !equal(uid, expected_uid, 8)) return 0;
    /* Always attempt both pages, including if the first write reports error. */
    page_write(5, old);
    page_write(6, old + 1);
    return page_read(5, readback) == 0 && equal(old, readback, 8);
}

INLINE u8 reset_reel(const u8 *expected_uid) {
    /* Stock print-start checks plus print-session and update-session guards.
     * Allow only inactive/finished print parser states (0 and 7).
     */
    u8 state = *PTR8(0x203a4);
    if (*PTR8(0x207d0) != 2 || (state != 0 && state != 7) ||
        *PTR8(0x21cf1) || *PTR8(0x21cec) || *PTR8(0x204d5) ||
        *PTR8(0x207f0) == 1 || *PTR8(0x207c8) || *PTR8(0x207ec)) return 2;

    u32 plain[30], readback[4], uid[3], original[2], encrypted[2];
    u8 uid_len = 0;
    u8 result = 3;
    if (select_tag(uid, &uid_len) != 0) goto done;
    if (uid_len != 8 || !equal(uid, expected_uid, 8)) {
        result = 5;
        goto done;
    }
    /* Read all 120 encrypted bytes into local buffers. Do not replace the
     * active roll's RAM record or let stock history lookup restore its count.
     */
    for (u32 offset = 0; offset < 120; offset += 16) {
        if (page_read(5 + offset / 4, readback) != 0) goto done;
        if (offset == 0) {
            original[0] = readback[0]; original[1] = readback[1];
        }
        FN(0x7eb8, CryptoFn)(readback, (u8 *)plain + offset);
        if (offset + 8 < 120)
            FN(0x7eb8, CryptoFn)(readback + 2, (u8 *)plain + offset + 8);
    }
    if (crc(plain, 4) != plain[1] || crc(plain + 2, 108) != plain[29]) {
        result = 4;
        goto done;
    }
    if (!equal(uid, plain + 2, 8)) { result = 5; goto done; }

    /* Preserve the reserved halfword, all identity/type/limit metadata,
     * password, and lock/configuration pages. Only pages 5 and 6 are written.
     */
    plain[0] &= 0xffff;
    plain[1] = crc(plain, 4);
    FN(0x7f18, CryptoFn)(plain, encrypted);
    uid_len = 0;
    if (select_tag(uid, &uid_len) != 0) goto done;
    if (uid_len != 8 || !equal(uid, expected_uid, 8)) { result = 5; goto done; }
    if (page_write(5, encrypted) != 0 || page_write(6, encrypted + 1) != 0) {
        result = restore_counter(original, readback, expected_uid) ? 6 : 9;
        goto done;
    }
    if (page_read(5, readback) != 0 || !equal(readback, encrypted, 8)) {
        result = restore_counter(original, readback, expected_uid) ? 7 : 9;
        goto done;
    }

    /* Prepare the full settings image locally. These default offsets match
     * stock 0x125d8 exactly, including fields outside the history region.
     * Do not mutate active settings until the checked flash write succeeds.
     */
    {
        u32 settings[79];
        u8 *s = (u8 *)settings;
        for (u32 i = 0; i < 79; i++) settings[i] = PTR32(0x20900)[i];
        s[4] = s[5] = s[7] = 3;
        s[6] = s[8] = s[0x128] = s[0x129] = 1;
        s[0x130] = 2;
        for (u32 i = 0x28; i < 0x11c; i++) s[i] = 0;
        settings[0] = crc(s + 4, 0x138);
        feed();
        if (FN(0xc6f0, FlashFn)(0x010ff000, settings, sizeof(settings)) != 0) {
            /* Flash may already be partly modified. Report an error and
             * do not reboot or claim a transactional rollback of flash.
             */
            result = 8;
            goto done;
        }
        for (u32 i = 0; i < 79; i++) PTR32(0x20900)[i] = settings[i];
    }
    /* No foreground NFC/print workers run between this handler and the
     * post-send reboot hook. Clear pending usage before returning success.
     */
    *PTR16(0x20782) = 0;
    *PTR16(0x20784) = 0;
    *PTR16(0x4830a) = 0;
    *PTR8(0x2077e) &= (u8)~0x43;
    *PTR32(0x207e4) &= ~(1u << 19);
    /* SDK backup registers 2/3 have no reset function. Stock application
     * and recovered bootloader do not reference them. Use a cookie and its
     * complement, and verify retention-register writes before ACK/restart.
     * Arm only after the NFC and settings transactions have succeeded.
     */
    FN(0x40c4, void (*)(u32))(1); /* MLPM write-access unlock */
    FN(0x40f0, void (*)(u32))(1); /* MLPM register clock */
    RESTART_MARKER[0] = RESTART_COOKIE;
    RESTART_MARKER[1] = ~RESTART_COOKIE;
    if (RESTART_MARKER[0] != RESTART_COOKIE ||
        RESTART_MARKER[1] != ~RESTART_COOKIE) {
        RESTART_MARKER[0] = RESTART_MARKER[1] = 0;
        result = 10; /* counts saved at zero, but no reboot requested */
        goto done;
    }
    result = 0;
done:
    power(0);
    return result;
}

/* Replaces the single dispatcher call at app offset 0x4eee. Ordinary
 * commands still use the stock dispatcher, including the r1 reset patch.
 */
__attribute__((used))
int refill_dispatch(const u8 *request, u8 *output, u8 *output_len) {
    if (request[3] != 0xf0)
        return FN(0x4d94, DispatchFn)(request, output, output_len);
    u8 status = 1;
    if (request[4] == 1 && request[5] == 0) status = 0x10;
    else if (request[4] == 16 &&
             request[5] == 'R' && request[6] == 'E' &&
             request[7] == 'F' && request[8] == 'I' &&
             request[9] == 'L' && request[10] == 'L' &&
             request[11] == 1 && request[12] == 0xa5)
        status = reset_reel(request + 13);
    /* Wire response F1, payload "RF", protocol version 1, status. */
    output[0] = output[1] = 0x55;
    output[2] = 0xf1; output[3] = 4;
    output[4] = 'R'; output[5] = 'F'; output[6] = 1; output[7] = status;
    output[8] = 0xf1 ^ 4 ^ 'R' ^ 'F' ^ 1 ^ status;
    output[9] = output[10] = 0xaa;
    *output_len = 11;
    return 1;
}

/* Replaces the response-send call at 0x4efc. The send completes before
 * reboot is requested. No extra persistent RAM or interrupt hook is used.
 */
__attribute__((used))
void refill_send(const u8 *packet, u32 length, u32 transport) {
    int reboot = length == 11 && packet[2] == 0xf1 && packet[3] == 4 &&
        packet[4] == 'R' && packet[5] == 'F' && packet[6] == 1 && packet[7] == 0;
    FN(0x4dc4, SendFn)(packet, length, transport);
    if (!reboot) return;
    u32 start = FN(0x78c8, u32 (*)(void))();
    /* Allow 500 ms for the radio/transport interrupt path, feeding the
     * watchdog. Do not run foreground workers that could restore history.
     * An ACK is best effort: the caller must reconnect and check the result.
     */
    while (!FN(0x78d4, int (*)(u32, u32))(start, 500)) feed();
    __asm__ volatile ("cpsid i" ::: "memory");
    /* Request the same ARM system reset used by the recovered stock
     * bootloader at 0x0100111c. The checked backup-register marker was armed
     * before the success reply; reset-status bits are not used as storage.
     */
    __asm__ volatile ("dsb" ::: "memory");
    *PTR32(0xe000ed0c) = 0x05fa0004; /* AIRCR.VECTKEY | SYSRESETREQ */
    __asm__ volatile ("dsb" ::: "memory");
    for (;;) __asm__ volatile ("nop");
}

/* Replaces the final startup call at 0xe284, after peripheral initialization
 * and before foreground workers. Stock state 0 otherwise enters shutdown at
 * 0xf470 when the power button is released, even after a software reset.
 * Consume the verified backup-register cookie once and use stock power-on
 * path (0x46d4), which also enables Bluetooth and initializes NFC state.
 * Ordinary cold boots, update/fault resets without our cookie, and already
 * active/test states keep stock behavior. A pending cookie is consumed even
 * if a fault interrupts a requested restart, so it cannot cause a boot loop.
 * No retained RAM, settings-flash flag or synthetic button is needed.
 */
__attribute__((used))
void refill_startup(void) {
    int restart = RESTART_MARKER[0] == RESTART_COOKIE &&
        RESTART_MARKER[1] == ~RESTART_COOKIE;
    if (restart) {
        RESTART_MARKER[0] = 0;
        RESTART_MARKER[1] = 0;
    }
    FN(0xd708, VoidFn)(); /* original factory-test startup check */
    if (restart && *PTR8(0x207d0) == 0)
        FN(0x46d4, VoidFn)();
}
