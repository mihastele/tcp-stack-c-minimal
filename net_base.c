#define _GNU_SOURCE
#include "net_base.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

int tap_alloc(char *dev) {
    struct ifreq ifr;
    int fd, err;

    /*
     * Open the clone device node provided by the Linux universal TUN/TAP driver.
     * Requires CAP_NET_ADMIN capability (or root).
     */
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("open(/dev/net/tun)");
        return -1;
    }

    /*
     * Zero-initialize struct ifreq so no uninitialized stack bytes leak into
     * the kernel's tun_set_iff() handler.
     */
    memset(&ifr, 0, sizeof(ifr));

    /*
     * Flags:
     * - IFF_TAP:   Operate at Layer 2 (Ethernet frames with 14-byte 802.3 header).
     * - IFF_NO_PI: Omit the 4-byte Linux packet info prefix (flags + proto),
     *              giving us raw wire-format IEEE 802.3 frames starting at byte 0.
     */
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (dev && *dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }

    if (dev) {
        strcpy(dev, ifr.ifr_name);
    }

    return fd;
}

uint16_t checksum16_fold(uint64_t acc) {
    /*
     * Fold 64-bit accumulator down to 32 bits, then 16 bits.
     * Because two folds of 32->16 can still produce a 17th carry bit (e.g.,
     * 0xFFFF + 0xFFFF = 0x1FFFE), we loop until the upper bits are zero.
     */
    acc = (acc & 0xFFFFFFFFULL) + (acc >> 32);
    acc = (acc & 0xFFFFFFFFULL) + (acc >> 32);
    acc = (acc & 0xFFFFULL) + (acc >> 16);
    acc = (acc & 0xFFFFULL) + (acc >> 16);

    return (uint16_t)(~acc);
}

uint64_t checksum16_accumulate(const void *data, size_t len, uint64_t acc) {
    const uint8_t *ptr = (const uint8_t *)data;

    /*
     * Fold any existing upper bits before starting so `acc` has headroom
     * for at least 2^32 - 1 additions of 32-bit words without 64-bit overflow.
     */
    acc = (acc & 0xFFFFFFFFULL) + (acc >> 32);

    /*
     * Step 1: 4-byte alignment prologue.
     * Note on odd addresses: If `ptr` is at an odd memory address, stepping by
     * 2 bytes will never make `(uintptr_t)ptr` even, whereas stepping by 1 byte
     * would invert the byte lane polarity of all subsequent words.
     * Therefore, we only align to a 4-byte boundary when `ptr` is already
     * 2-byte aligned (`((uintptr_t)ptr & 1) == 0`). If `ptr` is odd-aligned,
     * `memcpy` safely handles unaligned loads on all C99 targets.
     */
    if ((((uintptr_t)ptr & 1) == 0) && (((uintptr_t)ptr & 2) != 0) && len >= 2) {
        uint16_t word;
        memcpy(&word, ptr, sizeof(word));
        acc += word;
        ptr += 2;
        len -= 2;
    }

    /*
     * Step 2: 32-byte unrolled loop accumulating 32-bit words into the 64-bit
     * accumulator.
     *
     * CRITICAL ARITHMETIC INVARIANT:
     * Why accumulate `uint32_t` words into `uint64_t` instead of `uint64_t` into
     * `uint64_t`?
     * If we loaded `uint64_t w` and computed `acc += w`, any sum exceeding
     * 2^64 - 1 would silently wrap modulo 2^64 and LOSE the end-around carry
     * required by RFC 1071 one's complement arithmetic!
     * By loading eight 32-bit words (`uint32_t`) and widening them into a 64-bit
     * accumulator, each 32-bit word is at most 0xFFFFFFFF, so we can accumulate
     * over 4 billion 32-bit words (16 GiB of packet data) before `uint64_t`
     * can possibly overflow—zero carry checks needed inside the hot loop!
     */
    while (len >= 32) {
        uint32_t w0, w1, w2, w3, w4, w5, w6, w7;
        memcpy(&w0, ptr +  0, 4);
        memcpy(&w1, ptr +  4, 4);
        memcpy(&w2, ptr +  8, 4);
        memcpy(&w3, ptr + 12, 4);
        memcpy(&w4, ptr + 16, 4);
        memcpy(&w5, ptr + 20, 4);
        memcpy(&w6, ptr + 24, 4);
        memcpy(&w7, ptr + 28, 4);

        acc += (uint64_t)w0 + w1 + w2 + w3 + w4 + w5 + w6 + w7;

        ptr += 32;
        len -= 32;
    }

    /*
     * Step 3: Consume remaining 4-byte (32-bit) words.
     */
    while (len >= 4) {
        uint32_t w;
        memcpy(&w, ptr, 4);
        acc += w;
        ptr += 4;
        len -= 4;
    }

    /*
     * Step 4: Consume leftover 2-byte (16-bit) word if present.
     */
    if (len >= 2) {
        uint16_t word;
        memcpy(&word, ptr, 2);
        acc += word;
        ptr += 2;
        len -= 2;
    }

    /*
     * Step 5: Handle an odd trailing byte (padded with a zero byte on the wire
     * per RFC 1071). By placing `*ptr` at byte offset 0 of a 16-bit zeroed local,
     * its byte lane matches the first byte of every 16-bit `memcpy` above
     * regardless of whether the host CPU is little-endian or big-endian.
     */
    if (len == 1) {
        uint16_t trailing = 0;
        *(uint8_t *)&trailing = *ptr;
        acc += trailing;
    }

    return acc;
}

uint16_t checksum16_optimized(const void *data, size_t len) {
    return checksum16_fold(checksum16_accumulate(data, len, 0));
}
