#ifndef NET_BASE_H
#define NET_BASE_H

#include <stdint.h>
#include <stddef.h>

/**
 * Open or allocate a Linux TAP interface (Layer 2 Ethernet).
 * @param dev Name of the interface (e.g., "tap0"). Must point to a buffer of
 *            at least IFNAMSIZ (16) bytes if dynamic name writeback is used.
 * @return File descriptor to the tap device, or -1 on fatal error.
 */
int tap_alloc(char *dev);

/**
 * High-performance Internet Checksum (RFC 1071) calculation.
 * Uses a 64-bit wide parallel accumulator over 32-bit lanes (with carry-safe
 * 64-bit unrolling) followed by 32-bit and 16-bit folding to minimize
 * pipeline stalls and branches while strictly preserving 1's complement carries.
 *
 * @param data Pointer to the memory buffer to checksum.
 * @param len  Length of the buffer in bytes.
 * @return 16-bit one's complement sum in network byte order (invariant under
 *         RFC 1071 byte-order folding, suitable for direct wire comparison
 *         or assignment to a __attribute__((packed)) header field).
 */
uint16_t checksum16_optimized(const void *data, size_t len);

/**
 * Incremental / scatter-gather checksum accumulation helper (unfolded).
 * Useful for Layer 4 (TCP/UDP) pseudo-header + payload checksumming without
 * copying into a contiguous scratch buffer.
 *
 * @param data Pointer to memory slice.
 * @param len  Length of slice in bytes (must be even for non-terminal slices).
 * @param acc  Initial 64-bit accumulator state.
 * @return Updated 64-bit accumulator (fold with checksum16_fold()).
 */
uint64_t checksum16_accumulate(const void *data, size_t len, uint64_t acc);

/**
 * Fold a 64-bit one's complement accumulator down to its final inverted 16-bit sum.
 */
uint16_t checksum16_fold(uint64_t acc);

#endif /* NET_BASE_H */
