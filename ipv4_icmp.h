#ifndef IPV4_ICMP_H
#define IPV4_ICMP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "eth_arp.h"

/* ==========================================================================
 * Layer 3: RFC 791 IPv4 Wire Definitions
 * ========================================================================== */

#define IPV4_VERSION        4
#define IPV4_MIN_IHL        5       /* Minimum IHL in 32-bit words (20 bytes) */
#define IPV4_HDR_MIN_LEN    20      /* 5 * 4 bytes                            */
#define IPV4_DEFAULT_TTL    64      /* Standard Linux default TTL             */

/* IPv4 Fragmentation Flags & Offset Mask (in Host Byte Order before htons)  */
#define IPV4_FLAG_RESERVED  0x8000U /* Reserved bit (must be zero)            */
#define IPV4_FLAG_DF        0x4000U /* Don't Fragment (DF)                    */
#define IPV4_FLAG_MF        0x2000U /* More Fragments (MF)                    */
#define IPV4_FRAG_OFFSET    0x1FFFU /* Fragment offset in 8-byte units        */

/* Assigned Internet Protocol Numbers (RFC 790 / IANA)                        */
#define IPPROTO_ICMP_VAL    1       /* Internet Control Message Protocol      */
#define IPPROTO_TCP_VAL     6       /* Transmission Control Protocol          */
#define IPPROTO_UDP_VAL     17      /* User Datagram Protocol                 */

/**
 * RFC 791 IPv4 Header (20 bytes minimum, excluding optional variable options).
 *
 * Wire Layout (offsets relative to start of IPv4 packet, i.e., frame + 14):
 *  +0      : ver_ihl  (1 byte)  - Upper nibble: Version (4), Lower nibble: IHL
 *  +1      : tos      (1 byte)  - DSCP (6 bits) + ECN (2 bits)
 *  +2..+3  : tot_len  (2 bytes) - Total IP packet length (header + L4 payload)
 *  +4..+5  : id       (2 bytes) - Identification for fragmentation
 *  +6..+7  : frag_off (2 bytes) - 3-bit Flags (R, DF, MF) + 13-bit Frag Offset
 *  +8      : ttl      (1 byte)  - Time to Live (decremented per router hop)
 *  +9      : proto    (1 byte)  - L4 protocol identifier (1=ICMP, 6=TCP)
 *  +10..+11: check    (2 bytes) - RFC 1071 header-only one's complement sum
 *  +12..+15: saddr    (4 bytes) - Source IPv4 address (Network Byte Order)
 *  +16..+19: daddr    (4 bytes) - Destination IPv4 address (Network Byte Order)
 *
 * Why use `uint8_t ver_ihl` instead of C bitfields `uint8_t ihl:4, version:4`?
 * The C99 standard (ISO/IEC 9899:1999 §6.7.2.1) leaves bitfield ordering
 * within a storage unit implementation-defined: little-endian targets pack
 * bitfields from LSB to MSB, whereas big-endian targets pack from MSB to LSB.
 * Explicit shift/mask macros (`IPV4_VER(h)`, `IPV4_IHL(h)`) are 100% portable
 * and immune to compiler bitfield ordering differences.
 */
struct ipv4_hdr {
    uint8_t  ver_ihl;       /* Bits 7..4: Version (4), Bits 3..0: IHL (>= 5)  */
    uint8_t  tos;           /* Type of Service / DSCP + ECN                   */
    uint16_t tot_len;       /* Total length in bytes (Network Byte Order)     */
    uint16_t id;            /* Identification (Network Byte Order)            */
    uint16_t frag_off;      /* Flags + Fragment Offset (Network Byte Order)   */
    uint8_t  ttl;           /* Time To Live                                   */
    uint8_t  proto;         /* Protocol (IPPROTO_ICMP_VAL, IPPROTO_TCP_VAL)   */
    uint16_t check;         /* Header checksum (Network Byte Order)           */
    uint32_t saddr;         /* Source IP address (Network Byte Order)         */
    uint32_t daddr;         /* Destination IP address (Network Byte Order)    */
} __attribute__((packed));

#define IPV4_VER(hdr)       (((hdr)->ver_ihl >> 4) & 0x0FU)
#define IPV4_IHL(hdr)       ((hdr)->ver_ihl & 0x0FU)
#define IPV4_HDR_BYTES(hdr) ((size_t)IPV4_IHL(hdr) * 4U)

/* ==========================================================================
 * Layer 3.5: RFC 792 ICMPv4 Wire Definitions
 * ========================================================================== */

#define ICMP_TYPE_ECHO_REPLY    0   /* Echo Reply (ping response)             */
#define ICMP_TYPE_DEST_UNREACH  3   /* Destination Unreachable                */
#define ICMP_TYPE_ECHO_REQUEST  8   /* Echo Request (ping probe)              */
#define ICMP_TYPE_TIME_EXCEEDED 11  /* Time Exceeded                          */

/**
 * RFC 792 ICMPv4 Base Header (8 bytes).
 *
 * Wire Layout (offsets relative to start of ICMP message):
 *  +0      : type     (1 byte)  - Message type (8 = Echo Request, 0 = Reply)
 *  +1      : code     (1 byte)  - Message subtype (0 for Echo)
 *  +2..+3  : checksum (2 bytes) - RFC 1071 checksum over entire ICMP message
 *  +4..+5  : id       (2 bytes) - Echo Identifier (Network Byte Order)
 *  +6..+7  : seq      (2 bytes) - Echo Sequence Number (Network Byte Order)
 */
struct icmp_hdr {
    uint8_t  type;          /* ICMP message type                              */
    uint8_t  code;          /* ICMP message sub-code                          */
    uint16_t checksum;      /* One's complement checksum over header+payload  */
    uint16_t id;            /* Echo Identifier (or unused/Mtu in other types) */
    uint16_t seq;           /* Echo Sequence Number                           */
} __attribute__((packed));

/* ==========================================================================
 * Public Layer 3 API
 * ========================================================================== */

/**
 * Register a Layer 4 TCP reception callback invoked by `ipv4_rx()` when a
 * valid, non-fragmented `IPPROTO_TCP_VAL` packet arrives.
 */
typedef void (*tcp_rx_fn)(struct netdev *dev, const struct ipv4_hdr *ip_hdr,
                          const uint8_t *tcp_seg, size_t tcp_len, uint64_t now_ms);

void ipv4_set_tcp_handler(tcp_rx_fn fn);

/**
 * Process an incoming IPv4 packet demultiplexed from `eth_rx()`.
 * Validates framing, Version/IHL, RFC 1071 checksum, fragmentation flags,
 * destination IP address, and dispatches to ICMPv4 or TCP.
 */
void ipv4_rx(struct netdev *dev, const uint8_t *pkt, size_t len, uint64_t now_ms);

/**
 * Encapsulate a Layer 4 payload inside an RFC 791 IPv4 header, compute the
 * optimized header checksum, and transmit via `netdev_tx_ipv4()`.
 *
 * @param dev       Network device context.
 * @param dst_ip_be Destination IPv4 address (Network Byte Order).
 * @param proto     L4 protocol number (`IPPROTO_ICMP_VAL` or `IPPROTO_TCP_VAL`).
 * @param payload   Pointer to L4 header + payload.
 * @param len       Length of L4 payload in bytes (must be <= 1480 for 1500 MTU).
 * @param now_ms    Current monotonic timestamp in milliseconds.
 * @return 0 on success, -1 on error.
 */
int ipv4_tx(struct netdev *dev, uint32_t dst_ip_be, uint8_t proto,
            const void *payload, size_t len, uint64_t now_ms);

/**
 * Process an incoming ICMPv4 packet (RFC 792).
 * Responds to Type 8 (Echo Request) with Type 0 (Echo Reply).
 */
void icmp_rx(struct netdev *dev, const struct ipv4_hdr *ip_hdr,
             const uint8_t *icmp_pkt, size_t len, uint64_t now_ms);

#endif /* IPV4_ICMP_H */
