#ifndef ETH_ARP_H
#define ETH_ARP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ==========================================================================
 * Layer 2: IEEE 802.3 Ethernet Wire Definitions
 * ========================================================================== */

#define ETH_ALEN        6       /* Octets in one Ethernet MAC address       */
#define ETH_HDR_LEN     14      /* Total octets in standard Ethernet header */
#define ETH_ZLEN        60      /* Min frame bytes without 4-byte FCS       */
#define ETH_FRAME_MAX   1514    /* Max standard Ethernet frame (1500 MTU)   */

/* EtherType values in Host Byte Order (convert with htons/ntohs on wire)   */
#define ETH_P_IP        0x0800  /* IPv4 packet                              */
#define ETH_P_ARP       0x0806  /* Address Resolution Protocol (RFC 826)    */
#define ETH_P_IPV6      0x86DD  /* IPv6 packet                              */

/**
 * IEEE 802.3 Ethernet II Frame Header (14 bytes).
 *
 * Wire Layout:
 *  +0..+5  : dst_mac   (6 bytes) - Destination hardware address
 *  +6..+11 : src_mac   (6 bytes) - Source hardware address
 *  +12..+13: ethertype (2 bytes) - Big-endian protocol identifier
 *
 * Alignment Warning:
 * Because ETH_HDR_LEN is 14 bytes (14 % 4 == 2), the Layer 3 payload
 * immediately following this header at offset +14 is 2-byte aligned, NOT
 * 4-byte aligned, relative to the start of the Ethernet frame buffer.
 */
struct eth_hdr {
    uint8_t  dst_mac[ETH_ALEN];
    uint8_t  src_mac[ETH_ALEN];
    uint16_t ethertype;         /* Network byte order (Big-Endian) */
} __attribute__((packed));

/* ==========================================================================
 * Layer 2.5: RFC 826 Address Resolution Protocol (ARP) Wire Definitions
 * ========================================================================== */

#define ARP_HRD_ETHER   1       /* Ethernet 10Mbps hardware type            */
#define ARP_PRO_IP      0x0800  /* IPv4 protocol type (matches ETH_P_IP)    */
#define ARP_OP_REQUEST  1       /* ARP Request                              */
#define ARP_OP_REPLY    2       /* ARP Reply                                */

/**
 * RFC 826 Fixed Header + IPv4-over-Ethernet Payload (28 bytes total).
 *
 * Wire Layout (offsets relative to start of ARP packet, i.e., frame + 14):
 *  +0..+1  : ar_hrd (2 bytes) - Hardware address space (htons(1) for Ethernet)
 *  +2..+3  : ar_pro (2 bytes) - Protocol address space (htons(0x0800) for IPv4)
 *  +4      : ar_hln (1 byte)  - Byte length of hardware address (6)
 *  +5      : ar_pln (1 byte)  - Byte length of protocol address (4)
 *  +6..+7  : ar_op  (2 bytes) - Opcode (htons(1)=Request, htons(2)=Reply)
 *  +8..+13 : sha    (6 bytes) - Sender hardware address (MAC)
 *  +14..+17: spa    (4 bytes) - Sender protocol address (IPv4, network order)
 *  +18..+23: tha    (6 bytes) - Target hardware address (MAC)
 *  +24..+27: tpa    (4 bytes) - Target protocol address (IPv4, network order)
 *
 * Alignment Note:
 * `spa` sits at ARP offset +14 (frame offset +28, 4-byte aligned if frame is
 * 4-byte aligned), while `tpa` sits at ARP offset +24 (frame offset +38, only
 * 2-byte aligned). `__attribute__((packed))` instructs the compiler to emit
 * unaligned-safe instructions on strict-alignment architectures (ARMv5/MIPS).
 */
struct arp_ipv4_pkt {
    uint16_t ar_hrd;            /* Hardware type (Network byte order)       */
    uint16_t ar_pro;            /* Protocol type (Network byte order)       */
    uint8_t  ar_hln;            /* Hardware address length (6)              */
    uint8_t  ar_pln;            /* Protocol address length (4)              */
    uint16_t ar_op;             /* Operation code (Network byte order)      */
    uint8_t  sha[ETH_ALEN];     /* Sender hardware address                  */
    uint32_t spa;               /* Sender IPv4 address (Network byte order) */
    uint8_t  tha[ETH_ALEN];     /* Target hardware address                  */
    uint32_t tpa;               /* Target IPv4 address (Network byte order) */
} __attribute__((packed));

/* ==========================================================================
 * O(1) Hash-Indexed ARP Cache with Intrusive Doubly-Linked LRU
 * ========================================================================== */

/*
 * ARP_CACHE_CAPACITY is the maximum number of active entries.
 * ARP_HASH_BUCKETS must be a power of two >= 2 * ARP_CACHE_CAPACITY to keep
 * the open-addressing load factor <= 0.5, guaranteeing O(1) expected probes.
 */
#define ARP_CACHE_CAPACITY  64
#define ARP_HASH_BUCKETS    128
#define ARP_NULL_IDX        0xFFFFU

/* Timeouts in milliseconds (inspired by Linux net/ipv4/arp.c defaults) */
#define ARP_REACHABLE_TIME_MS   30000ULL    /* 30s before REACHABLE -> STALE */
#define ARP_INCOMPLETE_TIME_MS   3000ULL    /* 3s timeout for ARP Request    */

/**
 * Neighbor Cache Entry States (modeled after RFC 4861 / Linux NUD states).
 */
enum arp_state {
    ARP_STATE_FREE       = 0,   /* Slot unused                              */
    ARP_STATE_INCOMPLETE = 1,   /* Request sent, awaiting ARP Reply         */
    ARP_STATE_REACHABLE  = 2,   /* Valid mapping, confirmed within timeout  */
    ARP_STATE_STALE      = 3    /* Mapping usable, needs re-verification    */
};

/**
 * Individual ARP Table Entry in the pre-allocated node pool.
 */
struct arp_entry {
    uint32_t       ip_be;           /* Key: IPv4 address in Network Byte Order */
    uint8_t        mac[ETH_ALEN];   /* Resolved 48-bit Ethernet MAC address    */
    uint8_t        state;           /* enum arp_state                          */
    uint8_t        retries;         /* Number of ARP probes transmitted        */
    uint64_t       updated_ms;      /* Monotonic timestamp of last transition  */

    /* Intrusive doubly-linked list indices for O(1) LRU promotion & eviction */
    uint16_t       lru_prev;        /* Index toward MRU head (or ARP_NULL_IDX) */
    uint16_t       lru_next;        /* Index toward LRU tail (or ARP_NULL_IDX) */

    /*
     * Single-packet hold queue while in ARP_STATE_INCOMPLETE (RFC 1122 2.3.2.2:
     * "The link layer SHOULD save (rather than discard) at least one
     * (the latest) packet of each set of packets destined to the same
     * unresolved IP address, and transmit the saved packet when the address
     * has been resolved.")
     */
    uint16_t       pending_len;     /* Length of queued L3 payload (0 if none) */
    uint16_t       pending_proto;   /* Host-order EtherType of queued payload  */
    uint8_t        pending_pkt[ETH_FRAME_MAX - ETH_HDR_LEN];
};

/**
 * O(1) ARP Cache Structure.
 * Combines:
 * 1. An open-addressing hash table (`buckets[]`) mapping `hash(ip_be)` to a
 *    slot index in `pool[]` using linear probing and backward-shift deletion.
 * 2. A fixed-size node pool (`pool[]`) with an intrusive doubly-linked LRU
 *    list (`lru_head`, `lru_tail`) and free-list (`free_head`) for zero-malloc
 *    deterministic operation.
 */
struct arp_cache {
    uint16_t         buckets[ARP_HASH_BUCKETS];
    struct arp_entry pool[ARP_CACHE_CAPACITY];
    uint16_t         lru_head;      /* Most Recently Used (MRU) index  */
    uint16_t         lru_tail;      /* Least Recently Used (LRU) index */
    uint16_t         free_head;     /* Singly-linked free slot stack   */
    uint16_t         count;         /* Active entries in cache         */
};

/**
 * Network Device / Interface Context representing our Userspace Stack's NIC.
 */
struct netdev {
    int              tap_fd;        /* File descriptor from tap_alloc()        */
    uint8_t          mac[ETH_ALEN]; /* Local 48-bit MAC address                */
    uint32_t         ip_be;         /* Local IPv4 address (Network Byte Order) */
    uint32_t         netmask_be;    /* Local Subnet Mask (Network Byte Order)  */
    uint32_t         gateway_be;    /* Default Gateway IP (Network Byte Order) */
    struct arp_cache arp;           /* O(1) ARP Cache instance                 */

    /* Optional callback invoked when a valid IPv4 packet is demultiplexed     */
    void (*ip_rx_cb)(struct netdev *dev, const uint8_t *pkt, size_t len, uint64_t now_ms);
};

/* ==========================================================================
 * Public API
 * ========================================================================== */

/**
 * Initialize the O(1) ARP cache, resetting all hash buckets and linking all
 * pool nodes into the O(1) free list.
 */
void arp_cache_init(struct arp_cache *cache);

/**
 * Initialize a network device context with local MAC and IPv4 configuration.
 */
void netdev_init(struct netdev *dev, int tap_fd, const uint8_t mac[ETH_ALEN],
                 uint32_t ip_be, uint32_t netmask_be, uint32_t gateway_be);

/**
 * O(1) lookup of an IPv4 address (Network Byte Order) in the ARP cache.
 * Promotes the entry to the MRU head and transitions REACHABLE -> STALE if
 * `now_ms - entry->updated_ms >= ARP_REACHABLE_TIME_MS`.
 *
 * @return Pointer to the resolved arp_entry, or NULL if not found.
 */
struct arp_entry *arp_cache_lookup(struct arp_cache *cache, uint32_t ip_be, uint64_t now_ms);

/**
 * O(1) insert or update of a confirmed (ip_be -> mac) mapping.
 * Sets state to ARP_STATE_REACHABLE, promotes to MRU head, and if the entry
 * was previously ARP_STATE_INCOMPLETE with a pending packet, flushes that
 * packet onto the wire immediately.
 */
struct arp_entry *arp_cache_upsert(struct netdev *dev, uint32_t ip_be,
                                   const uint8_t mac[ETH_ALEN], uint64_t now_ms);

/**
 * Construct and transmit an Ethernet II frame over the TAP device.
 *
 * @param dev       Network device context.
 * @param dst_mac   6-byte destination MAC address.
 * @param ethertype Host-byte-order EtherType (e.g., ETH_P_IP, ETH_P_ARP).
 * @param payload   Pointer to Layer 3 payload buffer.
 * @param len       Length of Layer 3 payload in bytes (0..1500).
 * @return 0 on success, -1 on error.
 */
int eth_tx(struct netdev *dev, const uint8_t dst_mac[ETH_ALEN],
           uint16_t ethertype, const void *payload, size_t len);

/**
 * Transmit an IPv4 payload to `dst_ip_be`, resolving the next-hop MAC via the
 * O(1) ARP cache or queueing the packet and emitting an ARP Request if needed.
 */
int netdev_tx_ipv4(struct netdev *dev, uint32_t dst_ip_be,
                   const void *ipv4_pkt, size_t len, uint64_t now_ms);

/**
 * Broadcast an RFC 826 ARP Request for target IPv4 address `target_ip_be`.
 */
int arp_send_request(struct netdev *dev, uint32_t target_ip_be);

/**
 * Unicast an RFC 826 ARP Reply to `(target_mac, target_ip_be)`.
 */
int arp_send_reply(struct netdev *dev, const uint8_t target_mac[ETH_ALEN],
                   uint32_t target_ip_be);

/**
 * Process an incoming ARP packet (RFC 826 state machine).
 */
void arp_rx(struct netdev *dev, const uint8_t *pkt, size_t len, uint64_t now_ms);

/**
 * Demultiplex an incoming raw Ethernet frame read from the TAP descriptor.
 */
void eth_rx(struct netdev *dev, const uint8_t *frame, size_t len, uint64_t now_ms);

#endif /* ETH_ARP_H */
