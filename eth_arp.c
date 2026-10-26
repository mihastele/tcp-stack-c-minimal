#define _GNU_SOURCE
#include "eth_arp.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

/* Broadcast Ethernet MAC address (FF:FF:FF:FF:FF:FF) */
static const uint8_t ETH_BROADCAST_MAC[ETH_ALEN] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/* Zero Ethernet MAC address used in ARP Request Target Hardware Address (THA) */
static const uint8_t ETH_ZERO_MAC[ETH_ALEN] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* ==========================================================================
 * Internal Helpers: Hashing & Intrusive Doubly-Linked LRU List
 * ========================================================================== */

/**
 * MurmurHash3 32-bit finalizer (fmix32).
 *
 * Why use an avalanche mixer on `ip_be` instead of modulo `ip_be & (N - 1)`?
 * In a typical /24 LAN, IPv4 addresses in Network Byte Order vary only in their
 * most significant byte on little-endian hosts (or least significant byte in
 * big-endian value), and structured subnets can cause severe clustering if
 * masked directly. `fmix32` achieves full bit avalanche in 5 instructions
 * (shifts, XORs, and multiplications), ensuring uniform distribution across
 * our power-of-two `ARP_HASH_BUCKETS` table.
 */
static inline uint32_t arp_hash_ip(uint32_t ip_be) {
    uint32_t h = ip_be;
    h ^= h >> 16;
    h *= 0x85ebca6bU;
    h ^= h >> 13;
    h *= 0xc2b2ae35U;
    h ^= h >> 16;
    return h & (ARP_HASH_BUCKETS - 1);
}

/**
 * Detach node `idx` from the intrusive doubly-linked LRU list in O(1) time.
 */
static void lru_remove(struct arp_cache *cache, uint16_t idx) {
    struct arp_entry *e = &cache->pool[idx];

    if (e->lru_prev != ARP_NULL_IDX) {
        cache->pool[e->lru_prev].lru_next = e->lru_next;
    } else {
        cache->lru_head = e->lru_next;
    }

    if (e->lru_next != ARP_NULL_IDX) {
        cache->pool[e->lru_next].lru_prev = e->lru_prev;
    } else {
        cache->lru_tail = e->lru_prev;
    }

    e->lru_prev = ARP_NULL_IDX;
    e->lru_next = ARP_NULL_IDX;
}

/**
 * Insert node `idx` at the MRU (Most Recently Used) head of the list in O(1).
 */
static void lru_push_front(struct arp_cache *cache, uint16_t idx) {
    struct arp_entry *e = &cache->pool[idx];

    e->lru_prev = ARP_NULL_IDX;
    e->lru_next = cache->lru_head;

    if (cache->lru_head != ARP_NULL_IDX) {
        cache->pool[cache->lru_head].lru_prev = idx;
    } else {
        cache->lru_tail = idx;
    }

    cache->lru_head = idx;
}

/**
 * Promote an already-linked node `idx` to the MRU head in O(1).
 */
static void lru_touch(struct arp_cache *cache, uint16_t idx) {
    if (cache->lru_head == idx) {
        return; /* Already MRU; avoid unnecessary pointer writes */
    }
    lru_remove(cache, idx);
    lru_push_front(cache, idx);
}

/**
 * Remove `target_idx` from the open-addressing hash table using Knuth's
 * Algorithm R (backward-shift deletion) so no tombstones degrade lookup speed.
 *
 * Why backward-shift deletion instead of tombstones?
 * In a long-running network stack under ARP churn, tombstones accumulate and
 * turn O(1) open-addressing lookups into O(N) linear scans unless the entire
 * table is periodically rehashed. Backward-shift deletion restores the exact
 * probe invariant in O(1) amortized steps with zero tombstones.
 */
static void hash_remove_bucket(struct arp_cache *cache, uint32_t bucket_idx) {
    uint32_t i = bucket_idx;
    uint32_t j = i;

    for (;;) {
        cache->buckets[i] = ARP_NULL_IDX;
        for (;;) {
            j = (j + 1) & (ARP_HASH_BUCKETS - 1);
            uint16_t slot = cache->buckets[j];
            if (slot == ARP_NULL_IDX) {
                return; /* End of probe cluster reached */
            }
            /* Compute the ideal home bucket `k` for the entry sitting at `j` */
            uint32_t k = arp_hash_ip(cache->pool[slot].ip_be);

            /*
             * Check if `k` lies cyclically outside the interval (i, j].
             * If so, `slot` belongs at or before `i` and must be shifted back.
             */
            if ((i <= j) ? ((k <= i) || (k > j)) : ((k <= i) && (k > j))) {
                break;
            }
        }
        cache->buckets[i] = cache->buckets[j];
        i = j;
    }
}

/* ==========================================================================
 * ARP Cache Initialization, Lookup, and Eviction
 * ========================================================================== */

void arp_cache_init(struct arp_cache *cache) {
    memset(cache, 0, sizeof(*cache));

    for (size_t i = 0; i < ARP_HASH_BUCKETS; i++) {
        cache->buckets[i] = ARP_NULL_IDX;
    }

    /* Chain all pool slots into a singly-linked free stack via `lru_next` */
    for (uint16_t i = 0; i < ARP_CACHE_CAPACITY; i++) {
        cache->pool[i].state    = ARP_STATE_FREE;
        cache->pool[i].lru_prev = ARP_NULL_IDX;
        cache->pool[i].lru_next = (i + 1 < ARP_CACHE_CAPACITY) ? (uint16_t)(i + 1) : ARP_NULL_IDX;
    }

    cache->lru_head  = ARP_NULL_IDX;
    cache->lru_tail  = ARP_NULL_IDX;
    cache->free_head = 0;
    cache->count     = 0;
}

void netdev_init(struct netdev *dev, int tap_fd, const uint8_t mac[ETH_ALEN],
                 uint32_t ip_be, uint32_t netmask_be, uint32_t gateway_be) {
    memset(dev, 0, sizeof(*dev));
    dev->tap_fd     = tap_fd;
    memcpy(dev->mac, mac, ETH_ALEN);
    dev->ip_be      = ip_be;
    dev->netmask_be = netmask_be;
    dev->gateway_be = gateway_be;
    arp_cache_init(&dev->arp);
}

/**
 * Internal helper to locate the hash bucket holding `ip_be`, or the first
 * empty bucket in its linear-probing cluster.
 */
static uint32_t arp_find_bucket(const struct arp_cache *cache, uint32_t ip_be, bool *found) {
    uint32_t b = arp_hash_ip(ip_be);

    for (uint32_t step = 0; step < ARP_HASH_BUCKETS; step++) {
        uint16_t slot = cache->buckets[b];
        if (slot == ARP_NULL_IDX) {
            *found = false;
            return b;
        }
        if (cache->pool[slot].ip_be == ip_be) {
            *found = true;
            return b;
        }
        b = (b + 1) & (ARP_HASH_BUCKETS - 1);
    }

    *found = false;
    return b;
}

struct arp_entry *arp_cache_lookup(struct arp_cache *cache, uint32_t ip_be, uint64_t now_ms) {
    bool found = false;
    uint32_t b = arp_find_bucket(cache, ip_be, &found);
    if (!found) {
        return NULL;
    }

    uint16_t slot = cache->buckets[b];
    struct arp_entry *e = &cache->pool[slot];

    /*
     * Lazy aging transition:
     * If the entry was REACHABLE and its confirmation timestamp has aged past
     * ARP_REACHABLE_TIME_MS, transition it to ARP_STATE_STALE.
     */
    if (e->state == ARP_STATE_REACHABLE &&
        (now_ms >= e->updated_ms) &&
        (now_ms - e->updated_ms >= ARP_REACHABLE_TIME_MS)) {
        e->state = ARP_STATE_STALE;
    }

    lru_touch(cache, slot);
    return e;
}

/**
 * Allocate a slot in `cache->pool` for `ip_be` (evicting the LRU tail in O(1)
 * if the pool is at capacity) and insert it into the open-addressing table.
 */
static struct arp_entry *arp_cache_alloc_entry(struct arp_cache *cache, uint32_t ip_be, uint64_t now_ms) {
    uint16_t slot;

    if (cache->free_head != ARP_NULL_IDX) {
        /* Pop from O(1) free list */
        slot = cache->free_head;
        cache->free_head = cache->pool[slot].lru_next;
        cache->count++;
    } else {
        /*
         * Cache full: Evict the Least Recently Used entry at `cache->lru_tail`.
         * Find its bucket in O(1) expected probes and remove via backward-shift.
         */
        slot = cache->lru_tail;
        struct arp_entry *victim = &cache->pool[slot];
        bool found = false;
        uint32_t victim_bucket = arp_find_bucket(cache, victim->ip_be, &found);
        if (found) {
            hash_remove_bucket(cache, victim_bucket);
        }
        lru_remove(cache, slot);
    }

    /* Find target insertion bucket for the new `ip_be` key */
    bool found = false;
    uint32_t b = arp_find_bucket(cache, ip_be, &found);
    cache->buckets[b] = slot;

    struct arp_entry *e = &cache->pool[slot];
    memset(e, 0, sizeof(*e));
    e->ip_be      = ip_be;
    e->state      = ARP_STATE_INCOMPLETE;
    e->updated_ms = now_ms;
    e->lru_prev   = ARP_NULL_IDX;
    e->lru_next   = ARP_NULL_IDX;

    lru_push_front(cache, slot);
    return e;
}

struct arp_entry *arp_cache_upsert(struct netdev *dev, uint32_t ip_be,
                                   const uint8_t mac[ETH_ALEN], uint64_t now_ms) {
    struct arp_cache *cache = &dev->arp;
    bool found = false;
    uint32_t b = arp_find_bucket(cache, ip_be, &found);
    struct arp_entry *e;

    if (found) {
        uint16_t slot = cache->buckets[b];
        e = &cache->pool[slot];
        lru_touch(cache, slot);
    } else {
        e = arp_cache_alloc_entry(cache, ip_be, now_ms);
    }

    memcpy(e->mac, mac, ETH_ALEN);
    e->state      = ARP_STATE_REACHABLE;
    e->retries    = 0;
    e->updated_ms = now_ms;

    /*
     * RFC 1122 Section 2.3.2.2:
     * If a packet was held while awaiting ARP resolution (INCOMPLETE -> REACHABLE),
     * transmit it immediately and clear the hold buffer.
     */
    if (e->pending_len > 0) {
        uint16_t len   = e->pending_len;
        uint16_t proto = e->pending_proto;
        e->pending_len = 0;
        eth_tx(dev, e->mac, proto, e->pending_pkt, len);
    }

    return e;
}

/* ==========================================================================
 * Layer 2 Frame Transmission & ARP Packet Generation
 * ========================================================================== */

int eth_tx(struct netdev *dev, const uint8_t dst_mac[ETH_ALEN],
           uint16_t ethertype, const void *payload, size_t len) {
    /*
     * Defensive bounds check: Standard IEEE 802.3 payload cannot exceed 1500
     * bytes (ETH_FRAME_MAX - ETH_HDR_LEN). Reject oversized writes to prevent
     * stack buffer overflow.
     */
    if (len > (ETH_FRAME_MAX - ETH_HDR_LEN)) {
        return -1;
    }

    uint8_t frame[ETH_FRAME_MAX];
    struct eth_hdr *hdr = (struct eth_hdr *)frame;

    memcpy(hdr->dst_mac, dst_mac, ETH_ALEN);
    memcpy(hdr->src_mac, dev->mac, ETH_ALEN);
    hdr->ethertype = htons(ethertype);

    if (len > 0 && payload != NULL) {
        memcpy(frame + ETH_HDR_LEN, payload, len);
    }

    size_t total_len = ETH_HDR_LEN + len;

    /*
     * IEEE 802.3 minimum frame length enforcement:
     * An Ethernet frame (excluding the 4-byte hardware FCS) must be at least
     * 60 bytes (ETH_ZLEN). Zero-pad short frames (such as 42-byte ARP frames)
     * so we never leak uninitialized stack memory onto the wire.
     */
    if (total_len < ETH_ZLEN) {
        memset(frame + total_len, 0, ETH_ZLEN - total_len);
        total_len = ETH_ZLEN;
    }

    ssize_t written = write(dev->tap_fd, frame, total_len);
    return (written == (ssize_t)total_len) ? 0 : -1;
}

int arp_send_request(struct netdev *dev, uint32_t target_ip_be) {
    struct arp_ipv4_pkt arp;

    arp.ar_hrd = htons(ARP_HRD_ETHER);
    arp.ar_pro = htons(ARP_PRO_IP);
    arp.ar_hln = ETH_ALEN;
    arp.ar_pln = 4;
    arp.ar_op  = htons(ARP_OP_REQUEST);

    memcpy(arp.sha, dev->mac, ETH_ALEN);
    arp.spa = dev->ip_be;

    /*
     * Per RFC 826, Target Hardware Address (THA) in an ARP Request is ignored
     * by receivers and conventionally set to all-zeros (00:00:00:00:00:00),
     * while the Ethernet frame destination is broadcast (FF:FF:FF:FF:FF:FF).
     */
    memcpy(arp.tha, ETH_ZERO_MAC, ETH_ALEN);
    arp.tpa = target_ip_be;

    return eth_tx(dev, ETH_BROADCAST_MAC, ETH_P_ARP, &arp, sizeof(arp));
}

int arp_send_reply(struct netdev *dev, const uint8_t target_mac[ETH_ALEN],
                   uint32_t target_ip_be) {
    struct arp_ipv4_pkt arp;

    arp.ar_hrd = htons(ARP_HRD_ETHER);
    arp.ar_pro = htons(ARP_PRO_IP);
    arp.ar_hln = ETH_ALEN;
    arp.ar_pln = 4;
    arp.ar_op  = htons(ARP_OP_REPLY);

    memcpy(arp.sha, dev->mac, ETH_ALEN);
    arp.spa = dev->ip_be;
    memcpy(arp.tha, target_mac, ETH_ALEN);
    arp.tpa = target_ip_be;

    return eth_tx(dev, target_mac, ETH_P_ARP, &arp, sizeof(arp));
}

int netdev_tx_ipv4(struct netdev *dev, uint32_t dst_ip_be,
                   const void *ipv4_pkt, size_t len, uint64_t now_ms) {
    if (len > (ETH_FRAME_MAX - ETH_HDR_LEN)) {
        return -1;
    }

    /*
     * Limited Broadcast (255.255.255.255) or Directed Subnet Broadcast maps
     * directly to Ethernet broadcast FF:FF:FF:FF:FF:FF without ARP resolution.
     */
    if (dst_ip_be == 0xFFFFFFFFU ||
        (dev->netmask_be != 0 &&
         (dst_ip_be & ~dev->netmask_be) == (~dev->netmask_be))) {
        return eth_tx(dev, ETH_BROADCAST_MAC, ETH_P_IP, ipv4_pkt, len);
    }

    /*
     * Next-hop routing decision:
     * Perform bitwise AND in Network Byte Order (endianness-invariant for
     * equality comparisons). If the destination IP is on our local subnet,
     * resolve `dst_ip_be` directly; otherwise resolve our default gateway.
     */
    uint32_t nexthop_ip_be = dst_ip_be;
    if (((dst_ip_be ^ dev->ip_be) & dev->netmask_be) != 0) {
        if (dev->gateway_be == 0) {
            return -1; /* No route to host */
        }
        nexthop_ip_be = dev->gateway_be;
    }

    struct arp_entry *e = arp_cache_lookup(&dev->arp, nexthop_ip_be, now_ms);

    if (e != NULL && (e->state == ARP_STATE_REACHABLE || e->state == ARP_STATE_STALE)) {
        /*
         * If STALE, transmit immediately using the cached MAC so there is zero
         * latency penalty, and trigger a background ARP Request probe to
         * re-confirm reachability.
         */
        int rc = eth_tx(dev, e->mac, ETH_P_IP, ipv4_pkt, len);
        if (e->state == ARP_STATE_STALE) {
            arp_send_request(dev, nexthop_ip_be);
        }
        return rc;
    }

    /*
     * No resolved MAC available: create or update an INCOMPLETE entry,
     * save the latest outbound packet in its hold buffer, and emit an
     * ARP Request (rate-limited to once per ARP_INCOMPLETE_TIME_MS or initial).
     */
    bool send_probe = false;
    if (e == NULL) {
        e = arp_cache_alloc_entry(&dev->arp, nexthop_ip_be, now_ms);
        send_probe = true;
    } else if (now_ms - e->updated_ms >= ARP_INCOMPLETE_TIME_MS) {
        e->updated_ms = now_ms;
        send_probe = true;
    }

    memcpy(e->pending_pkt, ipv4_pkt, len);
    e->pending_len   = (uint16_t)len;
    e->pending_proto = ETH_P_IP;

    if (send_probe) {
        e->retries++;
        return arp_send_request(dev, nexthop_ip_be);
    }
    return 0;
}

/* ==========================================================================
 * Layer 2 & RFC 826 Reception State Machines
 * ========================================================================== */

void arp_rx(struct netdev *dev, const uint8_t *pkt, size_t len, uint64_t now_ms) {
    /*
     * 1. Defensive Bounds Check:
     * Ensure the buffer contains at least a full 28-byte IPv4-over-Ethernet
     * ARP packet before dereferencing any struct fields.
     */
    if (len < sizeof(struct arp_ipv4_pkt)) {
        return;
    }

    const struct arp_ipv4_pkt *arp = (const struct arp_ipv4_pkt *)pkt;

    /*
     * 2. Hardware and Protocol Space Validation (RFC 826 "Packet Reception"):
     *    - Do I have the hardware type in ar$hrd? (Ethernet = 1)
     *    - Do I speak the protocol in ar$pro? (IPv4 = 0x0800)
     *    - Verify hardware length (6) and protocol length (4).
     */
    if (ntohs(arp->ar_hrd) != ARP_HRD_ETHER ||
        ntohs(arp->ar_pro) != ARP_PRO_IP ||
        arp->ar_hln != ETH_ALEN ||
        arp->ar_pln != 4) {
        return;
    }

    /*
     * Reject bogus source MACs (multicast/broadcast bit 0 of byte 0 set, or
     * all-zeros) to prevent ARP cache poisoning with unroutable hardware addresses.
     */
    if ((arp->sha[0] & 0x01) != 0 ||
        memcmp(arp->sha, ETH_ZERO_MAC, ETH_ALEN) == 0 ||
        arp->spa == 0) {
        return;
    }

    /*
     * 3. RFC 826 "Merge_flag" Rule (exact specification order):
     *    Merge_flag := false
     *    If the pair <protocol type, sender protocol address> is already in my
     *    translation table, update the sender hardware address field of the
     *    entry with the new information in the packet and set Merge_flag to true.
     *
     * Notice why RFC 826 performs this BEFORE checking if we are the target:
     * Even if an ARP broadcast is targeting another host on the LAN (or is a
     * Gratuitous ARP), any host that already caches the sender's IP refreshes
     * its MAC mapping for free without generating extra traffic!
     */
    bool merge_flag = false;
    bool found = false;
    (void)arp_find_bucket(&dev->arp, arp->spa, &found);
    if (found) {
        arp_cache_upsert(dev, arp->spa, arp->sha, now_ms);
        merge_flag = true;
    }

    /*
     * 4. Target Protocol Address Check:
     *    "Am I the target protocol address? If not, discard the packet."
     */
    if (arp->tpa != dev->ip_be) {
        return;
    }

    /*
     * 5. Selective Cache Insertion:
     *    "If Merge_flag is false, add the triplet <protocol type, sender
     *    protocol address, sender hardware address> to the translation table."
     *    Because the sender is explicitly addressing us (`tpa == dev->ip_be`),
     *    they are about to communicate with us, so we proactively cache their
     *    MAC now to avoid an ARP Request round-trip when our upper layers reply.
     */
    if (!merge_flag) {
        arp_cache_upsert(dev, arp->spa, arp->sha, now_ms);
    }

    /*
     * 6. Opcode Dispatch:
     *    If Opcode == ARP_OP_REQUEST, generate a unicast ARP_OP_REPLY with
     *    our local MAC and IP.
     */
    uint16_t op = ntohs(arp->ar_op);
    if (op == ARP_OP_REQUEST) {
        arp_send_reply(dev, arp->sha, arp->spa);
    }
}

void eth_rx(struct netdev *dev, const uint8_t *frame, size_t len, uint64_t now_ms) {
    /*
     * 1. Frame Length Validation:
     * Must contain at least the 14-byte IEEE 802.3 header.
     */
    if (len < ETH_HDR_LEN) {
        return;
    }

    const struct eth_hdr *hdr = (const struct eth_hdr *)frame;

    /*
     * 2. Destination MAC Filtering (Promiscuous-Mode Guard):
     * Accept frames addressed to:
     *   - Our exact unicast MAC (`dev->mac`)
     *   - Ethernet Broadcast (`FF:FF:FF:FF:FF:FF`)
     *   - IPv4 Multicast (`01:00:5E:xx:xx:xx`) if needed; drop foreign unicast.
     */
    bool is_our_mac   = (memcmp(hdr->dst_mac, dev->mac, ETH_ALEN) == 0);
    bool is_broadcast = (memcmp(hdr->dst_mac, ETH_BROADCAST_MAC, ETH_ALEN) == 0);
    if (!is_our_mac && !is_broadcast) {
        return;
    }

    const uint8_t *payload = frame + ETH_HDR_LEN;
    size_t payload_len     = len - ETH_HDR_LEN;
    uint16_t ethertype     = ntohs(hdr->ethertype);

    /*
     * 3. EtherType Demultiplexing:
     */
    switch (ethertype) {
        case ETH_P_ARP:
            arp_rx(dev, payload, payload_len, now_ms);
            break;

        case ETH_P_IP:
            if (dev->ip_rx_cb != NULL) {
                dev->ip_rx_cb(dev, payload, payload_len, now_ms);
            }
            break;

        default:
            /* Unsupported L3 protocol (e.g., IPv6 Neighbor Discovery): drop */
            break;
    }
}
