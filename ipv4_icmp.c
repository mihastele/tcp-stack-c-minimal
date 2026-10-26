#define _GNU_SOURCE
#include "ipv4_icmp.h"
#include "net_base.h"

#include <string.h>
#include <arpa/inet.h>

/* Monotonically incrementing IPv4 Identification counter (host byte order) */
static uint16_t g_ipv4_id_counter = 1;

/* Registered Layer 4 TCP demultiplexer callback */
static tcp_rx_fn g_tcp_rx_handler = NULL;

void ipv4_set_tcp_handler(tcp_rx_fn fn) {
    g_tcp_rx_handler = fn;
}

int ipv4_tx(struct netdev *dev, uint32_t dst_ip_be, uint8_t proto,
            const void *payload, size_t len, uint64_t now_ms) {
    /*
     * Defensive MTU check:
     * Standard Ethernet payload is 1500 bytes (ETH_FRAME_MAX - ETH_HDR_LEN).
     * With a 20-byte IPv4 header, the maximum unfragmented L4 payload is 1480
     * bytes. Reject oversized L4 frames to avoid silent truncation.
     */
    const size_t max_l4_len = (ETH_FRAME_MAX - ETH_HDR_LEN) - IPV4_HDR_MIN_LEN;
    if (len > max_l4_len) {
        return -1;
    }

    uint8_t pkt[ETH_FRAME_MAX - ETH_HDR_LEN];
    struct ipv4_hdr *hdr = (struct ipv4_hdr *)pkt;
    size_t total_len = IPV4_HDR_MIN_LEN + len;

    /*
     * Construct the 20-byte IPv4 header:
     * - ver_ihl = (4 << 4) | 5 = 0x45 (Version 4, 5 x 32-bit words = 20 bytes)
     * - frag_off = htons(IPV4_FLAG_DF) (Set Don't Fragment for PMTUD compliance)
     */
    hdr->ver_ihl  = (uint8_t)((IPV4_VERSION << 4) | IPV4_MIN_IHL);
    hdr->tos      = 0;
    hdr->tot_len  = htons((uint16_t)total_len);
    hdr->id       = htons(g_ipv4_id_counter++);
    hdr->frag_off = htons(IPV4_FLAG_DF);
    hdr->ttl      = IPV4_DEFAULT_TTL;
    hdr->proto    = proto;
    hdr->check    = 0; /* Must be zeroed before computing RFC 1071 checksum */
    hdr->saddr    = dev->ip_be;
    hdr->daddr    = dst_ip_be;

    /*
     * Compute the 16-bit one's complement checksum over the 20-byte IPv4 header
     * only (RFC 791: unlike TCP/ICMP, IPv4 does not checksum the L4 payload).
     */
    hdr->check = checksum16_optimized(hdr, IPV4_HDR_MIN_LEN);

    if (len > 0 && payload != NULL) {
        memcpy(pkt + IPV4_HDR_MIN_LEN, payload, len);
    }

    return netdev_tx_ipv4(dev, dst_ip_be, pkt, total_len, now_ms);
}

void icmp_rx(struct netdev *dev, const struct ipv4_hdr *ip_hdr,
             const uint8_t *icmp_pkt, size_t len, uint64_t now_ms) {
    /*
     * 1. Minimum Bounds Validation:
     * An RFC 792 ICMP header is at least 8 bytes.
     */
    if (len < sizeof(struct icmp_hdr)) {
        return;
    }

    /*
     * 2. Verify Full ICMP Checksum (Header + Echo Data Payload):
     * By RFC 1071, computing the one's complement checksum over a valid buffer
     * that includes its own wire checksum field yields 0x0000 (or 0xFFFF in
     * negative-zero representation, which ~acc normalizes to 0x0000).
     */
    if (checksum16_optimized(icmp_pkt, len) != 0) {
        return;
    }

    const struct icmp_hdr *req = (const struct icmp_hdr *)icmp_pkt;

    /*
     * 3. Handle ICMP Echo Request (Type 8, Code 0):
     * Per RFC 792, to form an Echo Reply message (Type 0, Code 0):
     *   - Swap source and destination IPv4 addresses
     *   - Change Type from 8 to 0
     *   - Preserve Identifier (`id`), Sequence Number (`seq`), and exact data
     *   - Recompute the ICMP checksum
     */
    if (req->type == ICMP_TYPE_ECHO_REQUEST && req->code == 0) {
        if (len > (ETH_FRAME_MAX - ETH_HDR_LEN - IPV4_HDR_MIN_LEN)) {
            return;
        }

        uint8_t reply_buf[ETH_FRAME_MAX - ETH_HDR_LEN - IPV4_HDR_MIN_LEN];
        memcpy(reply_buf, icmp_pkt, len);

        struct icmp_hdr *rep = (struct icmp_hdr *)reply_buf;
        rep->type     = ICMP_TYPE_ECHO_REPLY;
        rep->code     = 0;
        rep->checksum = 0;

        /*
         * Note on Incremental Checksum Adjustment (RFC 1624):
         * Because only `type` changes from 0x0800 to 0x0000 in 16-bit network
         * word 0, one could incrementally update `~(~old_check + ~0x0800)`.
         * Calling `checksum16_optimized()` over the reply buffer exercises our
         * 64-bit accumulator across arbitrary payload sizes and alignment.
         */
        rep->checksum = checksum16_optimized(reply_buf, len);

        ipv4_tx(dev, ip_hdr->saddr, IPPROTO_ICMP_VAL, reply_buf, len, now_ms);
    }
}

void ipv4_rx(struct netdev *dev, const uint8_t *pkt, size_t len, uint64_t now_ms) {
    /*
     * 1. Minimum Frame Slice Check:
     * Reject truncated frames smaller than the mandatory 20-byte IPv4 header.
     */
    if (len < IPV4_HDR_MIN_LEN) {
        return;
    }

    const struct ipv4_hdr *hdr = (const struct ipv4_hdr *)pkt;

    /*
     * 2. Version and Internet Header Length (IHL) Validation:
     *    - Version MUST be 4 (IPv4).
     *    - IHL is measured in 32-bit words and MUST be >= 5 (20 bytes).
     *    - The actual buffer `len` must hold the full `ihl_bytes` header.
     */
    if (IPV4_VER(hdr) != IPV4_VERSION) {
        return;
    }

    size_t ihl_bytes = IPV4_HDR_BYTES(hdr);
    if (ihl_bytes < IPV4_HDR_MIN_LEN || len < ihl_bytes) {
        return;
    }

    /*
     * 3. Total Length Validation & IEEE 802.3 Padding Strip:
     *    Why can `tot_len` be smaller than `len`?
     *    Ethernet frames must be at least 60 bytes (`ETH_ZLEN`). A 20-byte IPv4
     *    header + 20-byte TCP SYN has `tot_len = 40`, which sits inside a
     *    46-byte Ethernet payload (`14 + 46 = 60`).
     *    We MUST clamp the L3 packet length to `tot_len` so trailing Ethernet
     *    zero-padding is never fed into the L4 (TCP/ICMP) checksum or parser!
     */
    uint16_t tot_len = ntohs(hdr->tot_len);
    if (tot_len < ihl_bytes || tot_len > len) {
        return;
    }

    /*
     * 4. Time-To-Live (TTL) Check:
     *    Drop packets with TTL == 0 on arrival.
     */
    if (hdr->ttl == 0) {
        return;
    }

    /*
     * 5. RFC 1071 IPv4 Header Checksum Verification:
     *    Calculated over `ihl_bytes` (including any IPv4 options).
     *    A valid header with its intact checksum field folds to 0x0000.
     */
    if (checksum16_optimized(hdr, ihl_bytes) != 0) {
        return;
    }

    /*
     * 6. Destination Address Filtering (RFC 1122 §3.2.1.3):
     *    Accept packets addressed to:
     *      - Our unicast IPv4 address (`dev->ip_be`)
     *      - Limited broadcast (`255.255.255.255`)
     *      - Directed subnet broadcast (`(daddr & ~netmask) == ~netmask`)
     */
    bool is_unicast = (hdr->daddr == dev->ip_be);
    bool is_bcast   = (hdr->daddr == 0xFFFFFFFFU) ||
                      (dev->netmask_be != 0 &&
                       (hdr->daddr & ~dev->netmask_be) == (~dev->netmask_be));
    if (!is_unicast && !is_bcast) {
        return;
    }

    /*
     * 7. Fragmentation Check (RFC 791):
     *    A packet is a fragment if either:
     *      - The `More Fragments` (MF, 0x2000) flag is set, OR
     *      - The 13-bit `Fragment Offset` (0x1FFF) is non-zero.
     *    Also reject packets with the RFC 3514 "Evil Bit" / Reserved flag set.
     */
    uint16_t frag = ntohs(hdr->frag_off);
    if ((frag & IPV4_FLAG_RESERVED) != 0) {
        return;
    }
    if ((frag & (IPV4_FLAG_MF | IPV4_FRAG_OFFSET)) != 0) {
        /* Drop fragmented IPv4 datagrams (TCP uses MSS negotiation + DF bit) */
        return;
    }

    /*
     * 8. Demultiplex Upper-Layer Protocol Payload:
     *    Slice starts at `pkt + ihl_bytes` with exact length `tot_len - ihl_bytes`.
     */
    const uint8_t *l4_payload = pkt + ihl_bytes;
    size_t l4_len             = (size_t)tot_len - ihl_bytes;

    switch (hdr->proto) {
        case IPPROTO_ICMP_VAL:
            icmp_rx(dev, hdr, l4_payload, l4_len, now_ms);
            break;

        case IPPROTO_TCP_VAL:
            /* Reject TCP segments sent to broadcast addresses (RFC 1122 §4.2.3.10) */
            if (is_unicast && g_tcp_rx_handler != NULL) {
                g_tcp_rx_handler(dev, hdr, l4_payload, l4_len, now_ms);
            }
            break;

        default:
            break;
    }
}
