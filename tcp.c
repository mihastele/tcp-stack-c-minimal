#define _GNU_SOURCE
#include "tcp.h"
#include "net_base.h"

#include <string.h>
#include <arpa/inet.h>

/* Singleton pointer used to bridge `ipv4_set_tcp_handler` to our stack */
static struct tcp_stack *g_active_tcp_stack = NULL;

static void tcp_ipv4_rx_bridge(struct netdev *dev, const struct ipv4_hdr *ip_hdr,
                               const uint8_t *tcp_seg, size_t tcp_len, uint64_t now_ms) {
    (void)dev;
    if (g_active_tcp_stack != NULL) {
        tcp_rx_segment(g_active_tcp_stack, ip_hdr, tcp_seg, tcp_len, now_ms);
    }
}

/* ==========================================================================
 * 1. Zero-Copy Scatter-Gather TCP Checksum (RFC 793 / RFC 1071)
 * ========================================================================== */

uint16_t tcp_checksum(uint32_t saddr_be, uint32_t daddr_be,
                      const void *tcp_seg, size_t tcp_len) {
    struct ipv4_pseudo_hdr phdr;
    phdr.saddr   = saddr_be;
    phdr.daddr   = daddr_be;
    phdr.zero    = 0;
    phdr.proto   = IPPROTO_TCP_VAL;
    phdr.tcp_len = htons((uint16_t)tcp_len);

    /*
     * Accumulate the 12-byte IPv4 pseudo-header first (12 is even, so byte
     * lane alignment is preserved), then accumulate the TCP header + payload
     * directly in-place, and fold the 64-bit sum down to 16 bits.
     */
    uint64_t acc = checksum16_accumulate(&phdr, sizeof(phdr), 0);
    acc = checksum16_accumulate(tcp_seg, tcp_len, acc);
    return checksum16_fold(acc);
}

/* ==========================================================================
 * 2. O(1) 4-Tuple Hash Table with MurmurHash3 & Backward-Shift Deletion
 * ========================================================================== */

static inline uint32_t fmix32(uint32_t h) {
    h ^= h >> 16;
    h *= 0x85ebca6bU;
    h ^= h >> 13;
    h *= 0xc2b2ae35U;
    h ^= h >> 16;
    return h;
}

/**
 * Hash a 4-tuple `(local_ip_be, remote_ip_be, local_port_be, remote_port_be)`
 * into `[0, TCP_HASH_BUCKETS - 1]`.
 *
 * We pack `local_port_be` and `remote_port_be` into a single 32-bit word and
 * mix all three 32-bit words with golden-ratio / Murmur3 constants so single-bit
 * differences in ephemeral ports produce uniform bucket distribution.
 */
static inline uint32_t tcp_hash_4tuple(uint32_t local_ip_be, uint32_t remote_ip_be,
                                       uint16_t local_port_be, uint16_t remote_port_be) {
    uint32_t ports = ((uint32_t)local_port_be << 16) | (uint32_t)remote_port_be;
    uint32_t h = local_ip_be ^ (remote_ip_be * 0x9e3779b9U) ^ (ports * 0x85ebca6bU);
    return fmix32(h) & (TCP_HASH_BUCKETS - 1U);
}

static uint32_t tcp_find_bucket(const struct tcp_stack *stack,
                                uint32_t local_ip_be, uint32_t remote_ip_be,
                                uint16_t local_port_be, uint16_t remote_port_be,
                                bool *found) {
    uint32_t b = tcp_hash_4tuple(local_ip_be, remote_ip_be, local_port_be, remote_port_be);

    for (uint32_t step = 0; step < TCP_HASH_BUCKETS; step++) {
        uint16_t slot = stack->buckets[b];
        if (slot == TCP_NULL_IDX) {
            *found = false;
            return b;
        }
        const struct tcp_tcb *tcb = &stack->pool[slot];
        if (tcb->local_ip_be    == local_ip_be &&
            tcb->remote_ip_be   == remote_ip_be &&
            tcb->local_port_be  == local_port_be &&
            tcb->remote_port_be == remote_port_be) {
            *found = true;
            return b;
        }
        b = (b + 1U) & (TCP_HASH_BUCKETS - 1U);
    }

    *found = false;
    return b;
}

/**
 * Knuth Algorithm R (Backward-Shift Deletion) on `stack->buckets[]`.
 * Eliminates tombstones so long-lived servers accepting and closing millions
 * of connections never suffer probe-cluster degradation.
 */
static void tcp_hash_remove_bucket(struct tcp_stack *stack, uint32_t bucket_idx) {
    uint32_t i = bucket_idx;
    uint32_t j = i;

    for (;;) {
        stack->buckets[i] = TCP_NULL_IDX;
        for (;;) {
            j = (j + 1U) & (TCP_HASH_BUCKETS - 1U);
            uint16_t slot = stack->buckets[j];
            if (slot == TCP_NULL_IDX) {
                return;
            }
            const struct tcp_tcb *tcb = &stack->pool[slot];
            uint32_t k = tcp_hash_4tuple(tcb->local_ip_be, tcb->remote_ip_be,
                                         tcb->local_port_be, tcb->remote_port_be);
            if ((i <= j) ? ((k <= i) || (k > j)) : ((k <= i) && (k > j))) {
                break;
            }
        }
        stack->buckets[i] = stack->buckets[j];
        i = j;
    }
}

struct tcp_tcb *tcp_lookup_tcb(struct tcp_stack *stack,
                               uint32_t local_ip_be, uint32_t remote_ip_be,
                               uint16_t local_port_be, uint16_t remote_port_be) {
    bool found = false;
    uint32_t b = tcp_find_bucket(stack, local_ip_be, remote_ip_be,
                                 local_port_be, remote_port_be, &found);
    if (!found) {
        return NULL;
    }
    return &stack->pool[stack->buckets[b]];
}

/* ==========================================================================
 * 3. Intrusive Delta-List Timer Queue & RFC 6298 RTT/RTO Engine
 * ========================================================================== */

/**
 * Unlink `tcb` from the intrusive delta-list timer queue in O(1) time.
 *
 * Mechanical Invariant:
 * Because every node after `tcb` has its expiration expressed as a delta
 * relative to `tcb`, removing `tcb` requires adding `tcb->timer_delta_ms`
 * to its immediate successor (`tcb->timer_next`) so all downstream expiration
 * times remain unchanged!
 */
static void timer_cancel(struct tcp_stack *stack, struct tcp_tcb *tcb) {
    if (!tcb->timer_active) {
        return;
    }

    if (tcb->timer_next != TCP_NULL_IDX) {
        stack->pool[tcb->timer_next].timer_delta_ms += tcb->timer_delta_ms;
        stack->pool[tcb->timer_next].timer_prev = tcb->timer_prev;
    }

    if (tcb->timer_prev != TCP_NULL_IDX) {
        stack->pool[tcb->timer_prev].timer_next = tcb->timer_next;
    } else {
        stack->timer_head = tcb->timer_next;
    }

    tcb->timer_active   = false;
    tcb->timer_delta_ms = 0;
    tcb->timer_prev     = TCP_NULL_IDX;
    tcb->timer_next     = TCP_NULL_IDX;
}

/**
 * Advance the delta-list head by `now_ms - stack->last_tick_ms` without
 * firing callbacks yet, keeping `stack->last_tick_ms` synchronized before
 * inserting a new relative timer.
 */
static void timer_sync_clock(struct tcp_stack *stack, uint64_t now_ms) {
    if (now_ms <= stack->last_tick_ms) {
        return;
    }
    uint64_t elapsed = now_ms - stack->last_tick_ms;
    stack->last_tick_ms = now_ms;

    uint16_t cur_idx = stack->timer_head;
    while (cur_idx != TCP_NULL_IDX && elapsed > 0) {
        struct tcp_tcb *cur = &stack->pool[cur_idx];
        if (cur->timer_delta_ms >= elapsed) {
            cur->timer_delta_ms -= elapsed;
            elapsed = 0;
        } else {
            elapsed -= cur->timer_delta_ms;
            cur->timer_delta_ms = 0;
            cur_idx = cur->timer_next;
        }
    }
}

/**
 * Schedule or reschedule `tcb` to fire `delay_ms` milliseconds after `now_ms`
 * in the intrusive delta-list.
 */
static void timer_schedule(struct tcp_stack *stack, struct tcp_tcb *tcb,
                           uint64_t delay_ms, uint64_t now_ms) {
    timer_sync_clock(stack, now_ms);
    timer_cancel(stack, tcb);

    uint64_t remaining = delay_ms;
    uint16_t prev_idx  = TCP_NULL_IDX;
    uint16_t cur_idx   = stack->timer_head;

    /* Walk down the delta-list subtracting each node's delta */
    while (cur_idx != TCP_NULL_IDX) {
        struct tcp_tcb *cur = &stack->pool[cur_idx];
        if (remaining < cur->timer_delta_ms) {
            break;
        }
        remaining -= cur->timer_delta_ms;
        prev_idx = cur_idx;
        cur_idx  = cur->timer_next;
    }

    tcb->timer_active   = true;
    tcb->timer_delta_ms = remaining;
    tcb->timer_prev     = prev_idx;
    tcb->timer_next     = cur_idx;

    if (prev_idx != TCP_NULL_IDX) {
        stack->pool[prev_idx].timer_next = tcb->pool_idx;
    } else {
        stack->timer_head = tcb->pool_idx;
    }

    if (cur_idx != TCP_NULL_IDX) {
        stack->pool[cur_idx].timer_delta_ms -= remaining;
        stack->pool[cur_idx].timer_prev = tcb->pool_idx;
    }
}

/**
 * RFC 6298 (Jacobson / Karels Algorithm) RTT & RTO Update.
 *
 * Given a new round-trip time sample `rtt_ms` from an un-retransmitted segment:
 *  - First sample R:
 *      SRTT   <- R
 *      RTTVAR <- R / 2
 *  - Subsequent sample R':
 *      RTTVAR <- (3/4) * RTTVAR + (1/4) * |SRTT - R'|
 *      SRTT   <- (7/8) * SRTT   + (1/8) * R'
 *  - RTO <- SRTT + max(G, 4 * RTTVAR), clamped to [TCP_RTO_MIN_MS, TCP_RTO_MAX_MS].
 */
static void tcp_update_rtt(struct tcp_tcb *tcb, uint64_t rtt_ms) {
    /* Convert ms to us (with a minimum floor of 1000 us = 1 ms) */
    uint32_t r_us = (rtt_ms > 0) ? (uint32_t)(rtt_ms * 1000ULL) : 1000U;

    if (!tcb->rtt_measured) {
        tcb->rtt_measured = true;
        tcb->srtt_us      = r_us;
        tcb->rttvar_us    = r_us >> 1;
    } else {
        uint32_t diff_us = (tcb->srtt_us >= r_us)
                         ? (tcb->srtt_us - r_us)
                         : (r_us - tcb->srtt_us);
        /* RTTVAR <- (3 * RTTVAR + |SRTT - R'|) / 4 */
        tcb->rttvar_us = ((tcb->rttvar_us * 3U) + diff_us) >> 2;
        /* SRTT <- (7 * SRTT + R') / 8 */
        tcb->srtt_us   = ((tcb->srtt_us * 7U) + r_us) >> 3;
    }

    uint32_t four_rttvar = tcb->rttvar_us << 2;
    uint32_t k_rttvar    = (four_rttvar > TCP_RTT_GRANULARITY_US)
                         ? four_rttvar
                         : TCP_RTT_GRANULARITY_US;

    uint32_t rto_ms = (tcb->srtt_us + k_rttvar) / 1000U;
    if (rto_ms < TCP_RTO_MIN_MS) {
        rto_ms = TCP_RTO_MIN_MS;
    } else if (rto_ms > TCP_RTO_MAX_MS) {
        rto_ms = TCP_RTO_MAX_MS;
    }
    tcb->rto_ms = rto_ms;
}

/* ==========================================================================
 * 4. Monotonic Circular Ring Buffer & Out-of-Order Interval Reassembly
 * ========================================================================== */

/**
 * Compute how many unread in-order bytes currently sit in `tcb->rcv_buf`
 * waiting for or during delivery, and update `tcb->rcv_wnd`.
 *
 * Notice how the monotonic circular buffer works:
 * Any sequence number `s` maps directly to `rcv_buf[(s - (irs + 1)) & MASK]`.
 * Because out-of-order segments beyond `rcv_nxt` must lie strictly below
 * `rcv_read_seq + TCP_RCV_BUF_SIZE`, the advertised window from `rcv_nxt` is:
 * `TCP_RCV_BUF_SIZE - (rcv_nxt - rcv_read_seq)`.
 */
static void tcp_update_rcv_wnd(struct tcp_tcb *tcb) {
    uint32_t unread = tcb->rcv_nxt - tcb->rcv_read_seq;
    if (unread >= TCP_RCV_BUF_SIZE) {
        tcb->rcv_wnd = 0;
    } else {
        tcb->rcv_wnd = TCP_RCV_BUF_SIZE - unread;
    }
}

/**
 * Write `len` payload bytes starting at sequence number `seq` into the
 * circular receive buffer `tcb->rcv_buf` using at most two `memcpy` calls.
 */
static void tcp_rcv_write_ring(struct tcp_tcb *tcb, uint32_t seq,
                               const uint8_t *data, size_t len) {
    if (len == 0) {
        return;
    }

    uint32_t base_seq = tcb->irs + 1U;
    uint32_t ring_off = (seq - base_seq) & TCP_RCV_BUF_MASK;
    size_t first_chunk = TCP_RCV_BUF_SIZE - ring_off;

    if (len <= first_chunk) {
        memcpy(tcb->rcv_buf + ring_off, data, len);
    } else {
        memcpy(tcb->rcv_buf + ring_off, data, first_chunk);
        memcpy(tcb->rcv_buf, data + first_chunk, len - first_chunk);
    }
}

/**
 * Insert sequence interval `[start_seq, end_seq)` into the sorted,
 * auto-coalescing out-of-order interval list `tcb->ooo[]`.
 *
 * Algorithmic Behavior:
 * 1. Find the insertion point where `start_seq` belongs in sorted order
 *    (using modular `SEQ_LT` / `SEQ_LEQ`).
 * 2. Insert the new interval (or drop if `TCP_MAX_OOO_INTERVALS` is full and
 *    it lies beyond all existing intervals).
 * 3. Single linear coalesce pass: merge any adjacent or overlapping intervals
 *    where `SEQ_LEQ(ooo[i+1].start_seq, ooo[i].end_seq)`.
 */
static void tcp_ooo_insert(struct tcp_tcb *tcb, uint32_t start_seq, uint32_t end_seq) {
    if (SEQ_GEQ(start_seq, end_seq)) {
        return;
    }

    /* Step 1: Locate sorted insertion index `pos` */
    uint8_t pos = 0;
    while (pos < tcb->ooo_count && SEQ_LT(tcb->ooo[pos].start_seq, start_seq)) {
        pos++;
    }

    /* Step 2: Insert at `pos` if space permits (or if we can merge immediately) */
    if (tcb->ooo_count < TCP_MAX_OOO_INTERVALS) {
        for (uint8_t i = tcb->ooo_count; i > pos; i--) {
            tcb->ooo[i] = tcb->ooo[i - 1U];
        }
        tcb->ooo[pos].start_seq = start_seq;
        tcb->ooo[pos].end_seq   = end_seq;
        tcb->ooo_count++;
    } else {
        /* If table is full, merge into an overlapping neighbor if possible */
        for (uint8_t i = 0; i < tcb->ooo_count; i++) {
            if (SEQ_LEQ(start_seq, tcb->ooo[i].end_seq) &&
                SEQ_GEQ(end_seq, tcb->ooo[i].start_seq)) {
                if (SEQ_LT(start_seq, tcb->ooo[i].start_seq)) {
                    tcb->ooo[i].start_seq = start_seq;
                }
                if (SEQ_GT(end_seq, tcb->ooo[i].end_seq)) {
                    tcb->ooo[i].end_seq = end_seq;
                }
                break;
            }
        }
    }

    /* Step 3: Coalesce overlapping or contiguous intervals */
    if (tcb->ooo_count <= 1) {
        return;
    }

    uint8_t write_idx = 0;
    for (uint8_t read_idx = 1; read_idx < tcb->ooo_count; read_idx++) {
        if (SEQ_LEQ(tcb->ooo[read_idx].start_seq, tcb->ooo[write_idx].end_seq)) {
            if (SEQ_GT(tcb->ooo[read_idx].end_seq, tcb->ooo[write_idx].end_seq)) {
                tcb->ooo[write_idx].end_seq = tcb->ooo[read_idx].end_seq;
            }
        } else {
            write_idx++;
            tcb->ooo[write_idx] = tcb->ooo[read_idx];
        }
    }
    tcb->ooo_count = (uint8_t)(write_idx + 1U);
}

/**
 * Advance `tcb->rcv_nxt` across any out-of-order intervals that have now
 * become contiguous with `tcb->rcv_nxt`, and deliver the newly contiguous
 * stream slice `[rcv_read_seq, rcv_nxt)` to the application callback.
 */
static void tcp_reassemble_and_deliver(struct tcp_stack *stack, struct tcp_tcb *tcb) {
    /*
     * Consume all OOO intervals whose `start_seq <= rcv_nxt`.
     */
    uint8_t consumed = 0;
    while (consumed < tcb->ooo_count &&
           SEQ_LEQ(tcb->ooo[consumed].start_seq, tcb->rcv_nxt)) {
        if (SEQ_GT(tcb->ooo[consumed].end_seq, tcb->rcv_nxt)) {
            tcb->rcv_nxt = tcb->ooo[consumed].end_seq;
        }
        consumed++;
    }

    if (consumed > 0) {
        uint8_t remaining = (uint8_t)(tcb->ooo_count - consumed);
        for (uint8_t i = 0; i < remaining; i++) {
            tcb->ooo[i] = tcb->ooo[i + consumed];
        }
        tcb->ooo_count = remaining;
    }

    /*
     * Deliver newly contiguous in-order bytes `[rcv_read_seq, rcv_nxt)` to the
     * application. Because the ring buffer may wrap around at `TCP_RCV_BUF_SIZE`,
     * we deliver in at most two contiguous slices with zero intermediate copies!
     */
    uint32_t avail = tcb->rcv_nxt - tcb->rcv_read_seq;
    if (avail > 0) {
        uint32_t base_seq = tcb->irs + 1U;
        uint32_t ring_off = (tcb->rcv_read_seq - base_seq) & TCP_RCV_BUF_MASK;
        size_t first_chunk = TCP_RCV_BUF_SIZE - ring_off;

        tcb->rcv_read_seq = tcb->rcv_nxt;
        tcp_update_rcv_wnd(tcb);

        if (tcb->cb.on_recv != NULL) {
            if (avail <= first_chunk) {
                tcb->cb.on_recv(stack, tcb, tcb->rcv_buf + ring_off, avail);
            } else {
                tcb->cb.on_recv(stack, tcb, tcb->rcv_buf + ring_off, first_chunk);
                tcb->cb.on_recv(stack, tcb, tcb->rcv_buf, avail - first_chunk);
            }
        }
    } else {
        tcp_update_rcv_wnd(tcb);
    }
}

/* ==========================================================================
 * 5. TCB Lifecycle & Segment Transmission Helpers
 * ========================================================================== */

static struct tcp_tcb *tcp_alloc_tcb(struct tcp_stack *stack,
                                     uint32_t local_ip_be, uint32_t remote_ip_be,
                                     uint16_t local_port_be, uint16_t remote_port_be) {
    if (stack->free_head == TCP_NULL_IDX) {
        return NULL;
    }

    bool found = false;
    uint32_t b = tcp_find_bucket(stack, local_ip_be, remote_ip_be,
                                 local_port_be, remote_port_be, &found);
    if (found) {
        return NULL;
    }

    uint16_t slot = stack->free_head;
    stack->free_head = stack->pool[slot].timer_next;
    stack->buckets[b] = slot;

    struct tcp_tcb *tcb = &stack->pool[slot];
    memset(tcb, 0, sizeof(*tcb));

    tcb->local_ip_be    = local_ip_be;
    tcb->remote_ip_be   = remote_ip_be;
    tcb->local_port_be  = local_port_be;
    tcb->remote_port_be = remote_port_be;
    tcb->state          = TCP_STATE_CLOSED;
    tcb->pool_idx       = slot;
    tcb->mss            = TCP_DEFAULT_MSS;
    tcb->rcv_wnd        = TCP_RCV_BUF_SIZE;
    tcb->rto_ms         = TCP_RTO_INITIAL_MS;
    tcb->timer_prev     = TCP_NULL_IDX;
    tcb->timer_next     = TCP_NULL_IDX;

    return tcb;
}

static void tcp_free_tcb(struct tcp_stack *stack, struct tcp_tcb *tcb) {
    timer_cancel(stack, tcb);

    bool found = false;
    uint32_t b = tcp_find_bucket(stack, tcb->local_ip_be, tcb->remote_ip_be,
                                 tcb->local_port_be, tcb->remote_port_be, &found);
    if (found) {
        tcp_hash_remove_bucket(stack, b);
    }

    uint16_t slot = tcb->pool_idx;
    tcb->state      = TCP_STATE_CLOSED;
    tcb->timer_next = stack->free_head;
    stack->free_head = slot;
}

/**
 * Generate a cryptographic/hashed Initial Sequence Number (ISN) per
 * RFC 6528 (`ISN = M + F(local_ip, local_port, remote_ip, remote_port, secret)`),
 * where `M` is a 4-microsecond (250 kHz) monotonic counter.
 */
static uint32_t tcp_generate_isn(struct tcp_stack *stack,
                                 uint32_t local_ip_be, uint32_t remote_ip_be,
                                 uint16_t local_port_be, uint16_t remote_port_be,
                                 uint64_t now_ms) {
    uint32_t h = tcp_hash_4tuple(local_ip_be, remote_ip_be, local_port_be, remote_port_be);
    h = fmix32(h ^ stack->isn_secret++);
    uint32_t m = (uint32_t)(now_ms * 250ULL); /* 4us ticks */
    return m + h;
}

/**
 * Low-level TCP segment constructor & transmitter.
 * Builds a 20-byte TCP header (or 24-byte header with the 4-byte MSS option
 * when `TCP_FLAG_SYN` is set), calculates the scatter-gather checksum, and
 * hands the segment to `ipv4_tx()`.
 */
static int tcp_tx_raw(struct tcp_stack *stack,
                      uint32_t saddr_be, uint32_t daddr_be,
                      uint16_t sport_be, uint16_t dport_be,
                      uint32_t seq, uint32_t ack_seq,
                      uint8_t flags, uint16_t wnd,
                      const uint8_t *payload, size_t payload_len,
                      uint64_t now_ms) {
    uint8_t seg[ETH_FRAME_MAX - ETH_HDR_LEN - IPV4_HDR_MIN_LEN];
    struct tcp_hdr *hdr = (struct tcp_hdr *)seg;

    bool include_mss = ((flags & TCP_FLAG_SYN) != 0);
    size_t hdr_len   = include_mss ? (TCP_HDR_MIN_LEN + 4U) : TCP_HDR_MIN_LEN;

    if (hdr_len + payload_len > sizeof(seg)) {
        return -1;
    }

    hdr->sport     = sport_be;
    hdr->dport     = dport_be;
    hdr->seq       = htonl(seq);
    hdr->ack_seq   = htonl(ack_seq);
    hdr->doff_rsvd = (uint8_t)(((hdr_len / 4U) << 4) & 0xF0U);
    hdr->flags     = flags;
    hdr->window    = htons(wnd);
    hdr->check     = 0;
    hdr->urg_ptr   = 0;

    if (include_mss) {
        /* 4-byte MSS Option: Kind=2, Len=4, MSS=htons(TCP_DEFAULT_MSS) */
        uint8_t *opt = seg + TCP_HDR_MIN_LEN;
        opt[0] = TCP_OPT_MSS;
        opt[1] = 4U;
        uint16_t mss_be = htons(TCP_DEFAULT_MSS);
        memcpy(opt + 2, &mss_be, 2);
    }

    if (payload_len > 0 && payload != NULL) {
        memcpy(seg + hdr_len, payload, payload_len);
    }

    size_t total_tcp_len = hdr_len + payload_len;
    hdr->check = tcp_checksum(saddr_be, daddr_be, seg, total_tcp_len);

    return ipv4_tx(stack->dev, daddr_be, IPPROTO_TCP_VAL, seg, total_tcp_len, now_ms);
}

static int tcp_tx_ctrl(struct tcp_stack *stack, struct tcp_tcb *tcb,
                       uint8_t flags, uint64_t now_ms) {
    uint16_t wnd = (tcb->rcv_wnd > 0xFFFFU) ? 0xFFFFU : (uint16_t)tcb->rcv_wnd;
    return tcp_tx_raw(stack,
                      tcb->local_ip_be, tcb->remote_ip_be,
                      tcb->local_port_be, tcb->remote_port_be,
                      tcb->snd_nxt, tcb->rcv_nxt,
                      flags, wnd, NULL, 0, now_ms);
}

/**
 * Write `len` bytes into `tcb->snd_buf` starting at sequence number `seq`.
 */
static void tcp_snd_write_ring(struct tcp_tcb *tcb, uint32_t seq,
                               const uint8_t *data, size_t len) {
    uint32_t base_seq = tcb->iss + 1U;
    uint32_t ring_off = (seq - base_seq) & TCP_SND_BUF_MASK;
    size_t first_chunk = TCP_SND_BUF_SIZE - ring_off;

    if (len <= first_chunk) {
        memcpy(tcb->snd_buf + ring_off, data, len);
    } else {
        memcpy(tcb->snd_buf + ring_off, data, first_chunk);
        memcpy(tcb->snd_buf, data + first_chunk, len - first_chunk);
    }
}

/**
 * Copy `len` bytes out of `tcb->snd_buf` starting at sequence number `seq`
 * into a linear staging slice `dst` for packet transmission / retransmission.
 */
static void tcp_snd_read_ring(const struct tcp_tcb *tcb, uint32_t seq,
                              uint8_t *dst, size_t len) {
    uint32_t base_seq = tcb->iss + 1U;
    uint32_t ring_off = (seq - base_seq) & TCP_SND_BUF_MASK;
    size_t first_chunk = TCP_SND_BUF_SIZE - ring_off;

    if (len <= first_chunk) {
        memcpy(dst, tcb->snd_buf + ring_off, len);
    } else {
        memcpy(dst, tcb->snd_buf + ring_off, first_chunk);
        memcpy(dst + first_chunk, tcb->snd_buf, len - first_chunk);
    }
}

/**
 * Compute the total ending sequence number of data queued in `tcb->snd_buf`
 * (excluding any queued FIN).
 */
static uint32_t tcp_snd_data_end_seq(const struct tcp_tcb *tcb) {
    return tcb->fin_queued ? tcb->fin_seq : tcb->snd_nxt;
}

/**
 * Retransmit the oldest unacknowledged segment starting at `tcb->snd_una`.
 * Invoked upon RFC 6298 Retransmission Timeout (RTO) expiration.
 */
static void tcp_retransmit_oldest(struct tcp_stack *stack, struct tcp_tcb *tcb,
                                  uint64_t now_ms) {
    /* Per Karn's Algorithm, invalidate any active RTT measurement on retransmit */
    tcb->rtt_probe_active = false;

    uint16_t wnd = (tcb->rcv_wnd > 0xFFFFU) ? 0xFFFFU : (uint16_t)tcb->rcv_wnd;

    if (tcb->state == TCP_STATE_SYN_SENT) {
        tcp_tx_raw(stack, tcb->local_ip_be, tcb->remote_ip_be,
                   tcb->local_port_be, tcb->remote_port_be,
                   tcb->iss, 0, TCP_FLAG_SYN, wnd, NULL, 0, now_ms);
        return;
    }

    if (tcb->state == TCP_STATE_SYN_RECEIVED) {
        tcp_tx_raw(stack, tcb->local_ip_be, tcb->remote_ip_be,
                   tcb->local_port_be, tcb->remote_port_be,
                   tcb->iss, tcb->rcv_nxt,
                   TCP_FLAG_SYN | TCP_FLAG_ACK, wnd, NULL, 0, now_ms);
        return;
    }

    /* Calculate how many unacknowledged data bytes sit at `snd_una` */
    uint32_t data_end = tcp_snd_data_end_seq(tcb);
    uint32_t unacked_data = SEQ_LT(tcb->snd_una, data_end)
                          ? (data_end - tcb->snd_una)
                          : 0U;

    uint8_t payload[TCP_DEFAULT_MSS];
    size_t seg_data_len = unacked_data;
    if (seg_data_len > tcb->mss) {
        seg_data_len = tcb->mss;
    }
    if (seg_data_len > sizeof(payload)) {
        seg_data_len = sizeof(payload);
    }

    uint8_t flags = TCP_FLAG_ACK;
    if (seg_data_len > 0) {
        tcp_snd_read_ring(tcb, tcb->snd_una, payload, seg_data_len);
        flags |= TCP_FLAG_PSH;
    }

    /* Attach FIN if all queued data fits in this segment and FIN is unacked */
    if (tcb->fin_queued && (tcb->snd_una + seg_data_len == tcb->fin_seq)) {
        flags |= TCP_FLAG_FIN;
    }

    if (seg_data_len > 0 || (flags & TCP_FLAG_FIN) != 0) {
        tcp_tx_raw(stack, tcb->local_ip_be, tcb->remote_ip_be,
                   tcb->local_port_be, tcb->remote_port_be,
                   tcb->snd_una, tcb->rcv_nxt,
                   flags, wnd, payload, seg_data_len, now_ms);
    }
}

/* ==========================================================================
 * 6. Public Stack Initialization, Listen, Connect, Send, and Close
 * ========================================================================== */

void tcp_stack_init(struct tcp_stack *stack, struct netdev *dev, uint64_t now_ms) {
    memset(stack, 0, sizeof(*stack));
    stack->dev          = dev;
    stack->timer_head   = TCP_NULL_IDX;
    stack->last_tick_ms = now_ms;
    stack->isn_secret   = 0xA5A5F00DU;

    for (uint32_t i = 0; i < TCP_HASH_BUCKETS; i++) {
        stack->buckets[i] = TCP_NULL_IDX;
    }

    for (uint16_t i = 0; i < TCP_MAX_CONNS; i++) {
        stack->pool[i].state      = TCP_STATE_CLOSED;
        stack->pool[i].pool_idx   = i;
        stack->pool[i].timer_prev = TCP_NULL_IDX;
        stack->pool[i].timer_next = (i + 1U < TCP_MAX_CONNS) ? (uint16_t)(i + 1U) : TCP_NULL_IDX;
    }
    stack->free_head = 0;

    g_active_tcp_stack = stack;
    ipv4_set_tcp_handler(tcp_ipv4_rx_bridge);
    dev->ip_rx_cb = ipv4_rx;
}

int tcp_listen(struct tcp_stack *stack, uint16_t port_host,
               struct tcp_callbacks cb) {
    uint16_t port_be = htons(port_host);

    for (size_t i = 0; i < TCP_MAX_LISTENERS; i++) {
        if (stack->listeners[i].active && stack->listeners[i].local_port_be == port_be) {
            stack->listeners[i].cb = cb;
            return 0;
        }
    }

    for (size_t i = 0; i < TCP_MAX_LISTENERS; i++) {
        if (!stack->listeners[i].active) {
            stack->listeners[i].active        = true;
            stack->listeners[i].local_port_be = port_be;
            stack->listeners[i].cb            = cb;
            return 0;
        }
    }
    return -1;
}

struct tcp_tcb *tcp_connect(struct tcp_stack *stack, uint32_t remote_ip_be,
                            uint16_t local_port_host, uint16_t remote_port_host,
                            struct tcp_callbacks cb, uint64_t now_ms) {
    uint16_t lport_be = htons(local_port_host);
    uint16_t rport_be = htons(remote_port_host);

    struct tcp_tcb *tcb = tcp_alloc_tcb(stack, stack->dev->ip_be, remote_ip_be,
                                        lport_be, rport_be);
    if (tcb == NULL) {
        return NULL;
    }

    tcb->cb      = cb;
    tcb->iss     = tcp_generate_isn(stack, tcb->local_ip_be, tcb->remote_ip_be,
                                    lport_be, rport_be, now_ms);
    tcb->snd_una = tcb->iss;
    tcb->snd_nxt = tcb->iss + 1U; /* SYN consumes 1 sequence number */
    tcb->state   = TCP_STATE_SYN_SENT;

    /* Start Karn RTT probe for the SYN segment */
    tcb->rtt_probe_active = true;
    tcb->rtt_probe_seq    = tcb->iss;
    tcb->rtt_probe_ts_ms  = now_ms;

    uint16_t wnd = (tcb->rcv_wnd > 0xFFFFU) ? 0xFFFFU : (uint16_t)tcb->rcv_wnd;
    tcp_tx_raw(stack, tcb->local_ip_be, tcb->remote_ip_be,
               tcb->local_port_be, tcb->remote_port_be,
               tcb->iss, 0, TCP_FLAG_SYN, wnd, NULL, 0, now_ms);

    timer_schedule(stack, tcb, tcb->rto_ms, now_ms);
    return tcb;
}

ssize_t tcp_send(struct tcp_stack *stack, struct tcp_tcb *tcb,
                 const void *data, size_t len, uint64_t now_ms) {
    if (tcb == NULL ||
        (tcb->state != TCP_STATE_ESTABLISHED && tcb->state != TCP_STATE_CLOSE_WAIT) ||
        tcb->fin_queued) {
        return -1;
    }

    if (len == 0) {
        return 0;
    }

    /*
     * Calculate available space in both `tcb->snd_buf` and the peer's
     * advertised `snd_wnd`.
     */
    uint32_t in_flight = tcb->snd_nxt - tcb->snd_una;
    uint32_t buf_limit = ( tcb->snd_wnd < TCP_SND_BUF_SIZE )
                       ? tcb->snd_wnd
                       : TCP_SND_BUF_SIZE;

    if (in_flight >= buf_limit) {
        return 0; /* Send window or ring buffer full */
    }

    size_t can_send = buf_limit - in_flight;
    if (len < can_send) {
        can_send = len;
    }

    const uint8_t *ptr = (const uint8_t *)data;
    size_t sent_total  = 0;

    while (sent_total < can_send) {
        size_t chunk = can_send - sent_total;
        if (chunk > tcb->mss) {
            chunk = tcb->mss;
        }
        if (chunk > TCP_DEFAULT_MSS) {
            chunk = TCP_DEFAULT_MSS;
        }

        uint32_t seg_seq = tcb->snd_nxt;
        tcp_snd_write_ring(tcb, seg_seq, ptr + sent_total, chunk);
        tcb->snd_nxt += (uint32_t)chunk;

        if (!tcb->rtt_probe_active && tcb->rtx_count == 0) {
            tcb->rtt_probe_active = true;
            tcb->rtt_probe_seq    = seg_seq;
            tcb->rtt_probe_ts_ms  = now_ms;
        }

        uint16_t wnd = (tcb->rcv_wnd > 0xFFFFU) ? 0xFFFFU : (uint16_t)tcb->rcv_wnd;
        tcp_tx_raw(stack, tcb->local_ip_be, tcb->remote_ip_be,
                   tcb->local_port_be, tcb->remote_port_be,
                   seg_seq, tcb->rcv_nxt,
                   TCP_FLAG_ACK | TCP_FLAG_PSH, wnd,
                   ptr + sent_total, chunk, now_ms);

        sent_total += chunk;
    }

    if (!tcb->timer_active) {
        timer_schedule(stack, tcb, tcb->rto_ms, now_ms);
    }

    return (ssize_t)sent_total;
}

int tcp_close(struct tcp_stack *stack, struct tcp_tcb *tcb, uint64_t now_ms) {
    if (tcb == NULL) {
        return -1;
    }

    if (tcb->state == TCP_STATE_SYN_SENT) {
        tcp_free_tcb(stack, tcb);
        return 0;
    }

    if (tcb->state == TCP_STATE_ESTABLISHED ||
        tcb->state == TCP_STATE_SYN_RECEIVED ||
        tcb->state == TCP_STATE_CLOSE_WAIT) {
        if (!tcb->fin_queued) {
            uint32_t fin_seq  = tcb->snd_nxt;
            tcb->fin_queued   = true;
            tcb->fin_seq      = fin_seq;
            tcb->snd_nxt     += 1U; /* FIN consumes 1 sequence number */

            uint16_t wnd = (tcb->rcv_wnd > 0xFFFFU) ? 0xFFFFU : (uint16_t)tcb->rcv_wnd;
            tcp_tx_raw(stack, tcb->local_ip_be, tcb->remote_ip_be,
                       tcb->local_port_be, tcb->remote_port_be,
                       fin_seq, tcb->rcv_nxt,
                       TCP_FLAG_FIN | TCP_FLAG_ACK, wnd, NULL, 0, now_ms);

            if (!tcb->timer_active) {
                timer_schedule(stack, tcb, tcb->rto_ms, now_ms);
            }
        }

        if (tcb->state == TCP_STATE_CLOSE_WAIT) {
            tcb->state = TCP_STATE_LAST_ACK;
        } else {
            tcb->state = TCP_STATE_FIN_WAIT_1;
        }
        return 0;
    }

    return -1;
}

/* ==========================================================================
 * 7. RFC 793 Segment Acceptability & Option Parsing Helpers
 * ========================================================================== */

/**
 * Parse TCP Options in `[opt_ptr, opt_ptr + opt_len)` to extract the peer's
 * Maximum Segment Size (Kind = 2, Length = 4).
 */
static void tcp_parse_options(struct tcp_tcb *tcb, const uint8_t *opt_ptr, size_t opt_len) {
    size_t i = 0;
    while (i < opt_len) {
        uint8_t kind = opt_ptr[i];
        if (kind == TCP_OPT_EOL) {
            break;
        }
        if (kind == TCP_OPT_NOP) {
            i++;
            continue;
        }
        if (i + 1 >= opt_len) {
            break; /* Malformed option truncated before length byte */
        }
        uint8_t len = opt_ptr[i + 1];
        if (len < 2 || i + len > opt_len) {
            break; /* Malformed option length */
        }
        if (kind == TCP_OPT_MSS && len == 4) {
            uint16_t peer_mss;
            memcpy(&peer_mss, opt_ptr + i + 2, 2);
            peer_mss = ntohs(peer_mss);
            if (peer_mss >= 68U && peer_mss < TCP_DEFAULT_MSS) {
                tcb->mss = peer_mss;
            }
        }
        i += len;
    }
}

/**
 * Compute the sequence space length `SEG.LEN` occupied by a segment.
 * Per RFC 793 §3.3, `SYN` and `FIN` each occupy 1 sequence number in addition
 * to the data payload bytes.
 */
static size_t tcp_seg_seq_len(uint8_t flags, size_t payload_len) {
    size_t seq_len = payload_len;
    if ((flags & TCP_FLAG_SYN) != 0) {
        seq_len++;
    }
    if ((flags & TCP_FLAG_FIN) != 0) {
        seq_len++;
    }
    return seq_len;
}

/**
 * RFC 793 Section 3.9 "Event Processing -> SEGMENT ARRIVES":
 * Exact 4-case Segment Acceptability Test across `SEG.LEN` and `RCV.WND`:
 *
 *  SEG.LEN  RCV.WND  Test
 *  -------  -------  -------------------------------------------------------
 *     0        0     SEG.SEQ == RCV.NXT
 *     0       >0     RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND
 *    >0        0     not acceptable
 *    >0       >0     (RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND)
 *                 or (RCV.NXT <= SEG.SEQ + SEG.LEN - 1 < RCV.NXT + RCV.WND)
 */
static bool tcp_segment_acceptable(const struct tcp_tcb *tcb,
                                   uint32_t seg_seq, size_t seg_len) {
    uint32_t rcv_nxt = tcb->rcv_nxt;
    uint32_t rcv_wnd = tcb->rcv_wnd;

    if (seg_len == 0) {
        if (rcv_wnd == 0) {
            return (seg_seq == rcv_nxt);
        }
        return SEQ_GEQ(seg_seq, rcv_nxt) && SEQ_LT(seg_seq, rcv_nxt + rcv_wnd);
    } else {
        if (rcv_wnd == 0) {
            return false;
        }
        uint32_t seg_end_inclusive = seg_seq + (uint32_t)seg_len - 1U;
        bool start_in_wnd = SEQ_GEQ(seg_seq, rcv_nxt) &&
                            SEQ_LT(seg_seq, rcv_nxt + rcv_wnd);
        bool end_in_wnd   = SEQ_GEQ(seg_end_inclusive, rcv_nxt) &&
                            SEQ_LT(seg_end_inclusive, rcv_nxt + rcv_wnd);
        return start_in_wnd || end_in_wnd;
    }
}

/* ==========================================================================
 * 8. Full RFC 793 TCP Reception State Machine (`tcp_rx_segment`)
 * ========================================================================== */

void tcp_rx_segment(struct tcp_stack *stack, const struct ipv4_hdr *ip_hdr,
                    const uint8_t *seg, size_t seg_len, uint64_t now_ms) {
    /*
     * Step 1: Header Bounds & Data Offset Validation
     */
    if (seg_len < TCP_HDR_MIN_LEN) {
        return;
    }

    const struct tcp_hdr *hdr = (const struct tcp_hdr *)seg;
    size_t doff_bytes = TCP_HDR_BYTES(hdr);
    if (doff_bytes < TCP_HDR_MIN_LEN || doff_bytes > seg_len) {
        return;
    }

    /*
     * Step 2: Verify RFC 793 Pseudo-Header + Segment Checksum
     */
    if (tcp_checksum(ip_hdr->saddr, ip_hdr->daddr, seg, seg_len) != 0) {
        return;
    }

    const uint8_t *opt_ptr     = seg + TCP_HDR_MIN_LEN;
    size_t         opt_len     = doff_bytes - TCP_HDR_MIN_LEN;
    const uint8_t *payload     = seg + doff_bytes;
    size_t         payload_len = seg_len - doff_bytes;

    uint32_t seg_seq = ntohl(hdr->seq);
    uint32_t seg_ack = ntohl(hdr->ack_seq);
    uint16_t seg_wnd = ntohs(hdr->window);
    uint8_t  flags   = hdr->flags;
    size_t   seq_len = tcp_seg_seq_len(flags, payload_len);

    /*
     * Step 3: O(1) 4-Tuple TCB Lookup
     */
    struct tcp_tcb *tcb = tcp_lookup_tcb(stack,
                                         ip_hdr->daddr, ip_hdr->saddr,
                                         hdr->dport, hdr->sport);

    /*
     * Step 4: If no active TCB exists, check passive `LISTEN` table on `dport`.
     */
    if (tcb == NULL) {
        struct tcp_listener *listener = NULL;
        for (size_t i = 0; i < TCP_MAX_LISTENERS; i++) {
            if (stack->listeners[i].active &&
                stack->listeners[i].local_port_be == hdr->dport) {
                listener = &stack->listeners[i];
                break;
            }
        }

        /*
         * RFC 793 "CLOSED" state processing when no listener matches:
         * Any incoming segment not containing a RST causes a RST to be sent
         * in response.
         */
        if (listener == NULL) {
            if ((flags & TCP_FLAG_RST) == 0) {
                if ((flags & TCP_FLAG_ACK) != 0) {
                    tcp_tx_raw(stack, ip_hdr->daddr, ip_hdr->saddr,
                               hdr->dport, hdr->sport,
                               seg_ack, 0, TCP_FLAG_RST, 0, NULL, 0, now_ms);
                } else {
                    tcp_tx_raw(stack, ip_hdr->daddr, ip_hdr->saddr,
                               hdr->dport, hdr->sport,
                               0, seg_seq + (uint32_t)seq_len,
                               TCP_FLAG_RST | TCP_FLAG_ACK, 0, NULL, 0, now_ms);
                }
            }
            return;
        }

        /*
         * RFC 793 "LISTEN" state processing:
         * 1. First check for an RST: An incoming RST should be ignored.
         * 2. Second check for an ACK: Any acknowledgment is bad if it arrives
         *    on a connection still in the LISTEN state -> send `<SEQ=SEG.ACK><CTL=RST>`.
         * 3. Third check for a SYN: Allocate TCB, record IRS, send SYN+ACK,
         *    and enter `SYN_RECEIVED`.
         */
        if ((flags & TCP_FLAG_RST) != 0) {
            return;
        }
        if ((flags & TCP_FLAG_ACK) != 0) {
            tcp_tx_raw(stack, ip_hdr->daddr, ip_hdr->saddr,
                       hdr->dport, hdr->sport,
                       seg_ack, 0, TCP_FLAG_RST, 0, NULL, 0, now_ms);
            return;
        }
        if ((flags & TCP_FLAG_SYN) != 0) {
            tcb = tcp_alloc_tcb(stack, ip_hdr->daddr, ip_hdr->saddr,
                                hdr->dport, hdr->sport);
            if (tcb == NULL) {
                return;
            }
            tcb->cb           = listener->cb;
            tcb->irs          = seg_seq;
            tcb->rcv_nxt      = seg_seq + 1U;
            tcb->rcv_read_seq = seg_seq + 1U;
            tcb->snd_wnd      = seg_wnd;
            tcb->snd_wl1      = seg_seq;
            tcb->snd_wl2      = seg_seq;
            tcb->iss          = tcp_generate_isn(stack, tcb->local_ip_be, tcb->remote_ip_be,
                                                 tcb->local_port_be, tcb->remote_port_be, now_ms);
            tcb->snd_una      = tcb->iss;
            tcb->snd_nxt      = tcb->iss + 1U;
            tcb->state        = TCP_STATE_SYN_RECEIVED;

            tcp_parse_options(tcb, opt_ptr, opt_len);

            tcb->rtt_probe_active = true;
            tcb->rtt_probe_seq    = tcb->iss;
            tcb->rtt_probe_ts_ms  = now_ms;

            uint16_t wnd = (tcb->rcv_wnd > 0xFFFFU) ? 0xFFFFU : (uint16_t)tcb->rcv_wnd;
            tcp_tx_raw(stack, tcb->local_ip_be, tcb->remote_ip_be,
                       tcb->local_port_be, tcb->remote_port_be,
                       tcb->iss, tcb->rcv_nxt,
                       TCP_FLAG_SYN | TCP_FLAG_ACK, wnd, NULL, 0, now_ms);

            timer_schedule(stack, tcb, tcb->rto_ms, now_ms);
        }
        return;
    }

    /*
     * Step 5: RFC 793 `SYN_SENT` State Processing
     */
    if (tcb->state == TCP_STATE_SYN_SENT) {
        /* 5a. Check the ACK bit */
        if ((flags & TCP_FLAG_ACK) != 0) {
            if (SEQ_LEQ(seg_ack, tcb->iss) || SEQ_GT(seg_ack, tcb->snd_nxt)) {
                if ((flags & TCP_FLAG_RST) == 0) {
                    tcp_tx_raw(stack, tcb->local_ip_be, tcb->remote_ip_be,
                               tcb->local_port_be, tcb->remote_port_be,
                               seg_ack, 0, TCP_FLAG_RST, 0, NULL, 0, now_ms);
                }
                return;
            }
        }

        /* 5b. Check the RST bit */
        if ((flags & TCP_FLAG_RST) != 0) {
            if ((flags & TCP_FLAG_ACK) != 0) {
                if (tcb->cb.on_closed != NULL) {
                    tcb->cb.on_closed(stack, tcb);
                }
                tcp_free_tcb(stack, tcb);
            }
            return;
        }

        /* 5c. Check the SYN bit */
        if ((flags & TCP_FLAG_SYN) != 0) {
            tcb->irs          = seg_seq;
            tcb->rcv_nxt      = seg_seq + 1U;
            tcb->rcv_read_seq = seg_seq + 1U;
            tcp_parse_options(tcb, opt_ptr, opt_len);

            if ((flags & TCP_FLAG_ACK) != 0) {
                tcb->snd_una   = seg_ack;
                tcb->snd_wnd   = seg_wnd;
                tcb->snd_wl1   = seg_seq;
                tcb->snd_wl2   = seg_ack;
                tcb->rtx_count = 0;

                if (tcb->rtt_probe_active && SEQ_GT(seg_ack, tcb->rtt_probe_seq)) {
                    tcb->rtt_probe_active = false;
                    tcp_update_rtt(tcb, now_ms - tcb->rtt_probe_ts_ms);
                }
                timer_cancel(stack, tcb);
            }

            if (SEQ_GT(tcb->snd_una, tcb->iss)) {
                /* Active 3-way handshake completed: SYN_SENT -> ESTABLISHED */
                tcb->state = TCP_STATE_ESTABLISHED;
                tcp_tx_ctrl(stack, tcb, TCP_FLAG_ACK, now_ms);
                if (tcb->cb.on_connected != NULL) {
                    tcb->cb.on_connected(stack, tcb);
                }
            } else {
                /* Simultaneous open: SYN_SENT -> SYN_RECEIVED */
                tcb->state = TCP_STATE_SYN_RECEIVED;
                uint16_t wnd = (tcb->rcv_wnd > 0xFFFFU) ? 0xFFFFU : (uint16_t)tcb->rcv_wnd;
                tcp_tx_raw(stack, tcb->local_ip_be, tcb->remote_ip_be,
                           tcb->local_port_be, tcb->remote_port_be,
                           tcb->iss, tcb->rcv_nxt,
                           TCP_FLAG_SYN | TCP_FLAG_ACK, wnd, NULL, 0, now_ms);
            }
        }
        return;
    }

    /*
     * Step 6: All Other States (`SYN_RECEIVED`, `ESTABLISHED`, `FIN_WAIT_1`,
     *         `FIN_WAIT_2`, `CLOSE_WAIT`, `CLOSING`, `LAST_ACK`, `TIME_WAIT`)
     *
     * 6a. First check sequence number acceptability (RFC 793 §3.9).
     */
    if (!tcp_segment_acceptable(tcb, seg_seq, seq_len)) {
        /* If an incoming segment is not acceptable, send an ACK (unless RST) */
        if ((flags & TCP_FLAG_RST) == 0) {
            tcp_tx_ctrl(stack, tcb, TCP_FLAG_ACK, now_ms);
        }
        return;
    }

    /*
     * 6b. Second check the RST bit.
     */
    if ((flags & TCP_FLAG_RST) != 0) {
        if (tcb->cb.on_closed != NULL && tcb->state != TCP_STATE_SYN_RECEIVED) {
            tcb->cb.on_closed(stack, tcb);
        }
        tcp_free_tcb(stack, tcb);
        return;
    }

    /*
     * 6c. Fourth check the SYN bit:
     *     A SYN inside the window in a synchronized state is an error; send
     *     a challenge ACK or reset and drop.
     */
    if ((flags & TCP_FLAG_SYN) != 0) {
        tcp_tx_raw(stack, tcb->local_ip_be, tcb->remote_ip_be,
                   tcb->local_port_be, tcb->remote_port_be,
                   seg_ack, 0, TCP_FLAG_RST, 0, NULL, 0, now_ms);
        if (tcb->cb.on_closed != NULL) {
            tcb->cb.on_closed(stack, tcb);
        }
        tcp_free_tcb(stack, tcb);
        return;
    }

    /*
     * 6d. Fifth check the ACK field: if off, drop the segment and return.
     */
    if ((flags & TCP_FLAG_ACK) == 0) {
        return;
    }

    /*
     * State-specific ACK Processing:
     */
    if (tcb->state == TCP_STATE_SYN_RECEIVED) {
        if (SEQ_GT(seg_ack, tcb->snd_una) && SEQ_LEQ(seg_ack, tcb->snd_nxt)) {
            tcb->state   = TCP_STATE_ESTABLISHED;
            tcb->snd_wnd = seg_wnd;
            tcb->snd_wl1 = seg_seq;
            tcb->snd_wl2 = seg_ack;
            if (tcb->cb.on_connected != NULL) {
                tcb->cb.on_connected(stack, tcb);
            }
        } else {
            tcp_tx_raw(stack, tcb->local_ip_be, tcb->remote_ip_be,
                       tcb->local_port_be, tcb->remote_port_be,
                       seg_ack, 0, TCP_FLAG_RST, 0, NULL, 0, now_ms);
            return;
        }
    }

    /* Advance `SND.UNA` if `SND.UNA < SEG.ACK <= SND.NXT` */
    if (SEQ_GT(seg_ack, tcb->snd_una) && SEQ_LEQ(seg_ack, tcb->snd_nxt)) {
        tcb->snd_una   = seg_ack;
        tcb->rtx_count = 0;

        /* Karn's Algorithm + RFC 6298 RTT update */
        if (tcb->rtt_probe_active && SEQ_GT(seg_ack, tcb->rtt_probe_seq)) {
            tcb->rtt_probe_active = false;
            tcp_update_rtt(tcb, now_ms - tcb->rtt_probe_ts_ms);
        }

        if (tcb->snd_una == tcb->snd_nxt) {
            /* All outstanding bytes/SYN/FIN acknowledged: disarm RTO timer */
            timer_cancel(stack, tcb);
        } else {
            /* Still have unacknowledged bytes in flight: restart RTO timer */
            timer_schedule(stack, tcb, tcb->rto_ms, now_ms);
        }
    } else if (SEQ_GT(seg_ack, tcb->snd_nxt)) {
        /* ACK for something not yet sent: reply with current ACK and drop */
        tcp_tx_ctrl(stack, tcb, TCP_FLAG_ACK, now_ms);
        return;
    }

    /* RFC 793 Window Update Check (`SND.UNA <= SEG.ACK <= SND.NXT`) */
    if (SEQ_LEQ(tcb->snd_una, seg_ack) && SEQ_LEQ(seg_ack, tcb->snd_nxt)) {
        if (SEQ_LT(tcb->snd_wl1, seg_seq) ||
            (tcb->snd_wl1 == seg_seq && SEQ_LEQ(tcb->snd_wl2, seg_ack))) {
            tcb->snd_wnd = seg_wnd;
            tcb->snd_wl1 = seg_seq;
            tcb->snd_wl2 = seg_ack;
        }
    }

    /* Post-ACK State Transitions for FIN-states */
    bool our_fin_acked = (tcb->fin_queued && (tcb->snd_una == tcb->snd_nxt));
    if (tcb->state == TCP_STATE_FIN_WAIT_1 && our_fin_acked) {
        tcb->state = TCP_STATE_FIN_WAIT_2;
    } else if (tcb->state == TCP_STATE_CLOSING && our_fin_acked) {
        tcb->state = TCP_STATE_TIME_WAIT;
        timer_schedule(stack, tcb, TCP_TIME_WAIT_MS, now_ms);
    } else if (tcb->state == TCP_STATE_LAST_ACK && our_fin_acked) {
        if (tcb->cb.on_closed != NULL) {
            tcb->cb.on_closed(stack, tcb);
        }
        tcp_free_tcb(stack, tcb);
        return;
    }

    /*
     * 6e. Seventh: Process Segment Payload Data (In-Order + Out-of-Order Reassembly)
     */
    bool need_ack = false;

    if (payload_len > 0 &&
        (tcb->state == TCP_STATE_ESTABLISHED ||
         tcb->state == TCP_STATE_FIN_WAIT_1  ||
         tcb->state == TCP_STATE_FIN_WAIT_2)) {

        uint32_t wnd_start = tcb->rcv_nxt;
        uint32_t wnd_end   = tcb->rcv_nxt + tcb->rcv_wnd;
        uint32_t data_start = seg_seq;
        uint32_t data_end   = seg_seq + (uint32_t)payload_len;
        const uint8_t *slice_ptr = payload;

        /* Trim leading bytes already received prior to `RCV.NXT` */
        if (SEQ_LT(data_start, wnd_start)) {
            uint32_t trim_lead = wnd_start - data_start;
            slice_ptr  += trim_lead;
            data_start  = wnd_start;
        }

        /* Trim trailing bytes extending beyond `RCV.NXT + RCV.WND` */
        if (SEQ_GT(data_end, wnd_end)) {
            data_end = wnd_end;
        }

        if (SEQ_LT(data_start, data_end)) {
            size_t trimmed_len = (size_t)(data_end - data_start);

            /*
             * Write payload directly into its final ring-buffer offset!
             */
            tcp_rcv_write_ring(tcb, data_start, slice_ptr, trimmed_len);

            if (data_start == tcb->rcv_nxt) {
                /*
                 * In-order segment arrival: advance `RCV.NXT`, coalesce any
                 * bridged out-of-order intervals, and deliver contiguous stream!
                 */
                tcb->rcv_nxt = data_end;
                tcp_reassemble_and_deliver(stack, tcb);
            } else {
                /*
                 * Out-of-order segment arrival (`data_start > RCV.NXT`):
                 * Record `[data_start, data_end)` in the sorted OOO interval
                 * list and emit a duplicate ACK for `RCV.NXT` (RFC 5681).
                 */
                tcp_ooo_insert(tcb, data_start, data_end);
            }
            need_ack = true;
        }
    }

    /*
     * 6f. Eighth: Check the FIN bit.
     *     Only process FIN once all preceding payload bytes up to `seg_seq + payload_len`
     *     have been reassembled in-order (`tcb->rcv_nxt == seg_seq + payload_len`).
     */
    if ((flags & TCP_FLAG_FIN) != 0 &&
        (tcb->rcv_nxt == seg_seq + (uint32_t)payload_len)) {

        tcb->rcv_nxt += 1U; /* FIN consumes 1 sequence number */
        need_ack = true;

        switch (tcb->state) {
            case TCP_STATE_SYN_RECEIVED:
            case TCP_STATE_ESTABLISHED:
                tcb->state = TCP_STATE_CLOSE_WAIT;
                if (tcb->cb.on_closed != NULL) {
                    tcb->cb.on_closed(stack, tcb);
                }
                break;

            case TCP_STATE_FIN_WAIT_1:
                if (our_fin_acked) {
                    tcb->state = TCP_STATE_TIME_WAIT;
                    timer_schedule(stack, tcb, TCP_TIME_WAIT_MS, now_ms);
                } else {
                    tcb->state = TCP_STATE_CLOSING;
                }
                break;

            case TCP_STATE_FIN_WAIT_2:
                tcb->state = TCP_STATE_TIME_WAIT;
                timer_schedule(stack, tcb, TCP_TIME_WAIT_MS, now_ms);
                if (tcb->cb.on_closed != NULL) {
                    tcb->cb.on_closed(stack, tcb);
                }
                break;

            case TCP_STATE_TIME_WAIT:
                /* Restart 2*MSL TIME_WAIT timer on duplicate FIN */
                timer_schedule(stack, tcb, TCP_TIME_WAIT_MS, now_ms);
                break;

            default:
                break;
        }
    }

    if (need_ack) {
        tcp_tx_ctrl(stack, tcb, TCP_FLAG_ACK, now_ms);
    }
}

/* ==========================================================================
 * 9. Delta-List Timer Tick Dispatcher (`tcp_timers_tick`)
 * ========================================================================== */

void tcp_timers_tick(struct tcp_stack *stack, uint64_t now_ms) {
    timer_sync_clock(stack, now_ms);

    /*
     * Fire all head nodes whose relative delta has reached 0.
     * Because `timer_sync_clock()` already subtracted elapsed milliseconds
     * down the chain, popping expired timers from `stack->timer_head` is O(1).
     */
    while (stack->timer_head != TCP_NULL_IDX) {
        struct tcp_tcb *tcb = &stack->pool[stack->timer_head];
        if (tcb->timer_delta_ms > 0) {
            break;
        }

        /* Pop head timer */
        timer_cancel(stack, tcb);

        if (tcb->state == TCP_STATE_TIME_WAIT) {
            /* 2*MSL TIME_WAIT expired -> transition to CLOSED and free TCB */
            tcp_free_tcb(stack, tcb);
            continue;
        }

        /*
         * RFC 6298 Section 5: Retransmission Timeout (RTO) Expiration:
         * 1. If `rtx_count >= TCP_MAX_RETRIES`, abort connection with RST.
         * 2. Retransmit the earliest unacknowledged segment (`SND.UNA`).
         * 3. Back off the RTO exponentially: `RTO <- min(2 * RTO, TCP_RTO_MAX_MS)`.
         * 4. Restart the retransmission timer with the backed-off RTO.
         */
        if (tcb->rtx_count >= TCP_MAX_RETRIES) {
            tcp_tx_ctrl(stack, tcb, TCP_FLAG_RST | TCP_FLAG_ACK, now_ms);
            if (tcb->cb.on_closed != NULL) {
                tcb->cb.on_closed(stack, tcb);
            }
            tcp_free_tcb(stack, tcb);
            continue;
        }

        tcb->rtx_count++;
        tcp_retransmit_oldest(stack, tcb, now_ms);

        uint32_t backed_off = tcb->rto_ms << 1;
        if (backed_off > TCP_RTO_MAX_MS) {
            backed_off = TCP_RTO_MAX_MS;
        }
        tcb->rto_ms = backed_off;

        timer_schedule(stack, tcb, tcb->rto_ms, now_ms);
    }
}
