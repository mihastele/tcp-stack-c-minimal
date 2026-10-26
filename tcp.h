#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include "ipv4_icmp.h"

/* ==========================================================================
 * Layer 4: RFC 793 / RFC 1122 / RFC 6298 TCP Wire & Protocol Definitions
 * ========================================================================== */

#define TCP_HDR_MIN_LEN         20U     /* 5 x 32-bit words (no options)    */
#define TCP_HDR_MAX_LEN         60U     /* 15 x 32-bit words                */
#define TCP_DEFAULT_MSS         1460U   /* 1500 MTU - 20 IPv4 - 20 TCP      */

/* TCP Control Flags (bitmask in byte 13 of struct tcp_hdr)                 */
#define TCP_FLAG_FIN            0x01U   /* No more data from sender         */
#define TCP_FLAG_SYN            0x02U   /* Synchronize sequence numbers     */
#define TCP_FLAG_RST            0x04U   /* Reset the connection             */
#define TCP_FLAG_PSH            0x08U   /* Push function                    */
#define TCP_FLAG_ACK            0x10U   /* Acknowledgment field significant */
#define TCP_FLAG_URG            0x20U   /* Urgent pointer field significant */
#define TCP_FLAG_ECE            0x40U   /* ECN-Echo (RFC 3168)              */
#define TCP_FLAG_CWR            0x80U   /* Congestion Window Reduced        */

/* TCP Option Kind Numbers (RFC 793)                                        */
#define TCP_OPT_EOL             0U      /* End of Option List               */
#define TCP_OPT_NOP             1U      /* No-Operation (1-byte padding)    */
#define TCP_OPT_MSS             2U      /* Maximum Segment Size (len = 4)   */

/**
 * RFC 793 Section 3.3 Modular 32-bit Sequence Number Comparisons.
 *
 * Why `(int32_t)((a) - (b)) < 0` works across the 2^32 wraparound boundary:
 * TCP sequence numbers operate in the ring Z / 2^32 Z. So long as the window
 * size is strictly less than 2^31 (2 GiB), `a` is "before" `b` in sequence
 * space if and only if the unsigned difference `a - b` lies in `[2^31, 2^32 - 1]`,
 * which in two's complement signed 32-bit representation is strictly negative!
 */
#define SEQ_LT(a, b)            ((int32_t)((uint32_t)(a) - (uint32_t)(b)) < 0)
#define SEQ_LEQ(a, b)           ((int32_t)((uint32_t)(a) - (uint32_t)(b)) <= 0)
#define SEQ_GT(a, b)            ((int32_t)((uint32_t)(a) - (uint32_t)(b)) > 0)
#define SEQ_GEQ(a, b)           ((int32_t)((uint32_t)(a) - (uint32_t)(b)) >= 0)

/**
 * RFC 793 TCP Header (20 bytes minimum, followed by optional 0..40 bytes).
 *
 * Wire Layout:
 *  +0..+1  : sport     (2 bytes) - Source Port (Network Byte Order)
 *  +2..+3  : dport     (2 bytes) - Destination Port (Network Byte Order)
 *  +4..+7  : seq       (4 bytes) - Sequence Number (Network Byte Order)
 *  +8..+11 : ack_seq   (4 bytes) - Acknowledgment Number (Network Byte Order)
 *  +12     : doff_rsvd (1 byte)  - Bits 7..4: Data Offset (in 32-bit words)
 *                                  Bits 3..0: Reserved / NS bit
 *  +13     : flags     (1 byte)  - Control flags (CWR,ECE,URG,ACK,PSH,RST,SYN,FIN)
 *  +14..+15: window    (2 bytes) - Receive Window size (Network Byte Order)
 *  +16..+17: check     (2 bytes) - RFC 1071 Checksum over Pseudo-Hdr + Segment
 *  +18..+19: urg_ptr   (2 bytes) - Urgent Pointer (Network Byte Order)
 */
struct tcp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  doff_rsvd;
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} __attribute__((packed));

#define TCP_DOFF(hdr)           (((hdr)->doff_rsvd >> 4) & 0x0FU)
#define TCP_HDR_BYTES(hdr)      ((size_t)TCP_DOFF(hdr) * 4U)

/**
 * RFC 793 12-Byte IPv4 Pseudo-Header prefixed virtually for TCP Checksum.
 */
struct ipv4_pseudo_hdr {
    uint32_t saddr;             /* Source IPv4 address (Network Byte Order) */
    uint32_t daddr;             /* Dest IPv4 address (Network Byte Order)   */
    uint8_t  zero;              /* Must be 0                                */
    uint8_t  proto;             /* IPPROTO_TCP_VAL (6)                      */
    uint16_t tcp_len;           /* TCP Header + Payload length (Net Order)  */
} __attribute__((packed));

/* ==========================================================================
 * RFC 793 TCP Connection State Machine & TCB Data Structures
 * ========================================================================== */

enum tcp_state {
    TCP_STATE_CLOSED       = 0,
    TCP_STATE_LISTEN       = 1,
    TCP_STATE_SYN_SENT     = 2,
    TCP_STATE_SYN_RECEIVED = 3,
    TCP_STATE_ESTABLISHED  = 4,
    TCP_STATE_FIN_WAIT_1   = 5,
    TCP_STATE_FIN_WAIT_2   = 6,
    TCP_STATE_CLOSE_WAIT   = 7,
    TCP_STATE_CLOSING      = 8,
    TCP_STATE_LAST_ACK     = 9,
    TCP_STATE_TIME_WAIT    = 10
};

/*
 * Buffer & Table Sizing (all power-of-two for mask-based O(1) indexing):
 * - TCP_RCV_BUF_SIZE: 16 KiB circular receive ring buffer per connection.
 * - TCP_SND_BUF_SIZE: 16 KiB circular transmit/retransmit ring buffer.
 * - TCP_MAX_OOO_INTERVALS: 16 disjoint out-of-order intervals per TCB.
 * - TCP_MAX_CONNS: 32 concurrent active TCBs in the fixed pool.
 * - TCP_HASH_BUCKETS: 64 open-addressing buckets (load factor <= 0.5).
 */
#define TCP_RCV_BUF_SIZE        16384U
#define TCP_RCV_BUF_MASK        (TCP_RCV_BUF_SIZE - 1U)
#define TCP_SND_BUF_SIZE        16384U
#define TCP_SND_BUF_MASK        (TCP_SND_BUF_SIZE - 1U)

#define TCP_MAX_OOO_INTERVALS   16U
#define TCP_MAX_CONNS           32U
#define TCP_HASH_BUCKETS        64U
#define TCP_MAX_LISTENERS       16U
#define TCP_NULL_IDX            0xFFFFU

/*
 * RFC 6298 Retransmission Timer Constants:
 * - Initial RTO: 1000 ms (1 second)
 * - Min RTO:      200 ms (RFC 6298 recommends 1s, Linux uses 200ms on LAN)
 * - Max RTO:    60000 ms (60 seconds)
 * - Clock Granularity G: 1000 us (1 ms)
 * - Max Retransmissions: 8
 * - TIME_WAIT 2*MSL duration: 4000 ms (4s in userspace stack; 60s on WAN)
 */
#define TCP_RTO_INITIAL_MS      1000U
#define TCP_RTO_MIN_MS          200U
#define TCP_RTO_MAX_MS          60000U
#define TCP_RTT_GRANULARITY_US  1000U
#define TCP_MAX_RETRIES         8U
#define TCP_TIME_WAIT_MS        4000U

/**
 * Out-of-Order Reassembly Interval (`[start_seq, end_seq)` in sequence space).
 * The actual payload bytes already sit inside `tcb->rcv_buf` at their exact
 * ring-buffer offsets; this interval descriptor merely tracks which byte
 * ranges above `RCV.NXT` have already arrived.
 */
struct tcp_ooo_interval {
    uint32_t start_seq;         /* Inclusive starting sequence number       */
    uint32_t end_seq;           /* Exclusive ending sequence number         */
};

struct tcp_tcb;
struct tcp_stack;

/**
 * Application-Layer Event Callbacks per TCB / Listener.
 */
struct tcp_callbacks {
    void (*on_connected)(struct tcp_stack *stack, struct tcp_tcb *tcb);
    void (*on_recv)(struct tcp_stack *stack, struct tcp_tcb *tcb,
                    const uint8_t *data, size_t len);
    void (*on_closed)(struct tcp_stack *stack, struct tcp_tcb *tcb);
};

/**
 * Transmission Control Block (TCB) - RFC 793 §3.2.
 */
struct tcp_tcb {
    /* 4-Tuple Connection Key (all in Network Byte Order for fast hashing)  */
    uint32_t local_ip_be;
    uint32_t remote_ip_be;
    uint16_t local_port_be;
    uint16_t remote_port_be;

    uint8_t  state;             /* enum tcp_state                           */
    uint16_t pool_idx;          /* Index of this TCB in `stack->pool[]`     */
    uint16_t mss;               /* Peer-advertised Maximum Segment Size     */

    /* RFC 793 Send Sequence Variables (Host Byte Order)                    */
    uint32_t snd_una;           /* Send Unacknowledged                      */
    uint32_t snd_nxt;           /* Send Next                                */
    uint32_t snd_wnd;           /* Send Window                              */
    uint32_t snd_wl1;           /* Segment seq used for last window update  */
    uint32_t snd_wl2;           /* Segment ack used for last window update  */
    uint32_t iss;               /* Initial Send Sequence Number             */

    /* RFC 793 Receive Sequence Variables (Host Byte Order)                 */
    uint32_t rcv_nxt;           /* Receive Next expected sequence number    */
    uint32_t rcv_wnd;           /* Receive Window advertised to peer        */
    uint32_t irs;               /* Initial Receive Sequence Number          */
    uint32_t rcv_read_seq;      /* Sequence number up to which app has read */

    /* Monotonic Circular Receive Buffer + Out-of-Order Interval List       */
    uint8_t  rcv_buf[TCP_RCV_BUF_SIZE];
    uint8_t  ooo_count;
    struct tcp_ooo_interval ooo[TCP_MAX_OOO_INTERVALS];

    /* Circular Transmit & Retransmission Ring Buffer                       */
    uint8_t  snd_buf[TCP_SND_BUF_SIZE];
    bool     fin_queued;        /* True if local FIN is queued at end       */
    uint32_t fin_seq;           /* Sequence number occupied by our FIN      */

    /* RFC 6298 Jacobson/Karels RTT & RTO Estimator                         */
    bool     rtt_measured;      /* True after first valid RTT sample        */
    uint32_t srtt_us;           /* Smoothed RTT in microseconds             */
    uint32_t rttvar_us;         /* RTT variance in microseconds             */
    uint32_t rto_ms;            /* Current Retransmission Timeout (ms)      */

    /* Karn's Algorithm RTT Measurement Tracking                            */
    bool     rtt_probe_active;  /* True if timing an un-retransmitted seq   */
    uint32_t rtt_probe_seq;     /* Target sequence number being timed       */
    uint64_t rtt_probe_ts_ms;   /* Timestamp when probe segment was sent    */
    uint8_t  rtx_count;         /* Consecutive retransmission count         */

    /* Intrusive Delta-List Timer Queue Fields                              */
    bool     timer_active;      /* True if linked into stack's delta-list   */
    uint64_t timer_delta_ms;    /* Relative ms after previous timer node    */
    uint16_t timer_prev;        /* Previous TCB index in delta-list         */
    uint16_t timer_next;        /* Next TCB index in delta-list             */

    struct tcp_callbacks cb;
    void    *app_ctx;           /* Optional opaque application pointer      */
};

/**
 * Passive Listener Entry for `LISTEN` sockets.
 */
struct tcp_listener {
    bool                 active;
    uint16_t             local_port_be;
    struct tcp_callbacks cb;
};

/**
 * Complete Userspace TCP Stack Instance.
 */
struct tcp_stack {
    struct netdev       *dev;
    uint16_t             buckets[TCP_HASH_BUCKETS];
    struct tcp_tcb       pool[TCP_MAX_CONNS];
    struct tcp_listener  listeners[TCP_MAX_LISTENERS];
    uint16_t             free_head;
    uint16_t             timer_head;        /* Head of intrusive delta-list */
    uint64_t             last_tick_ms;      /* Last timestamp of timer tick */
    uint32_t             isn_secret;        /* Secret seed for ISN hashing  */
};

/* ==========================================================================
 * Public Layer 4 TCP API
 * ========================================================================== */

/**
 * Initialize the TCP stack and attach it as the IPv4 TCP handler on `dev`.
 */
void tcp_stack_init(struct tcp_stack *stack, struct netdev *dev, uint64_t now_ms);

/**
 * Compute the RFC 793 16-bit one's complement checksum over the 12-byte IPv4
 * pseudo-header and the TCP segment without copying memory.
 */
uint16_t tcp_checksum(uint32_t saddr_be, uint32_t daddr_be,
                      const void *tcp_seg, size_t tcp_len);

/**
 * Open a passive `LISTEN` socket on `port_host` (Host Byte Order).
 */
int tcp_listen(struct tcp_stack *stack, uint16_t port_host,
               struct tcp_callbacks cb);

/**
 * Initiate an active open (`SYN_SENT`) to `(remote_ip_be, remote_port_host)`.
 */
struct tcp_tcb *tcp_connect(struct tcp_stack *stack, uint32_t remote_ip_be,
                            uint16_t local_port_host, uint16_t remote_port_host,
                            struct tcp_callbacks cb, uint64_t now_ms);

/**
 * Queue application bytes into `tcb->snd_buf` and transmit segments up to
 * the peer's advertised `SND.WND` and `MSS`.
 *
 * @return Number of bytes accepted into the send buffer, or -1 on error.
 */
ssize_t tcp_send(struct tcp_stack *stack, struct tcp_tcb *tcb,
                 const void *data, size_t len, uint64_t now_ms);

/**
 * Initiate an orderly connection close (queues `FIN` and transitions
 * `ESTABLISHED -> FIN_WAIT_1` or `CLOSE_WAIT -> LAST_ACK`).
 */
int tcp_close(struct tcp_stack *stack, struct tcp_tcb *tcb, uint64_t now_ms);

/**
 * O(1) 4-tuple lookup in the open-addressing hash table.
 */
struct tcp_tcb *tcp_lookup_tcb(struct tcp_stack *stack,
                               uint32_t local_ip_be, uint32_t remote_ip_be,
                               uint16_t local_port_be, uint16_t remote_port_be);

/**
 * Process an incoming TCP segment demultiplexed from `ipv4_rx()`.
 */
void tcp_rx_segment(struct tcp_stack *stack, const struct ipv4_hdr *ip_hdr,
                    const uint8_t *seg, size_t seg_len, uint64_t now_ms);

/**
 * Advance the intrusive delta-list timer queue to `now_ms`, firing any
 * expired RFC 6298 Retransmission Timeouts (RTO) or `TIME_WAIT` (2*MSL) timers.
 */
void tcp_timers_tick(struct tcp_stack *stack, uint64_t now_ms);

#endif /* TCP_H */
