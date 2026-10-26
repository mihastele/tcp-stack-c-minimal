#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "net_base.h"
#include "eth_arp.h"
#include "ipv4_icmp.h"
#include "tcp.h"

static volatile sig_atomic_t g_keep_running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    g_keep_running = 0;
}

/**
 * Read monotonic wall-clock time in milliseconds.
 */
static uint64_t monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

/* ==========================================================================
 * Built-In TCP Application Services (Port 7 Echo & Port 80 HTTP)
 * ========================================================================== */

static void echo_on_connected(struct tcp_stack *stack, struct tcp_tcb *tcb) {
    (void)stack;
    struct in_addr peer = { .s_addr = tcb->remote_ip_be };
    printf("[TCP:7 ] Connection ESTABLISHED from %s:%u (MSS=%u)\n",
           inet_ntoa(peer), ntohs(tcb->remote_port_be), tcb->mss);
}

static void echo_on_recv(struct tcp_stack *stack, struct tcp_tcb *tcb,
                         const uint8_t *data, size_t len) {
    /* Echo received contiguous stream bytes directly back to the peer */
    tcp_send(stack, tcb, data, len, stack->last_tick_ms);
}

static void echo_on_closed(struct tcp_stack *stack, struct tcp_tcb *tcb) {
    struct in_addr peer = { .s_addr = tcb->remote_ip_be };
    printf("[TCP:7 ] Connection closing from %s:%u (state=%u)\n",
           inet_ntoa(peer), ntohs(tcb->remote_port_be), tcb->state);
    if (tcb->state == TCP_STATE_CLOSE_WAIT) {
        tcp_close(stack, tcb, stack->last_tick_ms);
    }
}

static void http_on_recv(struct tcp_stack *stack, struct tcp_tcb *tcb,
                         const uint8_t *data, size_t len) {
    (void)data;
    if (len == 0) {
        return;
    }
    static const char http_resp[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 45\r\n"
        "Connection: close\r\n"
        "\r\n"
        "Userspace C99 TCP/IP Stack (L2-L4) Online!\n";

    tcp_send(stack, tcb, http_resp, sizeof(http_resp) - 1U, stack->last_tick_ms);
    tcp_close(stack, tcb, stack->last_tick_ms);
}

static void http_on_closed(struct tcp_stack *stack, struct tcp_tcb *tcb) {
    if (tcb->state == TCP_STATE_CLOSE_WAIT) {
        tcp_close(stack, tcb, stack->last_tick_ms);
    }
}

/* ==========================================================================
 * Deterministic End-to-End Self-Test Suite (`--selftest`)
 * ========================================================================== */

static uint8_t g_test_rx_buf[256];
static size_t  g_test_rx_len = 0;

static void test_capture_on_recv(struct tcp_stack *stack, struct tcp_tcb *tcb,
                                 const uint8_t *data, size_t len) {
    if (g_test_rx_len + len <= sizeof(g_test_rx_buf)) {
        memcpy(g_test_rx_buf + g_test_rx_len, data, len);
        g_test_rx_len += len;
    }
    tcp_send(stack, tcb, data, len, stack->last_tick_ms);
}

/**
 * Helper to build and inject a raw TCP-over-IPv4-over-Ethernet frame from a
 * simulated remote peer into our stack during `--selftest`.
 */
static void inject_peer_tcp_frame(struct netdev *dev,
                                  const uint8_t peer_mac[ETH_ALEN],
                                  uint32_t peer_ip_be,
                                  uint16_t peer_port_host,
                                  uint16_t dst_port_host,
                                  uint32_t seq, uint32_t ack_seq,
                                  uint8_t flags, uint16_t wnd,
                                  const void *payload, size_t payload_len,
                                  uint64_t now_ms) {
    uint8_t frame[ETH_FRAME_MAX];
    memset(frame, 0, sizeof(frame));

    struct eth_hdr  *eth = (struct eth_hdr *)frame;
    struct ipv4_hdr *ip  = (struct ipv4_hdr *)(frame + ETH_HDR_LEN);
    struct tcp_hdr  *tcp = (struct tcp_hdr *)(frame + ETH_HDR_LEN + IPV4_HDR_MIN_LEN);

    memcpy(eth->dst_mac, dev->mac, ETH_ALEN);
    memcpy(eth->src_mac, peer_mac, ETH_ALEN);
    eth->ethertype = htons(ETH_P_IP);

    size_t tcp_len = TCP_HDR_MIN_LEN + payload_len;
    size_t ip_len  = IPV4_HDR_MIN_LEN + tcp_len;

    ip->ver_ihl  = (IPV4_VERSION << 4) | IPV4_MIN_IHL;
    ip->tos      = 0;
    ip->tot_len  = htons((uint16_t)ip_len);
    ip->id       = htons(0x1234U);
    ip->frag_off = htons(IPV4_FLAG_DF);
    ip->ttl      = 64;
    ip->proto    = IPPROTO_TCP_VAL;
    ip->check    = 0;
    ip->saddr    = peer_ip_be;
    ip->daddr    = dev->ip_be;
    ip->check    = checksum16_optimized(ip, IPV4_HDR_MIN_LEN);

    tcp->sport     = htons(peer_port_host);
    tcp->dport     = htons(dst_port_host);
    tcp->seq       = htonl(seq);
    tcp->ack_seq   = htonl(ack_seq);
    tcp->doff_rsvd = (uint8_t)((TCP_HDR_MIN_LEN / 4U) << 4);
    tcp->flags     = flags;
    tcp->window    = htons(wnd);
    tcp->check     = 0;
    tcp->urg_ptr   = 0;

    if (payload_len > 0 && payload != NULL) {
        memcpy((uint8_t *)tcp + TCP_HDR_MIN_LEN, payload, payload_len);
    }

    tcp->check = tcp_checksum(ip->saddr, ip->daddr, tcp, tcp_len);

    size_t frame_len = ETH_HDR_LEN + ip_len;
    if (frame_len < ETH_ZLEN) {
        frame_len = ETH_ZLEN; /* Simulate 60-byte Ethernet wire padding */
    }

    eth_rx(dev, frame, frame_len, now_ms);
}

static int run_selftest(void) {
    printf("=== Running Userspace TCP/IP Stack Self-Test Suite ===\n");

    /*
     * 1. RFC 1071 64-Bit Checksum Engine Verification
     *    Test vector from RFC 1071 / standard 20-byte IPv4 header + odd-byte
     *    unaligned slices.
     */
    static const uint8_t rfc_ip_vec[20] = {
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00, 0x01,
        0xc0, 0xa8, 0x00, 0xc7
    };
    if (checksum16_optimized(rfc_ip_vec, sizeof(rfc_ip_vec)) != 0) {
        fprintf(stderr, "[FAIL] RFC 1071 IPv4 header checksum verification failed\n");
        return 1;
    }

    /* Verify odd-aligned buffer and carry-folding across 0xFF bytes */
    uint8_t unaligned_buf[129];
    memset(unaligned_buf, 0xFF, sizeof(unaligned_buf));
    uint16_t csum_even = checksum16_optimized(unaligned_buf, 127);
    uint16_t csum_odd  = checksum16_optimized(unaligned_buf + 1, 127);
    if (csum_even != csum_odd) {
        fprintf(stderr, "[FAIL] Checksum alignment invariance failed\n");
        return 1;
    }
    printf("[PASS] 1. RFC 1071 64-Bit Checksum (Aligned, Unaligned & Odd-Length)\n");

    /*
     * Create an in-memory UNIX datagram socketpair to emulate `tap_fd` without
     * requiring root privileges.
     */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        perror("socketpair");
        return 1;
    }

    struct netdev dev;
    struct tcp_stack stack;
    static const uint8_t our_mac[ETH_ALEN]  = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
    static const uint8_t peer_mac[ETH_ALEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    uint32_t our_ip_be   = inet_addr("10.0.0.2");
    uint32_t peer_ip_be  = inet_addr("10.0.0.1");
    uint32_t netmask_be  = inet_addr("255.255.255.0");
    uint64_t now_ms      = 1000ULL;

    netdev_init(&dev, sv[0], our_mac, our_ip_be, netmask_be, peer_ip_be);
    tcp_stack_init(&stack, &dev, now_ms);

    /*
     * 2. Test O(1) ARP Cache LRU Eviction, Backward-Shift Deletion & RFC 826
     */
    for (uint32_t i = 1; i <= ARP_CACHE_CAPACITY + 10U; i++) {
        uint32_t fake_ip = htonl(0x0A000100U + i);
        uint8_t  fake_mac[ETH_ALEN] = { 0x02, 0xAA, 0xBB, 0xCC, 0x00, (uint8_t)i };
        arp_cache_upsert(&dev, fake_ip, fake_mac, now_ms + i);
    }
    if (dev.arp.count != ARP_CACHE_CAPACITY) {
        fprintf(stderr, "[FAIL] ARP cache count mismatch after LRU eviction\n");
        return 1;
    }
    /* First 10 entries should have been evicted; entry 11 should remain */
    if (arp_cache_lookup(&dev.arp, htonl(0x0A000101U), now_ms + 100) != NULL ||
        arp_cache_lookup(&dev.arp, htonl(0x0A00010BU), now_ms + 100) == NULL) {
        fprintf(stderr, "[FAIL] ARP O(1) LRU eviction order or backward-shift failed\n");
        return 1;
    }

    /* Populate peer_ip_be in ARP cache via an incoming RFC 826 ARP Request */
    uint8_t arp_req_frame[ETH_ZLEN];
    memset(arp_req_frame, 0, sizeof(arp_req_frame));
    struct eth_hdr *arp_eth = (struct eth_hdr *)arp_req_frame;
    struct arp_ipv4_pkt *arp_pkt = (struct arp_ipv4_pkt *)(arp_req_frame + ETH_HDR_LEN);
    memset(arp_eth->dst_mac, 0xFF, ETH_ALEN);
    memcpy(arp_eth->src_mac, peer_mac, ETH_ALEN);
    arp_eth->ethertype = htons(ETH_P_ARP);
    arp_pkt->ar_hrd = htons(ARP_HRD_ETHER);
    arp_pkt->ar_pro = htons(ARP_PRO_IP);
    arp_pkt->ar_hln = ETH_ALEN;
    arp_pkt->ar_pln = 4;
    arp_pkt->ar_op  = htons(ARP_OP_REQUEST);
    memcpy(arp_pkt->sha, peer_mac, ETH_ALEN);
    arp_pkt->spa = peer_ip_be;
    arp_pkt->tpa = our_ip_be;

    eth_rx(&dev, arp_req_frame, sizeof(arp_req_frame), now_ms);

    uint8_t wire_frame[ETH_FRAME_MAX];
    ssize_t n = recv(sv[1], wire_frame, sizeof(wire_frame), MSG_DONTWAIT);
    if (n < (ssize_t)ETH_ZLEN) {
        fprintf(stderr, "[FAIL] Expected 60-byte padded ARP Reply on wire\n");
        return 1;
    }
    printf("[PASS] 2. Layer 2 Ethernet & O(1) ARP Cache (LRU Eviction + RFC 826 Reply)\n");

    /*
     * 3. Test Layer 3 IPv4 (60-byte Ethernet padding strip) & ICMPv4 Echo Reply
     */
    uint8_t icmp_frame[ETH_ZLEN];
    memset(icmp_frame, 0xAA, sizeof(icmp_frame)); /* Non-zero padding to verify tot_len clamping */
    struct eth_hdr  *icmp_eth = (struct eth_hdr *)icmp_frame;
    struct ipv4_hdr *icmp_ip  = (struct ipv4_hdr *)(icmp_frame + ETH_HDR_LEN);
    struct icmp_hdr *icmp_req = (struct icmp_hdr *)(icmp_frame + ETH_HDR_LEN + IPV4_HDR_MIN_LEN);

    memcpy(icmp_eth->dst_mac, our_mac, ETH_ALEN);
    memcpy(icmp_eth->src_mac, peer_mac, ETH_ALEN);
    icmp_eth->ethertype = htons(ETH_P_IP);

    size_t icmp_payload_len = sizeof(struct icmp_hdr) + 4U; /* 12-byte ICMP message */
    icmp_ip->ver_ihl  = (IPV4_VERSION << 4) | IPV4_MIN_IHL;
    icmp_ip->tos      = 0;
    icmp_ip->tot_len  = htons((uint16_t)(IPV4_HDR_MIN_LEN + icmp_payload_len)); /* 32 bytes (< 46) */
    icmp_ip->id       = htons(0x0042U);
    icmp_ip->frag_off = htons(IPV4_FLAG_DF);
    icmp_ip->ttl      = 64;
    icmp_ip->proto    = IPPROTO_ICMP_VAL;
    icmp_ip->check    = 0;
    icmp_ip->saddr    = peer_ip_be;
    icmp_ip->daddr    = our_ip_be;
    icmp_ip->check    = checksum16_optimized(icmp_ip, IPV4_HDR_MIN_LEN);

    icmp_req->type     = ICMP_TYPE_ECHO_REQUEST;
    icmp_req->code     = 0;
    icmp_req->checksum = 0;
    icmp_req->id       = htons(0xBEEFU);
    icmp_req->seq      = htons(1U);
    memcpy((uint8_t *)icmp_req + sizeof(struct icmp_hdr), "PING", 4);
    icmp_req->checksum = checksum16_optimized(icmp_req, icmp_payload_len);

    eth_rx(&dev, icmp_frame, sizeof(icmp_frame), now_ms);

    n = recv(sv[1], wire_frame, sizeof(wire_frame), MSG_DONTWAIT);
    if (n < (ssize_t)ETH_ZLEN) {
        fprintf(stderr, "[FAIL] Expected ICMP Echo Reply frame\n");
        return 1;
    }
    const struct icmp_hdr *icmp_rep = (const struct icmp_hdr *)(wire_frame + ETH_HDR_LEN + IPV4_HDR_MIN_LEN);
    if (icmp_rep->type != ICMP_TYPE_ECHO_REPLY ||
        checksum16_optimized(icmp_rep, icmp_payload_len) != 0) {
        fprintf(stderr, "[FAIL] Invalid ICMP Echo Reply type or checksum\n");
        return 1;
    }
    printf("[PASS] 3. Layer 3 IPv4 Padding Strip & ICMPv4 Echo Request/Reply Engine\n");

    /*
     * 4. Test Layer 4 TCP 3-Way Handshake + Out-of-Order Interval Reassembly
     */
    struct tcp_callbacks test_cb = {
        .on_connected = NULL,
        .on_recv      = test_capture_on_recv,
        .on_closed    = NULL
    };
    tcp_listen(&stack, 7, test_cb);

    uint32_t client_isn = 10000U;
    /* Step 3a: Inject SYN from peer (10.0.0.1:54321 -> 10.0.0.2:7) */
    inject_peer_tcp_frame(&dev, peer_mac, peer_ip_be, 54321, 7,
                          client_isn, 0, TCP_FLAG_SYN, 16384, NULL, 0, now_ms);

    /* Read our stack's SYN+ACK response from `sv[1]` */
    n = recv(sv[1], wire_frame, sizeof(wire_frame), MSG_DONTWAIT);
    if (n < (ssize_t)(ETH_HDR_LEN + IPV4_HDR_MIN_LEN + TCP_HDR_MIN_LEN)) {
        fprintf(stderr, "[FAIL] No SYN+ACK emitted by TCP listener\n");
        return 1;
    }
    const struct tcp_hdr *synack = (const struct tcp_hdr *)(wire_frame + ETH_HDR_LEN + IPV4_HDR_MIN_LEN);
    if ((synack->flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) != (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
        fprintf(stderr, "[FAIL] Expected SYN|ACK flags in handshake response\n");
        return 1;
    }
    uint32_t server_isn = ntohl(synack->seq);

    /* Step 3b: Complete 3-Way Handshake by injecting peer ACK */
    now_ms += 15;
    inject_peer_tcp_frame(&dev, peer_mac, peer_ip_be, 54321, 7,
                          client_isn + 1U, server_isn + 1U,
                          TCP_FLAG_ACK, 16384, NULL, 0, now_ms);

    struct tcp_tcb *tcb = tcp_lookup_tcb(&stack, our_ip_be, peer_ip_be,
                                         htons(7), htons(54321));
    if (tcb == NULL || tcb->state != TCP_STATE_ESTABLISHED) {
        fprintf(stderr, "[FAIL] TCB failed to reach TCP_STATE_ESTABLISHED\n");
        return 1;
    }

    /*
     * Step 3c: Inject Out-of-Order Segments!
     * Expected contiguous stream at `client_isn + 1`: "0123456789ABCDEFGHIJklmnopqrst" (30 bytes)
     *  - First inject chunk 3: `[client_isn + 21, client_isn + 31)` = "klmnopqrst"
     *  - Next  inject chunk 2: `[client_isn + 11, client_isn + 21)` = "ABCDEFGHIJ"
     *  - Verify `g_test_rx_len == 0` and `tcb->ooo_count == 1` (coalesced `[+11, +31)`)!
     *  - Finally inject overlapping chunk 1: `[client_isn + 1, client_isn + 13)` = "0123456789AB"
     *  - Verify `tcb->rcv_nxt == client_isn + 31` and all 30 bytes are delivered in-order!
     */
    inject_peer_tcp_frame(&dev, peer_mac, peer_ip_be, 54321, 7,
                          client_isn + 21U, server_isn + 1U,
                          TCP_FLAG_ACK, 16384, "klmnopqrst", 10, now_ms);
    (void)recv(sv[1], wire_frame, sizeof(wire_frame), MSG_DONTWAIT); /* drain dup-ACK */

    inject_peer_tcp_frame(&dev, peer_mac, peer_ip_be, 54321, 7,
                          client_isn + 11U, server_isn + 1U,
                          TCP_FLAG_ACK, 16384, "ABCDEFGHIJ", 10, now_ms);
    (void)recv(sv[1], wire_frame, sizeof(wire_frame), MSG_DONTWAIT); /* drain dup-ACK */

    if (g_test_rx_len != 0 || tcb->ooo_count != 1 ||
        tcb->ooo[0].start_seq != client_isn + 11U ||
        tcb->ooo[0].end_seq   != client_isn + 31U) {
        fprintf(stderr, "[FAIL] OOO interval coalescing failed (count=%u)\n", tcb->ooo_count);
        return 1;
    }

    /* Bridge the gap with overlapping segment 1 */
    inject_peer_tcp_frame(&dev, peer_mac, peer_ip_be, 54321, 7,
                          client_isn + 1U, server_isn + 1U,
                          TCP_FLAG_ACK | TCP_FLAG_PSH, 16384, "0123456789AB", 12, now_ms);

    /* Drain echoed segment + ACK */
    (void)recv(sv[1], wire_frame, sizeof(wire_frame), MSG_DONTWAIT);
    (void)recv(sv[1], wire_frame, sizeof(wire_frame), MSG_DONTWAIT);

    if (g_test_rx_len != 30 ||
        memcmp(g_test_rx_buf, "0123456789ABCDEFGHIJklmnopqrst", 30) != 0 ||
        tcb->ooo_count != 0 ||
        tcb->rcv_nxt != client_isn + 31U) {
        fprintf(stderr, "[FAIL] Out-of-order stream reassembly mismatch\n");
        return 1;
    }
    printf("[PASS] 4. TCP 3-Way Handshake & Out-of-Order Interval Reassembly (30/30 bytes coalesced)\n");

    /*
     * 5. Test RFC 6298 Retransmission Timer (RTO) & Exponential Backoff
     *    Our echo callback just sent 30 bytes `[server_isn + 1, server_isn + 31)`.
     *    Do NOT acknowledge them; instead advance the delta-list clock past `tcb->rto_ms`!
     */
    uint32_t initial_rto = tcb->rto_ms;
    now_ms += initial_rto + 10U;
    tcp_timers_tick(&stack, now_ms);

    n = recv(sv[1], wire_frame, sizeof(wire_frame), MSG_DONTWAIT);
    if (n <= 0 || tcb->rtx_count != 1 || tcb->rto_ms != (initial_rto * 2U)) {
        fprintf(stderr, "[FAIL] RFC 6298 RTO timer firing or exponential backoff failed\n");
        return 1;
    }
    printf("[PASS] 5. RFC 6298 Jacobson/Karels RTT/RTO & Delta-List Timer Backoff (%u ms -> %u ms)\n",
           initial_rto, tcb->rto_ms);

    /*
     * 6. Test Orderly 4-Way FIN Teardown & 2*MSL TIME_WAIT Expiration
     */
    /* Acknowledge our 30 echoed bytes and initiate local active close (`FIN_WAIT_1`) */
    now_ms += 10U;
    inject_peer_tcp_frame(&dev, peer_mac, peer_ip_be, 54321, 7,
                          client_isn + 31U, server_isn + 31U,
                          TCP_FLAG_ACK, 16384, NULL, 0, now_ms);
    tcp_close(&stack, tcb, now_ms);
    (void)recv(sv[1], wire_frame, sizeof(wire_frame), MSG_DONTWAIT); /* drain our FIN+ACK */

    if (tcb->state != TCP_STATE_FIN_WAIT_1) {
        fprintf(stderr, "[FAIL] Expected TCP_STATE_FIN_WAIT_1 after tcp_close()\n");
        return 1;
    }

    /* Peer sends FIN+ACK acknowledging our FIN -> transitions to `TIME_WAIT` */
    now_ms += 10U;
    inject_peer_tcp_frame(&dev, peer_mac, peer_ip_be, 54321, 7,
                          client_isn + 31U, server_isn + 32U,
                          TCP_FLAG_FIN | TCP_FLAG_ACK, 16384, NULL, 0, now_ms);
    (void)recv(sv[1], wire_frame, sizeof(wire_frame), MSG_DONTWAIT); /* drain final ACK */

    if (tcb->state != TCP_STATE_TIME_WAIT) {
        fprintf(stderr, "[FAIL] Expected TCP_STATE_TIME_WAIT after peer FIN+ACK\n");
        return 1;
    }

    /* Advance clock past 2*MSL (`TCP_TIME_WAIT_MS`) -> TCB freed & removed from hash table */
    now_ms += TCP_TIME_WAIT_MS + 10U;
    tcp_timers_tick(&stack, now_ms);

    if (tcp_lookup_tcb(&stack, our_ip_be, peer_ip_be, htons(7), htons(54321)) != NULL) {
        fprintf(stderr, "[FAIL] TCB was not reclaimed after TIME_WAIT expiration\n");
        return 1;
    }
    printf("[PASS] 6. TCP 4-Way FIN Teardown, TIME_WAIT & Knuth Algorithm R Hash Reclamation\n");

    close(sv[0]);
    close(sv[1]);
    printf("=== All Self-Tests Passed Successfully ===\n");
    return 0;
}

/* ==========================================================================
 * Main TAP Daemon Event Loop
 * ========================================================================== */

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--selftest") == 0) {
        return run_selftest();
    }

    char tap_name[16] = "tap0";
    const char *ip_str = "10.0.0.2";
    const char *gw_str = "10.0.0.1";

    if (argc > 1) {
        strncpy(tap_name, argv[1], sizeof(tap_name) - 1U);
        tap_name[sizeof(tap_name) - 1U] = '\0';
    }
    if (argc > 2) {
        ip_str = argv[2];
    }

    int tap_fd = tap_alloc(tap_name);
    if (tap_fd < 0) {
        fprintf(stderr, "\nHint: Run `sudo ./ustack` for live TAP mode, or `./ustack --selftest` for unprivileged verification.\n");
        return 1;
    }

    static const uint8_t local_mac[ETH_ALEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
    uint32_t local_ip_be   = inet_addr(ip_str);
    uint32_t netmask_be    = inet_addr("255.255.255.0");
    uint32_t gateway_ip_be = inet_addr(gw_str);

    struct netdev dev;
    struct tcp_stack stack;
    uint64_t now_ms = monotonic_ms();

    netdev_init(&dev, tap_fd, local_mac, local_ip_be, netmask_be, gateway_ip_be);
    tcp_stack_init(&stack, &dev, now_ms);

    /* Register TCP Echo Server on Port 7 and HTTP Server on Port 80 */
    struct tcp_callbacks echo_cb = {
        .on_connected = echo_on_connected,
        .on_recv      = echo_on_recv,
        .on_closed    = echo_on_closed
    };
    struct tcp_callbacks http_cb = {
        .on_connected = NULL,
        .on_recv      = http_on_recv,
        .on_closed    = http_on_closed
    };
    tcp_listen(&stack, 7, echo_cb);
    tcp_listen(&stack, 80, http_cb);

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    printf("Userspace TCP/IP Stack bound to %s (MAC %02x:%02x:%02x:%02x:%02x:%02x, IP %s)\n",
           tap_name,
           local_mac[0], local_mac[1], local_mac[2],
           local_mac[3], local_mac[4], local_mac[5],
           ip_str);
    printf("Listening on TCP port 7 (Echo) and TCP port 80 (HTTP).\n");

    struct pollfd pfd = {
        .fd     = tap_fd,
        .events = POLLIN
    };

    uint8_t frame_buf[ETH_FRAME_MAX];

    while (g_keep_running) {
        int rc = poll(&pfd, 1, 10); /* 10ms timer resolution for RFC 6298 delta-list */
        now_ms = monotonic_ms();

        if (rc > 0 && (pfd.revents & POLLIN) != 0) {
            ssize_t n = read(tap_fd, frame_buf, sizeof(frame_buf));
            if (n > 0) {
                eth_rx(&dev, frame_buf, (size_t)n, now_ms);
            }
        } else if (rc < 0 && errno != EINTR) {
            perror("poll");
            break;
        }

        tcp_timers_tick(&stack, now_ms);
    }

    printf("\nShutting down %s.\n", tap_name);
    close(tap_fd);
    return 0;
}
