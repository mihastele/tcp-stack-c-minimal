# Userspace TCP/IP Stack in C99

A high-performance, RFC-compliant userspace network stack implemented in standard C (C99, POSIX, Linux TAP). This implementation covers the networking layers from raw Layer 2 Ethernet frames up to Layer 4 TCP stream reassembly and connection lifecycle management, avoiding naive implementations in favor of production systems algorithms.

---

## Architectural Highlights

### Layer 2: Ethernet & ARP
- **Linux TAP Allocation**: Direct Layer 2 access via `/dev/net/tun` using `IFF_TAP | IFF_NO_PI` without packet metadata headers.
- **IEEE 802.3 Framing**: Strict MAC demultiplexing, minimum 60-byte (`ETH_ZLEN`) frame padding, and broadcast handling.
- **O(1) Hash-Indexed ARP Cache**: Fixed-capacity pool (64 entries) indexed by a 128-bucket power-of-two open-addressing hash table using MurmurHash3 finalizer mixing (`fmix32`).
- **Zero-Tombstone Deletion**: Employs Knuth's Algorithm R (backward-shift deletion) on hash collisions to prevent cluster degradation under high neighbor turnover.
- **Intrusive Doubly-Linked LRU**: 16-bit node indices (`lru_prev`, `lru_next`) track entry age for O(1) promotion and eviction without heap allocation.
- **RFC 826 Compliance**: Implements the `Merge_flag` algorithm (refreshing existing neighbor entries before checking target addresses) and RFC 1122 hold queue (queuing pending Layer 3 frames until address resolution completes).

### Layer 3: IPv4 & ICMPv4
- **Portable Bitfield Parsing**: Eliminates implementation-defined bitfield packing by using explicit bit-shift and mask operations for `ver_ihl`.
- **Ethernet Padding Stripping**: Enforces `tot_len` boundaries, stripping IEEE 802.3 zero-padding before passing payload to Layer 4 to preserve pseudo-header checksum integrity.
- **Optimized 64-Bit Checksum Engine**: Implements an unrolled 32-byte loop accumulating 32-bit words into a 64-bit accumulator. Avoids unsigned 64-bit overflow carry loss and maintains 4-byte alignment safety across architectures.
- **Scatter-Gather Checksum Calculation**: Calculates one's complement sums over disjoint buffers (such as pseudo-headers and TCP segments) in-place without memory copies.
- **ICMPv4 Echo Engine**: RFC 792 Type 8 (Echo Request) processing and Type 0 (Echo Reply) generation with matching identifiers, sequence numbers, and payload checksums.

### Layer 4: Transmission Control Block & TCP State Machine
- **Full RFC 793 / RFC 1122 State Engine**: Covers all 11 TCP states (`CLOSED`, `LISTEN`, `SYN_SENT`, `SYN_RECEIVED`, `ESTABLISHED`, `FIN_WAIT_1`, `FIN_WAIT_2`, `CLOSE_WAIT`, `CLOSING`, `LAST_ACK`, `TIME_WAIT`).
- **O(1) 4-Tuple Hash Table**: Fast lookup for `(local_ip, remote_ip, local_port, remote_port)` using power-of-two open addressing with backward-shift deletion, paired with a listener registry for passive opens.
- **Modular Sequence Space Arithmetic**: Handles 32-bit sequence number wraparound via signed two's complement difference macros (`SEQ_LT`, `SEQ_LEQ`, `SEQ_GT`, `SEQ_GEQ`).
- **Monotonic Circular Ring Buffer**: Power-of-two 16 KiB circular receive buffer mapped via `(seq - irs - 1) & mask`. Segments are copied directly into their target sequence offsets with at most two `memcpy` calls.
- **Out-of-Order Interval Reassembly**: Non-contiguous segments falling within the receive window are written directly to the ring buffer and tracked by a sorted interval list. When sequence gaps are bridged, `RCV.NXT` advances monotonically across contiguous ranges in a single pass with zero memory shifting.
- **RFC 6298 Retransmission Timer**: Jacobson/Karels dynamic RTT estimation tracking smoothed RTT (`SRTT`) and RTT variance (`RTTVAR`) with Karn's algorithm to ignore samples from retransmitted segments.
- **Intrusive Delta-List Timer Queue**: Chained timer list where each node stores only the delta relative to its predecessor. Advancing the clock on event loop ticks requires modifying only the head node, ensuring O(1) tick maintenance.

---

## Codebase Layout

| Source File | Header File | Responsibilities |
| :--- | :--- | :--- |
| `net_base.c` | `net_base.h` | TAP interface creation, 64-bit unrolled RFC 1071 checksum engine and folding primitives. |
| `eth_arp.c` | `eth_arp.h` | Ethernet frame encode/decode, O(1) ARP cache with backward-shift deletion, intrusive LRU, and RFC 826 state machine. |
| `ipv4_icmp.c` | `ipv4_icmp.h` | IPv4 validation, padding stripping, fragmentation filtering, and ICMPv4 echo engine. |
| `tcp.c` | `tcp.h` | 4-tuple TCB lookup, TCP pseudo-header checksums, sequence space arithmetic, circular ring reassembly, delta-list timers, and RFC 793 state machine. |
| `main.c` | - | Event loop integrating TAP descriptor polling with delta-list timers, built-in Echo (Port 7) and HTTP (Port 80) servers, and unprivileged test harness. |
| `Makefile` | - | Strict build rules using `-O3 -Wall -Wextra -Werror -std=c99 -pedantic`. |

---

## Building and Verification

### Prerequisites
- GCC or Clang supporting C99.
- Linux kernel with TUN/TAP support (`/dev/net/tun`).
- Standard Linux networking utilities (`ip`, `arping`, `ping`, `nc`, `curl`).

### Compilation
Build the complete project with strict warning and standards flags:

```bash
make clean
make
```

### Deterministic Unit and Integration Tests
You can verify every layer of the stack without root privileges or TAP device allocation using the built-in self-test suite. The test harness runs over an in-memory `AF_UNIX` datagram socketpair to evaluate wire formatting and algorithmic correctness:

```bash
make test
```

The test runner validates:
1. RFC 1071 64-bit checksum engine across aligned, unaligned, and odd-length buffers.
2. Layer 2 Ethernet padding and O(1) ARP cache LRU eviction, backward-shift deletion, and RFC 826 reply generation.
3. Layer 3 IPv4 frame padding stripping and ICMPv4 echo reply validation.
4. TCP 3-way handshake and out-of-order segment reassembly across multiple disjoint and overlapping chunks.
5. RFC 6298 RTO timer expiration, retransmission execution, and exponential backoff.
6. TCP 4-way FIN closing sequence, `TIME_WAIT` transition, and TCB memory reclamation.

---

## Running on a Live TAP Device

To run the stack on a virtual network device and interact with host-side applications:

### Step 1: Start the Userspace Stack
Run the binary as root (or with `CAP_NET_ADMIN` capability) specifying the TAP interface name and desired IP:

```bash
sudo ./ustack tap0 10.0.0.2
```

The stack creates `tap0`, binds local IP `10.0.0.2/24`, and begins listening on TCP port 7 (Echo) and TCP port 80 (HTTP).

### Step 2: Configure the Host Interface
In a separate terminal, assign an IP on the same subnet to the host side of `tap0` and bring the link up:

```bash
sudo ip addr add 10.0.0.1/24 dev tap0
sudo ip link set dev tap0 up
```

### Step 3: Run Host-Side Verifications

#### Test ARP Resolution (RFC 826)
Verify address resolution and O(1) ARP cache reply handling:
```bash
sudo arping -I tap0 -c 3 10.0.0.2
```

#### Test ICMP Echo Request / Reply (RFC 792)
Verify IPv4 header parsing and round-trip ping response:
```bash
ping -c 4 10.0.0.2
```

#### Test TCP Echo Server (RFC 862, Port 7)
Open an interactive TCP stream to verify bidirectional segment exchange:
```bash
nc -v 10.0.0.2 7
```
Any text entered into standard input will be echoed back by the userspace stack.

#### Test HTTP / 1.1 Server & Orderly Teardown (Port 80)
Verify payload transmission and clean 4-way FIN closure:
```bash
curl -v http://10.0.0.2/
```

Expected HTTP output:
```http
* Connected to 10.0.0.2 (10.0.0.2) port 80
> GET / HTTP/1.1
> Host: 10.0.0.2
> User-Agent: curl/...
> Accept: */*
> 
< HTTP/1.1 200 OK
< Content-Type: text/plain
< Content-Length: 45
< Connection: close
< 
Userspace C99 TCP/IP Stack (L2-L4) Online!
```

---

## Algorithmic and Systems Design Details

### 1. Checksum Optimization and Carry Safety
Naive 16-bit checksum loops generate pipeline stalls due to dependencies on carry flags. While expanding to 64-bit reads provides high throughput, accumulating `uint64_t` words directly causes silent carry loss on unsigned overflow. 

This implementation processes data in 32-byte blocks by loading eight 32-bit unsigned integers (`uint32_t`) and widening them into a single `uint64_t` accumulator. Because each word is bounded by `0xFFFFFFFF`, the accumulator can process up to $2^{32} - 1$ words (16 GiB of data) before an overflow can occur, eliminating in-loop carry checks entirely.

### 2. O(1) Open-Addressing ARP Cache with Backward-Shift Deletion
Many hash table implementations rely on tombstone markers to handle deletions. Over time, recurring insertions and evictions fill tables with tombstones, turning lookups into linear scans. 

This stack avoids tombstones by applying Knuth's Algorithm R:
- When a slot is cleared, subsequent entries in the probe sequence are inspected.
- If an entry's natural hash position falls cyclically outside the current range, it is shifted backward into the vacated slot.
- This maintains contiguous probe clusters without tombstones, ensuring $O(1)$ lookup guarantees throughout continuous operation.

### 3. Out-of-Order Reassembly via Direct-Placement Ring Buffers
Conventional network stacks often buffer out-of-order packets in linked lists of dynamic allocations, requiring contiguous copying once holes are filled. 

This stack preallocates a power-of-two 16 KiB circular buffer per connection:
- Sequence numbers map deterministically to ring offsets: `offset = (seq - irs - 1) & (BUF_SIZE - 1)`.
- When an out-of-order segment arrives within the advertised window, payload bytes are copied directly to their final positions in the ring buffer.
- An intrusive interval list tracks the boundaries of unread contiguous data blocks.
- Once the missing segment arrives at `RCV.NXT`, the contiguous boundary advances across bridged intervals and delivers data to the application layer with zero memory relocation.

### 4. Delta-List Timing Wheel for Retransmission
Managing retransmission timeouts for numerous connections with absolute timestamps can lead to $O(N)$ timer scans on every tick. 

Here, TCBs are organized in a sorted intrusive delta list:
- The head node stores the milliseconds remaining until its expiration.
- Each subsequent node stores only the delta in milliseconds relative to the preceding node.
- On each tick of the event loop, only the head node's delta is decremented.
- When the head delta reaches zero, the timer fires, the node is removed, and the subsequent node becomes the new head. This guarantees $O(1)$ timer overhead per tick.

---

## Technical Specifications and RFC References

- **RFC 791**: Internet Protocol Specification (IPv4 header parsing, total length validation, TTL, fragmentation filtering).
- **RFC 792**: Internet Control Message Protocol (Echo Request and Echo Reply generation).
- **RFC 793**: Transmission Control Protocol (Connection state machine, sequence space logic, segment acceptability).
- **RFC 826**: Ethernet Address Resolution Protocol (Packet formats, merge flag handling, reply rules).
- **RFC 1071**: Computing the Internet Checksum (One's complement arithmetic and 32/64-bit folding).
- **RFC 1122**: Requirements for Internet Hosts (Single-packet hold queues during address resolution, padding handling).
- **RFC 6298**: Computing TCP's Retransmission Timer (Jacobson/Karels algorithm, Karn's algorithm, RTO bounding).
