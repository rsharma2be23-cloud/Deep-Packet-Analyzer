# DEEP PACKET INSPECTION (DPI) SYSTEM TECHNICAL REPORT

## 1. PROJECT OVERVIEW

* **Project Name:** DPI Engine / Deep Packet Inspection System (referenced also as Packet Analyzer).
* **Main Purpose/Problem Being Solved:** The project solves the problem of analyzing, classifying, and filtering network traffic captures (PCAP files) at the application layer without relying on external packet capture libraries like `libpcap`. It addresses the need to identify applications using encrypted (TLS SNI) or unencrypted (HTTP Host) traffic and apply traffic-blocking rules (IP, Port, Domain, Application) to produce a clean, filtered PCAP file alongside comprehensive traffic statistics.
* **What the System Actually Does:** It reads PCAP capture files, parses Ethernet headers, IPv4 headers, and TCP/UDP transport headers. It groups packets into stateful bidirectional network flows. It inspects packet payloads to extract Server Name Indication (SNI) from TLS Client Hellos, Host headers from HTTP requests, and domain names from DNS queries. It checks these details against configured rules to decide whether to forward or drop each packet, writing allowed packets into an output PCAP and generating a detailed traffic breakdown.
* **Main Use Cases:** 
  1. Content filtering and parental/corporate control (blocking applications like YouTube or Facebook).
  2. Network security auditing (identifying malicious IPs or unauthorized protocols).
  3. Traffic profiling and reporting (generating application breakdowns and identifying top domains).
* **Current Project Status:** Functional, intermediate-level project. It contains complete single-threaded and multi-threaded processing pipelines that parse, track, block, and output PCAP files.
* **What Appears Complete vs Incomplete:**
  * **Complete:** PCAP header reading/writing, Ethernet/IPv4/TCP/UDP parsing, TLS Client Hello SNI parser, HTTP Host header extractor, DNS Query label decoder, stateful connection trackers, thread-safe queues, hash-based Load Balancers, Fast Path workers, and stats reporting.
  * **Incomplete / Planned:** 
    * *IPv6 Parsing:* Defined in header enums but not implemented in the parser (`PacketParser::parse` only descends into the IPv4 parsing branch).
    * *QUIC Decryption:* Heuristic SNI searching is implemented, but full QUIC framing/decryption is not.
    * *Live Capture:* The system reads static PCAP files only; it lacks support for live network interfaces.
    * *Dynamic Rule Updates:* Rules are static or CLI-provided; there is no runtime API/control channel to add/remove rules.

---

## 2. TECHNOLOGY STACK

* **C++17:** Core programming language. Used for low-level byte manipulation, memory efficiency, and stateful tracking.
* **C++ Standard Library (STL):** Used for data structures (`std::unordered_map`, `std::vector`, `std::unordered_set`) and I/O streams. No external dependencies are used (not even `libpcap`).
* **C++ Concurrency Library:** Standard multithreading primitives (`std::thread`, `std::mutex`, `std::shared_mutex`, `std::condition_variable`, `std::atomic`).
* **Python 3:** Used for the helper script `generate_test_pcap.py` to create custom simulated network traffic captures.
* **CMake (3.16+):** Build configuration system.
* **Network Protocols:**
  * *Ethernet (IEEE 802.3):* MAC addresses, EtherType.
  * *IPv4 (RFC 791):* TTL, Protocol, Source/Destination IPs.
  * *TCP (RFC 793):* Source/Destination Ports, Seq/Ack Numbers, Flags (SYN, ACK, FIN, RST, PSH, URG), Payload offsets.
  * *UDP (RFC 768):* Source/Destination Ports, Header Length.
  * *TLS 1.0–1.3 (RFC 8446):* Client Hello Handshake parsing, Extension parsing, SNI extraction.
  * *HTTP/1.1:* GET/POST/etc. request identification, case-insensitive `Host` header extraction.
  * *DNS (RFC 1035):* Query flag checking, label-length domain decoding.

---

## 3. COMPLETE PROJECT STRUCTURE

```text
Packet_analyzer/
│
├── include/                            # Header files containing declarations
│   ├── platform.h                      # Portable endianness detection & swapping utilities
│   ├── types.h                         # Core enums (AppType, ConnectionState, PacketAction) and structs
│   ├── pcap_reader.h                   # PCAP Global/Packet structures and PcapReader declaration
│   ├── packet_parser.h                 # Protocol headers and PacketParser class declaration
│   ├── sni_extractor.h                 # TLS, QUIC, HTTP Host, and DNS query parsers
│   ├── rule_manager.h                  # Thread-safe rule storage and wildcard matcher
│   ├── connection_tracker.h            # Stateful flow table and global stats aggregator
│   ├── load_balancer.h                 # Thread-safe LoadBalancer & LBManager declarations
│   ├── fast_path.h                     # Thread-safe FastPathProcessor & FPManager declarations
│   ├── thread_safe_queue.h             # Template thread-safe queue for worker pipelines
│   └── dpi_engine.h                    # Orchestrator for the modular multi-threaded pipeline
│
├── src/                                # Source files containing implementations
│   ├── types.cpp                       # SNI to AppType mappings, string formatters
│   ├── pcap_reader.cpp                 # PCAP magic check, byte-swap handling, raw read loops
│   ├── packet_parser.cpp               # Byte-offset protocol parser, ntohs/ntohl emulation
│   ├── sni_extractor.cpp               # Parsers for TLS Client Hello, HTTP Host, DNS labels
│   ├── rule_manager.cpp                # Persistence (load/save) and IP/App/Domain matching rules
│   ├── connection_tracker.cpp          # Bidirectional flow lookups, cleanups, reports
│   ├── load_balancer.cpp               # Dispatcher routing packets based on 5-tuple hash
│   ├── fast_path.cpp                   # Worker threads processing DPI classification and rules
│   ├── dpi_engine.cpp                  # DPIEngine orchestrator implementation
│   ├── dpi_mt.cpp                      # Self-contained multi-threaded program implementation
│   ├── main_dpi.cpp                    # Driver CLI for the modular multi-threaded pipeline
│   ├── main_working.cpp                # Driver CLI for the single-threaded pipeline
│   ├── main.cpp                        # Basic packet dumper/analyzer driver
│   └── main_simple.cpp                 # Basic parser/SNI tester driver
│
├── CMakeLists.txt                      # Project build system configuration
├── README.md                           # Main user documentation
├── WINDOWS_SETUP.md                    # Windows compilation instructions
├── generate_test_pcap.py               # Test-data generator script
└── test_dpi.pcap                       # Generated test traffic
```

---

## 4. SYSTEM ARCHITECTURE

The system implements two distinct architectures:

### 1. Stateful Single-Threaded Architecture (`src/main_working.cpp`)
All packet ingestion, protocol parsing, connection tracking, payload classification, rule matching, and output writing run sequentially on the main thread:
```text
[PCAP File] ──> [PcapReader] ──> [PacketParser] ──> [Flow Table (Map)] ──> [Rules Engine] ──> [Filter/Write] ──> [Output PCAP]
```

### 2. Multi-Threaded Pipeline Architecture
The system supports a multi-threaded processing model, implemented in two ways:
* **Modular Pipeline** (orchestrated by `src/main_dpi.cpp` via `src/dpi_engine.cpp`)
* **Self-Contained Pipeline** (implemented entirely inside `src/dpi_mt.cpp`)

Both pipelines utilize the same architectural concept:

```text
                  [Reader Thread]
                         │
        ┌────────────────┴────────────────┐ (hash(5-tuple) % 2)
        ▼                                 ▼
┌───────────────┐                 ┌───────────────┐
│ LoadBalancer0 │                 │ LoadBalancer1 │
└───────┬───────┘                 └───────┬───────┘
        │ (hash(5-tuple) % 2)             │ (hash(5-tuple) % 2)
   ┌────┴────┐                       ┌────┴────┐
   ▼         ▼                       ▼         ▼
┌─────┐   ┌─────┐                 ┌─────┐   ┌─────┐
│ FP0 │   │ FP1 │                 │ FP2 │   │ FP3 │
└──┬──┘   └──┬──┘                 └──┬──┘   └──┬──┘
   │         │                       │         │ (If Action == FORWARD)
   └─────────┴───────────┬───────────┴─────────┘
                         ▼
                  ┌──────────────┐
                  │ Output Queue │
                  └──────┬───────┘
                         ▼
               [Output Writer Thread]
                         │
                         ▼
                   [Output PCAP]
```

* **Reader Thread:** Reads raw packets from PCAP, parses Ethernet/IP headers, filters out non-IP/TCP/UDP traffic, and dispatches matching packets to the target LoadBalancer based on the hash of their 5-tuple.
* **Load Balancer Threads:** Distribute packets to their assigned Fast Path (FP) threads by computing the 5-tuple hash relative to their local worker pool.
* **Fast Path (FP) Worker Threads:** Perform stateful tracking and deep inspection. Each FP thread operates a local connection table. This is lock-free because consistent hashing ensures packets from a given flow are always routed to the same FP thread. The FP thread classifies the flow, applies blocking rules, and drops blocked packets while pushing allowed packets to the shared output queue.
* **Output Writer Thread:** Reads from the output queue and writes packets sequentially to the output PCAP file.

---

## 5. CORE WORKFLOW

When a packet is processed by the DPI Engine:

1. **Ingestion:** `PcapReader::readNextPacket` reads a 16-byte packet header and the raw payload from the file stream into a buffer.
2. **First-Pass Parsing:** `PacketParser::parse` extracts the offsets for the Ethernet header (starts at byte 0), IPv4 header (offset 14), and TCP/UDP header. It extracts the raw IPs, ports, and protocols in network byte order and swaps them to host byte order using `ntohs` / `ntohl`.
3. **Queue Ingestion:** The packet details are wrapped into a `PacketJob` (modular) or `Packet` (self-contained) struct and queued.
4. **Flow Mapping:** The Fast Path worker uses the packet's `FiveTuple` (Source IP, Destination IP, Source Port, Destination Port, Protocol) to query its flow table. If it's a new flow, a `Connection` entry is created.
5. **DPI / Classification (if not already classified):**
   * If it is a TCP packet on port 443, it parses the TLS Client Hello to extract the SNI hostname.
   * If it is a TCP packet on port 80, it parses the HTTP Host header.
   * If it is a UDP packet on port 53, it extracts the DNS query domain.
   * If successful, the flow entry is marked as `CLASSIFIED` with the detected application and domain.
6. **Rule Evaluation:** The extracted parameters are evaluated by `RuleManager::shouldBlock`.
7. **Action:**
   * **DROP:** If a rule matches, the flow state is updated to `BLOCKED`. The packet is dropped, and future packets matching this flow are dropped immediately during the flow mapping step.
   * **FORWARD:** The packet is pushed to the output queue and written to the destination PCAP file.

---

## 6. PACKET PROCESSING / DPI LOGIC

* **How PCAP Files are Read:** `PcapReader::open` reads the 24-byte global header and verifies the magic number. If the magic number is `0xd4c3b2a1` (swapped byte order), it sets `needs_byte_swap_ = true`. `readNextPacket` reads the 16-byte packet header, swaps fields if `needs_byte_swap_` is true, resizes a `RawPacket` buffer to match `incl_len`, and reads the raw bytes from disk.
* **How Packets are Parsed:** `PacketParser::parse` performs bounds checks at each layer:
  * *Ethernet:* Validates that length $\ge 14$ bytes. Extracts source/destination MACs and the 2-byte EtherType.
  * *IPv4:* If EtherType is `0x0800`, validates version (must be 4) and length $\ge 20$. Extracts header length from IHL, TTL, Protocol, and IPs.
  * *TCP:* If Protocol is 6, validates header length $\ge 20$. Extracts ports, Seq/Ack, data offset, and TCP flags.
  * *UDP:* If Protocol is 17, validates header length $\ge 8$. Extracts ports.
* **Supported Protocols:** Ethernet (MAC), IPv4, TCP, UDP. 
* **Protocol Handling:** IPv6 is defined as an enum value but parsing logic does not exist. TCP flags (SYN, ACK, FIN, RST) are tracked inside `FastPathProcessor::updateTCPState` to manage connection states (e.g., transitions to `ESTABLISHED` or `CLOSED`).
* **How Flows are Tracked:** Flows are stored in a hash map using a `FiveTuple` key. To support bidirectional tracking, `getConnection` falls back to searching for `tuple.reverse()` if the exact tuple matches nothing.
* **How Applications are Identified:** 
  * **TLS SNI Extraction:** `SNIExtractor::extract` checks that the payload begins with a TLS Handshake record type (`0x16`), a version byte between `0x0300` and `0x0304`, and a handshake type Client Hello (`0x01`). It skips the random bytes, session ID, cipher suites, and compression methods to reach the extensions block. It iterates through extensions to find type `0x0000` (SNI), validates the server name type `0x00` (hostname), and copies the string.
  * **HTTP Host Extraction:** `HTTPHostExtractor::extract` validates that the payload starts with an HTTP request method (e.g., `GET `, `POST`, `PUT `). It performs a case-insensitive search for `"Host: "` or `"host:"`, advances past whitespace, and extracts the characters up to the carriage return or newline. Port suffixes are stripped.
  * **DNS Query Extraction:** `DNSExtractor::extractQuery` checks if the QR bit in flags is 0 (query) and QDCOUNT > 0. It starts reading labels at byte 12, joining them with `.` until it hits a label of length 0.
* **Malformed Packet Handling:** Safe offsets are maintained. If any parser detects that a header field or offset exceeds the packet's captured length, it returns `false`, and the packet is ignored.

---

## 7. TRAFFIC-BLOCKING / RULE ENGINE

* **Representation:** Rules are managed via `RuleManager` (modular) or `Rules` (self-contained). They store blocked criteria in hash sets or vectors:
  * `blocked_ips_` (`std::unordered_set<uint32_t>`)
  * `blocked_apps_` (`std::unordered_set<AppType>`)
  * `blocked_domains_` (`std::unordered_set<std::string>`)
  * `domain_patterns_` (`std::vector<std::string>` for wildcard patterns)
  * `blocked_ports_` (`std::unordered_set<uint16_t>`)
* **Triggering Criteria:** Matching Source IP, matching Destination Port, matching Application type (e.g., `AppType::YOUTUBE`), or matching Destination Domain (supports wildcards like `*.facebook.com`).
* **Configuration:** Rules are loaded from a text file containing section markers (e.g., `[BLOCKED_IPS]`, `[BLOCKED_DOMAINS]`) or supplied via CLI options (`--block-ip`, `--block-app`, `--block-domain`).
* **Matching Logic:** `RuleManager::shouldBlock` executes checks in this order:
  1. Checks if the packet's Source IP is in `blocked_ips_`.
  2. Checks if the Destination Port is in `blocked_ports_`.
  3. Checks if the classified AppType is in `blocked_apps_`.
  4. Checks if the domain string matches any exact domain or wildcard pattern.
* **Enforcement:** Blocking is simulated by dropping packets during processing. Allowed packets are written to the output file; blocked packets are not written.
* **Limitations:** Blocking is stateful only for future packets in the flow. The system cannot inject TCP reset (RST) packets or ICMP unreachable messages back to the network hosts. Additionally, because domain classification occurs on application-layer payloads, connection handshake packets (TCP SYN, SYN-ACK, ACK) are forwarded *before* the application type or domain name is discovered and blocked.

---

## 8. SINGLE-THREADED IMPLEMENTATION

The single-threaded runner (`src/main_working.cpp`) executes sequentially on one thread:

* **Entry Point:** `main` in `src/main_working.cpp`.
* **Processing Loop:** A `while (reader.readNextPacket(raw))` loop drives execution.
* **Data Flow:**
  1. Read packet `raw`.
  2. Parse packet to structure `ParsedPacket`.
  3. Skip packet if not IP and TCP/UDP.
  4. Form `FiveTuple` and check `flows` map.
  5. If flow is unclassified, calculate offsets to extract SNI (port 443) or HTTP Host (port 80).
  6. Map domain string to `AppType` using `sniToAppType`.
  7. Check rules using `rules.isBlocked()`. If blocked, mark flow as blocked.
  8. If flow is blocked, increment `dropped` counter.
  9. If allowed, write packet to output file stream and increment `forwarded` counter.
* **Outputs:** Generates an output PCAP, prints live block messages, and displays a formatting report to stdout.

---

## 9. MULTI-THREADED / PIPELINE IMPLEMENTATION

* **Thread Roles:**
  * **Reader Thread:** Driven by `readerThreadFunc`. Reads raw packets, parses basic headers, assigns them to an LB thread.
  * **Load Balancer (LB) Threads:** Driven by `LoadBalancer::run`. Routinely pop jobs, compute hashes, and forward to a Fast Path thread.
  * **Fast Path (FP) Threads:** Driven by `FastPathProcessor::run` (modular) or `FastPath::run` (self-contained). Perform DPI, maintain state, check rules.
  * **Output Writer Thread:** Driven by `outputThreadFunc` (modular) or custom thread lambda (self-contained). Writes allowed packets to disk.
* **Queues:** Thread-safe template queues (`ThreadSafeQueue` / `TSQueue`) parameterized with `PacketJob` / `Packet`. Queues block on `push` when full (default capacity 10000) and block on `pop` when empty (wakes up via condition variables).
* **Synchronization & Lock Primitives:**
  * Mutexes and condition variables (`std::mutex`, `std::condition_variable`) synchronize the queues.
  * Shared mutexes (`std::shared_mutex`, `std::shared_lock`, `std::unique_lock`) permit concurrent reads of the rule database while blocking reads during rule updates.
  * Atomics (`std::atomic<uint64_t>`, `std::atomic<bool>`) track system statistics.
* **Work Distribution:** Consistently routes packets by hashing the five-tuple. This maps a specific network conversation to the same worker thread, keeping connection maps thread-local and lock-free.
* **Shutdown Behavior:** `stop()` or `stopAll()` sets the `running_` flag to `false` and calls `queue.shutdown()`. This wakes up all blocked threads, letting them exit their run loops and join.

---

## 10. IMPORTANT CLASSES, STRUCTS AND FUNCTIONS

| Symbol Name | File | Type | Responsibility |
| :--- | :--- | :--- | :--- |
| `FiveTuple` | [types.h](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/types.h) | `struct` | Represents unique connection key; implements `reverse()` for bidirectional lookups. |
| `Connection` | [types.h](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/types.h) | `struct` | Stores state, app type, extracted SNI, packet/byte counters, and TCP flags for a flow. |
| `PcapReader` | [pcap_reader.h](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/pcap_reader.h) | `class` | Handles binary file streams, magic number checking, and byte order swapping for PCAPs. |
| `PacketParser` | [packet_parser.h](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/packet_parser.h) | `class` | Parses raw buffers and populates `ParsedPacket` structures. |
| `SNIExtractor` | [sni_extractor.h](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/sni_extractor.h) | `class` | Navigates TLS Client Hello handshake packets and extracts the SNI hostname string. |
| `HTTPHostExtractor` | [sni_extractor.h](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/sni_extractor.h) | `class` | Identifies HTTP methods and extracts the case-insensitive `Host` header. |
| `DNSExtractor` | [sni_extractor.h](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/sni_extractor.h) | `class` | Decodes domain queries from DNS port 53 packets. |
| `RuleManager` | [rule_manager.h](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/rule_manager.h) | `class` | Stores IP, application, port, and domain blocking rules; thread-safe via `std::shared_mutex`. |
| `ConnectionTracker` | [connection_tracker.h](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/connection_tracker.h) | `class` | Thread-local storage for connections; triggers LRU evictions and stale-connection timeouts. |
| `FastPathProcessor` | [fast_path.h](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/fast_path.h) | `class` | Coordinates thread execution, payload extraction, TCP state tracking, and rule evaluations. |
| `LoadBalancer` | [load_balancer.h](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/load_balancer.h) | `class` | Distributes packets to target FastPath queues based on five-tuple hash. |
| `ThreadSafeQueue` | [thread_safe_queue.h](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/thread_safe_queue.h) | `template class` | Producer-consumer queue. |
| `DPIEngine` | [dpi_engine.h](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/dpi_engine.h) | `class` | Orchestrates the modular pipeline threads. |

---

## 11. DATA FLOW

A packet flows through these key data structures during execution:

```text
[PCAP File] 
    │ (Read bytes)
    ▼
[RawPacket] ──> data (std::vector<uint8_t>), header (PcapPacketHeader)
    │
    ▼ (Passed to PacketParser::parse)
[ParsedPacket] ──> MACs, IPs, ports, offsets, payload pointer, tcp_flags
    │
    ▼ (Mapped to PacketJob / Packet)
[PacketJob] ──> packet_id, tuple (FiveTuple), data (copy), offsets, payload_length
    │
    ▼ (Pushed into LB Queue, then forwarded to FP Queue)
[FastPathProcessor] 
    │ (Looks up tuple in connection tracker)
    ├─> [ConnectionTracker] ──> std::unordered_map<FiveTuple, Connection>
    │                                 │
    │                                 ▼ (Updates state, extracts SNI/Host)
    │                           [Connection] ──> AppType, SNI, Action, State
    │
    ▼ (If Action is FORWARD, pushed to output queue)
[Output Queue] ──> [Output Writer Thread] ──> [Output File Stream] ──> [Output PCAP]
```

---

## 12. BUILD AND EXECUTION

### Required Dependencies
* **Compiler:** C++17 compatible compiler (GCC 7+, Clang 5+, or MSVC 2017+).
* **Python 3:** Needed to run the test-generation script.
* **CMake:** Version 3.16 or higher.

### Compile Commands

#### Building with CMake:
```bash
mkdir build
cd build
cmake ..
cmake --build .
```
*(Note: The default `CMakeLists.txt` builds the base `packet_analyzer` binary which uses `src/main.cpp`. Refer to the manual compile commands below to build the DPI engine and simple DPI runner).*

#### Building the Single-Threaded Version (`dpi_simple`):
* **GCC/Clang:**
  ```bash
  g++ -std=c++17 -O2 -I include -o dpi_simple src/main_working.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
  ```
* **MSVC (Developer Command Prompt):**
  ```cmd
  cl /EHsc /std:c++17 /O2 /I include /Fe:dpi_simple.exe src\main_working.cpp src\pcap_reader.cpp src\packet_parser.cpp src\sni_extractor.cpp src\types.cpp
  ```

#### Building the Multi-Threaded Version (`dpi_engine`):
* **GCC/Clang:**
  ```bash
  g++ -std=c++17 -pthread -O2 -I include -o dpi_engine src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
  ```
* **MSVC (Developer Command Prompt):**
  ```cmd
  cl /EHsc /std:c++17 /O2 /I include /Fe:dpi_engine.exe src\dpi_mt.cpp src\pcap_reader.cpp src\packet_parser.cpp src\sni_extractor.cpp src\types.cpp
  ```

### Run Commands

#### Single-Threaded Version:
```bash
./dpi_simple test_dpi.pcap output_simple.pcap --block-app YouTube --block-ip 192.168.1.50 --block-domain facebook.com
```

#### Multi-Threaded Version:
```bash
./dpi_engine test_dpi.pcap output_mt.pcap --block-app YouTube --block-ip 192.168.1.50 --block-domain facebook --lbs 2 --fps 2
```

---

## 13. TESTING

The test suite is manual. It relies on a Python script and mock packet comparison:

* **What is Tested:** Protocol parser extraction accuracy, stateful connection mapping, domain parsing (TLS SNI, HTTP Host, DNS queries), and IP/application blocking rules.
* **Test Structure:**
  1. Run `python generate_test_pcap.py` to create a simulated `test_dpi.pcap`.
  2. Execute the compiled DPI binaries using different blocking rules.
  3. Validate the printed analytics report and inspect the filtered output file using Wireshark or the base packet analyzer binary (`./packet_analyzer`).
* **Test Coverage:** Excellent coverage for protocol parsers and connection tracking logic.
* **Testing Gaps:** Lacks automated unit tests (like GTest or Catch2) and integration validation. It also lacks tests for edge cases like out-of-order TCP segments or packet fragmentation.

---

## 14. SAMPLE DATA / PCAP FILES

The repository includes a Python utility to generate sample captures:

* **`generate_test_pcap.py`:** A binary packet builder that outputs `test_dpi.pcap`.
* **Generated Contents:**
  * *16 TLS Connections:* Synthesizes TCP handshakes (SYN, SYN-ACK, ACK) and TLS Client Hellos containing realistic SNI extensions (e.g., `www.google.com`, `www.youtube.com`, `www.tiktok.com`, `github.com`).
  * *2 HTTP Connections:* Synthesizes TCP handshakes and GET requests containing Host headers (e.g., `example.com`, `httpbin.org`).
  * *4 DNS Queries:* Generates UDP port 53 packets querying domains.
  * *Blocked Source IP Traffic:* Inserts TCP SYN packets originating from the simulated blocked IP `192.168.1.50`.

---

## 15. PERFORMANCE / CONCURRENCY

* **Threading Model:** Multi-threaded pipeline consisting of 1 Reader, $N$ Load Balancer threads, and $M$ Fast Path worker threads, alongside 1 Output Writer thread.
* **Lock-Free Fast Paths:** Work distribution utilizes consistent hashing. By hashing the 5-tuple, packets from a given flow are always processed by the same Fast Path worker thread. This keeps connection trackers thread-local, eliminating lock contention.
* **Lock Contention Points:**
  * *Rules Modification:* Shared mutexes (`std::shared_mutex`) protect the rule databases. Fast Path threads require a shared read lock (`std::shared_lock`) to verify rules, which blocks if rules are written.
  * *Writer Serialization:* Fast Path threads contend for the shared output queue when pushing allowed packets, and the writer thread sequentially writes these packets to disk.
* **Data Structures Complexity:**
  * *Flow Lookups:* $O(1)$ average complexity via hash maps (`std::unordered_map` with `FiveTupleHash`).
  * *Domain Wildcards:* $O(K \cdot L)$ where $K$ is the number of wildcard rules and $L$ is the domain length. Matches suffix substrings sequentially.
  * *LRU Eviction:* $O(N)$ lookup to find the oldest entry. This could be optimized to $O(1)$ with a linked list.

---

## 16. ERROR HANDLING AND EDGE CASES

* **Truncated & Malformed Packets:** Every parsing step validates byte offsets. If a header boundary exceeds `incl_len`, the parser aborts and returns `false`, preventing buffer overflows.
* **Unsupported Protocols:** Non-IP and non-TCP/UDP packets are filtered out at the Reader stage.
* **Byte Order Issues:** Automatically checks endianness. The system reads the global PCAP magic number to determine if the bytes need to be swapped, using its own portable `swapBytes` operations.
* **Empty/Missing Fields:** If a TLS Client Hello has no extensions or lacks an SNI host, classification falls back to generic TLS or port-based defaults (e.g., HTTPS).
* **Missing Command-line Files:** If an input PCAP does not exist or the output path is write-protected, the program logs an error and exits cleanly with return code 1.

---

## 17. CONFIGURATION

The system configuration is handled through command-line arguments and rule files:

### CLI Arguments
* `input.pcap`: Input capture path (positional argument 1).
* `output.pcap`: Filtered capture destination (positional argument 2).
* `--block-ip <ip>`: Registers a blocked source IP.
* `--block-app <app>`: Registers a blocked application (e.g. `YouTube`, `Facebook`).
* `--block-domain <domain>`: Registers a blocked domain (e.g. `twitter.com`, `*.tiktok.com`).
* `--lbs <count>`: Number of Load Balancer threads (default: 2).
* `--fps <count>`: Fast Path threads per Load Balancer (default: 2).
* `--rules <file>`: Load blocking rules from a text file.
* `--verbose`: Enables verbose engine printouts.

### Rule File Format
Plaintext file with section blocks:
```ini
[BLOCKED_IPS]
192.168.1.50

[BLOCKED_APPS]
YouTube
TikTok

[BLOCKED_DOMAINS]
facebook.com
*.instagram.com

[BLOCKED_PORTS]
8080
```

---

## 18. CURRENT IMPLEMENTATION VS README

* **IPv6 Parsing:** The README claims Ethernet, IPv4, and IPv6 packet parsing are supported. However, inspecting `packet_parser.cpp` reveals that when `parsed.ether_type == EtherType::IPv6`, the parser does not descend into any parsing branch. IPv6 is currently *unimplemented* in the parsing logic.
* **Bidirectional Flow Hashing Bug:** The README states that hashing the 5-tuple keeps packets of the same flow associated with the same Fast Path worker thread. However, inspecting the hash function in `include/types.h` shows:
  ```cpp
  size_t h = 0;
  h ^= std::hash<uint32_t>{}(tuple.src_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
  h ^= std::hash<uint32_t>{}(tuple.dst_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
  ```
  Because the hash state is accumulated sequentially, this function is asymmetric: `hash(src_ip, dst_ip) != hash(dst_ip, src_ip)`. This means that outbound packets hash to one worker, while inbound packets hash to another worker. The connection tracker's bidirectional lookup (`getConnection(tuple.reverse())`) will never match because each thread only sees one direction of the traffic.

---

## 19. KNOWN ISSUES / WEAKNESSES

### Confirmed Issues:
1. **Asymmetric 5-Tuple Hash (Bug):** Outbound and inbound packets for a flow hash to different worker threads. This prevents proper bidirectional flow tracking in the multi-threaded pipeline.
2. **Hardcoded outbound flag (Discrepancy):** In `FastPathProcessor::processPacket` in `src/fast_path.cpp`, the `is_outbound` flag is hardcoded to `true`. This causes connection stats to only update the outbound counters, leaving the inbound packet and byte counts at 0.
3. **Big-endian IP string bug (Portability Issue):** `PacketParser::ipToString` extracts octets using shifts (`ip >> 0`, `ip >> 8`). This assumes the target system is little-endian and will output incorrect IP strings on big-endian hosts.
4. **Lack of IPv6 implementation:** The parser lacks code to decode IPv6 headers, despite the type being defined.
5. **Inefficient LRU Eviction:** Triggers an $O(N)$ linear search of the connection map when the table is full.

---

## 20. PROJECT MATURITY

* **Assessment:** Intermediate prototype.
* **What works well:** Reading and writing binary PCAP files without external dependencies, extracting SNI/HTTP headers, and the pipeline architecture.
* **What is incomplete:** Automated tests, live interface capture, IPv6 parsing, and proper TCP state management (out-of-order packets and fragmentation are ignored).
* **Production-Ready Requirements:**
  1. Fix the asymmetric flow hashing bug to ensure bidirectional flow tracking.
  2. Implement an $O(1)$ linked-list for connection table LRU evictions.
  3. Integrate GTest unit tests and CTest validation.
  4. Implement live capture support using `libpcap` / `Npcap`.
  5. Add IPv6 parsing support.

---

## 21. IMPORTANT DESIGN DECISIONS

* **No External Dependencies (Self-contained PCAP Parser):** The project parses PCAP files directly via binary streams. This design choice eliminates external library dependencies, making compilation straightforward across Windows, Linux, and macOS.
* **Pipeline-based Concurrency:** The pipeline separates packet reading, load balancing, fast path inspection, and packet writing. This structure keeps execution stages decoupled and maximizes CPU core utilization.
* **Consistent Hashing for Flow Pinning:** Hashing the five-tuple binds connections to specific worker threads. This keeps connection tables thread-local, avoiding the need for synchronization locks on the flow maps.

---

## 22. DEPENDENCY MAP

```text
               [main_dpi.cpp] / [main_working.cpp]
                      │
                      ▼
               [dpi_engine.h] ──> [platform.h]
                /     │     \
               /      │      \
              ▼       ▼       ▼
   [load_balancer.h]  │   [fast_path.h]
          │           │     /       \
          │           ▼    ▼         ▼
          │   [connection_tracker.h] [rule_manager.h]
          │           │       │       │
          ▼           ▼       ▼       ▼
    [thread_safe_queue.h] ──> [types.h]
                                  ▲
                                  │
    [pcap_reader.h] ◄────────[packet_parser.h]
          ▲                       │
          │                       ▼
    [sni_extractor.h] <───────────┘
```

---

## 23. END-TO-END EXAMPLE

We process `test_dpi.pcap` to block application `YouTube`:

1. **Invocation:** `./dpi_engine test_dpi.pcap output.pcap --block-app YouTube` starts the pipeline.
2. **Initialization:** The rules engine registers `AppType::YOUTUBE` in `blocked_apps_`. 1 Reader, 2 Load Balancer, 4 Fast Path, and 1 Output Writer threads start.
3. **Processing Packets:**
   * Packets 1–3 (TCP handshake for `www.youtube.com` connection) are read and parsed. Since they have no payload, they are classified as `AppType::UNKNOWN` and forwarded.
   * Packet 4 (TLS Client Hello) contains the payload. The Fast Path worker parses the payload, identifies the SNI hostname as `www.youtube.com`, maps it to `AppType::YOUTUBE`, and classifies the flow.
   * The rule checker evaluates the flow. Since `AppType::YOUTUBE` is blocked, the flow is marked as `BLOCKED` and the packet is dropped.
   * Packets 5+ matching this connection's 5-tuple are dropped immediately.
4. **Shutdown:** The reader thread finishes reading the file, the queue drains, and the statistics report is printed to stdout. `output.pcap` contains all packets except the dropped YouTube traffic.

---

## 24. CONCEPTUAL ONBOARDING

For developers onboarding to this project, keep these 6 concepts in mind:

1. **PCAP Format Layout:** Understand the binary structure of a PCAP file, including the 24-byte global header and the 16-byte packet headers.
2. **Layered Protocol Offsets:** Packet parsing is offset-driven: Ethernet starts at 0, IPv4 at 14, and TCP/UDP at $14 + (\text{IHL} \times 4)$.
3. **Five-Tuple Identity:** Flows are tracked using five values: Source IP, Destination IP, Source Port, Destination Port, and Protocol.
4. **Flow Pinning:** Packets are consistently routed to the same worker thread by hashing the 5-tuple, keeping worker connection tables thread-local.
5. **DPI Extraction:** Application identification occurs by parsing the TLS Client Hello handshake (for SNI), checking the HTTP Host header, or decoding DNS labels.
6. **Stateful Drops:** Once a flow matches a blocking rule, the entire flow is marked as blocked, and subsequent packets are dropped immediately.

---

## 25. FUTURE WORK / NEXT STEPS

### Bug Fixes:
* Make the 5-tuple hash function symmetric (e.g. sort IPs and ports before hashing) so bidirectional flows map to the same worker thread.
* Stop hardcoding `is_outbound = true` to enable tracking of inbound packet statistics.
* Update `PacketParser::ipToString` to work correctly on big-endian architectures.

### Missing Features:
* Add IPv6 header decoding.
* Support live interface capture.
* Implement dynamic rule modifications at runtime.

---

## 26. QUICK REFERENCE

* **Main Goal:** Stateful deep packet inspection, application classification, and rule-based PCAP filtering.
* **Stack:** C++17, Python 3, CMake. No external libraries required.
* **Entry Points:**
  * Modular multi-threaded: `src/main_dpi.cpp`
  * Single-threaded: `src/main_working.cpp`
  * Self-contained multi-threaded: `src/dpi_mt.cpp`
* **Compiling (Multi-threaded):**
  `g++ -std=c++17 -pthread -O2 -I include -o dpi_engine src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp`
* **Running:**
  `./dpi_engine input.pcap output.pcap --block-app YouTube`

---

# CONTEXT FOR ANOTHER AI

This section provides a dense summary of the project state, architectures, and known issues for subsequent AI assistants.

### Project & Goal
C++17 Deep Packet Inspection (DPI) and traffic filtering system. It reads PCAP files, parses protocol headers (Ethernet, IPv4, TCP, UDP), tracks flows, classifies application-layer protocols (HTTPS via TLS SNI, HTTP Host header, DNS domain query), and drops blocked packets to write allowed traffic to an output PCAP file.

### Codebase Organization
* `include/` & `src/`: Core implementation files.
* `src/main_working.cpp`: Self-contained single-threaded runner (`dpi_simple`).
* `src/dpi_mt.cpp`: Self-contained multi-threaded runner (`dpi_engine`).
* `src/main_dpi.cpp`: Orchestrated modular multi-threaded runner (`dpi_modular`).
* `generate_test_pcap.py`: Generates mock TLS/HTTP/DNS packet captures.

### Execution Pipelines
* **Single-threaded:** Sequential read, parse, track, block, and write on a single thread.
* **Multi-threaded (Pipeline):**
  1. *Reader Thread:* Reads PCAP, parses basic headers, selects LB thread using a 5-tuple hash.
  2. *Load Balancer Threads:* Distribute packets to FP threads by hashing the 5-tuple.
  3. *Fast Path (FP) Worker Threads:* Run stateful connection maps, inspect payloads, evaluate rules, and drop blocked packets. Allowed packets are forwarded to the output queue.
  4. *Output Writer Thread:* Writes allowed packets from the queue to the destination PCAP file.

### Critical System Constraints & Rules
* **No external packet libraries:** Implementing new protocols requires manual header parsing at correct byte offsets.
* **Consistent Hashing Design:** Intended to route both directions of a flow to the same FP thread, keeping connection tracking lock-free.
* **Rule Match Lifecycle:** handshakes (TCP SYN/ACK) are allowed through first. Once application-layer metadata is extracted, matching rules trigger a state transition to `BLOCKED` on the flow, dropping all subsequent packets in the connection.

### Critical Issues & Architecture Bugs (For Modifying/Debugging)
1. **Asymmetric 5-Tuple Hash (Critical Bug):** The hash function in `FiveTupleHash::operator()` in `include/types.h` is asymmetric. `hash(A, B) != hash(B, A)`. Consequently, inbound and outbound traffic map to different worker threads, rendering bidirectional flow matching non-functional.
2. **Hardcoded Outbound Statistics (Bug):** `FastPathProcessor::processPacket` sets `is_outbound = true`, meaning only outbound counters are updated.
3. **Big-endian IP parsing bug:** `PacketParser::ipToString` shifts network byte order variables directly, which will fail on big-endian architectures.
4. **Unimplemented IPv6 support:** Defined in headers but ignored by the packet parser.
5. **LRU Connection Eviction:** Runs an $O(N)$ lookup on connection tables instead of using an $O(1)$ linked list.
