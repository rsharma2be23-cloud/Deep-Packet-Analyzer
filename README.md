# Deep Packet Inspection (DPI) Engine

A high-performance C++17-based Deep Packet Inspection (DPI) engine for stateful network traffic analysis, flow tracking, protocol extraction, and rule-based filtering. The engine parses raw Ethernet, IPv4, TCP, and UDP packets, tracks connection states, extracts application-layer identifiers (TLS SNI, HTTP Host, DNS queries), and applies configurable blocking rules at line rate.

The project features a modular architecture supporting both a simple single-threaded processing loop and a multi-threaded, pipelined design utilizing consistent hashing for lock-free worker thread execution.

---

## Technical Highlights
* **Zero-Copy Parser:** Direct, boundary-validated parsing of Ethernet frames, IPv4 packets, TCP segments (including flags/sequence matching), and UDP datagrams.
* **Stateful Flow Tracking:** Lightweight flow identification via five-tuples, tracking connection states (`NEW`, `ESTABLISHED`, `CLASSIFIED`, `BLOCKED`, `CLOSED`) and inbound/outbound stats.
* **Deep Packet Inspection:** Fully compliant parsers for TLS Client Hello (Server Name Indication - SNI), HTTP requests (`Host` header), and DNS queries (QNAME label decoding).
* **Multi-Threaded Pipeline:** Reader/Writer thread decoupling, symmetric hash-based load balancing, and lock-free Fast Path workers.
* **CTest Regression Suite:** Fully automated unit tests covering packet parsing, rule matching, connection trackers, and extractors.
* **Profiling & Sanitizers:** Standard configuration hooks for GCC compiler sanitizers (ASan/UBSan) and `gprof` performance profiling.

---

## System Architecture

```mermaid
graph TD
    Input[PCAP Input File] --> Reader[PcapReader Thread]
    Reader --> LB[Load Balancers]
    LB -->|hash(5-tuple) % Workers| FP[Fast Path Workers]
    FP --> Tracker[ConnectionTracker]
    FP --> Rules[RuleManager]
    Rules -->|Allow| OutQueue[Output Queue]
    Rules -->|Block| Drop[Drop Packet]
    OutQueue --> Writer[PcapWriter Thread]
    Writer --> Output[Output PCAP File]
```

### Ingestion & Work Distribution (Multi-Threaded Mode)
1. **Reader:** Ingests packets from PCAP and queues them to the Load Balancers.
2. **Load Balancer:** Uses a symmetric 5-tuple hash to route both directions of a flow to the same Fast Path worker thread.
3. **Fast Path Worker:** Performs connection tracking, payload parsing, application classification, and rule application within its thread-local space.
4. **Writer:** Consumes allowed packets from the output queue and writes them to the output PCAP.

---

## Core Design Decisions

### Directional Five-Tuple Equality vs. Symmetric Hashing
* **Directional Equality:** [`FiveTuple::operator==`](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/types.h#L24) remains strictly directional (`A->B != B->A`). This is required to determine the packet flow direction (identifying which side initiated the flow and tracking separate inbound/outbound byte and packet counts).
* **Symmetric Hashing:** The [`FiveTupleHash`](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/types.h#L41) canonicalizes endpoints by sorting the source/destination IP and port pairs before hashing. This guarantees that `A->B` and `B->A` generate the identical hash value, routing both directions to the same Fast Path worker thread.

### Bidirectional Flow Tracking
* In [`ConnectionTracker`](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/connection_tracker.h#L27), connection records are stored using a canonicalized `FiveTuple` key.
* When a packet arrives, its key is canonicalized. This maps both directions of the flow to a single `Connection` record in exactly **one map lookup**.
* Directionality is preserved by storing the initial initiating tuple inside the `Connection` record. If the packet's tuple matches the initiating tuple, it is classified as `outbound` (out); otherwise, it is `inbound` (in).

### Thread-Local & Lock-Free State
Because the Load Balancer pins flows to specific Fast Path threads using the symmetric hash, each thread manages its own [`ConnectionTracker`](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/connection_tracker.h#L27). This eliminates the need for thread synchronization or mutex locks during packet lookup and classification, keeping the Fast Path lock-free.

---

## Performance Benchmark

We evaluated the performance of the modular DPI engine on a deterministic 38,500-packet PCAP dataset (generated with scale `500`). Throughput is reported as the median of 3 consecutive runs.

| Fast Path Workers | Baseline Throughput (pkt/s) | Optimized Throughput (pkt/s) | Throughput Change |
| :---: | ---: | ---: | :---: |
| **1** | 14,212.0 | 41,472.9 | **+191.8%** |
| **2** | *N/A* | 38,378.9 | *baseline unavailable* |
| **4** | 38,021.0 | 48,295.0 | **+27.0%** |
| **8** | 41,330.0 | 47,459.6 | **+14.8%** |

*Note: The major performance gain was achieved by optimizing the redundant connection map lookup path and eliminating duplicate connection record creations for bidirectional flows.*

---

## Development & Build Environment

The project is configured for Windows builds using the MSYS2 UCRT64 toolchain.

### Prerequisites
* **OS:** Windows 10/11
* **Compiler:** GCC/G++ 16.2.0 (MSYS2 UCRT64)
* **Build System:** CMake (>= 3.16) + Ninja
* **Python:** Python 3.x (for generating test data)

### Building the Project
1. Open PowerShell or Command Prompt.
2. Add the UCRT64 bin directory to your path:
   ```powershell
   $env:PATH = "C:\msys64\ucrt64\bin;" + $env:PATH
   ```
3. Generate the build files and compile:
   ```powershell
   cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -B build-ucrt64 -S .
   cmake --build build-ucrt64
   ```

---

## Running and Testing

### 1. Generate Test Traffic
Generate a deterministic PCAP file containing TLS (SNI), HTTP (Host), DNS, and blocked IP traffic:
```powershell
python generate_test_pcap.py
```
This generates `test_dpi.pcap` in the root folder.

### 2. Run Automated Regression Tests (CTest)
```powershell
cd build-ucrt64
ctest -C Release --output-on-failure
```

### 3. Run the DPI Engine (Application Blocking Example)
Run the multi-threaded DPI engine blocking all traffic classified as `YouTube` and outputting the filtered stream:
```powershell
.\build-ucrt64\dpi_modular.exe test_dpi.pcap output.pcap --block-app YouTube
```

### 4. Run Benchmarks
Run the automated benchmark suite:
```powershell
python run_benchmarks.py
```

---

## Sanitizers & Profiling

* **Sanitizers:** Although CMake supports enabling address and undefined behavior sanitizers via `-DENABLE_SANITIZERS=ON`, they are currently disabled due to environment toolchain limitations (missing `libasan` and `libubsan` runtime libraries in the local MSYS2 environment).
* **Profiling:** You can generate profiling binaries using the GCC `-pg` flags in `build-profile` to analyze hotspots via `gprof`. *(Note: Due to lack of native POSIX interval timer support on Windows, gprof may report "no time accumulated" for fast execution runs).*

---

## Project Structure

```text
Packet_analyzer/
├── include/
│   ├── dpi_engine.h          # Orchestrates LB, FPs, and Reader/Writer pipelines
│   ├── fast_path.h           # Fast Path processor thread class
│   ├── load_balancer.h       # Flow-pinning load balancer thread
│   ├── connection_tracker.h  # Stateful flow tracking map
│   ├── rule_manager.h        # Blocking rule management
│   ├── sni_extractor.h       # TLS SNI, HTTP Host, and DNS label extractors
│   ├── thread_safe_queue.h   # Multi-producer multi-consumer queue
│   ├── packet_parser.h       # Zero-copy header parsers
│   ├── pcap_reader.h         # Read/write PCAP records
│   └── types.h               # Core types (FiveTuple, AppType, Connection)
├── src/
│   ├── dpi_engine.cpp
│   ├── fast_path.cpp
│   ├── load_balancer.cpp
│   ├── connection_tracker.cpp
│   ├── rule_manager.cpp
│   ├── sni_extractor.cpp
│   ├── packet_parser.cpp
│   ├── pcap_reader.cpp
│   ├── types.cpp
│   └── main_dpi.cpp          # Entry point for the modular multi-threaded engine
├── tests/
│   ├── test_connection_tracker.cpp
│   ├── test_extractors.cpp
│   ├── test_rules.cpp
│   └── test_types.cpp
├── CMakeLists.txt
├── generate_test_pcap.py
└── README.md
```

---

## Engineering Challenges & Lessons

1. **Bidirectional Pair Mapping:** Solved the directional boundary issue by canonicalizing connection keys while preserving the original flow initiator tuple to accurately measure inbound vs. outbound statistics.
2. **C++ Member Initialization Order:** Fixed a critical multithreaded crash in [`LoadBalancer`](file:///d:/Desktop/DPI%20engine/Packet_analyzer/include/load_balancer.h#L36) by ensuring vector allocations refer to parameters initialized earlier in the constructor's declaration sequence.
3. **Truncated/Malformed Input Resilience:** Enforced strict size verification at each layer of protocol parsing (Record, Handshake, Extension, and String parsing) to guarantee resilience against malformed packets and prevent buffer overflows.

---

## Future Improvements
* Support for IPv6 parsing and flow tracking.
* QUIC / HTTP3 parsing for modern SNI extraction.
* Porting to DPDK for kernel-bypass packet capture.
* Persistent rule file configuration reloading.

---

## License & Disclaimer
This software is intended for educational, research, and authorized network security analysis only. Ensure you have the appropriate permissions before capturing or analyzing network traffic.

