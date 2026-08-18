# DPI Engine — Deep Packet Inspection System

A C++17-based Deep Packet Inspection (DPI) engine for analyzing network traffic stored in PCAP files. The system parses Ethernet, IPv4, TCP, and UDP packets, tracks network flows using five-tuples, identifies applications through TLS SNI and HTTP Host information, and applies configurable traffic-blocking rules.

The project includes both a **single-threaded implementation** for straightforward packet processing and a **multi-threaded processing pipeline** designed to distribute packet analysis across multiple worker threads.

---

## Overview

Deep Packet Inspection goes beyond inspecting basic packet headers by analyzing packet payloads to identify higher-level protocols, domains, and applications.

This project processes captured network traffic through the following pipeline:

```text
                 PCAP Input
                     │
                     ▼
              ┌─────────────┐
              │ PCAP Reader │
              └──────┬──────┘
                     │
                     ▼
              ┌─────────────┐
              │Packet Parser│
              └──────┬──────┘
                     │
                     ▼
              ┌─────────────┐
              │Flow Tracking│
              └──────┬──────┘
                     │
                     ▼
              ┌─────────────┐
              │ DPI / SNI   │
              │ Classification│
              └──────┬──────┘
                     │
                     ▼
              ┌─────────────┐
              │Rule Manager │
              └──────┬──────┘
                     │
              ┌──────┴──────┐
              ▼             ▼
           Forward         Drop
              │
              ▼
         Output PCAP
```

The engine can identify traffic such as **HTTP, HTTPS, DNS, Google, YouTube, Facebook**, and other applications represented by the configured application signatures.

---

## Key Features

* **PCAP file parsing**
* Ethernet, IPv4, TCP, and UDP packet parsing
* Five-tuple based flow tracking
* TLS Client Hello inspection
* TLS **Server Name Indication (SNI)** extraction
* HTTP `Host` header extraction
* Application/domain classification
* Source-IP based blocking
* Application based blocking
* Domain based blocking
* Flow-level traffic blocking
* Single-threaded processing mode
* Multi-threaded processing pipeline
* Load Balancer and Fast Path architecture
* Thread-safe producer-consumer queues
* Traffic statistics and processing reports
* Application-level traffic breakdown
* Configurable number of Load Balancer and Fast Path threads
* Test PCAP generation

---

## Architecture

### Single-Threaded Pipeline

The simple implementation processes packets sequentially:

```text
PCAP
 │
 ▼
PCAP Reader
 │
 ▼
Packet Parser
 │
 ▼
Five-Tuple / Flow Tracking
 │
 ▼
SNI / HTTP Inspection
 │
 ▼
Application Classification
 │
 ▼
Blocking Rules
 │
 ├── Block ──► Drop
 │
 └── Allow ──► Output PCAP
```

This implementation is useful for understanding the complete packet-processing flow and for analyzing smaller captures.

### Multi-Threaded Pipeline

The multi-threaded implementation distributes packet processing across multiple workers:

```text
                    ┌───────────────┐
                    │ Reader Thread │
                    └───────┬───────┘
                            │
                            ▼
                    ┌───────────────┐
                    │ Load Balancers│
                    └───────┬───────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
          ┌────────┐    ┌────────┐    ┌────────┐
          │FastPath│    │FastPath│    │FastPath│
          │   FP   │    │   FP   │    │   FP   │
          └────┬───┘    └────┬───┘    └────┬───┘
               │             │             │
               └─────────────┼─────────────┘
                             ▼
                    ┌────────────────┐
                    │ Output Queue   │
                    └───────┬────────┘
                            ▼
                    ┌────────────────┐
                    │ Output Writer  │
                    └────────────────┘
```

Packets are distributed using a hash of their five-tuple:

```text
hash(5-tuple) % number_of_workers
```

This keeps packets belonging to the same flow associated with the same Fast Path worker, allowing flow state to be maintained locally.

---

## Packet Processing Flow

### 1. Read the PCAP

The `PcapReader` opens the input capture and reads the PCAP global header followed by individual packet records.

```cpp
PcapReader reader;

reader.open("capture.pcap");

while (reader.readNextPacket(raw)) {
    // Process packet
}
```

Each packet contains:

* Timestamp
* Captured length
* Original packet length
* Raw packet bytes

---

### 2. Parse Network Protocols

The packet parser extracts information from the protocol headers.

```text
Ethernet
   │
   ▼
IPv4
   │
   ├── TCP
   │
   └── UDP
```

The parser extracts fields such as:

* Source/destination MAC addresses
* Source/destination IP addresses
* Source/destination ports
* IP protocol
* TCP flags
* TCP sequence information
* Payload location

Network byte order is handled using functions such as `ntohs()` and `ntohl()`.

---

### 3. Track Network Flows

Each flow is represented using a five-tuple:

```text
Source IP
Destination IP
Source Port
Destination Port
Protocol
```

Example:

```text
192.168.1.100:54321
        │
        ▼
172.217.14.206:443
Protocol: TCP
```

The five-tuple is used as the key for the flow table.

```cpp
Flow& flow = flows[tuple];
```

This allows multiple packets belonging to the same connection to share state.

---

## Deep Packet Inspection

### TLS SNI Extraction

For HTTPS traffic, the engine examines the TLS Client Hello and attempts to extract the Server Name Indication (SNI).

For example:

```text
TLS Client Hello
       │
       ▼
SNI Extension
       │
       ▼
www.youtube.com
       │
       ▼
Application Classification
       │
       ▼
YouTube
```

The SNI extractor:

1. Validates the TLS record.
2. Checks for a Client Hello.
3. Navigates through the Client Hello fields.
4. Locates the SNI extension.
5. Extracts the hostname.
6. Maps the hostname to an application type.

Example:

```cpp
if (sni.find("youtube") != std::string::npos) {
    return AppType::YOUTUBE;
}
```

### HTTP Host Extraction

For HTTP traffic, the system can inspect the request payload and extract the `Host` header.

This provides another mechanism for identifying the destination domain.

---

## Application Classification

Applications are represented using the `AppType` enumeration.

Examples include:

```cpp
enum class AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    GOOGLE,
    YOUTUBE,
    FACEBOOK
};
```

Domain/SNI patterns are mapped to application types.

For example:

```text
www.youtube.com
       │
       ▼
    YouTube

www.facebook.com
       │
       ▼
   Facebook
```

The application classification system can be extended by adding additional domain signatures.

---

## Traffic Blocking

The Rule Manager supports three main types of blocking rules.

| Rule        | Example        | Effect                              |
| ----------- | -------------- | ----------------------------------- |
| Source IP   | `192.168.1.50` | Blocks traffic from the source      |
| Application | `YouTube`      | Blocks matching application traffic |
| Domain      | `facebook`     | Blocks matching SNI/domain traffic  |

### Blocking Flow

```text
Packet
  │
  ▼
Source IP blocked?
  │
  ├── Yes ──► DROP
  │
  ▼
Application blocked?
  │
  ├── Yes ──► DROP
  │
  ▼
Domain blocked?
  │
  ├── Yes ──► DROP
  │
  ▼
FORWARD
```

### Flow-Level Blocking

Blocking is maintained at the flow level.

Once a flow is identified as blocked, subsequent packets belonging to that flow are also dropped.

```text
SYN
 │
 ▼
SYN-ACK
 │
 ▼
ACK
 │
 ▼
TLS Client Hello
 │
 ▼
SNI detected
 │
 ▼
Application identified
 │
 ▼
Flow marked BLOCKED
 │
 ├── Future packet ──► DROP
 ├── Future packet ──► DROP
 └── Future packet ──► DROP
```

This allows the system to make a classification decision once sufficient information becomes available and maintain that decision for the rest of the connection.

---

## Multi-Threading

The multi-threaded implementation uses a pipeline consisting of:

* Reader thread
* Load Balancer threads
* Fast Path threads
* Output Writer thread

### Load Balancer

Load Balancers distribute incoming packets to Fast Path workers.

```cpp
size_t fp_idx = hash(pkt.tuple) % num_fps_;
fps_[fp_idx]->queue().push(pkt);
```

### Fast Path

Fast Path workers perform the main DPI processing:

```text
Receive Packet
     │
     ▼
Flow Lookup
     │
     ▼
DPI Classification
     │
     ▼
Apply Rules
     │
 ┌───┴────┐
 ▼        ▼
DROP    FORWARD
           │
           ▼
      Output Queue
```

### Thread-Safe Queues

Producer-consumer communication is implemented using thread-safe queues based on:

* `std::mutex`
* `std::condition_variable`
* `std::queue`

This allows worker threads to safely exchange packets without continuously polling for work.

---

## Project Structure

```text
Packet_analyzer/
│
├── include/
│   ├── pcap_reader.h
│   ├── packet_parser.h
│   ├── sni_extractor.h
│   ├── types.h
│   ├── rule_manager.h
│   ├── connection_tracker.h
│   ├── load_balancer.h
│   ├── fast_path.h
│   ├── thread_safe_queue.h
│   └── dpi_engine.h
│
├── src/
│   ├── pcap_reader.cpp
│   ├── packet_parser.cpp
│   ├── sni_extractor.cpp
│   ├── types.cpp
│   ├── main_working.cpp
│   └── dpi_mt.cpp
│
├── generate_test_pcap.py
├── test_dpi.pcap
├── output.pcap
├── CMakeLists.txt
├── WINDOWS_SETUP.md
└── README.md
```

### Important Components

| Component            | Responsibility                                 |
| -------------------- | ---------------------------------------------- |
| `pcap_reader`        | Reads PCAP files and packet records            |
| `packet_parser`      | Parses Ethernet/IP/TCP/UDP headers             |
| `sni_extractor`      | Extracts TLS SNI and HTTP Host information     |
| `types`              | Core structures and application classification |
| `rule_manager`       | Manages traffic-blocking rules                 |
| `connection_tracker` | Maintains flow state                           |
| `load_balancer`      | Distributes packets to processing workers      |
| `fast_path`          | Performs DPI processing                        |
| `thread_safe_queue`  | Synchronizes packet communication              |
| `dpi_engine`         | Coordinates DPI components                     |

---

## Requirements

* C++17-compatible compiler
* `g++` or `clang++`
* Python 3 for generating test PCAP data

The existing implementation uses standard C++ facilities for packet processing and does not require an external packet-processing library.

---

## Build

### Single-Threaded Version

```bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

### Multi-Threaded Version

```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

---

## Usage

### Basic Analysis

```bash
./dpi_engine test_dpi.pcap output.pcap
```

### Enable Application Blocking

```bash
./dpi_engine test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok
```

### Block a Source IP

```bash
./dpi_engine test_dpi.pcap output.pcap \
    --block-ip 192.168.1.50
```

### Block a Domain

```bash
./dpi_engine test_dpi.pcap output.pcap \
    --block-domain facebook
```

### Configure Processing Threads

```bash
./dpi_engine input.pcap output.pcap --lbs 4 --fps 4
```

This configures four Load Balancer threads and four Fast Path workers per the project's multi-threaded processing model.

---

## Generate Test Traffic

The repository includes a Python utility for generating test PCAP data.

```bash
python3 generate_test_pcap.py
```

This generates:

```text
test_dpi.pcap
```

which can then be processed by the DPI engine.

---

## Output

The engine produces processing statistics including:

* Total packets
* Total bytes
* TCP packets
* UDP packets
* Forwarded packets
* Dropped packets
* Thread processing statistics
* Application breakdown
* Detected domains/SNIs

Example:

```text
PROCESSING REPORT

Total Packets: 77
Total Bytes:   5738

TCP Packets:   73
UDP Packets:    4

Forwarded:     69
Dropped:        8

APPLICATION BREAKDOWN

HTTPS
Unknown
YouTube
DNS
Facebook

Detected SNIs

www.youtube.com
www.facebook.com
www.google.com
github.com
```

---

## Technical Concepts Demonstrated

This project combines several important systems and networking concepts:

### Networking

* Ethernet frames
* IPv4 packet structure
* TCP/UDP
* TCP flags
* Network byte order
* PCAP format
* TLS Client Hello
* SNI

### Systems Programming

* C++17
* Binary file processing
* Raw byte parsing
* Hash-based data structures
* Memory and buffer handling

### Concurrency

* Multi-threaded processing
* Producer-consumer architecture
* Mutexes
* Condition variables
* Thread-safe queues
* Work distribution
* Flow-aware packet routing

### Network Security

* Deep Packet Inspection
* Application classification
* Domain identification
* Rule-based traffic filtering
* Flow-level blocking

---

## Design Highlights

### Five-Tuple Flow Tracking

Using:

```text
Source IP
Destination IP
Source Port
Destination Port
Protocol
```

allows packets belonging to the same network conversation to be grouped into a single flow.

### Flow-Aware Worker Assignment

The multi-threaded architecture hashes the flow's five-tuple to consistently route packets belonging to the same connection to the same Fast Path worker.

This simplifies state management because each worker can maintain its own flow state.

### Producer-Consumer Processing

The multi-threaded architecture separates packet ingestion, processing, and output through queues, allowing different stages of the pipeline to operate concurrently.

---

## Future Improvements

Potential extensions include:

* Additional application signatures
* More protocol support
* QUIC / HTTP3 inspection
* Persistent rule configuration
* Bandwidth throttling
* Live traffic statistics
* Expanded test coverage
* Performance benchmarking
* Additional PCAP formats and capture sources

---

## Learning Outcomes

This project provides hands-on experience with:

1. Network packet structure and protocol parsing
2. PCAP file processing
3. Stateful network flow tracking
4. TLS SNI inspection
5. Rule-based traffic filtering
6. C++ systems programming
7. Multi-threaded pipeline design
8. Producer-consumer synchronization
9. Hash-based work distribution
10. Network security concepts

---

## Disclaimer

This project is intended for **educational, research, and controlled network-analysis purposes**. Only analyze network traffic that you are authorized to inspect.

---

## License

Add the appropriate license for this project here.

---

## Contributors

Developed collaboratively by the project contributors.

If you are using this repository as part of your portfolio, see the project history and individual contributions for implementation details.
