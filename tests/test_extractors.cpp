#include <iostream>
#include <vector>
#include <cstdlib>
#include "sni_extractor.h"

using namespace DPI;

#define TEST_ASSERT(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "Assertion failed: " << #cond \
                      << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

void testTLSSNIExtraction() {
    // Construct a mock TLS Client Hello payload containing SNI "www.youtube.com"
    std::vector<uint8_t> payload = {
        0x16, // Content Type Handshake
        0x03, 0x03, // Version TLS 1.2
        0x00, 0x47, // Record Length (71 bytes)
        0x01, // Handshake Type Client Hello
        0x00, 0x00, 0x43, // Handshake Length (67 bytes)
        0x03, 0x03, // Version TLS 1.2
        // Random (32 bytes)
        0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,
        0x00, // Session ID Length (0)
        0x00, 0x02, // Cipher Suites Length (2)
        0x00, 0x2f, // Cipher suite
        0x01, // Compression Methods Length (1)
        0x00, // Compression method (null)
        0x00, 0x18, // Extensions Length (24 bytes)
        // SNI Extension
        0x00, 0x00, // Extension Type (0x0000 = SNI)
        0x00, 0x14, // Extension Length (20 bytes)
        0x00, 0x12, // SNI List Length (18 bytes)
        0x00, // SNI Type (0x00 = hostname)
        0x00, 0x0F, // SNI Length (15 bytes = "www.youtube.com")
        'w','w','w','.','y','o','u','t','u','b','e','.','c','o','m'
    };

    auto sni = SNIExtractor::extract(payload.data(), payload.size());
    TEST_ASSERT(sni.has_value());
    TEST_ASSERT(sni.value() == "www.youtube.com");
    std::cout << "TLS SNI extraction passed!\n";
}

void testHTTPHostExtraction() {
    std::string http_req = "GET /index.html HTTP/1.1\r\n"
                           "User-Agent: Mozilla/5.0\r\n"
                           "Host: www.google.com\r\n"
                           "Accept: */*\r\n\r\n";
    
    auto host = HTTPHostExtractor::extract(reinterpret_cast<const uint8_t*>(http_req.data()), http_req.size());
    TEST_ASSERT(host.has_value());
    TEST_ASSERT(host.value() == "www.google.com");
    std::cout << "HTTP Host extraction passed!\n";
}

void testDNSExtraction() {
    // Construct mock DNS query for "www.wikipedia.org"
    // Transaction ID (2 bytes), Flags (2 bytes), QDCOUNT (2 bytes) = 1, etc.
    std::vector<uint8_t> payload = {
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags (standard query, recursive)
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0
        // Query Name: www.wikipedia.org
        3, 'w', 'w', 'w',
        9, 'w', 'i', 'k', 'i', 'p', 'e', 'd', 'i', 'a',
        3, 'o', 'r', 'g',
        0, // null terminator
        0x00, 0x01, // QTYPE = A
        0x00, 0x01  // QCLASS = IN
    };

    auto domain = DNSExtractor::extractQuery(payload.data(), payload.size());
    TEST_ASSERT(domain.has_value());
    TEST_ASSERT(domain.value() == "www.wikipedia.org");
    std::cout << "DNS extraction passed!\n";
}

void testMalformedInputSafety() {
    // Truncated TLS Client Hello
    std::vector<uint8_t> trunc_tls = { 0x16, 0x03, 0x03 };
    auto sni = SNIExtractor::extract(trunc_tls.data(), trunc_tls.size());
    TEST_ASSERT(!sni.has_value());

    // Invalid HTTP request (random noise)
    std::vector<uint8_t> junk = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46 };
    auto host = HTTPHostExtractor::extract(junk.data(), junk.size());
    TEST_ASSERT(!host.has_value());

    // Truncated DNS Query
    std::vector<uint8_t> trunc_dns = { 0x12, 0x34, 0x01, 0x00, 0x00, 0x01 };
    auto domain = DNSExtractor::extractQuery(trunc_dns.data(), trunc_dns.size());
    TEST_ASSERT(!domain.has_value());
    
    std::cout << "Malformed safety checks passed!\n";
}

int main() {
    testTLSSNIExtraction();
    testHTTPHostExtraction();
    testDNSExtraction();
    testMalformedInputSafety();
    std::cout << "test_extractors passed successfully!\n";
    return 0;
}
