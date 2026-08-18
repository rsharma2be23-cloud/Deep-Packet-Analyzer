#include <iostream>
#include <cstdlib>
#include "connection_tracker.h"

using namespace DPI;

#define TEST_ASSERT(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "Assertion failed: " << #cond \
                      << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

void testConnectionTracking() {
    ConnectionTracker tracker(0); // FP ID = 0

    // Setup endpoints
    FiveTuple forward{0x0100007F, 0x0200007F, 50000, 443, 6}; // 127.0.0.1:50000 -> 127.0.0.2:443 TCP
    FiveTuple reverse{0x0200007F, 0x0100007F, 443, 50000, 6}; // 127.0.0.2:443 -> 127.0.0.1:50000 TCP

    // 1. Create a new flow/connection
    Connection* conn = tracker.getOrCreateConnection(forward);
    TEST_ASSERT(conn != nullptr);
    TEST_ASSERT(conn->state == ConnectionState::NEW);
    TEST_ASSERT(conn->packets_in == 0);
    TEST_ASSERT(conn->packets_out == 0);
    TEST_ASSERT(conn->bytes_in == 0);
    TEST_ASSERT(conn->bytes_out == 0);

    // 2. Lookup existing connection (forward and reverse)
    Connection* lookup_fwd = tracker.getConnection(forward);
    Connection* lookup_rev = tracker.getConnection(reverse);
    TEST_ASSERT(lookup_fwd == conn);
    TEST_ASSERT(lookup_rev == conn); // Bidirectional mapping to same Connection record

    // 3. Update connection statistics
    // Outbound packet
    tracker.updateConnection(conn, 150, true);
    TEST_ASSERT(conn->packets_out == 1);
    TEST_ASSERT(conn->bytes_out == 150);
    TEST_ASSERT(conn->packets_in == 0);
    TEST_ASSERT(conn->bytes_in == 0);

    // Inbound packet
    tracker.updateConnection(conn, 300, false);
    TEST_ASSERT(conn->packets_out == 1);
    TEST_ASSERT(conn->bytes_out == 150);
    TEST_ASSERT(conn->packets_in == 1);
    TEST_ASSERT(conn->bytes_in == 300);

    // 4. Classify connection
    tracker.classifyConnection(conn, AppType::YOUTUBE, "www.youtube.com");
    TEST_ASSERT(conn->state == ConnectionState::CLASSIFIED);
    TEST_ASSERT(conn->app_type == AppType::YOUTUBE);
    TEST_ASSERT(conn->sni == "www.youtube.com");

    // 5. Block connection
    tracker.blockConnection(conn);
    TEST_ASSERT(conn->state == ConnectionState::BLOCKED);
    TEST_ASSERT(conn->action == PacketAction::DROP);

    // Verify stats
    auto stats = tracker.getStats();
    TEST_ASSERT(stats.active_connections == 1);
    TEST_ASSERT(stats.blocked_connections == 1);
}

int main() {
    testConnectionTracking();
    std::cout << "test_connection_tracker passed successfully!\n";
    return 0;
}
