#include <iostream>
#include <cstdlib>
#include "rule_manager.h"

using namespace DPI;

#define TEST_ASSERT(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "Assertion failed: " << #cond \
                      << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

void testRulesMatching() {
    RuleManager rules;

    // 1. Test IP Blocking
    rules.blockIP("192.168.1.50");
    uint32_t ip1 = 0x3201A8C0; // 192.168.1.50 in host-shift order (bits 0-7 = 192)
    uint32_t ip2 = 0x0100007F; // 127.0.0.1
    TEST_ASSERT(rules.isIPBlocked(ip1) == true);
    TEST_ASSERT(rules.isIPBlocked(ip2) == false);

    // 2. Test Port Blocking
    rules.blockPort(8080);
    TEST_ASSERT(rules.isPortBlocked(8080) == true);
    TEST_ASSERT(rules.isPortBlocked(443) == false);

    // 3. Test App Blocking
    rules.blockApp(AppType::YOUTUBE);
    TEST_ASSERT(rules.isAppBlocked(AppType::YOUTUBE) == true);
    TEST_ASSERT(rules.isAppBlocked(AppType::GOOGLE) == false);

    // 4. Test Domain Blocking (exact and wildcard)
    rules.blockDomain("blocked.com");
    rules.blockDomain("*.facebook.com");

    TEST_ASSERT(rules.isDomainBlocked("blocked.com") == true);
    TEST_ASSERT(rules.isDomainBlocked("unblocked.com") == false);
    TEST_ASSERT(rules.isDomainBlocked("facebook.com") == true); // matches wildcard/suffix check or standard
    TEST_ASSERT(rules.isDomainBlocked("www.facebook.com") == true);
    TEST_ASSERT(rules.isDomainBlocked("facebook.com.attacker.com") == false);
}

int main() {
    testRulesMatching();
    std::cout << "test_rules passed successfully!\n";
    return 0;
}
