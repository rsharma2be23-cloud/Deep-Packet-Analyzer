#include <iostream>
#include <cstdlib>
#include "types.h"

using namespace DPI;

#define TEST_ASSERT(cond) \
    do { \
        if (!(cond)) { \
            std::cerr << "Assertion failed: " << #cond \
                      << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            std::exit(1); \
        } \
    } while (0)

void testFiveTupleEquality() {
    FiveTuple t1{0x0100007F, 0x0200007F, 80, 50000, 6}; // 127.0.0.1 -> 127.0.0.2 TCP
    FiveTuple t2{0x0100007F, 0x0200007F, 80, 50000, 6}; // Same
    FiveTuple t3{0x0200007F, 0x0100007F, 50000, 80, 6}; // Reverse direction
    FiveTuple t4{0x0100007F, 0x0200007F, 80, 50000, 17}; // Different protocol (UDP)

    TEST_ASSERT(t1 == t2);
    TEST_ASSERT(!(t1 == t3)); // should be unequal (directional)
    TEST_ASSERT(!(t1 == t4)); // should be unequal (different protocol)
}

void testFiveTupleHash() {
    FiveTuple t1{0x0100007F, 0x0200007F, 80, 50000, 6};
    FiveTuple t2{0x0200007F, 0x0100007F, 50000, 80, 6}; // Reverse

    FiveTupleHash hasher;
    size_t h1 = hasher(t1);
    size_t h2 = hasher(t2);

    TEST_ASSERT(h1 == h2); // Symmetric hashing
}

int main() {
    testFiveTupleEquality();
    testFiveTupleHash();
    std::cout << "test_types passed successfully!\n";
    return 0;
}
