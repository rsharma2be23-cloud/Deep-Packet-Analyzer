cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
if(ENABLE_SANITIZERS)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
        message(STATUS "Sanitizers enabled: AddressSanitizer, UndefinedBehaviorSanitizer")
    elseif(MSVC)
        add_compile_options(/fsanitize=address)
        message(STATUS "AddressSanitizer enabled for MSVC")
    else()
        message(WARNING "Sanitizers not supported on this compiler")
    endif()
endif()

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# Original target
add_executable(packet_analyzer
    src/main.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
)

# Single-threaded DPI engine target
add_executable(dpi_simple
    src/main_working.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

# Self-contained multi-threaded DPI engine target
add_executable(dpi_engine
    src/dpi_mt.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)
# Enable threading for multi-threaded targets
find_package(Threads REQUIRED)
target_link_libraries(dpi_engine PRIVATE Threads::Threads)

# Modular multi-threaded DPI engine target
add_executable(dpi_modular
    src/main_dpi.cpp
    src/dpi_engine.cpp
    src/fast_path.cpp
    src/load_balancer.cpp
    src/connection_tracker.cpp
    src/rule_manager.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)
target_link_libraries(dpi_modular PRIVATE Threads::Threads)

# Enable CTest testing
enable_testing()
add_subdirectory(tests)
