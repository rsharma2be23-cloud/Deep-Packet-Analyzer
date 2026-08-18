# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# test_types
add_executable(test_types test_types.cpp ../src/types.cpp)
add_test(NAME TestTypes COMMAND test_types)

# test_extractors
add_executable(test_extractors test_extractors.cpp ../src/sni_extractor.cpp ../src/types.cpp)
add_test(NAME TestExtractors COMMAND test_extractors)

# test_rules
add_executable(test_rules test_rules.cpp ../src/rule_manager.cpp ../src/types.cpp)
add_test(NAME TestRules COMMAND test_rules)

# test_connection_tracker
add_executable(test_connection_tracker test_connection_tracker.cpp ../src/connection_tracker.cpp ../src/types.cpp)
add_test(NAME TestConnectionTracker COMMAND test_connection_tracker)
