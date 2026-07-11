add_executable(test_quic test_quic.cpp)
target_link_libraries(test_quic PRIVATE cppquic::cppquic GTest::gtest_main)
target_include_directories(test_quic PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

include(GoogleTest)
gtest_discover_tests(test_quic)
