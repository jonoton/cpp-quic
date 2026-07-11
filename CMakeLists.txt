cmake_minimum_required(VERSION 3.10)
project(cppquic LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()

# Force dependencies in this directory scope and below to build as static libraries
set(BUILD_SHARED_LIBS OFF)

set(CPPQUIC_UDPNET_TAG "main" CACHE STRING "Git tag/branch to use for cpp-udpnet dependency")
FetchContent_Declare(
  cppudpnet
  GIT_REPOSITORY https://github.com/jonoton/cpp-udpnet.git
  GIT_TAG ${CPPQUIC_UDPNET_TAG}
)
FetchContent_MakeAvailable(cppudpnet)

# Header-only library target
add_library(cppquic INTERFACE)
add_library(cppquic::cppquic ALIAS cppquic)

target_include_directories(cppquic INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(cppquic INTERFACE
    cppudpnet::cppudpnet
)

# Platform-specific link libraries
if(WIN32)
    target_link_libraries(cppquic INTERFACE ws2_32 bcrypt)
endif()

# Determine if this is the top-level project
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(CPPQUIC_IS_TOP_LEVEL ON)
else()
    set(CPPQUIC_IS_TOP_LEVEL OFF)
endif()

if(CPPQUIC_IS_TOP_LEVEL)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()

option(CPPQUIC_BUILD_EXAMPLES "Build example programs" ${CPPQUIC_IS_TOP_LEVEL})
option(CPPQUIC_BUILD_TESTS "Build tests" ${CPPQUIC_IS_TOP_LEVEL})

if(CPPQUIC_BUILD_TESTS)
    # Fetch GoogleTest for tests
    FetchContent_Declare(
      googletest
      GIT_REPOSITORY https://github.com/google/googletest.git
      GIT_TAG v1.14.0
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    enable_testing()
    add_subdirectory(tests)
endif()

if(CPPQUIC_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
